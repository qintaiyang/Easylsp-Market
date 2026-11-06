#!/usr/bin/env python3
"""Trusted marketplace CI: read-only PR inspection and protected fixed-artifact publishing."""
import base64
import io
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.request
import urllib.parse
import zipfile
import market

REPO = os.environ.get('GITHUB_REPOSITORY', 'qintaiyang/Easylsp-Market')
TOKEN = os.environ.get('GH_TOKEN', '')
ROOT = Path(__file__).resolve().parents[1]

class PublicRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        redirected = super().redirect_request(request, fp, code, message, headers, url)
        if redirected and urllib.parse.urlparse(request.full_url).netloc != urllib.parse.urlparse(url).netloc:
            redirected.remove_header('Authorization')
        return redirected

opener = urllib.request.build_opener(PublicRedirect())


def api(path, method='GET', body=None, binary=False):
    headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'Easylsp-market', 'X-GitHub-Api-Version': '2022-11-28'}
    if TOKEN:
        headers['Authorization'] = 'Bearer ' + TOKEN
    if binary and not path.endswith('/zip'):
        headers['Accept'] = 'application/octet-stream'
    if isinstance(body, bytes):
        headers['Content-Type'] = 'application/octet-stream'
    if isinstance(body, dict):
        body = json.dumps(body).encode(); headers['Content-Type'] = 'application/json'
    url = path if path.startswith('https://') else 'https://api.github.com' + path
    with opener.open(urllib.request.Request(url, data=body, headers=headers, method=method), timeout=60) as reply:
        data = reply.read(40 * 1024 * 1024 + 1)
        if len(data) > 40 * 1024 * 1024:
            raise ValueError('response exceeds 40 MiB')
        return data if binary else json.loads(data) if data else None


def validate_identity(manifest, resume=None):
    for path in (ROOT / 'catalog').glob('*.json'):
        previous = json.loads(path.read_text())
        if previous['catalogPluginId'] != manifest['catalogPluginId']: continue
        if previous['publisherId'] != manifest['publisherId']:
            raise ValueError('catalog identity belongs to another registered publisher')
        if previous['releaseId'] == manifest['releaseId']:
            if resume and previous.get('candidateRunId') == resume[0] and previous.get('candidateArtifactId') == resume[1]: continue
            raise ValueError('release identity is already published')
        if previous['versionCode'] >= manifest['versionCode']:
            raise ValueError('versionCode must exceed previous published/withdrawn versions')


def candidate(number, output):
    pr = api(f'/repos/{REPO}/pulls/{number}')
    files = api(f'/repos/{REPO}/pulls/{number}/files?per_page=100')
    if len(files) != 1 or files[0]['status'] not in ('added', 'modified') or not re.fullmatch(r'submissions/[A-Za-z0-9._-]+\.json', files[0]['filename']):
        raise ValueError('a submission PR must change exactly one submissions/*.json file')
    content = api(f"/repos/{pr['head']['repo']['full_name']}/contents/{files[0]['filename']}?ref={pr['head']['sha']}")
    submission = json.loads(base64.b64decode(content['content']))
    publisher = json.loads((ROOT / 'publishers' / (submission['publisherId'] + '.json')).read_text()) if market.identifier(submission['publisherId']) else None
    if not publisher or pr['user']['id'] != publisher['githubAccountId']:
        raise ValueError('PR account does not own registered publisher identity')
    repository = submission['repository']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('invalid author repository')
    author = api('/repos/' + repository)
    if author['private'] or author['id'] not in publisher['repositoryIds'] or author['owner']['id'] != publisher['githubAccountId']:
        raise ValueError('repository is not registered to the numeric publisher account')
    asset_id = int(submission['assetId']); release_id = int(submission['githubReleaseId'])
    release = api(f'/repos/{repository}/releases/{release_id}')
    asset = next(a for a in release['assets'] if a['id'] == asset_id)
    if release['draft'] or asset['name'] != 'plugin.zip' or asset['size'] > 32 * 1024 * 1024:
        raise ValueError('expected a public fixed plugin.zip asset, at most 32 MiB')
    commit = submission['sourceCommit']
    if not re.fullmatch(r'[a-f0-9]{40}', commit):
        raise ValueError('sourceCommit must be a full Git commit object ID')
    api(f'/repos/{repository}/commits/{commit}')
    output.mkdir(parents=True, exist_ok=True)
    archive = output / 'plugin.zip'
    archive.write_bytes(api(f'/repos/{repository}/releases/assets/{asset_id}', binary=True))
    manifest = market.read_release(archive)
    validate_identity(manifest)
    for field in ('catalogPluginId', 'publisherId', 'releaseId', 'versionCode'):
        if manifest[field] != submission[field]:
            raise ValueError('submission/manifest mismatch: ' + field)
    source_url = f'https://github.com/{repository}/tree/{commit}'
    if manifest['sourceUrl'] != source_url:
        raise ValueError('sourceUrl must bind the exact reviewed repository commit')
    review = {'schema': 1, 'pr': number, 'prHead': pr['head']['sha'], 'submissionPath': files[0]['filename'], 'accountId': publisher['githubAccountId'], 'repositoryId': author['id'], 'sourceCommit': commit, 'assetId': asset_id, 'githubReleaseId': release_id, 'manifest': manifest}
    (output / 'review.json').write_text(json.dumps(review, ensure_ascii=False, indent=2))
    (output / 'submission.json').write_text(json.dumps(submission, ensure_ascii=False, indent=2))
    print(json.dumps(review, ensure_ascii=False, indent=2))


def verify_review(pr, run, review, submission):
    if not pr['merged'] or pr['head']['sha'] != review['prHead'] or run['head_sha'] != review['prHead']:
        raise ValueError('merge the exact checked PR before protected publication')
    files = api(f"/repos/{REPO}/pulls/{review['pr']}/files?per_page=100")
    if len(files) != 1 or files[0]['filename'] != review['submissionPath'] or not re.fullmatch(r'submissions/[A-Za-z0-9._-]+\.json', files[0]['filename']):
        raise ValueError('reviewed PR must change only its fixed submission file')
    content = api(f"/repos/{pr['head']['repo']['full_name']}/contents/{files[0]['filename']}?ref={review['prHead']}")
    if json.loads(base64.b64decode(content['content'])) != submission:
        raise ValueError('candidate submission differs from exact PR head')
    manifest = review['manifest']
    if not market.identifier(manifest['publisherId']): raise ValueError('invalid publisher')
    publisher = json.loads((ROOT / 'publishers' / (manifest['publisherId'] + '.json')).read_text())
    if pr['user']['id'] != publisher['githubAccountId'] or review['accountId'] != publisher['githubAccountId']:
        raise ValueError('reviewed account does not own publisher identity')
    repository = submission['repository']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository): raise ValueError('invalid repository')
    author = api('/repos/' + repository)
    if author['private'] or author['id'] != review['repositoryId'] or author['id'] not in publisher['repositoryIds'] or author['owner']['id'] != publisher['githubAccountId']:
        raise ValueError('reviewed repository ownership mismatch')
    for field in ('catalogPluginId', 'publisherId', 'releaseId', 'versionCode'):
        if manifest[field] != submission[field]: raise ValueError('review identity mismatch: ' + field)
    for field in ('sourceCommit', 'assetId', 'githubReleaseId'):
        if review[field] != submission[field]: raise ValueError('review object mismatch: ' + field)
    if manifest['sourceUrl'] != f"https://github.com/{repository}/tree/{review['sourceCommit']}":
        raise ValueError('review source commit mismatch')


def publish(run_id, artifact_id):
    run = api(f'/repos/{REPO}/actions/runs/{run_id}')
    if run['event'] != 'pull_request' or run['conclusion'] != 'success' or run['path'] != '.github/workflows/candidate.yml':
        raise ValueError('expected successful candidate workflow run')
    artifact = api(f'/repos/{REPO}/actions/artifacts/{artifact_id}')
    if artifact['workflow_run']['id'] != run_id or artifact['name'] != 'reviewed-candidate' or artifact['expired']:
        raise ValueError('artifact does not belong to the selected candidate run')
    raw = api(f'/repos/{REPO}/actions/artifacts/{artifact_id}/zip', binary=True)
    with zipfile.ZipFile(io.BytesIO(raw)) as container:
        if set(container.namelist()) != {'plugin.zip', 'review.json', 'submission.json'}:
            raise ValueError('unexpected candidate artifact files')
        if any(e.file_size > (32 * 1024 * 1024 if e.filename == 'plugin.zip' else 1024 * 1024) for e in container.infolist()):
            raise ValueError('candidate artifact entry exceeds limit')
        review = json.loads(container.read('review.json'))
        submission = json.loads(container.read('submission.json'))
        archive_bytes = container.read('plugin.zip')
    pr = api(f"/repos/{REPO}/pulls/{review['pr']}")
    verify_review(pr, run, review, submission)
    # Only the immutable Actions artifact is consumed below; never fetch the author asset again.
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory); archive = directory / 'plugin.zip'; archive.write_bytes(archive_bytes)
        manifest = market.read_release(archive)
        validate_identity(manifest, (run_id, artifact_id))
        if manifest != review['manifest']:
            raise ValueError('candidate manifest mismatch')
        context = {key: manifest[key] for key in ('catalogPluginId', 'publisherId', 'releaseId', 'versionCode')}
        signature = directory / 'plugin.signature.json'
        market.sign(archive, Path(os.environ['MARKET_KEY_FILE']), os.environ.get('MARKET_KEY_ID', 'market-2026'), 'release', context, signature)
        tag = 'plugin-' + base64.urlsafe_b64encode((manifest['catalogPluginId'] + '/' + manifest['releaseId']).encode()).decode().rstrip('=')
        provenance = f"Reviewed PR #{review['pr']}; Actions run {run_id}, artifact {artifact_id}."
        try:
            release = api(f'/repos/{REPO}/releases/tags/{tag}')
        except urllib.error.HTTPError as error:
            if error.code != 404: raise
            release = api(f'/repos/{REPO}/releases', 'POST', {'tag_name': tag, 'name': manifest['name'] + ' ' + manifest['versionName'], 'body': f"{provenance}\nSource: {manifest['sourceUrl']}\n\n{manifest['changelog']}", 'draft': True})
        if not release['body'].startswith(provenance):
            raise ValueError('official tag belongs to a different reviewed candidate')
        urls = {}
        for name, payload in [('plugin.zip', archive_bytes), ('plugin.signature.json', signature.read_bytes()), ('review.json', json.dumps(review, ensure_ascii=False, indent=2).encode())]:
            uploaded = next((a for a in release['assets'] if a['name'] == name), None)
            if uploaded:
                if api(f"/repos/{REPO}/releases/assets/{uploaded['id']}", binary=True) != payload:
                    raise ValueError('official asset already exists with different bytes; never overwrite')
            else:
                url = f"https://uploads.github.com/repos/{REPO}/releases/{release['id']}/assets?name={name}"
                uploaded = api(url, 'POST', payload)
            # Draft asset URLs use temporary untagged-* names which disappear on publication.
            urls[name] = f'https://github.com/{REPO}/releases/download/{tag}/{name}'
        if release['draft']:
            api(f"/repos/{REPO}/releases/{release['id']}", 'PATCH', {'draft': False})
        record = {**manifest, 'state': 'PUBLISHED', 'downloadUrl': urls['plugin.zip'], 'signatureUrl': urls['plugin.signature.json'], 'reportUrl': f'https://github.com/{REPO}/issues/new?template=report.md', 'reviewUrl': urls['review.json'], 'candidateRunId': run_id, 'candidateArtifactId': artifact_id}
        (ROOT / 'catalog').mkdir(exist_ok=True)
        path = ROOT / 'catalog' / (manifest['catalogPluginId'] + '--' + manifest['releaseId'] + '.json')
        if path.exists() and json.loads(path.read_text()) != record:
            raise ValueError('immutable catalog record already exists with different metadata')
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n')
    generate_catalog(str(run_id) + '-' + str(artifact_id))


def generate_catalog(revision):
    records = [json.loads(p.read_text()) for p in sorted((ROOT / 'catalog').glob('*.json'))]
    publishers = [json.loads(p.read_text()) for p in (ROOT / 'publishers').glob('*.json')]
    public = ROOT / 'public'; public.mkdir(exist_ok=True)
    index = public / 'catalog.json'; index.write_text(json.dumps(market.catalog(records, publishers, revision), ensure_ascii=False, indent=2) + '\n')
    market.sign(index, Path(os.environ['MARKET_KEY_FILE']), os.environ.get('MARKET_KEY_ID', 'market-2026'), 'catalog', {'catalogRevision': revision}, public / 'catalog.signature.json')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(); sub = parser.add_subparsers(dest='command', required=True)
    check = sub.add_parser('candidate'); check.add_argument('pr', type=int); check.add_argument('--output', type=Path, default=Path('candidate'))
    release = sub.add_parser('publish'); release.add_argument('run', type=int); release.add_argument('artifact', type=int)
    catalog = sub.add_parser('catalog'); catalog.add_argument('revision')
    withdrawal = sub.add_parser('withdraw'); withdrawal.add_argument('plugin'); withdrawal.add_argument('release'); withdrawal.add_argument('reason')
    args = parser.parse_args()
    if args.command == 'candidate': candidate(args.pr, args.output)
    elif args.command == 'publish': publish(args.run, args.artifact)
    elif args.command == 'withdraw':
        if not market.identifier(args.plugin) or not market.identifier(args.release) or not args.reason.strip():
            raise ValueError('exact identity and nonempty withdrawal reason required')
        path = ROOT / 'catalog' / (args.plugin + '--' + args.release + '.json')
        record = json.loads(path.read_text())
        if record['state'] != 'PUBLISHED': raise ValueError('release is already withdrawn')
        from datetime import datetime, timezone
        record.update(state='WITHDRAWN', withdrawalReason=args.reason, withdrawnAt=datetime.now(timezone.utc).isoformat())
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n')
        generate_catalog('withdraw-' + os.environ['GITHUB_RUN_ID'])
    else: generate_catalog(args.revision)
