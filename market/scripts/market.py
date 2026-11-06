#!/usr/bin/env python3
"""Offline release/catalog tooling. Ed25519 uses OpenSSL; no digest scans or network writes."""
import argparse
import base64
import json
import re
from pathlib import Path, PurePosixPath
import struct
import subprocess
import tempfile
import zipfile

CAPABILITIES = {'native.symbol', 'native.elf-vaddr', 'native.module-lifecycle', 'native.chain', 'native.jni-register', 'native.intercept', 'java.beanshell'}


def identifier(value):
    return isinstance(value, str) and 1 <= len(value) <= 128 and value[0].isalnum() and all(c.isascii() and (c.isalnum() or c in '._:-') for c in value)


def read_release(path):
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > 200 or sum(e.file_size for e in entries) > 32 * 1024 * 1024:
            raise ValueError('archive exceeds 200 entries / 32 MiB')
        seen = set()
        for entry in entries:
            name = entry.filename
            parts = name.removesuffix('/').split('/')
            if not name or name.startswith('/') or '\\' in name or any(p in ('', '.', '..') for p in parts) or name in seen or (entry.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError(f'invalid/duplicate/symlink archive entry: {name}')
            if any('/'.join(parts[:i]) in seen for i in range(1, len(parts))):
                raise ValueError('file/directory path conflict')
            seen.add(name)
            limit = 16 * 1024 * 1024 if name == 'native/arm64-v8a/plugin.so' or name.startswith('java/lib/') else 1024 * 1024
            if entry.file_size > limit:
                raise ValueError(f'entry too large: {name}')
        files = {e.filename: archive.read(e) for e in entries if not e.is_dir()}
    if any(other.startswith(name + '/') for name in files for other in files if other != name):
        raise ValueError('file/directory path conflict')
    manifest = json.loads(files['manifest.json'])
    if manifest['formatVersion'] != 3 or manifest['runtime'] not in ('NATIVE', 'BEANSHELL'):
        raise ValueError('unsupported release format/runtime')
    for key in ('catalogPluginId', 'publisherId', 'releaseId'):
        if not identifier(manifest[key]):
            raise ValueError(f'invalid {key}')
    if not isinstance(manifest['versionCode'], int) or manifest['versionCode'] < 1 or manifest['pluginAbi'] != 1:
        raise ValueError('invalid release version/ABI')
    for key in ('name', 'versionName', 'license', 'sdkVersion', 'channel', 'publishedAt'):
        if not isinstance(manifest[key], str) or not manifest[key].strip():
            raise ValueError(f'missing {key}')
    if type(manifest['minHostVersion']) is not int or not 1 <= manifest['minHostVersion'] <= 9:
        raise ValueError('unsupported minimum host version')
    target = manifest['target']
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+', target['packageName']) or target['processScope'] not in ('main', 'children', 'all', 'exact'):
        raise ValueError('invalid target')
    if target['processScope'] == 'exact' and not (target['processName'] == target['packageName'] or target['processName'].startswith(target['packageName'] + ':')):
        raise ValueError('process does not belong to target')
    if not 0 <= target.get('minVersionCode', 0) <= target.get('maxVersionCode', 2**63 - 1):
        raise ValueError('invalid target version range')
    for key in ('description', 'changelog'):
        if not isinstance(manifest[key], str):
            raise ValueError(f'invalid {key}')
    if not manifest['sourceUrl'].startswith('https://') or not set(manifest['requiredCapabilities']) <= CAPABILITIES:
        raise ValueError('invalid source URL or unsupported capabilities')
    if 'README.md' not in files or 'LICENSE' not in files:
        raise ValueError('README.md and LICENSE are required')
    runtime = manifest['runtime']
    expected = 'native/arm64-v8a/plugin.so' if runtime == 'NATIVE' else 'java/main.java'
    if len(manifest['artifacts']) != 1 or manifest['artifacts'][0]['artifactPath'] != expected:
        raise ValueError('expected exactly one fixed artifact')
    artifact = manifest['artifacts'][0]
    if not 1 <= artifact['minApi'] <= 34 or artifact['abi'] != ('arm64-v8a' if runtime == 'NATIVE' else 'any'):
        raise ValueError('unsupported artifact platform')
    common = {'manifest.json', 'README.md', 'LICENSE', 'config.schema.json'}
    for name, data in files.items():
        allowed = name in common or (runtime == 'NATIVE' and (name == expected or name.startswith(('src/', 'include/')))) or (runtime == 'BEANSHELL' and (name == expected or name.startswith('java/lib/')))
        if not allowed:
            raise ValueError(f'undeclared payload: {name}')
        if name != expected or runtime != 'NATIVE':
            if not name.startswith('java/lib/'):
                if b'\0' in data:
                    raise ValueError(f'binary in text file: {name}')
                data.decode('utf-8')
    if 'config' in manifest:
        if runtime != 'NATIVE':
            raise ValueError('Java configuration is not implemented')
        config = manifest['config']
        if config['schemaPath'] != 'config.schema.json' or config['version'] < 1:
            raise ValueError('invalid config declaration')
        validate_config(json.loads(files['config.schema.json']), config['defaults'])
    if runtime == 'NATIVE':
        # The SDK validator checks segments, exports and dependencies; minApi is distinct in v3.
        import importlib.util
        validator_path = Path(__file__).resolve().parents[2] / 'scripts/native-sdk/validate-plugin.py'
        spec = importlib.util.spec_from_file_location('artifact_boundary', validator_path)
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        with tempfile.NamedTemporaryFile(suffix='.so') as so:
            so.write(files[expected]); so.flush()
            validator.inspect(so.name, declared_min_api=artifact['minApi'])
    return manifest


def validate_config(schema, values):
    if schema['type'] != 'object' or schema.get('additionalProperties', False) is not False or set(schema) - {'type', 'properties', 'required', 'additionalProperties', 'title', 'description'}:
        raise ValueError('unsupported config schema')
    properties = schema['properties']
    for field in properties.values():
        if field['type'] not in ('boolean', 'number', 'integer', 'string') or set(field) - {'type', 'title', 'description', 'enum', 'minimum', 'maximum', 'minLength', 'maxLength'}:
            raise ValueError('unsupported config field')
    if not isinstance(values, dict) or set(values) - set(properties) or set(schema.get('required', [])) - set(values) or len(json.dumps(values, ensure_ascii=False).encode()) > 8192:
        raise ValueError('invalid config object')
    for key, value in values.items():
        field = properties[key]
        valid = {'boolean': type(value) is bool, 'number': type(value) in (int, float), 'integer': type(value) in (int, float) and value % 1 == 0, 'string': isinstance(value, str)}[field['type']]
        if not valid or ('enum' in field and value not in field['enum']):
            raise ValueError('invalid config type/enum')
        if type(value) in (int, float) and not field.get('minimum', -1.7976931348623157e308) <= value <= field.get('maximum', 1.7976931348623157e308):
            raise ValueError('config numeric range')
        if isinstance(value, str) and not field.get('minLength', 0) <= len(value) <= field.get('maxLength', 8192):
            raise ValueError('config string length')


def signature_input(metadata, payload):
    if metadata['kind'] == 'release':
        names = ('keyId', 'catalogPluginId', 'publisherId', 'releaseId', 'versionCode')
    elif metadata['kind'] == 'catalog':
        names = ('keyId', 'catalogRevision')
    else:
        raise ValueError('unknown signature domain')
    result = b'Easylsp-Signature-v1\0'
    for name in ('kind', *names):
        value = str(metadata[name]).encode('utf-8')
        result += struct.pack('>I', len(value)) + value
    return result + struct.pack('>Q', len(payload)) + payload


def sign(payload_path, key, key_id, kind, context, output):
    payload = payload_path.read_bytes()
    metadata = {'schema': 1, 'kind': kind, 'keyId': key_id, **context}
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        data = directory / 'input'; data.write_bytes(signature_input(metadata, payload))
        signature = directory / 'signature'
        subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(key), '-in', str(data), '-out', str(signature)], check=True)
        metadata['signature'] = base64.b64encode(signature.read_bytes()).decode('ascii')
    output.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + '\n')


def verify(payload_path, metadata_path, public_key):
    metadata = json.loads(metadata_path.read_text())
    if metadata['schema'] != 1:
        raise ValueError('unsupported signature schema')
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        data = directory / 'input'; data.write_bytes(signature_input(metadata, payload_path.read_bytes()))
        signature = directory / 'signature'; signature.write_bytes(base64.b64decode(metadata['signature'], validate=True))
        subprocess.run(['openssl', 'pkeyutl', '-verify', '-rawin', '-pubin', '-inkey', str(public_key), '-in', str(data), '-sigfile', str(signature)], check=True, stdout=subprocess.DEVNULL)
    return metadata


def catalog(records, publishers, revision):
    owners = {row['publisherId']: row for row in publishers}
    identities = set()
    plugin_owners, versions = {}, set()
    releases = []
    for record in records:
        if record['publisherId'] not in owners or not isinstance(owners[record['publisherId']]['githubAccountId'], int):
            raise ValueError('unregistered publisher')
        plugin_id = record['catalogPluginId']
        if plugin_id in plugin_owners and plugin_owners[plugin_id] != record['publisherId']:
            raise ValueError('catalog identity cannot change publisher')
        plugin_owners[plugin_id] = record['publisherId']
        version = (plugin_id, record['versionCode'])
        if version in versions: raise ValueError('duplicate release versionCode')
        versions.add(version)
        identity = (record['catalogPluginId'], record['releaseId'])
        if identity in identities:
            raise ValueError('duplicate immutable release identity')
        identities.add(identity)
        if record['state'] not in ('PUBLISHED', 'WITHDRAWN'):
            raise ValueError('invalid catalog state')
        for key in ('downloadUrl', 'signatureUrl', 'reportUrl'):
            if not record[key].startswith('https://github.com/'):
                raise ValueError('catalog links must use fixed public GitHub objects')
        releases.append(record)
    return {'schema': 1, 'catalogRevision': revision, 'releases': sorted(releases, key=lambda r: (r['catalogPluginId'], r['versionCode']))}


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest='command', required=True)
    check = commands.add_parser('check-release'); check.add_argument('archive', type=Path)
    signing = commands.add_parser('sign'); signing.add_argument('payload', type=Path); signing.add_argument('--key', type=Path, required=True); signing.add_argument('--key-id', required=True); signing.add_argument('--kind', choices=['release', 'catalog'], required=True); signing.add_argument('--context', type=Path, required=True); signing.add_argument('--output', type=Path, required=True)
    verification = commands.add_parser('verify'); verification.add_argument('payload', type=Path); verification.add_argument('--metadata', type=Path, required=True); verification.add_argument('--public-key', type=Path, required=True)
    index = commands.add_parser('catalog'); index.add_argument('--records', type=Path, required=True); index.add_argument('--publishers', type=Path, required=True); index.add_argument('--revision', required=True); index.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'check-release': print(json.dumps(read_release(args.archive), ensure_ascii=False, indent=2))
    elif args.command == 'sign': sign(args.payload, args.key, args.key_id, args.kind, json.loads(args.context.read_text()), args.output)
    elif args.command == 'verify': print(json.dumps(verify(args.payload, args.metadata, args.public_key)))
    else: args.output.write_text(json.dumps(catalog(json.loads(args.records.read_text()), json.loads(args.publishers.read_text()), args.revision), ensure_ascii=False, indent=2) + '\n')

if __name__ == '__main__':
    main()
