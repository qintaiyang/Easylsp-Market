#!/usr/bin/env python3
"""Single artifact reception boundary, including stripped ELF dynamic symbols."""
import json
import struct
import sys
from pathlib import Path


def inspect(path, declared_min_api=34):
    data = Path(path).read_bytes()
    def unpack(fmt, offset):
        size = struct.calcsize('<' + fmt)
        if offset < 0 or offset + size > len(data):
            raise ValueError('ELF metadata outside artifact')
        return struct.unpack_from('<' + fmt, data, offset)
    if data[:7] != b'\x7fELF\x02\x01\x01':
        raise ValueError('Expected ELF64 little-endian')
    kind, machine = unpack('HH', 16)
    if (kind, machine) != (3, 183):
        raise ValueError('Expected Android AArch64 ET_DYN')
    phoff = unpack('Q', 32)[0]
    stride, count = unpack('HH', 54)
    if stride < 56 or not 0 < count <= 4096:
        raise ValueError('Invalid program header table')
    headers = [unpack('IIQQQQQQ', phoff + i * stride) for i in range(count)]
    loads, dynamic, api = [], {}, None
    for ptype, flags, offset, vaddr, _, filesz, memsz, align in headers:
        if offset + filesz > len(data) or filesz > memsz:
            raise ValueError('Invalid segment bounds')
        if ptype == 1:
            if align < 16384 or align & (align - 1) or offset % align != vaddr % align:
                raise ValueError('PT_LOAD must support 16 KB alignment')
            loads.append((offset, vaddr, filesz, align))
        if ptype == 2:
            for cursor in range(offset, offset + filesz, 16):
                tag, value = unpack('qQ', cursor)
                if tag == 0:
                    break
                dynamic.setdefault(tag, []).append(value)
        if ptype == 4:
            cursor = offset
            while cursor + 12 <= offset + filesz:
                namesz, descsz, ntype = unpack('III', cursor)
                cursor += 12
                name = data[cursor:cursor + namesz]
                cursor += (namesz + 3) & ~3
                if cursor + descsz > offset + filesz:
                    raise ValueError('Invalid ELF note')
                if name == b'Android\0' and ntype == 1 and descsz >= 4:
                    api = unpack('I', cursor)[0]
                cursor += (descsz + 3) & ~3
    def file_offset(address, size=1):
        for offset, vaddr, length, _ in loads:
            if vaddr <= address and address + size <= vaddr + length:
                return offset + address - vaddr
        raise ValueError('Dynamic address outside file-backed PT_LOAD')
    if not loads or api != declared_min_api:
        raise ValueError(f'Expected Android min API {declared_min_api} note; got {api}')
    strsize = dynamic[10][0]
    stroff = file_offset(dynamic[5][0], strsize)
    def string(index):
        if not 0 <= index < strsize:
            raise ValueError('Invalid dynamic string offset')
        end = data.find(b'\0', stroff + index, stroff + strsize)
        if end < 0:
            raise ValueError('Unterminated dynamic string')
        return data[stroff + index:end].decode('utf-8')
    needed = [string(index) for index in dynamic.get(1, [])]
    if set(needed) - {'libc.so', 'libdl.so', 'liblog.so', 'libm.so'}:
        raise ValueError(f'Unsupported dynamic dependencies: {needed}')
    # LLD emits both hashes by explicit flag; DT_HASH gives the complete dynamic symbol count.
    symcount = unpack('II', file_offset(dynamic[4][0], 8))[1]
    if dynamic[11][0] != 24:
        raise ValueError('Invalid dynamic symbol size')
    symoff = file_offset(dynamic[6][0], symcount * 24)
    exports = []
    for i in range(symcount):
        name, info, other, section, _, _ = unpack('IBBHQQ', symoff + i * 24)
        if section != 0 and info >> 4 in (1, 2) and other & 3 in (0, 3):
            exports.append((string(name), info & 15))
    if exports != [('easylsp_plugin_init_v1', 2)]:
        raise ValueError(f'Only the SDK function entry may be exported: {exports}')
    return dict(elfClass=64, machine=183, type='ET_DYN', minApi=api, needed=needed,
                loadAlignments=[segment[3] for segment in loads], exports=[name for name, _ in exports])

if __name__ == '__main__':
    print(json.dumps(inspect(sys.argv[1])))
