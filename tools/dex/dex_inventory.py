"""Inventory raw ordinary DEX files without claiming protected code is restored.

Bounded parser for header/string/type/class tables and declared methods. Header
repair is opt-in, writes a separate file, and changes only magic/checksum/SHA-1.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import zlib

TARGET = 'Lcn/com/chsi/chsiapp/base/idphoto/ui/CaptureIdPhotoActivity;'


def inventory(path):
    raw = path.read_bytes()
    if len(raw) < 112:
        raise ValueError('shorter than DEX header')
    def u32(off):
        return struct.unpack_from('<I', raw, off)[0]
    size, header, endian = u32(0x20), u32(0x24), u32(0x28)
    if header != 112 or endian != 0x12345678 or size > len(raw) or size < 112:
        raise ValueError('unsupported/corrupt header or truncated dump')
    def uleb(off):
        value = 0
        for i in range(5):
            if off >= size:
                raise ValueError('uleb out of file bounds')
            byte = raw[off]
            off += 1
            value |= (byte & 127) << (i * 7)
            if byte < 128:
                return value, off
        raise ValueError('invalid uleb')
    def table(off, width):
        count, start = u32(off), u32(off + 4)
        if count > 2000000 or start + count * width > size:
            raise ValueError('table out of file bounds')
        return count, start
    sc, so = table(0x38, 4)
    tc, to = table(0x40, 4)
    mc, mo = table(0x58, 8)
    cc, co = table(0x60, 32)
    strings = []
    for i in range(sc):
        off = u32(so + i * 4)
        _, off = uleb(off)
        end = raw.find(b'\0', off, size)
        if end < 0:
            raise ValueError('unterminated string')
        strings.append(raw[off:end].decode('utf-8', errors='replace'))
    types = [strings[u32(to + i * 4)] for i in range(tc)]
    classes = []
    interesting_methods = []
    native_methods = code_methods = absent_methods = abstract_methods = 0
    parse_errors = []
    for i in range(cc):
        start = co + i * 32
        name = types[u32(start)]
        classes.append(name)
        off = u32(start + 24)
        if off == 0:
            continue
        try:
            sizes = []
            for _ in range(4):
                value, off = uleb(off)
                sizes.append(value)
            if max(sizes) > 1000000:
                raise ValueError('unreasonable class_data counts')
            for _ in range(sizes[0] + sizes[1]):
                _, off = uleb(off)
                _, off = uleb(off)
            for method_count in sizes[2:]:
                index = 0
                for _ in range(method_count):
                    diff, off = uleb(off)
                    flags, off = uleb(off)
                    code, off = uleb(off)
                    index += diff
                    if index >= mc:
                        raise ValueError('method index out of bounds')
                    if flags & 0x100:
                        native_methods += 1
                    elif flags & 0x400:
                        abstract_methods += 1
                    elif code:
                        code_methods += 1
                    else:
                        absent_methods += 1
                    if 'idphoto' in name.lower() or 'CaptureIdPhoto' in name:
                        method_name = strings[u32(mo + index * 8 + 4)]
                        item = {'class': name, 'method': method_name,
                                'access_flags': hex(flags), 'code_off': code}
                        if code and code + 16 <= size:
                            insns = u32(code + 12)
                            item['instructions_u16'] = insns
                            item['code_in_bounds'] = code + 16 + 2 * insns <= size
                            item['first_instruction_bytes'] = raw[code + 16:code + 32].hex()
                        interesting_methods.append(item)
        except (IndexError, ValueError, struct.error) as exc:
            parse_errors.append({'class': name, 'error': str(exc)})
    pattern = re.compile(r'idphoto|chesicc|CaptureIdPhoto|upload|\.chsi\.com\.cn|photo', re.I)
    hits = [value for value in strings if pattern.search(value)]
    return {
        'file': str(path), 'sha256': hashlib.sha256(raw).hexdigest(),
        'bytes': len(raw), 'declared_bytes': size,
        'magic_hex': raw[:8].hex(),
        'magic_valid': bool(re.fullmatch(rb'dex\n0[34][0-9]\x00', raw[:8])),
        'sha1_valid': raw[12:32] == hashlib.sha1(raw[32:size]).digest(),
        'adler32_valid': u32(8) == zlib.adler32(raw[12:size]) & 0xffffffff,
        'string_count': sc, 'type_count': tc, 'method_id_count': mc,
        'declared_class_count': cc, 'declares_target': TARGET in classes,
        'idphoto_classes': [c for c in classes if 'idphoto' in c.lower()],
        'declared_method_counts': {'native': native_methods, 'abstract': abstract_methods,
                                   'with_code_offset': code_methods, 'unexpected_absent': absent_methods},
        'interesting_methods': interesting_methods,
        'string_hits': hits, 'class_data_parse_errors': parse_errors,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', type=Path, help='DEX file or directory with DEX files')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--repair-header', type=Path, help='directory for separate repaired copies')
    parser.add_argument('--magic-version', choices=('035', '037', '038', '039', '040'))
    args = parser.parse_args()
    if args.magic_version and not args.repair_header:
        parser.error('--magic-version requires --repair-header')
    paths = sorted(args.input.glob('*.dex')) if args.input.is_dir() else [args.input]
    result = []
    for path in paths:
        try:
            item = inventory(path)
            if args.repair_header:
                data = bytearray(path.read_bytes()[:item['declared_bytes']])
                if not item['magic_valid']:
                    if not args.magic_version:
                        raise ValueError('broken magic: explicitly select --magic-version before repair')
                    data[:8] = b'dex\n' + args.magic_version.encode('ascii') + b'\0'
                data[12:32] = hashlib.sha1(data[32:]).digest()
                struct.pack_into('<I', data, 8, zlib.adler32(data[12:]) & 0xffffffff)
                args.repair_header.mkdir(parents=True, exist_ok=True)
                repaired = args.repair_header / path.name
                if repaired.resolve() == path.resolve():
                    raise ValueError('repair output must differ from raw input')
                repaired.write_bytes(data)
                item['repaired_copy'] = str(repaired)
                item['repair_scope'] = 'header magic if requested, SHA-1, Adler-32 only; code unchanged'
            result.append(item)
        except Exception as exc:
            result.append({'file': str(path), 'error': str(exc)})
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(rendered, encoding='utf-8')
    print(rendered)


if __name__ == '__main__':
    main()
