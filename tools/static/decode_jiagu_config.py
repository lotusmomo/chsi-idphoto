#!/usr/bin/env python3
"""Recover only printable Jiagu configuration records from this APK.

This is a bounded static metadata decoder. It does not recover business DEX,
execute native libraries, contact services, or process any external QR token.
The byte substitution is inferred from the observed config records and is
validated against each record's measured boundaries. Unknown nibbles fail.
"""
import argparse
import json
import re
import struct
import zipfile
from pathlib import Path

TAG = bytes.fromhex('102b0000')
NIBBLE_MAP = {0x0: 0x0, 0x1: 0x7, 0x2: 0x6, 0x3: 0x5,
              0x5: 0x3, 0x6: 0x2, 0x7: 0x1, 0xc: 0x4}


def decode_config_byte(value):
    high = value >> 4
    if high not in NIBBLE_MAP:
        raise ValueError('Unsupported high nibble: %x' % high)
    return (NIBBLE_MAP[high] << 4) | (value & 15)


def decode_config_bytes(data):
    return bytes(decode_config_byte(value) for value in data)


def decode_config(apk):
    with zipfile.ZipFile(apk) as archive:
        dex = archive.read('classes.dex')
    if not dex.startswith(b'dex\n'):
        raise ValueError('Input does not start with DEX magic')
    data_size, data_off = struct.unpack_from('<II', dex, 0x68)
    append_off = data_off + data_size
    append = dex[append_off:]
    if append[:4] != bytes.fromhex('71680001'):
        raise ValueError('Unexpected append magic')
    declared_size, field_at_8 = struct.unpack_from('<II', append, 4)
    config_off = append_off + 12
    decoded = bytes(value ^ 0xc6 for value in append[12:])
    markers = [match.start() for match in re.finditer(re.escape(TAG), decoded)]
    records = []
    for index, offset in enumerate(markers[:-1]):
        next_offset = markers[index + 1]
        try:
            lens = decode_config_bytes(decoded[offset + 4:offset + 12])
            key_len, value_len = struct.unpack('<II', lens)
            raw = decoded[offset + 12:next_offset]
            text = decode_config_bytes(raw)
            if key_len + value_len != len(text):
                break
            if any(value < 0x20 or value > 0x7e for value in text):
                break
            key = text[:key_len].decode('ascii')
            value = text[key_len:].decode('ascii')
        except (ValueError, UnicodeError):
            break
        records.append({'offset': config_off + offset,
                        'offset_hex': hex(config_off + offset),
                        'key': key, 'value': value})
    return {'input': str(apk), 'dex_length': len(dex),
            'append_offset': append_off, 'append_offset_hex': hex(append_off),
            'append_magic_hex': append[:4].hex(),
            'append_length': len(append), 'header_u32_at_4': declared_size,
            'header_u32_at_8': field_at_8,
            'header_u32_at_4_equals_append_length_minus_11': declared_size == len(append) - 11,
            'config_offset': config_off, 'config_offset_hex': hex(config_off),
            'decoder_scope': 'Printable config records only; inferred substitution validated against record boundaries.',
            'records': records,
            'limitations': ['No business DEX recovered.',
                            'The append header field at +8 is not interpreted.',
                            'Binary records and main payload are not decoded.',
                            'No APK or native library executed; no network requests.']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('apk', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = decode_config(args.apk)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=True) + '\n', encoding='ascii')
    print('Saved %d printable records to %s' % (len(result['records']), args.output))


if __name__ == '__main__':
    main()
