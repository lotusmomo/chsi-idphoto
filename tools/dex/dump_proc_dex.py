"""Read-only /proc/PID/mem DEX fallback for the task's explicit emulator.

Requires an already root adb shell and an already running task application.
Does not spawn the application, inject agents, change process state, alter
network settings, or touch any photo/QR credential. No default ADB target.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import struct
import subprocess
import time

DEFAULT_PACKAGE = 'cn.com.chsi.chsiapp'
MIB = 1024 * 1024
MAP_LINE = re.compile(r'^([0-9a-f]+)-([0-9a-f]+)\s+([rwxps-]{4})\s+([0-9a-f]+)\s+\S+\s+\d+\s*(.*)$')
MAGIC = re.compile(rb'dex\n0[34][0-9]\x00')
FUZZY = b'\x70\x00\x00\x00\x78\x56\x34\x12'


def dex_header(data, start, max_size):
    if start < 0 or start + 112 > len(data):
        return None
    def u32(off):
        return struct.unpack_from('<I', data, start + off)[0]
    size = u32(0x20)
    if u32(0x24) != 112 or u32(0x28) != 0x12345678 or size < 112 or size > max_size:
        return None
    if start + size > len(data):
        return {'valid': False, 'reason': 'candidate crosses dumped mapping boundary', 'size': size}
    counts = []
    for off, width in zip((0x38, 0x40, 0x48, 0x50, 0x58, 0x60), (4, 4, 12, 8, 8, 32)):
        count, offset = u32(off), u32(off + 4)
        if (count == 0 and offset != 0) or (count and (offset < 112 or offset + count * width > size)):
            return None
        counts.append(count)
    if not counts[0] or not counts[1] or not counts[5]:
        return None
    if u32(0x68) + u32(0x6c) > size:
        return None
    return {'valid': True, 'size': size, 'magic_valid': MAGIC.fullmatch(data[start:start + 8]) is not None,
            'class_count': counts[5], 'string_count': counts[0]}


def extract(data, base, output, emit, source, max_size):
    positions = {match.start(): 'magic' for match in MAGIC.finditer(data)}
    offset = data.find(FUZZY)
    while offset >= 0:
        positions.setdefault(offset - 0x24, 'header-size-endian')
        offset = data.find(FUZZY, offset + 1)
    for pos, method in sorted(positions.items()):
        header = dex_header(data, pos, max_size)
        if header is None:
            continue
        meta = dict(header, source=source, source_offset=pos, address=hex(base + pos), method=method)
        if not header['valid']:
            emit('candidate-rejected', meta)
            continue
        dex = data[pos:pos + header['size']]
        digest = hashlib.sha256(dex).hexdigest()
        path = output / (digest + '.dex')
        existed = path.exists()
        if not existed:
            path.write_bytes(dex)
        emit('dex', dict(meta, sha256=digest, path=str(path), duplicate=existed))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--adb', default='adb')
    parser.add_argument('--package', default=DEFAULT_PACKAGE)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--pid', type=int, help='optional PID; still verified against task package cmdline')
    parser.add_argument('--max-range-mib', type=int, default=128)
    parser.add_argument('--max-total-mib', type=int, default=512)
    parser.add_argument('--discard-ranges', action='store_true', help='retain maps/logs/DEX but remove raw range bytes')
    parser.add_argument('--timeout', type=int, default=60, help='per-command timeout seconds, at most 60')
    args = parser.parse_args()
    if not re.fullmatch(r'emulator-\d+', args.serial):
        parser.error('An explicit emulator- serial is required; physical devices are refused.')
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+', args.package):
        parser.error('Expected an Android package name')
    if not (1 <= args.max_range_mib <= 128 and 1 <= args.max_total_mib <= 1024 and 1 <= args.timeout <= 60):
        parser.error('Limits: range 1..128 MiB, total 1..1024 MiB, timeout 1..60 seconds.')
    args.output.mkdir(parents=True, exist_ok=True)
    events_path = args.output / 'proc-events.jsonl'
    errors_path = args.output / 'proc-errors.txt'
    def emit(kind, meta):
        event = dict(kind=kind, timestamp=time.time(), **meta)
        with events_path.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps(event, ensure_ascii=False) + '\n')
        print(json.dumps(event, ensure_ascii=False), flush=True)
    def adb(*cmd):
        return subprocess.run([args.adb, '-s', args.serial, *cmd], capture_output=True, timeout=args.timeout)
    def checked_text(*cmd):
        proc = adb(*cmd)
        if proc.returncode:
            raise RuntimeError(proc.stderr.decode(errors='replace'))
        return proc.stdout.decode(errors='replace').strip()
    if checked_text('shell', 'getprop', 'ro.kernel.qemu') != '1':
        raise RuntimeError('Target does not report ro.kernel.qemu=1; refusing memory read.')
    if checked_text('shell', 'id', '-u') != '0':
        raise RuntimeError('This fallback requires an already root ADB shell. It will not change device root state.')
    if args.pid:
        pids = [args.pid]
    else:
        pid_text = checked_text('shell', 'pidof', args.package)
        pids = [int(value) for value in pid_text.split() if value.isdigit()]
    if not pids:
        raise RuntimeError('Task application is not running; this tool does not start it.')
    max_range = args.max_range_mib * MIB
    max_total = args.max_total_mib * MIB
    total = 0
    for pid in pids:
        proc = adb('exec-out', 'cat', '/proc/%d/cmdline' % pid)
        cmdline = proc.stdout.split(b'\0', 1)[0].decode(errors='replace')
        if proc.returncode or not (cmdline == args.package or cmdline.startswith(args.package + ':')):
            raise RuntimeError('PID %d is not the task package: %r' % (pid, cmdline))
        maps_result = adb('exec-out', 'cat', '/proc/%d/maps' % pid)
        (args.output / ('maps-%d.txt' % pid)).write_bytes(maps_result.stdout)
        if maps_result.returncode:
            raise RuntimeError('Cannot read maps for verified PID %d.' % pid)
        ranges = []
        for line in maps_result.stdout.decode(errors='replace').splitlines():
            match = MAP_LINE.match(line)
            if not match:
                continue
            start, end = int(match[1], 16), int(match[2], 16)
            permissions, path = match[3], match[5]
            related = args.package in path
            anonymous = not path or path == '[heap]' or path.startswith('[anon:') or path.startswith('/memfd:')
            if permissions[0] != 'r' or not (related or anonymous):
                continue
            size = end - start
            if size > max_range:
                emit('range-skipped', {'pid': pid, 'base': hex(start), 'size': size,
                                       'path': path, 'reason': 'range exceeds limit'})
                continue
            # App mappings first, then small read-only anonymous mappings (DEX is
            # often here), then remaining writable heap memory.
            priority = (0 if related else 1 if permissions[1] != 'w' else 2, size)
            ranges.append((priority, start, end, permissions, path))
        ranges.sort()
        emit('process', {'pid': pid, 'cmdline': cmdline, 'selected_ranges': len(ranges),
                         'selected_bytes': sum(item[2] - item[1] for item in ranges)})
        for _, start, end, permissions, path in ranges:
            size = end - start
            if total + size > max_total:
                emit('range-skipped', {'pid': pid, 'base': hex(start), 'size': size,
                                       'path': path, 'reason': 'total byte budget'})
                continue
            page = 4096
            aligned = start // page * page
            count = math.ceil((end - aligned) / page)
            name = 'pid%d-%x-%x.bin' % (pid, start, end)
            meta = {'pid': pid, 'base': hex(start), 'size': size, 'permissions': permissions,
                    'path': path, 'range_file': name}
            try:
                # No shell command interpolation; all arguments are separate.
                result = adb('exec-out', 'dd', 'if=/proc/%d/mem' % pid,
                             'bs=4096', 'skip=%d' % (aligned // page), 'count=%d' % count)
                total += size
                # exec-out may append remote dd statistics to its binary channel.
                # Restrict bytes to the exact requested mapping and record tail.
                begin = start - aligned
                data = result.stdout[begin:begin + size]
                tail = result.stdout[begin + size:]
                meta.update(returncode=result.returncode, received_bytes=len(data),
                            stderr=result.stderr.decode(errors='replace'),
                            trailing_output=tail[:2048].decode(errors='replace'))
                if result.returncode or len(data) != size:
                    emit('range-read-error', meta)
                    with errors_path.open('a', encoding='utf-8') as stream:
                        stream.write(json.dumps(meta, ensure_ascii=False) + '\n')
                else:
                    emit('range-read', meta)
                if data:
                    if not args.discard_ranges:
                        (args.output / name).write_bytes(data)
                    extract(data, start, args.output, emit, name, max_range)
            except Exception as exc:
                meta['error'] = str(exc)
                emit('range-exception', meta)
                with errors_path.open('a', encoding='utf-8') as stream:
                    stream.write(json.dumps(meta, ensure_ascii=False) + '\n')
    emit('complete', {'attempted_bytes': total, 'byte_budget': max_total,
                      'dex_files': len(list(args.output.glob('*.dex')))})


if __name__ == '__main__':
    main()
