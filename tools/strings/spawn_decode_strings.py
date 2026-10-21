"""Preload the constant decoder into a paused emulator process, then resume.

The caller explicitly selects an emulator and target package. This driver
spawns that package, but does not replace app methods, open a QR payload, or
request a business endpoint. The app's own normal initialization still occurs.
Runtime errors and partial strings are saved immediately.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import threading
import time
import traceback


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--serial', required=True)
    parser.add_argument('--package', default='cn.com.chsi.chsiapp')
    parser.add_argument('--adb', default='adb')
    parser.add_argument('--port', type=int, default=27042, help='Host forwarding port')
    parser.add_argument('--server-port', type=int, default=27042, help='Emulator Frida server port')
    parser.add_argument('--ids', type=Path, required=True)
    parser.add_argument('--agent', type=Path, default=Path(__file__).with_name('decode_strings.frida16.js'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--runtime', choices=('qjs', 'v8'), default='qjs')
    parser.add_argument('--interval-ms', type=int, default=25)
    parser.add_argument('--wait', type=float, default=15)
    parser.add_argument('--all-ids', action='store_true', help='Default: priority IDs only')
    args = parser.parse_args()
    if not args.serial.startswith('emulator-') or not args.serial[9:].isdigit():
        parser.error('An explicit emulator-NNNN serial is required')
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+', args.package):
        parser.error('Expected an Android package name')
    if not 25 <= args.interval_ms <= 50 or not 0 < args.wait <= 15 or not 1 <= args.port <= 65535 or not 1 <= args.server_port <= 65535:
        parser.error('Use 25..50 ms polling and no more than 15 seconds total wait')

    def adb(*command):
        return subprocess.check_output([args.adb, '-s', args.serial, *command], timeout=15).decode('utf-8', 'replace').strip()

    if adb('shell', 'getprop', 'ro.kernel.qemu') != '1':
        raise RuntimeError('Target did not report ro.kernel.qemu=1')
    config = json.loads(args.ids.read_text(encoding='utf-8-sig'))
    if isinstance(config, dict):
        ids = config['ids'] if args.all_ids else config.get('priority_ids', config.get('ids'))
    else:
        ids = config
    if not isinstance(ids, list) or not 1 <= len(ids) <= 1000 or any(type(number) is not int or not 0 <= number <= 2147483647 for number in ids):
        raise RuntimeError('Expected 1..1000 nonnegative int32 constant IDs')
    ids = list(dict.fromkeys(ids))
    if not args.agent.is_file():
        parser.error('Agent script is missing')
    import frida
    if frida.__version__.split('.')[0] != '16':
        raise RuntimeError('Use Frida 16.x with its built-in Java bridge; this plain script does not import the Frida 17 bridge')
    adb('forward', 'tcp:%d' % args.port, 'tcp:%d' % args.server_port)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    errors_path = args.output.with_suffix('.errors.json')
    events_path = args.output.with_suffix('.events.jsonl')
    metadata_path = args.output.with_suffix('.metadata.json')
    decoded = {}
    errors = []
    metadata = {'serial': args.serial, 'package': args.package, 'qr_used': False,
                'constant_ids': len(ids), 'started_at_unix': time.time()}
    lock = threading.RLock()
    finished = threading.Event()

    def save():
        args.output.write_text(json.dumps(decoded, ensure_ascii=False, indent=2), encoding='utf-8')
        errors_path.write_text(json.dumps(errors, ensure_ascii=False, indent=2), encoding='utf-8')
        metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding='utf-8')

    def event(payload):
        with lock:
            with events_path.open('a', encoding='utf-8') as stream:
                stream.write(json.dumps(payload, ensure_ascii=False) + '\n')

    def on_message(message, data):
        event(message)
        with lock:
            payload = message.get('payload', {})
            if message.get('type') == 'error':
                errors.append(message)
                save()
            elif payload.get('event') == 'constant-strings':
                for row in payload['rows']:
                    decoded[str(row['id'])] = row['value']
                save()
                print(json.dumps({'decoded': len(decoded), 'elapsed_ms': payload.get('elapsedMs')}), flush=True)
            elif payload.get('event') in ('poll-progress', 'poll-done'):
                metadata['last_poll'] = payload
                save()
                print(json.dumps({'poll': payload}, ensure_ascii=False), flush=True)
                if payload['event'] == 'poll-done':
                    finished.set()

    def on_detached(reason, crash=None):
        with lock:
            metadata['detached'] = {'reason': reason, 'crash': str(crash) if crash is not None else None}
            save()
        finished.set()

    manager = frida.get_device_manager()
    address = '127.0.0.1:%d' % args.port
    device = manager.add_remote_device(address)
    session = None
    pid = None
    resumed = False
    try:
        pid = device.spawn([args.package])
        metadata['pid'] = pid
        event({'event': 'spawned-paused', 'pid': pid})
        session = device.attach(pid)
        session.on('detached', on_detached)
        script = session.create_script(args.agent.read_text(encoding='utf-8'), runtime=args.runtime)
        script.on('message', on_message)
        script.load()
        event({'event': 'plain-agent-loaded', 'pid': pid})
        # Java checks happen on the injected timer. No synchronous wait for
        # Application readiness or original Application construction is used.
        metadata['poll_start'] = script.exports_sync.startpoll(ids, round(args.wait * 1000), args.interval_ms)
        device.resume(pid)
        resumed = True
        metadata['resumed_at_unix'] = time.time()
        event({'event': 'resumed', 'pid': pid})
        finished.wait(args.wait)
        if not finished.is_set():
            metadata['host_wait_expired'] = True
    except Exception as error:
        errors.append({'type': type(error).__name__, 'message': str(error), 'traceback': traceback.format_exc()})
        print(json.dumps({'driver_error': str(error)}, ensure_ascii=False), flush=True)
    finally:
        if pid is not None and not resumed:
            try:
                device.resume(pid)
                metadata['resumed_during_cleanup'] = True
            except Exception as error:
                errors.append({'cleanup_resume': str(error)})
        if session is not None:
            try:
                session.detach()
            except Exception as error:
                errors.append({'cleanup_detach': str(error)})
        metadata['ended_at_unix'] = time.time()
        with lock:
            save()
        try:
            manager.remove_remote_device(address)
        except Exception as error:
            errors.append({'cleanup_remote_device': str(error)})
            save()
        print(json.dumps({'output': str(args.output), 'decoded': len(decoded), 'errors': len(errors)}), flush=True)
    return 0 if metadata.get('last_poll', {}).get('reason') == 'all-decoded' else 2


if __name__ == '__main__':
    raise SystemExit(main())
