"""Collect integer StubApp.getString2 constants from a local JADX source tree."""
import argparse
import json
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sources', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--relative-prefix', action='append', default=[],
                        help='Optional source-relative directory prefix; repeat to select several packages')
    args = parser.parse_args()
    if not args.sources.is_dir():
        parser.error('JADX source directory is missing')
    prefixes = [value.replace('\\', '/').strip('/') + '/' for value in args.relative_prefix]
    pattern = re.compile(r'StubApp\.getString2\(\s*(\d+)\s*\)')
    occurrences = {}
    for source in sorted(args.sources.rglob('*.java')):
        relative = source.relative_to(args.sources).as_posix()
        if prefixes and not relative.startswith(tuple(prefixes)):
            continue
        for number, line in enumerate(source.read_text(encoding='utf-8', errors='replace').splitlines(), 1):
            for match in pattern.finditer(line):
                occurrences.setdefault(match.group(1), []).append({'file': relative, 'line': number})
    ids = sorted(map(int, occurrences))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({'ids': ids, 'priority_ids': ids, 'occurrences': occurrences},
                                     ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'output': str(args.output), 'ids': len(ids)}))


if __name__ == '__main__':
    main()
