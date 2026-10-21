"""Write a separate JADX source tree with decoded constant strings annotated."""
import argparse
import json
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sources', type=Path, required=True)
    parser.add_argument('--strings', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    sources_root, output_root = args.sources.resolve(), args.output.resolve()
    if sources_root == output_root or sources_root in output_root.parents or output_root in sources_root.parents:
        parser.error('Output must be separate from the raw source directory')
    if not args.sources.is_dir():
        parser.error('JADX source directory is missing')
    values = json.loads(args.strings.read_text(encoding='utf-8-sig'))
    pattern = re.compile(r'StubApp\.getString2\(\s*(\d+)\s*\)')
    count = 0
    files = 0

    def replace(match):
        nonlocal count
        key = match.group(1)
        if key not in values:
            return match.group(0)
        count += 1
        # This is an analysis view, not a compilable rebuild. Preserve the ID.
        return '(/* StubApp.getString2(%s) */ %s)' % (key, json.dumps(values[key], ensure_ascii=False))

    for source in args.sources.rglob('*.java'):
        original = source.read_text(encoding='utf-8', errors='replace')
        updated = pattern.sub(replace, original)
        if updated != original:
            destination = args.output / source.relative_to(args.sources)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(updated, encoding='utf-8')
            files += 1
    print(json.dumps({'output': str(args.output.resolve()), 'files': files, 'replacements': count}))


if __name__ == '__main__':
    main()
