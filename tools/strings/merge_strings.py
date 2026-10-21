"""Merge independent constant-decoding rounds without losing nonempty values."""
import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, nargs='+', required=True,
                        help='Round mappings, oldest first; later nonempty strings win')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--conflicts', type=Path, help='Optional decision log')
    args = parser.parse_args()
    merged = {}
    conflicts = []
    for source in args.input:
        mapping = json.loads(source.read_text(encoding='utf-8-sig'))
        if not isinstance(mapping, dict):
            parser.error('Each input must be an ID-to-string JSON object')
        for key, value in mapping.items():
            if not key.isdigit() or (value is not None and not isinstance(value, str)):
                parser.error('Mappings must use numeric string keys and string/null values')
            if key in merged and merged[key] != value:
                action = 'keep_existing_nonempty' if merged[key] and not value else 'take_later_value'
                conflicts.append({'id': key, 'input': str(source), 'action': action,
                                  'previous': merged[key], 'incoming': value})
            if merged.get(key) and not value:
                continue
            merged[key] = value
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding='utf-8')
    if args.conflicts:
        args.conflicts.parent.mkdir(parents=True, exist_ok=True)
        args.conflicts.write_text(json.dumps(conflicts, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'output': str(args.output), 'unique_ids': len(merged), 'conflicts': len(conflicts)}))


if __name__ == '__main__':
    main()
