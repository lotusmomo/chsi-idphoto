"""Reconstruct a public RSA key from local XML and recovered string constants.

All inputs and outputs are explicit CLI paths. This script does not make a
network request, read a QR payload, or acquire a service session.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def read_tlv(data, offset=0):
    if offset < 0 or offset + 2 > len(data):
        raise ValueError('Truncated DER tag/length')
    tag = data[offset]
    length = data[offset + 1]
    start = offset + 2
    if length & 0x80:
        size = length & 0x7f
        if size == 0 or size > 4 or start + size > len(data):
            raise ValueError('Unsupported or truncated DER length')
        length = int.from_bytes(data[start:start + size], 'big')
        start += size
    end = start + length
    if end > len(data):
        raise ValueError('DER value extends past input')
    return tag, data[start:end], end


def rsa_metadata(der):
    tag, sequence, end = read_tlv(der)
    if tag != 0x30 or end != len(der):
        raise ValueError('Expected one SubjectPublicKeyInfo SEQUENCE')
    tag, algorithm, next_offset = read_tlv(sequence)
    if tag != 0x30:
        raise ValueError('Expected AlgorithmIdentifier')
    oid_tag, oid, _ = read_tlv(algorithm)
    if oid_tag != 6 or oid != bytes.fromhex('2a864886f70d010101'):
        raise ValueError('Expected rsaEncryption OID')
    tag, bits, end = read_tlv(sequence, next_offset)
    if tag != 3 or not bits or bits[0] != 0 or end != len(sequence):
        raise ValueError('Expected byte-aligned public-key BIT STRING')
    tag, rsa, end = read_tlv(bits[1:])
    if tag != 0x30 or end != len(bits) - 1:
        raise ValueError('Expected RSAPublicKey SEQUENCE')
    tag, modulus_bytes, next_offset = read_tlv(rsa)
    if tag != 2 or not modulus_bytes or modulus_bytes[0] & 0x80:
        raise ValueError('Expected nonnegative RSA modulus')
    tag, exponent_bytes, end = read_tlv(rsa, next_offset)
    if tag != 2 or not exponent_bytes or exponent_bytes[0] & 0x80 or end != len(rsa):
        raise ValueError('Expected nonnegative RSA exponent')
    modulus = int.from_bytes(modulus_bytes, 'big')
    exponent = int.from_bytes(exponent_bytes, 'big')
    if modulus <= 0 or exponent < 3 or exponent % 2 == 0:
        raise ValueError('Invalid RSA public values')
    return {'algorithm': 'RSA', 'der_bytes': len(der), 'modulus_bits': modulus.bit_length(),
            'exponent': exponent, 'sha256_der': hashlib.sha256(der).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--resources', type=Path, required=True, help='Local res/values/strings.xml')
    parser.add_argument('--strings', type=Path, required=True, help='Merged ID-to-string JSON')
    parser.add_argument('--resource-name', default='k1')
    parser.add_argument('--string-ids', nargs='+', default=['7662', '7660', '7661'],
                        help='Recovered string IDs, in assembly order after the XML resource')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    values = json.loads(args.strings.read_text(encoding='utf-8-sig'))
    xml = ET.parse(args.resources).getroot()
    matching = [node for node in xml if node.tag == 'string' and node.attrib.get('name') == args.resource_name]
    if len(matching) != 1 or not matching[0].text:
        parser.error('Expected exactly one nonempty named string resource')
    parts = [matching[0].text]
    for key in args.string_ids:
        value = values.get(str(key))
        if not isinstance(value, str) or not value:
            parser.error('Missing or empty recovered key part: ' + str(key))
        parts.append(value)
    compact_base64 = ''.join(''.join(parts).split())
    der = base64.b64decode(compact_base64, validate=True)
    metadata = rsa_metadata(der)
    metadata['source'] = {'resource_name': args.resource_name, 'string_ids_in_order': args.string_ids}
    metadata['public_key_der_base64'] = base64.b64encode(der).decode('ascii')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key: value for key, value in metadata.items() if key != 'public_key_der_base64'}))


if __name__ == '__main__':
    main()
