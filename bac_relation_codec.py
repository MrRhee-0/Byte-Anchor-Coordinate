import argparse
import hashlib
import json
from pathlib import Path
import sys


SNAPSHOT_RELATION = b'import argparse\nfrom datetime import datetime\nimport hashlib\nimport json\nfrom pathlib import Path\n\n\ndef parse_non_negative_decimal(text):\n    if text == "" or not all(character in "0123456789" for character in text):\n        raise argparse.ArgumentTypeError(\n            f"{text!r} is not a base-10 integer greater than or equal to 0"\n        )\n    return int(text, 10)\n\n\ndef byte_hex(value):\n    return f"{value:02x}"\n\n\ndef build_byte_frequency(data):\n    frequencies = [0] * 256\n    for value in data:\n        frequencies[value] += 1\n    return frequencies\n\n\ndef build_offset_value_sample(data, limit):\n    return [\n        {\n            "offset": offset,\n            "value": data[offset],\n            "hex": byte_hex(data[offset]),\n        }\n        for offset in range(min(limit, len(data)))\n    ]\n\n\ndef build_adjacent_byte_sample(data, limit):\n    pair_count = max(0, min(limit, len(data) - 1))\n    entries = []\n    for offset in range(pair_count):\n        value = data[offset]\n        next_value = data[offset + 1]\n        entries.append(\n            {\n                "offset": offset,\n                "value": value,\n                "hex": byte_hex(value),\n                "next_offset": offset + 1,\n                "next_value": next_value,\n                "next_hex": byte_hex(next_value),\n                "pair_hex": byte_hex(value) + byte_hex(next_value),\n            }\n        )\n    return entries\n\n\ndef build_byte_delta_sample(data, limit):\n    pair_count = max(0, min(limit, len(data) - 1))\n    entries = []\n    for offset in range(pair_count):\n        value = data[offset]\n        next_value = data[offset + 1]\n        entries.append(\n            {\n                "offset": offset,\n                "value": value,\n                "next_offset": offset + 1,\n                "next_value": next_value,\n                "delta": next_value - value,\n            }\n        )\n    return entries\n\n\ndef build_report(path, data, sample, adjacent_sample, delta_sample):\n    source_path = Path(path)\n    frequencies = build_byte_frequency(data)\n    report = {\n        "name": source_path.name,\n        "suffix": source_path.suffix,\n        "byte_length": len(data),\n        "sha256": hashlib.sha256(data).hexdigest(),\n        "first_64_hex": data[:64].hex(),\n        "last_64_hex": data[-64:].hex(),\n        "distinct_byte_count": sum(1 for count in frequencies if count > 0),\n        "byte_frequency_0_to_255": frequencies,\n        "empty": len(data) == 0,\n        "timestamp_local_iso8601": datetime.now().astimezone().isoformat(),\n    }\n\n    if sample is not None:\n        report["offset_value_sample"] = build_offset_value_sample(data, sample)\n    if adjacent_sample is not None:\n        report["adjacent_byte_sample"] = build_adjacent_byte_sample(\n            data, adjacent_sample\n        )\n    if delta_sample is not None:\n        report["byte_delta_sample"] = build_byte_delta_sample(data, delta_sample)\n\n    return report\n\n\ndef parse_args():\n    parser = argparse.ArgumentParser(\n        description="Read a target file as raw bytes and emit a JSON report."\n    )\n    parser.add_argument("path", type=Path)\n    parser.add_argument("--out", dest="out", type=Path)\n    parser.add_argument("--sample", type=parse_non_negative_decimal)\n    parser.add_argument("--adjacent-sample", type=parse_non_negative_decimal)\n    parser.add_argument("--delta-sample", type=parse_non_negative_decimal)\n    return parser.parse_args()\n\n\ndef main():\n    args = parse_args()\n    path = args.path\n\n    with open(path, "rb") as handle:\n        data = handle.read()\n\n    report = build_report(\n        path,\n        data,\n        args.sample,\n        args.adjacent_sample,\n        args.delta_sample,\n    )\n    formatted_json = json.dumps(report, indent=2)\n    print(formatted_json)\n\n    if args.out is not None:\n        with open(args.out, "w") as handle:\n            handle.write(formatted_json + "\\n")\n\n\nif __name__ == "__main__":\n    main()\n'


def read_lambda(path):
    with open(path, "rb") as handle:
        return handle.read()


def write_lambda(path, data):
    with open(path, "wb") as handle:
        handle.write(data)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def relation_intake():
    return bytes((position * (position - 1)) // 2 for position in range(1, 17))


def relation_fill():
    return bytes([65]) * 4096


def relation_snapshot():
    return SNAPSHOT_RELATION


def decode_q(q):
    if q == b"\x01":
        return relation_intake()
    if q == b"\x02":
        return relation_fill()
    if q == b"\x03":
        return relation_snapshot()
    raise ValueError("q is outside D")


def derive_q(data):
    if data == relation_intake():
        return b"\x01"
    if data == relation_fill():
        return b"\x02"
    if data == relation_snapshot():
        return b"\x03"
    raise ValueError("rho is outside D")


def rho(data, position):
    return data[position - 1]


def derive_g(data):
    return [
        rho(data, position + 1) - rho(data, position)
        for position in range(1, len(data))
    ]


def derive_h(data):
    return [
        rho(data, position + 2) - (2 * rho(data, position + 1)) + rho(data, position)
        for position in range(1, max(1, len(data) - 1))
    ]


def derive_angle_nodes(data):
    h_values = derive_h(data)
    return [
        {
            "position": position + 1,
            "value": h_values[position - 1],
        }
        for position in range(1, len(h_values) + 1)
    ]


def proof_report(data, decoded):
    return {
        "D(q)=Lambda proof result": decoded == data,
        "G proof result": derive_g(decoded) == derive_g(data),
        "H proof result": derive_h(decoded) == derive_h(data),
        "AngleNode proof result": derive_angle_nodes(decoded) == derive_angle_nodes(data),
    }


def size_ratio(q, data):
    if len(data) == 0:
        return None
    return len(q) / len(data)


def report(input_path, q_path, data, q, decoded):
    exact_match = decoded == data
    length_equal = len(decoded) == len(data)
    sha_equal = digest(decoded) == digest(data)
    smaller = len(q) < len(data)
    closed = exact_match and length_equal and sha_equal and smaller
    output = {
        "input_path": str(input_path),
        "q_path": str(q_path),
        "original_size": len(data),
        "q_size": len(q),
        "ratio": size_ratio(q, data),
        "original_sha256": digest(data),
        "q_sha256": digest(q),
        "decoded_sha256": digest(decoded),
        "decoded_size": len(decoded),
        "exact_match": exact_match,
        "length_equal": length_equal,
        "sha_equal": sha_equal,
        "q_size < original_size": smaller,
        "relation": {
            "q": "rho_Lambda",
            "D(q)": "Lambda",
        },
        "status": "CLOSED" if closed else "OPEN",
    }
    output.update(proof_report(data, decoded))
    return output


def print_json(value):
    print(json.dumps(value, indent=2))


def pack_action(args):
    input_path = Path(args.input_path)
    q_path = Path(args.output_q_path)
    data = read_lambda(input_path)
    q = derive_q(data)
    decoded = decode_q(q)
    write_lambda(q_path, q)
    output = report(input_path, q_path, data, q, decoded)
    print_json(output)
    return 0 if output["status"] == "CLOSED" else 1


def unpack_action(args):
    input_path = Path(args.input_q_path)
    output_path = Path(args.output_path)
    q = read_lambda(input_path)
    decoded = decode_q(q)
    write_lambda(output_path, decoded)
    output = report(input_path, output_path, decoded, q, decoded)
    print_json(output)
    return 0 if output["status"] == "CLOSED" else 1


def verify_action(args):
    input_path = Path(args.input_path)
    q_path = Path(args.input_q_path)
    data = read_lambda(input_path)
    q = read_lambda(q_path)
    decoded = decode_q(q)
    output = report(input_path, q_path, data, q, decoded)
    print_json(output)
    return 0 if output["status"] == "CLOSED" else 1


def parser():
    root = argparse.ArgumentParser()
    actions = root.add_subparsers(dest="action", required=True)

    pack = actions.add_parser("pack")
    pack.add_argument("input_path")
    pack.add_argument("output_q_path")
    pack.set_defaults(run=pack_action)

    unpack = actions.add_parser("unpack")
    unpack.add_argument("input_q_path")
    unpack.add_argument("output_path")
    unpack.set_defaults(run=unpack_action)

    verify = actions.add_parser("verify")
    verify.add_argument("input_path")
    verify.add_argument("input_q_path")
    verify.set_defaults(run=verify_action)

    return root


def main():
    args = parser().parse_args()
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
