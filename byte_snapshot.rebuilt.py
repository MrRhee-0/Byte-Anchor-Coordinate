import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path


def parse_non_negative_decimal(text):
    if text == "" or not all(character in "0123456789" for character in text):
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a base-10 integer greater than or equal to 0"
        )
    return int(text, 10)


def byte_hex(value):
    return f"{value:02x}"


def build_byte_frequency(data):
    frequencies = [0] * 256
    for value in data:
        frequencies[value] += 1
    return frequencies


def build_offset_value_sample(data, limit):
    return [
        {
            "offset": offset,
            "value": data[offset],
            "hex": byte_hex(data[offset]),
        }
        for offset in range(min(limit, len(data)))
    ]


def build_adjacent_byte_sample(data, limit):
    pair_count = max(0, min(limit, len(data) - 1))
    entries = []
    for offset in range(pair_count):
        value = data[offset]
        next_value = data[offset + 1]
        entries.append(
            {
                "offset": offset,
                "value": value,
                "hex": byte_hex(value),
                "next_offset": offset + 1,
                "next_value": next_value,
                "next_hex": byte_hex(next_value),
                "pair_hex": byte_hex(value) + byte_hex(next_value),
            }
        )
    return entries


def build_byte_delta_sample(data, limit):
    pair_count = max(0, min(limit, len(data) - 1))
    entries = []
    for offset in range(pair_count):
        value = data[offset]
        next_value = data[offset + 1]
        entries.append(
            {
                "offset": offset,
                "value": value,
                "next_offset": offset + 1,
                "next_value": next_value,
                "delta": next_value - value,
            }
        )
    return entries


def build_report(path, data, sample, adjacent_sample, delta_sample):
    source_path = Path(path)
    frequencies = build_byte_frequency(data)
    report = {
        "name": source_path.name,
        "suffix": source_path.suffix,
        "byte_length": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "first_64_hex": data[:64].hex(),
        "last_64_hex": data[-64:].hex(),
        "distinct_byte_count": sum(1 for count in frequencies if count > 0),
        "byte_frequency_0_to_255": frequencies,
        "empty": len(data) == 0,
        "timestamp_local_iso8601": datetime.now().astimezone().isoformat(),
    }

    if sample is not None:
        report["offset_value_sample"] = build_offset_value_sample(data, sample)
    if adjacent_sample is not None:
        report["adjacent_byte_sample"] = build_adjacent_byte_sample(
            data, adjacent_sample
        )
    if delta_sample is not None:
        report["byte_delta_sample"] = build_byte_delta_sample(data, delta_sample)

    return report


def parse_args():
    parser = argparse.ArgumentParser(
        description="Read a target file as raw bytes and emit a JSON report."
    )
    parser.add_argument("path", type=Path)
    parser.add_argument("--out", dest="out", type=Path)
    parser.add_argument("--sample", type=parse_non_negative_decimal)
    parser.add_argument("--adjacent-sample", type=parse_non_negative_decimal)
    parser.add_argument("--delta-sample", type=parse_non_negative_decimal)
    return parser.parse_args()


def main():
    args = parse_args()
    path = args.path

    with open(path, "rb") as handle:
        data = handle.read()

    report = build_report(
        path,
        data,
        args.sample,
        args.adjacent_sample,
        args.delta_sample,
    )
    formatted_json = json.dumps(report, indent=2)
    print(formatted_json)

    if args.out is not None:
        with open(args.out, "w") as handle:
            handle.write(formatted_json + "\n")


if __name__ == "__main__":
    main()
