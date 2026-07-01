import argparse
import hashlib
import json
from pathlib import Path
import sys


FAILURE_RECONSTRUCTION_MISMATCH = "RECONSTRUCTION_MISMATCH"
FAILURE_PACKET_OVERCONSTRAINT = "PACKET_OVERCONSTRAINT"


class DecodeError(Exception):
    pass


class Reader:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def remaining(self):
        return len(self.data) - self.offset

    def read_byte(self):
        if self.offset >= len(self.data):
            raise DecodeError("unexpected end of coordinate")
        value = self.data[self.offset]
        self.offset += 1
        return value

    def read_varuint(self):
        shift = 0
        value = 0
        while True:
            byte = self.read_byte()
            value |= (byte & 0x7F) << shift
            if byte < 0x80:
                return value
            shift += 7
            if shift > 70:
                raise DecodeError("varuint is too long")

    def read_signed(self):
        return zigzag_decode(self.read_varuint())


def read_input_bytes(path):
    with open(path, "rb") as handle:
        data = handle.read()
    return data


def write_bytes(path, data):
    with open(path, "wb") as handle:
        handle.write(data)


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def encode_varuint(value):
    if value < 0:
        raise ValueError("varuint cannot encode a negative integer")
    output = []
    while True:
        byte = value & 0x7F
        value = value >> 7
        if value:
            output.append(byte | 0x80)
        else:
            output.append(byte)
            return bytes(output)


def zigzag_encode(value):
    if value >= 0:
        return value * 2
    return (-value * 2) - 1


def zigzag_decode(value):
    if value % 2 == 0:
        return value // 2
    return -((value + 1) // 2)


def encode_signed(value):
    return encode_varuint(zigzag_encode(value))


def lambda_g_h(data):
    lambda_values = list(data)
    g_values = []
    h_values = []
    for index in range(len(lambda_values) - 1):
        g_values.append(lambda_values[index + 1] - lambda_values[index])
    for index in range(len(g_values) - 1):
        h_values.append(g_values[index + 1] - g_values[index])
    return lambda_values, g_values, h_values


def all_equal(values):
    if len(values) == 0:
        return True
    first = values[0]
    for value in values:
        if value != first:
            return False
    return True


def coordinate_field_report(n, b0, g0, h_values, relation_name, relation_value_count):
    return {
        "lambda_length": n,
        "b0": b0,
        "g0": g0,
        "g_value_count": max(0, n - 1),
        "h_value_count": max(0, n - 2),
        "coordinate_relation": relation_name,
        "coordinate_relation_value_count": relation_value_count,
    }


def encode_coordinate(data):
    lambda_values, g_values, h_values = lambda_g_h(data)
    n = len(lambda_values)
    output = bytearray()
    output.extend(encode_varuint(n))

    if n == 0:
        return bytes(output), coordinate_field_report(n, None, None, h_values, "EMPTY_LAMBDA", 0)

    b0 = lambda_values[0]
    output.append(b0)

    if n == 1 or all_equal(lambda_values):
        return bytes(output), coordinate_field_report(n, b0, None, h_values, "CONSTANT_LAMBDA", 1)

    g0 = g_values[0]

    if all_equal(g_values):
        output.extend(encode_signed(g0))
        return bytes(output), coordinate_field_report(n, b0, g0, h_values, "CONSTANT_G", 1)

    if all_equal(h_values):
        output.extend(encode_signed(g0))
        output.extend(encode_signed(h_values[0]))
        return bytes(output), coordinate_field_report(n, b0, g0, h_values, "CONSTANT_H", 1)

    for value in g_values:
        output.extend(encode_signed(value))

    return bytes(output), coordinate_field_report(n, b0, g0, h_values, "G_SEQUENCE", len(g_values))


def ensure_byte(value):
    if value < 0 or value > 255:
        raise DecodeError("reconstructed byte out of range")
    return value


def reconstruct_from_h(n, b0, g0, h_values):
    if n == 0:
        return b""
    values = [b0]
    g_current = g0
    for index in range(1, n):
        values.append(ensure_byte(values[-1] + g_current))
        if index - 1 < len(h_values):
            g_current = g_current + h_values[index - 1]
    return bytes(values)


def reconstruct_from_g(n, b0, g_values):
    if n == 0:
        return b""
    if len(g_values) != n - 1:
        raise DecodeError("G length does not match Lambda length")
    values = [b0]
    for value in g_values:
        values.append(ensure_byte(values[-1] + value))
    return bytes(values)


def decode_coordinate(data):
    reader = Reader(data)
    n = reader.read_varuint()

    if n == 0:
        if reader.remaining() != 0:
            raise DecodeError("trailing bytes after coordinate")
        return {
            "data": b"",
            "coordinate_fields": coordinate_field_report(n, None, None, [], "EMPTY_LAMBDA", 0),
        }

    b0 = reader.read_byte()
    relation_values = []
    while reader.remaining() > 0:
        relation_values.append(reader.read_signed())

    if n == 1:
        if len(relation_values) != 0:
            raise DecodeError("trailing bytes after coordinate")
        return {
            "data": bytes([b0]),
            "coordinate_fields": coordinate_field_report(n, b0, None, [], "CONSTANT_LAMBDA", 1),
        }

    if len(relation_values) == 0:
        decoded = bytes([b0] * n)
        return {
            "data": decoded,
            "coordinate_fields": coordinate_field_report(n, b0, None, [], "CONSTANT_LAMBDA", 1),
        }

    g0 = relation_values[0]

    if len(relation_values) == 1:
        decoded = reconstruct_from_g(n, b0, [g0] * (n - 1))
        return {
            "data": decoded,
            "coordinate_fields": coordinate_field_report(n, b0, g0, [], "CONSTANT_G", 1),
        }

    if len(relation_values) == 2 and n >= 3:
        h0 = relation_values[1]
        h_values = [h0] * max(0, n - 2)
        decoded = reconstruct_from_h(n, b0, g0, h_values)
        return {
            "data": decoded,
            "coordinate_fields": coordinate_field_report(n, b0, g0, h_values, "CONSTANT_H", 1),
        }

    if len(relation_values) == n - 1:
        decoded = reconstruct_from_g(n, b0, relation_values)
        return {
            "data": decoded,
            "coordinate_fields": coordinate_field_report(n, b0, relation_values[0], [], "G_SEQUENCE", len(relation_values)),
        }

    raise DecodeError("coordinate relation does not match Lambda length")


def status_for(exact_match, length_equal, sha_equal, residual_zero, size_smaller):
    if exact_match and length_equal and sha_equal and residual_zero and size_smaller:
        return "CLOSED"
    return "FAILED"


def ratio_for(coordinate_size, original_size):
    if original_size == 0:
        return None
    return coordinate_size / original_size


def residual_report(original_data, decoded):
    if len(original_data) != len(decoded):
        return {
            "residual_zero": False,
            "residual_nonzero_count": None,
            "residual_abs_sum": None,
        }

    nonzero_count = 0
    abs_sum = 0
    for index in range(len(original_data)):
        delta = decoded[index] - original_data[index]
        if delta != 0:
            nonzero_count += 1
            if delta < 0:
                abs_sum += -delta
            else:
                abs_sum += delta

    return {
        "residual_zero": nonzero_count == 0,
        "residual_nonzero_count": nonzero_count,
        "residual_abs_sum": abs_sum,
    }


def failure_class_for(exact_match, length_equal, sha_equal, residual_zero, size_smaller):
    if exact_match and length_equal and sha_equal and residual_zero and not size_smaller:
        return FAILURE_PACKET_OVERCONSTRAINT
    if exact_match and length_equal and sha_equal and residual_zero and size_smaller:
        return None
    return FAILURE_RECONSTRUCTION_MISMATCH


def pack_report(input_path, output_path, original_data, coordinate, decoded_info, wrote):
    decoded = decoded_info["data"]
    original_sha = sha256_hex(original_data)
    decoded_sha = sha256_hex(decoded)
    exact_match = decoded == original_data
    length_equal = len(decoded) == len(original_data)
    sha_equal = decoded_sha == original_sha
    residual = residual_report(original_data, decoded)
    size_smaller = len(coordinate) < len(original_data)
    status = status_for(exact_match, length_equal, sha_equal, residual["residual_zero"], size_smaller)
    failure_class = failure_class_for(exact_match, length_equal, sha_equal, residual["residual_zero"], size_smaller)
    report = {
        "input_path": str(input_path),
        "output_path": str(output_path),
        "original_size": len(original_data),
        "coordinate_size": len(coordinate),
        "ratio": ratio_for(len(coordinate), len(original_data)),
        "size_smaller_than_carrier": size_smaller,
        "original_sha256": original_sha,
        "decoded_sha256": decoded_sha,
        "decoded_size": len(decoded),
        "exact_match": exact_match,
        "length_equal": length_equal,
        "sha_equal": sha_equal,
        "coordinate_fields": decoded_info["coordinate_fields"],
        "artifact_written": wrote,
        "status": status,
        "failure_class": failure_class,
    }
    report.update(residual)
    return report


def unpack_report(input_path, output_path, coordinate, decoded_info):
    decoded = decoded_info["data"]
    return {
        "input_path": str(input_path),
        "output_path": str(output_path),
        "coordinate_size": len(coordinate),
        "decoded_size": len(decoded),
        "decoded_sha256": sha256_hex(decoded),
        "coordinate_fields": decoded_info["coordinate_fields"],
        "status": "CLOSED",
    }


def verify_report(input_path, coordinate_path, original_data, coordinate, decoded_info):
    decoded = decoded_info["data"]
    original_sha = sha256_hex(original_data)
    decoded_sha = sha256_hex(decoded)
    exact_match = decoded == original_data
    length_equal = len(decoded) == len(original_data)
    sha_equal = decoded_sha == original_sha
    residual = residual_report(original_data, decoded)
    size_smaller = len(coordinate) < len(original_data)
    status = status_for(exact_match, length_equal, sha_equal, residual["residual_zero"], size_smaller)
    report = {
        "input_path": str(input_path),
        "coordinate_path": str(coordinate_path),
        "original_size": len(original_data),
        "coordinate_size": len(coordinate),
        "ratio": ratio_for(len(coordinate), len(original_data)),
        "size_smaller_than_carrier": size_smaller,
        "original_sha256": original_sha,
        "decoded_sha256": decoded_sha,
        "decoded_size": len(decoded),
        "exact_match": exact_match,
        "length_equal": length_equal,
        "sha_equal": sha_equal,
        "coordinate_fields": decoded_info["coordinate_fields"],
        "status": status,
        "failure_class": failure_class_for(exact_match, length_equal, sha_equal, residual["residual_zero"], size_smaller),
    }
    report.update(residual)
    return report


def print_report(report):
    print(json.dumps(report, indent=2))


def pack_command(args):
    input_path = Path(args.input_path)
    output_path = Path(args.output_bac_path)
    original_data = read_input_bytes(input_path)
    coordinate, coordinate_fields = encode_coordinate(original_data)
    decoded_info = decode_coordinate(coordinate)
    decoded_info["coordinate_fields"] = coordinate_fields
    decoded = decoded_info["data"]
    residual = residual_report(original_data, decoded)
    closed = (
        decoded == original_data
        and sha256_hex(decoded) == sha256_hex(original_data)
        and residual["residual_zero"]
        and len(coordinate) < len(original_data)
    )

    if closed:
        write_bytes(output_path, coordinate)
    else:
        output_path.unlink(missing_ok=True)

    report = pack_report(input_path, output_path, original_data, coordinate, decoded_info, closed)
    print_report(report)
    return 0 if closed else 1


def unpack_command(args):
    input_path = Path(args.input_bac_path)
    output_path = Path(args.output_path)
    coordinate = read_input_bytes(input_path)
    decoded_info = decode_coordinate(coordinate)
    write_bytes(output_path, decoded_info["data"])
    report = unpack_report(input_path, output_path, coordinate, decoded_info)
    print_report(report)
    return 0


def verify_command(args):
    input_path = Path(args.input_path)
    coordinate_path = Path(args.input_bac_path)
    original_data = read_input_bytes(input_path)
    coordinate = read_input_bytes(coordinate_path)
    decoded_info = decode_coordinate(coordinate)
    report = verify_report(input_path, coordinate_path, original_data, coordinate, decoded_info)
    print_report(report)
    return 0 if report["status"] == "CLOSED" else 1


def build_parser():
    parser = argparse.ArgumentParser(description="Pack, unpack, and verify BAC coordinates.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    pack_parser = subparsers.add_parser("pack")
    pack_parser.add_argument("input_path")
    pack_parser.add_argument("output_bac_path")
    pack_parser.set_defaults(func=pack_command)

    unpack_parser = subparsers.add_parser("unpack")
    unpack_parser.add_argument("input_bac_path")
    unpack_parser.add_argument("output_path")
    unpack_parser.set_defaults(func=unpack_command)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("input_path")
    verify_parser.add_argument("input_bac_path")
    verify_parser.set_defaults(func=verify_command)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
