import argparse
import hashlib
import json
from pathlib import Path
import sys


REL_EMPTY = 0
REL_CONSTANT_BYTE = 1
REL_CONSTANT_G = 2
REL_CONSTANT_H = 3

RELATION_NAMES = {
    REL_EMPTY: "EMPTY",
    REL_CONSTANT_BYTE: "CONSTANT_BYTE",
    REL_CONSTANT_G: "CONSTANT_G",
    REL_CONSTANT_H: "CONSTANT_H",
}

FAILURE_SIZE_CLOSURE_FAILED = "BAC_SIZE_CLOSURE_FAILED"
FAILURE_RESOLVER_INCOMPLETE = "IMPLEMENTED_COORDINATE_RESOLVER_INCOMPLETE"


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
    if not values:
        return True
    first = values[0]
    for value in values:
        if value != first:
            return False
    return True


def resolve_coordinate(data):
    lambda_values, g_values, h_values = lambda_g_h(data)
    n = len(lambda_values)

    if n == 0:
        return bytes([REL_EMPTY]), {
            "relation": RELATION_NAMES[REL_EMPTY],
            "n": 0,
        }

    b0 = lambda_values[0]

    if all_equal(lambda_values):
        return bytes([REL_CONSTANT_BYTE]) + encode_varuint(n) + bytes([b0]), {
            "relation": RELATION_NAMES[REL_CONSTANT_BYTE],
            "n": n,
            "b0": b0,
        }

    if all_equal(g_values):
        g0 = g_values[0]
        return (
            bytes([REL_CONSTANT_G])
            + encode_varuint(n)
            + bytes([b0])
            + encode_signed(g0)
        ), {
            "relation": RELATION_NAMES[REL_CONSTANT_G],
            "n": n,
            "b0": b0,
            "g0": g0,
        }

    if all_equal(h_values):
        g0 = g_values[0]
        h0 = h_values[0] if h_values else 0
        return (
            bytes([REL_CONSTANT_H])
            + encode_varuint(n)
            + bytes([b0])
            + encode_signed(g0)
            + encode_signed(h0)
        ), {
            "relation": RELATION_NAMES[REL_CONSTANT_H],
            "n": n,
            "b0": b0,
            "g0": g0,
            "h0": h0,
        }

    return None, {
        "lambda_resolved": True,
        "g_resolved": True,
        "h_resolved": True,
        "lambda_length": n,
        "g_value_count": len(g_values),
        "h_value_count": len(h_values),
        "implemented_relation": None,
    }


def ensure_byte(value):
    if value < 0 or value > 255:
        raise DecodeError("reconstructed byte out of range")
    return value


def reconstruct_constant_g(n, b0, g0):
    if n == 0:
        return b""
    values = [b0]
    for _ in range(1, n):
        values.append(ensure_byte(values[-1] + g0))
    return bytes(values)


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


def decode_coordinate(data):
    reader = Reader(data)
    relation_id = reader.read_byte()

    if relation_id == REL_EMPTY:
        decoded = b""
        fields = {"relation": RELATION_NAMES[relation_id], "n": 0}

    elif relation_id == REL_CONSTANT_BYTE:
        n = reader.read_varuint()
        b0 = reader.read_byte()
        decoded = bytes([b0]) * n
        fields = {"relation": RELATION_NAMES[relation_id], "n": n, "b0": b0}

    elif relation_id == REL_CONSTANT_G:
        n = reader.read_varuint()
        b0 = reader.read_byte()
        g0 = reader.read_signed()
        decoded = reconstruct_constant_g(n, b0, g0)
        fields = {"relation": RELATION_NAMES[relation_id], "n": n, "b0": b0, "g0": g0}

    elif relation_id == REL_CONSTANT_H:
        n = reader.read_varuint()
        b0 = reader.read_byte()
        g0 = reader.read_signed()
        h0 = reader.read_signed()
        h_values = [h0] * max(0, n - 2)
        decoded = reconstruct_from_h(n, b0, g0, h_values)
        fields = {
            "relation": RELATION_NAMES[relation_id],
            "n": n,
            "b0": b0,
            "g0": g0,
            "h0": h0,
        }

    else:
        raise DecodeError("unknown BAC relation id")

    if reader.remaining() != 0:
        raise DecodeError("trailing bytes after coordinate")

    return {
        "data": decoded,
        "relation_id": relation_id,
        "relation_name": RELATION_NAMES[relation_id],
        "coordinate_fields": fields,
    }


def status_for(exact_match, length_equal, sha_equal, coordinate_size, original_size):
    if exact_match and length_equal and sha_equal and coordinate_size < original_size:
        return "CLOSED"
    return "FAILED"


def ratio_for(coordinate_size, original_size):
    if original_size == 0:
        return None
    return coordinate_size / original_size


def pack_report(input_path, output_path, original_data, coordinate, decoded_info, wrote):
    decoded = decoded_info["data"]
    original_sha = sha256_hex(original_data)
    decoded_sha = sha256_hex(decoded)
    exact_match = decoded == original_data
    length_equal = len(decoded) == len(original_data)
    sha_equal = decoded_sha == original_sha
    status = status_for(exact_match, length_equal, sha_equal, len(coordinate), len(original_data))
    failure_class = None
    if status != "CLOSED":
        failure_class = FAILURE_SIZE_CLOSURE_FAILED
    return {
        "input_path": str(input_path),
        "output_path": str(output_path),
        "original_size": len(original_data),
        "coordinate_size": len(coordinate),
        "ratio": ratio_for(len(coordinate), len(original_data)),
        "original_sha256": original_sha,
        "decoded_sha256": decoded_sha,
        "decoded_size": len(decoded),
        "exact_match": exact_match,
        "length_equal": length_equal,
        "sha_equal": sha_equal,
        "relation_id": decoded_info["relation_id"],
        "relation_name": decoded_info["relation_name"],
        "coordinate_fields": decoded_info["coordinate_fields"],
        "artifact_written": wrote,
        "status": status,
        "failure_class": failure_class,
    }


def unresolved_pack_report(input_path, output_path, original_data, derived_info):
    return {
        "input_path": str(input_path),
        "output_path": str(output_path),
        "original_size": len(original_data),
        "coordinate_size": None,
        "ratio": None,
        "original_sha256": sha256_hex(original_data),
        "decoded_sha256": None,
        "decoded_size": None,
        "exact_match": False,
        "length_equal": False,
        "sha_equal": False,
        "relation_id": None,
        "relation_name": None,
        "coordinate_fields": None,
        "derived_relation_surface": derived_info,
        "artifact_written": False,
        "status": "FAILED",
        "failure_class": FAILURE_RESOLVER_INCOMPLETE,
    }


def unpack_report(input_path, output_path, coordinate, decoded_info):
    decoded = decoded_info["data"]
    status = "CLOSED" if len(coordinate) < len(decoded) else "FAILED"
    return {
        "input_path": str(input_path),
        "output_path": str(output_path),
        "coordinate_size": len(coordinate),
        "decoded_size": len(decoded),
        "decoded_sha256": sha256_hex(decoded),
        "relation_id": decoded_info["relation_id"],
        "relation_name": decoded_info["relation_name"],
        "status": status,
    }


def verify_report(input_path, coordinate_path, original_data, coordinate, decoded_info):
    decoded = decoded_info["data"]
    original_sha = sha256_hex(original_data)
    decoded_sha = sha256_hex(decoded)
    exact_match = decoded == original_data
    length_equal = len(decoded) == len(original_data)
    sha_equal = decoded_sha == original_sha
    status = status_for(exact_match, length_equal, sha_equal, len(coordinate), len(original_data))
    return {
        "input_path": str(input_path),
        "coordinate_path": str(coordinate_path),
        "original_size": len(original_data),
        "coordinate_size": len(coordinate),
        "ratio": ratio_for(len(coordinate), len(original_data)),
        "original_sha256": original_sha,
        "decoded_sha256": decoded_sha,
        "decoded_size": len(decoded),
        "exact_match": exact_match,
        "length_equal": length_equal,
        "sha_equal": sha_equal,
        "relation_id": decoded_info["relation_id"],
        "relation_name": decoded_info["relation_name"],
        "status": status,
    }


def print_report(report):
    print(json.dumps(report, indent=2))


def pack_command(args):
    input_path = Path(args.input_path)
    output_path = Path(args.output_bac_path)
    original_data = read_input_bytes(input_path)
    coordinate, derived_info = resolve_coordinate(original_data)

    if coordinate is None:
        output_path.unlink(missing_ok=True)
        report = unresolved_pack_report(input_path, output_path, original_data, derived_info)
        print_report(report)
        return 1

    decoded_info = decode_coordinate(coordinate)
    closed = (
        decoded_info["data"] == original_data
        and len(decoded_info["data"]) == len(original_data)
        and sha256_hex(decoded_info["data"]) == sha256_hex(original_data)
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
    return 0 if report["status"] == "CLOSED" else 1


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
    try:
        return args.func(args)
    except (DecodeError, ValueError, OSError) as error:
        print(json.dumps({"status": "FAILED", "error": str(error)}, indent=2))
        return 1


if __name__ == "__main__":
    sys.exit(main())
