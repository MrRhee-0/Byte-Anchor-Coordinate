import argparse
import hashlib
import json
from pathlib import Path
import sys


EQUATION = "q = P_{D(q)=Lambda}(rho_Lambda)"
RELATION = {
    "Lambda": "complete ordered byte carrier",
    "P_i": "i",
    "rho_Lambda(P_i)": "Lambda_i",
    "q": EQUATION,
    "D(q)": "Lambda",
}


def read_lambda(path):
    with open(path, "rb") as handle:
        return handle.read()


def write_bytes(path, data):
    with open(path, "wb") as handle:
        handle.write(data)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def rho_lambda(lambda_bytes, position):
    return lambda_bytes[position - 1]


def derive_minimal_coordinate(lambda_bytes):
    return bytes(
        rho_lambda(lambda_bytes, position)
        for position in range(1, len(lambda_bytes) + 1)
    )


def coordinate_bytes(q):
    return bytes(q)


def decode_coordinate(q):
    return bytes(q)


def derive_g(q):
    return [
        rho_lambda(q, position + 1) - rho_lambda(q, position)
        for position in range(1, len(q))
    ]


def derive_h(q):
    return [
        rho_lambda(q, position + 2)
        - (2 * rho_lambda(q, position + 1))
        + rho_lambda(q, position)
        for position in range(1, max(1, len(q) - 1))
    ]


def derive_angle_nodes(q):
    h_values = derive_h(q)
    return [
        {
            "position": position + 1,
            "value": h_values[position - 1],
        }
        for position in range(1, len(h_values) + 1)
    ]


def q_report(input_path, q_path, lambda_bytes, q, decoded, q_surface):
    exact_match = decoded == lambda_bytes
    length_equal = len(decoded) == len(lambda_bytes)
    sha_equal = sha256(decoded) == sha256(lambda_bytes)
    smaller = len(q_surface) < len(lambda_bytes)
    closed = exact_match and length_equal and sha_equal and smaller
    failed_reduction = exact_match and length_equal and sha_equal and not smaller
    return {
        "input_path": str(input_path),
        "q_path": str(q_path),
        "original_size": len(lambda_bytes),
        "q_size": len(q_surface),
        "ratio": len(q_surface) / len(lambda_bytes) if len(lambda_bytes) != 0 else None,
        "original_sha256": sha256(lambda_bytes),
        "q_sha256": sha256(q_surface),
        "decoded_sha256": sha256(decoded),
        "decoded_size": len(decoded),
        "exact_match": exact_match,
        "length_equal": length_equal,
        "sha_equal": sha_equal,
        "q_size < original_size": smaller,
        "relation": RELATION,
        "D(q)=Lambda proof result": exact_match,
        "G proof result": derive_g(q) == derive_g(derive_minimal_coordinate(decoded)),
        "H proof result": derive_h(q) == derive_h(derive_minimal_coordinate(decoded)),
        "AngleNode proof result": derive_angle_nodes(q)
        == derive_angle_nodes(derive_minimal_coordinate(decoded)),
        "status": "CLOSED" if closed else "FAILED",
        "failure_class": "Q_NOT_REDUCED" if failed_reduction else None,
    }


def unpack_report(input_path, output_path, q_surface, decoded):
    return {
        "input_path": str(input_path),
        "output_path": str(output_path),
        "q_size": len(q_surface),
        "q_sha256": sha256(q_surface),
        "decoded_size": len(decoded),
        "decoded_sha256": sha256(decoded),
        "relation": RELATION,
        "D(q)=Lambda proof result": decoded == decode_coordinate(q_surface),
        "G proof result": derive_g(decoded) == derive_g(decode_coordinate(q_surface)),
        "H proof result": derive_h(decoded) == derive_h(decode_coordinate(q_surface)),
        "AngleNode proof result": derive_angle_nodes(decoded)
        == derive_angle_nodes(decode_coordinate(q_surface)),
        "status": "UNPACKED_FROM_Q",
    }


def print_json(value):
    print(json.dumps(value, indent=2))


def pack_action(args):
    input_path = Path(args.input_path)
    q_path = Path(args.output_bac_path)
    lambda_bytes = read_lambda(input_path)
    q = derive_minimal_coordinate(lambda_bytes)
    q_surface = coordinate_bytes(q)
    write_bytes(q_path, q_surface)
    decoded = decode_coordinate(q_surface)
    report = q_report(input_path, q_path, lambda_bytes, q, decoded, q_surface)
    print_json(report)
    return 0 if report["status"] == "CLOSED" else 1


def unpack_action(args):
    input_path = Path(args.input_bac_path)
    output_path = Path(args.output_path)
    q_surface = read_lambda(input_path)
    decoded = decode_coordinate(q_surface)
    write_bytes(output_path, decoded)
    report = unpack_report(input_path, output_path, q_surface, decoded)
    print_json(report)
    return 0


def verify_action(args):
    input_path = Path(args.input_path)
    q_path = Path(args.input_bac_path)
    lambda_bytes = read_lambda(input_path)
    q_surface = read_lambda(q_path)
    decoded = decode_coordinate(q_surface)
    report = q_report(input_path, q_path, lambda_bytes, q_surface, decoded, q_surface)
    print_json(report)
    return 0 if report["status"] == "CLOSED" else 1


def build_parser():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)

    pack = commands.add_parser("pack")
    pack.add_argument("input_path")
    pack.add_argument("output_bac_path")
    pack.set_defaults(run=pack_action)

    unpack = commands.add_parser("unpack")
    unpack.add_argument("input_bac_path")
    unpack.add_argument("output_path")
    unpack.set_defaults(run=unpack_action)

    verify = commands.add_parser("verify")
    verify.add_argument("input_path")
    verify.add_argument("input_bac_path")
    verify.set_defaults(run=verify_action)

    return parser


def main():
    args = build_parser().parse_args()
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
