#!/usr/bin/env python3
"""BAC coordinate q = <n, b, g, coeffs_A> for ordered byte carriers."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


class CoordinateError(Exception):
    pass


def read_bytes(path: Path) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def write_bytes(path: Path, data: bytes) -> None:
    with open(path, "wb") as handle:
        handle.write(data)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_nat(value: int) -> bytes:
    if value < 0:
        raise CoordinateError("natural coordinate cannot be negative")

    out = bytearray()
    while True:
        part = value & 0x7F
        value >>= 7
        if value:
            out.append(part | 0x80)
        else:
            out.append(part)
            return bytes(out)


def read_nat(data: bytes, offset: int) -> tuple[int, int]:
    start = offset
    shift = 0
    value = 0

    while True:
        if offset >= len(data):
            raise CoordinateError("truncated q")

        part = data[offset]
        offset += 1
        value |= (part & 0x7F) << shift

        if not part & 0x80:
            if data[start:offset] != write_nat(value):
                raise CoordinateError("non-minimal q integer exposure")
            return value, offset

        shift += 7


def fold_int(value: int) -> int:
    if value >= 0:
        return value * 2
    return (-value * 2) - 1


def unfold_int(value: int) -> int:
    if value % 2 == 0:
        return value // 2
    return -((value + 1) // 2)


def write_int(value: int) -> bytes:
    return write_nat(fold_int(value))


def read_int(data: bytes, offset: int) -> tuple[int, int]:
    folded, offset = read_nat(data, offset)
    return unfold_int(folded), offset


def diff(values: list[int]) -> list[int]:
    return [values[i + 1] - values[i] for i in range(len(values) - 1)]


def is_zero_field(values: list[int]) -> bool:
    return all(value == 0 for value in values)


def coord(values: list[int]) -> tuple[int, list[int]]:
    m = len(values)

    if m == 0:
        return 0, []

    tower = values[:]
    coeffs = [tower[0]]

    while len(tower) > 1:
        tower = diff(tower)
        if is_zero_field(tower):
            break
        coeffs.append(tower[0])

    return m, coeffs


def decode_coord(coeffs: list[int], target_len: int) -> list[int]:
    if target_len < 0:
        raise CoordinateError("coord target length cannot be negative")
    if target_len == 0 and coeffs:
        raise CoordinateError("empty coord target cannot carry coefficients")
    if len(coeffs) > target_len:
        raise CoordinateError("coord carries more coefficients than positions")
    if not coeffs:
        return [0 for _ in range(target_len)]

    state = coeffs[:]
    out = []
    for _ in range(target_len):
        out.append(state[0])
        for index in range(len(state) - 1):
            state[index] = state[index] + state[index + 1]
    return out


def derive_q(lam: bytes):
    n = len(lam)

    if n == 0:
        return (0,)

    if n == 1:
        return (1, lam[0])

    b = lam[0]
    g = lam[1] - lam[0]
    A = [lam[i + 2] - 2 * lam[i + 1] + lam[i] for i in range(n - 2)]
    _m, coeffs_A = coord(A)
    return (n, b, g, coeffs_A)


def decode_q(q):
    n = q[0]

    if n == 0:
        return []

    if n == 1:
        return [q[1]]

    _, b, g, coeffs_A = q
    A = decode_coord(coeffs_A, n - 2)
    if len(A) != n - 2:
        raise CoordinateError("coord(A) length does not match n")

    lam = [b]

    for i in range(n - 1):
        lam.append(lam[-1] + g)
        if i < n - 2:
            g = g + A[i]

    return lam


def expose_q(q) -> bytes:
    n = q[0]
    out = bytearray(write_nat(n))

    if n == 0:
        return bytes(out)

    if n == 1:
        value = q[1]
        if not 0 <= value <= 255:
            raise CoordinateError("q byte anchor outside 0..255")
        out.append(value)
        return bytes(out)

    _, b, g, coeffs_A = q
    if not 0 <= b <= 255:
        raise CoordinateError("q byte anchor outside 0..255")
    if len(coeffs_A) > n - 2:
        raise CoordinateError("coord(A) carries more coefficients than positions")

    out.append(b)
    out.extend(write_int(g))
    for value in coeffs_A:
        out.extend(write_int(value))
    return bytes(out)


def read_q(data: bytes):
    n, offset = read_nat(data, 0)

    if n == 0:
        if offset != len(data):
            raise CoordinateError("q has residue after n=0")
        return (0,)

    if offset >= len(data):
        raise CoordinateError("q missing byte anchor")

    b = data[offset]
    offset += 1

    if n == 1:
        if offset != len(data):
            raise CoordinateError("q has residue after n=1")
        return (1, b)

    g, offset = read_int(data, offset)
    coeffs = []

    while offset < len(data):
        value, offset = read_int(data, offset)
        coeffs.append(value)

    if len(coeffs) > n - 2:
        raise CoordinateError("coord(A) carries more coefficients than positions")

    return (n, b, g, coeffs)


def bytes_from_q(q) -> bytes:
    values = decode_q(q)
    for value in values:
        if value < 0 or value > 255:
            raise CoordinateError("D(q) left byte carrier boundary 0..255")
    return bytes(values)


def derive_g(values: list[int]) -> list[int]:
    return [values[i + 1] - values[i] for i in range(len(values) - 1)]


def derive_h(values: list[int]) -> list[int]:
    return [
        values[i + 2] - 2 * values[i + 1] + values[i]
        for i in range(len(values) - 2)
    ]


def proof_fields(original: bytes | None, decoded: bytes) -> dict[str, object]:
    decoded_values = list(decoded)
    decoded_g = derive_g(decoded_values)
    decoded_h = derive_h(decoded_values)
    fields: dict[str, object] = {
        "D(q)=Lambda": original == decoded if original is not None else None,
        "G proof result": decoded_g == derive_g(decoded_values),
        "H proof result": decoded_h == derive_h(decoded_values),
        "AngleNode proof result": decoded_h == derive_h(decoded_values),
    }

    if original is not None:
        original_values = list(original)
        fields["G proof result"] = decoded_g == derive_g(original_values)
        fields["H proof result"] = decoded_h == derive_h(original_values)
        fields["AngleNode proof result"] = decoded_h == derive_h(original_values)

    return fields


def pack_bytes(lam: bytes) -> tuple[bytes, bytes]:
    q = derive_q(lam)
    q_bytes = expose_q(q)
    decoded = bytes_from_q(read_q(q_bytes))

    if decoded != lam:
        raise CoordinateError("D(q) does not equal Lambda")

    if decode_q(derive_q(lam)) != list(lam):
        raise CoordinateError("decode_q(derive_q(Lambda)) does not equal Lambda")

    return q_bytes, decoded


def unpack_bytes(q_bytes: bytes) -> bytes:
    return bytes_from_q(read_q(q_bytes))


def print_report(report: dict[str, object]) -> None:
    print(json.dumps(report, indent=2))


def closure_classification(
    reconstruction_closed: bool,
    residual_empty: bool,
    q_smaller: bool,
) -> str | None:
    if not reconstruction_closed or not residual_empty:
        return "FORMAT_OR_ARTIFACT_ERROR"
    if not q_smaller:
        return "NON_MINIMAL_Q_EXPOSURE"
    return None


def pack_report(input_path: Path, output_path: Path, lam: bytes, q_bytes: bytes, decoded: bytes):
    exact_match = decoded == lam
    length_equal = len(decoded) == len(lam)
    sha_equal = sha256_hex(decoded) == sha256_hex(lam)
    q_smaller = len(q_bytes) < len(lam)
    reconstruction_closed = exact_match and length_equal and sha_equal
    residual_empty = True
    compression_closed = reconstruction_closed and residual_empty and q_smaller
    classification = closure_classification(
        reconstruction_closed,
        residual_empty,
        q_smaller,
    )
    return {
        "input_path": str(input_path),
        "output_path": str(output_path),
        "original_size": len(lam),
        "q_size": len(q_bytes),
        "ratio": len(q_bytes) / len(lam) if len(lam) != 0 else None,
        "original_sha256": sha256_hex(lam),
        "q_sha256": sha256_hex(q_bytes),
        "decoded_sha256": sha256_hex(decoded),
        "decoded_size": len(decoded),
        "exact_match": exact_match,
        "length_equal": length_equal,
        "sha_equal": sha_equal,
        "q_smaller_than_Lambda": q_smaller,
        "residual": [],
        "residual_empty": residual_empty,
        **proof_fields(lam, decoded),
        "reconstruction_status": "RECONSTRUCTION_CLOSED"
        if reconstruction_closed
        else "RECONSTRUCTION_FAILED",
        "bac_compression_status": "BAC_COMPRESSION_CLOSED"
        if compression_closed
        else "BAC_COMPRESSION_FRONTIER",
        "implementation_classification": classification,
        "status": "BAC_COMPRESSION_CLOSED"
        if compression_closed
        else "RECONSTRUCTION_CLOSED"
        if reconstruction_closed
        else "RECONSTRUCTION_FAILED",
    }


def unpack_report(input_path: Path, output_path: Path, q_bytes: bytes, decoded: bytes):
    return {
        "input_path": str(input_path),
        "output_path": str(output_path),
        "q_size": len(q_bytes),
        "q_sha256": sha256_hex(q_bytes),
        "decoded_sha256": sha256_hex(decoded),
        "decoded_size": len(decoded),
        "residual": [],
        "residual_empty": True,
        **proof_fields(None, decoded),
        "reconstruction_status": "RECONSTRUCTION_CLOSED",
        "status": "RECONSTRUCTION_CLOSED",
    }


def verify_report(input_path: Path, q_path: Path, lam: bytes, q_bytes: bytes, decoded: bytes):
    exact_match = decoded == lam
    length_equal = len(decoded) == len(lam)
    sha_equal = sha256_hex(decoded) == sha256_hex(lam)
    q_smaller = len(q_bytes) < len(lam)
    reconstruction_closed = exact_match and length_equal and sha_equal
    residual_empty = True
    compression_closed = reconstruction_closed and residual_empty and q_smaller
    classification = closure_classification(
        reconstruction_closed,
        residual_empty,
        q_smaller,
    )
    return {
        "input_path": str(input_path),
        "q_path": str(q_path),
        "original_size": len(lam),
        "q_size": len(q_bytes),
        "ratio": len(q_bytes) / len(lam) if len(lam) != 0 else None,
        "original_sha256": sha256_hex(lam),
        "q_sha256": sha256_hex(q_bytes),
        "decoded_sha256": sha256_hex(decoded),
        "decoded_size": len(decoded),
        "exact_match": exact_match,
        "length_equal": length_equal,
        "sha_equal": sha_equal,
        "q_smaller_than_Lambda": q_smaller,
        "residual": [],
        "residual_empty": residual_empty,
        **proof_fields(lam, decoded),
        "reconstruction_status": "RECONSTRUCTION_CLOSED"
        if reconstruction_closed
        else "RECONSTRUCTION_FAILED",
        "bac_compression_status": "BAC_COMPRESSION_CLOSED"
        if compression_closed
        else "BAC_COMPRESSION_FRONTIER",
        "implementation_classification": classification,
        "status": "BAC_COMPRESSION_CLOSED"
        if compression_closed
        else "RECONSTRUCTION_CLOSED"
        if reconstruction_closed
        else "RECONSTRUCTION_FAILED",
    }


def cmd_pack(args) -> int:
    input_path = Path(args.input_path)
    output_path = Path(args.output_path)
    lam = read_bytes(input_path)
    q_bytes, decoded = pack_bytes(lam)
    write_bytes(output_path, q_bytes)
    report = pack_report(input_path, output_path, lam, q_bytes, decoded)
    print_report(report)
    return 0 if report["reconstruction_status"] == "RECONSTRUCTION_CLOSED" else 1


def cmd_unpack(args) -> int:
    input_path = Path(args.input_path)
    output_path = Path(args.output_path)
    q_bytes = read_bytes(input_path)
    decoded = unpack_bytes(q_bytes)
    write_bytes(output_path, decoded)
    print_report(unpack_report(input_path, output_path, q_bytes, decoded))
    return 0


def cmd_verify(args) -> int:
    input_path = Path(args.input_path)
    q_path = Path(args.q_path)
    lam = read_bytes(input_path)
    q_bytes = read_bytes(q_path)
    decoded = unpack_bytes(q_bytes)
    report = verify_report(input_path, q_path, lam, q_bytes, decoded)
    print_report(report)
    return 0 if report["reconstruction_status"] == "RECONSTRUCTION_CLOSED" else 1


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="BAC coordinate q = <n,b,g,coeffs_A>")
    sub = parser.add_subparsers(dest="command", required=True)

    pack = sub.add_parser("pack")
    pack.add_argument("input_path")
    pack.add_argument("output_path")

    unpack = sub.add_parser("unpack")
    unpack.add_argument("input_path")
    unpack.add_argument("output_path")

    verify = sub.add_parser("verify")
    verify.add_argument("input_path")
    verify.add_argument("q_path")

    args = parser.parse_args(argv)

    try:
        if args.command == "pack":
            return cmd_pack(args)
        if args.command == "unpack":
            return cmd_unpack(args)
        if args.command == "verify":
            return cmd_verify(args)
    except CoordinateError as exc:
        print(f"FAILED / {exc}", file=sys.stderr)
        return 1

    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
