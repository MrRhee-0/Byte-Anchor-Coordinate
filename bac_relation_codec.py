#!/usr/bin/env python3
"""
BAC AngleNode coordinate branch.

Artifact rule:
  The .bac payload is only q = <n, b1, g1, coord(A)> encoded as:
    uvarint(n) || byte(b1) || svarint(g1) || coord(A)

Admitted coord(A):
  AngleConst(a)
  AngleAffine(a1, step)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


class BACError(Exception):
    pass


ANGLE_CONST = 1
ANGLE_AFFINE = 2


def read_bytes(path: Path) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def write_bytes(path: Path, data: bytes) -> None:
    with open(path, "wb") as handle:
        handle.write(data)


def encode_uvarint(x: int) -> bytes:
    if x < 0:
        raise BACError("uvarint cannot encode negative value")
    out = bytearray()
    while True:
        b = x & 0x7F
        x >>= 7
        if x:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def read_uvarint(buf: bytes, pos: int) -> tuple[int, int]:
    start = pos
    shift = 0
    value = 0

    while True:
        if pos >= len(buf):
            raise BACError("truncated uvarint")
        b = buf[pos]
        pos += 1

        value |= (b & 0x7F) << shift

        if not (b & 0x80):
            consumed = buf[start:pos]
            if encode_uvarint(value) != consumed:
                raise BACError("non-minimal uvarint encoding")
            return value, pos

        shift += 7
        if shift > 63:
            raise BACError("uvarint too large for this BAC branch")


def zigzag_encode(x: int) -> int:
    return (x << 1) if x >= 0 else ((-x << 1) - 1)


def zigzag_decode(u: int) -> int:
    return (u >> 1) if (u & 1) == 0 else -((u + 1) >> 1)


def encode_svarint(x: int) -> bytes:
    return encode_uvarint(zigzag_encode(x))


def read_svarint(buf: bytes, pos: int) -> tuple[int, int]:
    u, pos = read_uvarint(buf, pos)
    return zigzag_decode(u), pos


def derive_g(data: bytes) -> list[int]:
    return [data[i + 1] - data[i] for i in range(len(data) - 1)]


def derive_angle_nodes_from_g(g: list[int]) -> list[int]:
    return [g[i + 1] - g[i] for i in range(len(g) - 1)]


def derive_angle_coordinate(data: bytes) -> tuple[int, int, int, tuple[int, ...]] | None:
    n = len(data)
    if n < 3:
        return None

    g = derive_g(data)
    angle = derive_angle_nodes_from_g(g)
    if not angle:
        return None

    first = angle[0]
    if all(node == first for node in angle):
        return n, data[0], g[0], (ANGLE_CONST, first)

    step = angle[1] - angle[0]
    for index, node in enumerate(angle):
        if node != first + (index * step):
            return None

    return n, data[0], g[0], (ANGLE_AFFINE, first, step)


def encode_angle_coord(angle_coord: tuple[int, ...]) -> bytes:
    kind = angle_coord[0]
    if kind == ANGLE_CONST:
        return bytes([kind]) + encode_svarint(angle_coord[1])
    if kind == ANGLE_AFFINE:
        return (
            bytes([kind])
            + encode_svarint(angle_coord[1])
            + encode_svarint(angle_coord[2])
        )
    raise BACError("unknown AngleNode coordinate")


def encode_q(q: tuple[int, int, int, tuple[int, ...]]) -> bytes:
    n, b1, g1, angle_coord = q
    if n < 3:
        raise BACError("AngleNode q requires n >= 3")
    if not 0 <= b1 <= 255:
        raise BACError("b1 must be a byte")

    return (
        encode_uvarint(n)
        + bytes([b1])
        + encode_svarint(g1)
        + encode_angle_coord(angle_coord)
    )


def decode_angle_coord(
    q_bytes: bytes,
    pos: int,
    angle_count: int,
) -> tuple[list[int], int, tuple[int, ...]]:
    if pos >= len(q_bytes):
        raise BACError("missing AngleNode coordinate")

    kind = q_bytes[pos]
    pos += 1

    if kind == ANGLE_CONST:
        value, pos = read_svarint(q_bytes, pos)
        return [value for _ in range(angle_count)], pos, (kind, value)

    if kind == ANGLE_AFFINE:
        first, pos = read_svarint(q_bytes, pos)
        step, pos = read_svarint(q_bytes, pos)
        angle = [first + (index * step) for index in range(angle_count)]
        return angle, pos, (kind, first, step)

    raise BACError("unknown AngleNode coordinate")


def decode_q(q_bytes: bytes) -> tuple[int, int, int, list[int], tuple[int, ...]]:
    pos = 0

    n, pos = read_uvarint(q_bytes, pos)
    if n < 3:
        raise BACError("AngleNode q requires n >= 3")

    if pos >= len(q_bytes):
        raise BACError("missing b1")
    b1 = q_bytes[pos]
    pos += 1

    g1, pos = read_svarint(q_bytes, pos)
    angle, pos, angle_coord = decode_angle_coord(q_bytes, pos, n - 2)

    if pos != len(q_bytes):
        raise BACError("trailing bytes: artifact is not exactly q")

    return n, b1, g1, angle, angle_coord


def reconstruct(q: tuple[int, int, int, list[int], tuple[int, ...]]) -> bytes:
    n, b1, g, angle, _angle_coord = q

    if n < 3:
        raise BACError("AngleNode q requires n >= 3")
    if not 0 <= b1 <= 255:
        raise BACError("b1 must be a byte")
    if len(angle) != n - 2:
        raise BACError("AngleNode coordinate expanded to wrong length")

    out = [b1]

    for edge_index in range(n - 1):
        nxt = out[-1] + g
        if not 0 <= nxt <= 255:
            raise BACError("reconstruction left byte carrier boundary 0..255")
        out.append(nxt)

        if edge_index < len(angle):
            g = g + angle[edge_index]

    return bytes(out)


def pack_bac(data: bytes) -> bytes | None:
    q = derive_angle_coordinate(data)
    if q is None:
        return None

    q_bytes = encode_q(q)

    decoded = reconstruct(decode_q(q_bytes))
    if decoded != data:
        raise BACError("internal closure failure: D(q) != Lambda")

    if len(q_bytes) >= len(data):
        return None

    return q_bytes


def unpack_bac(q_bytes: bytes) -> bytes:
    return reconstruct(decode_q(q_bytes))


def cmd_pack(src: Path, dst: Path) -> int:
    data = read_bytes(src)
    q_bytes = pack_bac(data)

    if q_bytes is None:
        print("FAILED / ANGLE_COORD_FRONTIER_OR_Q_NOT_REDUCED")
        return 2

    write_bytes(dst, q_bytes)
    print(f"CLOSED q_bytes={len(q_bytes)} carrier_bytes={len(data)}")
    return 0


def cmd_unpack(src: Path, dst: Path) -> int:
    q_bytes = read_bytes(src)
    data = unpack_bac(q_bytes)
    write_bytes(dst, data)
    print(f"DECODED carrier_bytes={len(data)}")
    return 0


def cmd_verify(original: Path, bac: Path) -> int:
    witness = read_bytes(original)
    q_bytes = read_bytes(bac)
    decoded = unpack_bac(q_bytes)

    closed = (
        decoded == witness
        and len(decoded) == len(witness)
        and len(q_bytes) < len(witness)
    )

    if closed:
        print("CLOSED")
        return 0

    print("FAILED")
    print(f"decoded_equals_witness={decoded == witness}")
    print(f"decoded_len={len(decoded)} witness_len={len(witness)}")
    print(f"q_len={len(q_bytes)} witness_len={len(witness)}")
    return 1


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description="BAC AngleNode coordinate branch")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_pack = sub.add_parser("pack")
    p_pack.add_argument("src", type=Path)
    p_pack.add_argument("dst", type=Path)

    p_unpack = sub.add_parser("unpack")
    p_unpack.add_argument("src", type=Path)
    p_unpack.add_argument("dst", type=Path)

    p_verify = sub.add_parser("verify")
    p_verify.add_argument("original", type=Path)
    p_verify.add_argument("bac", type=Path)

    args = p.parse_args(argv)

    try:
        if args.cmd == "pack":
            return cmd_pack(args.src, args.dst)
        if args.cmd == "unpack":
            return cmd_unpack(args.src, args.dst)
        if args.cmd == "verify":
            return cmd_verify(args.original, args.bac)
    except BACError as e:
        print(f"FAILED / {e}", file=sys.stderr)
        return 1

    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
