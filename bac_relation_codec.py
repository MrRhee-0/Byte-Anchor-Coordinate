from pathlib import Path
import hashlib


def read_byte_carrier(path: Path) -> tuple[bytes, str]:
    with open(path, "rb") as handle:
        carrier = handle.read()
    return carrier, hashlib.sha256(carrier).hexdigest()


def byte_quantity(carrier: bytes) -> int:
    return len(carrier)


def byte_to_bit_states(value: int) -> tuple[int, ...]:
    if value < 0 or value > 255:
        raise ValueError("byte value must be in [0, 255]")
    return tuple((value >> shift) & 1 for shift in range(7, -1, -1))
