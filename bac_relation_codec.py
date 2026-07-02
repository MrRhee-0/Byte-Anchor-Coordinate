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


def bit_states_to_byte(bits: tuple[int, ...]) -> int:
    if len(bits) != 8:
        raise ValueError("byte relation requires exactly 8 bit states")
    value = 0
    for bit in bits:
        if bit not in (0, 1):
            raise ValueError("bit state must be 0 or 1")
        value = (value << 1) | bit
    return value


def byte_carrier_to_bit_states(carrier: bytes) -> tuple[tuple[int, ...], ...]:
    return tuple(byte_to_bit_states(value) for value in carrier)
