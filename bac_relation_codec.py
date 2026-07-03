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


def bit_states_to_byte_carrier(
    bit_state_carrier: tuple[tuple[int, ...], ...]
) -> bytes:
    return bytes(bit_states_to_byte(bits) for bits in bit_state_carrier)


def flatten_bit_state_carrier(
    bit_state_carrier: tuple[tuple[int, ...], ...]
) -> tuple[int, ...]:
    return tuple(bit for byte_bits in bit_state_carrier for bit in byte_bits)


def unflatten_bit_state_carrier(
    flat_bits: tuple[int, ...]
) -> tuple[tuple[int, ...], ...]:
    if len(flat_bits) % 8 != 0:
        raise ValueError("flat bit-state carrier length must be divisible by 8")
    for bit in flat_bits:
        if bit not in (0, 1):
            raise ValueError("bit state must be 0 or 1")
    return tuple(
        tuple(flat_bits[offset : offset + 8])
        for offset in range(0, len(flat_bits), 8)
    )


def pack_flat_bits_to_bytes(flat_bits: tuple[int, ...]) -> tuple[bytes, int]:
    for bit in flat_bits:
        if bit not in (0, 1):
            raise ValueError("bit state must be 0 or 1")
    padding = (-len(flat_bits)) % 8
    padded_bits = flat_bits + ((0,) * padding)
    values = []
    for offset in range(0, len(padded_bits), 8):
        values.append(bit_states_to_byte(tuple(padded_bits[offset : offset + 8])))
    return bytes(values), padding


def unpack_bytes_to_flat_bits(packed: bytes, padding: int) -> tuple[int, ...]:
    if padding < 0 or padding > 7:
        raise ValueError("padding must be in [0, 7]")
    flat_bits = flatten_bit_state_carrier(byte_carrier_to_bit_states(packed))
    if padding == 0:
        return flat_bits
    if len(flat_bits) < padding:
        raise ValueError("padding exceeds flat bit-state length")
    if any(bit != 0 for bit in flat_bits[-padding:]):
        raise ValueError("padding bits must be 0")
    return flat_bits[:-padding]


def uint_bit_width(value: int) -> int:
    if value < 0:
        raise ValueError("uint value must be greater than or equal to 0")
    return max(1, value.bit_length())


def uint_to_minimal_bit_states(value: int) -> tuple[int, ...]:
    width = uint_bit_width(value)
    return tuple((value >> shift) & 1 for shift in range(width - 1, -1, -1))


def minimal_bit_states_to_uint(bits: tuple[int, ...]) -> int:
    if len(bits) == 0:
        raise ValueError("uint bit-state carrier must not be empty")
    value = 0
    for bit in bits:
        if bit not in (0, 1):
            raise ValueError("bit state must be 0 or 1")
        value = (value << 1) | bit
    return value


def byte_carrier_to_minimal_uint_bit_states(
    carrier: bytes
) -> tuple[tuple[int, ...], ...]:
    return tuple(uint_to_minimal_bit_states(value) for value in carrier)


def minimal_uint_bit_states_to_byte_carrier(
    minimal_carrier: tuple[tuple[int, ...], ...]
) -> bytes:
    values = []
    for bits in minimal_carrier:
        value = minimal_bit_states_to_uint(bits)
        if value > 255:
            raise ValueError("uint value must be in [0, 255] for byte carrier")
        if bits != uint_to_minimal_bit_states(value):
            raise ValueError("uint bit-state carrier must be minimal")
        values.append(value)
    return bytes(values)


def byte_carrier_uint_bit_widths(carrier: bytes) -> tuple[int, ...]:
    return tuple(uint_bit_width(value) for value in carrier)


def uint_bit_widths_to_codes(widths: tuple[int, ...]) -> tuple[int, ...]:
    codes = []
    for width in widths:
        if width < 1 or width > 8:
            raise ValueError("uint bit width for a byte must be in [1, 8]")
        codes.append(width - 1)
    return tuple(codes)


def uint_bit_width_codes_to_widths(codes: tuple[int, ...]) -> tuple[int, ...]:
    widths = []
    for code in codes:
        if code < 0 or code > 7:
            raise ValueError("uint bit width code for a byte must be in [0, 7]")
        widths.append(code + 1)
    return tuple(widths)


def uint_bit_width_codes_to_bit_states(codes: tuple[int, ...]) -> tuple[int, ...]:
    bits = []
    for code in codes:
        if code < 0 or code > 7:
            raise ValueError("uint bit width code for a byte must be in [0, 7]")
        bits.extend(((code >> 2) & 1, (code >> 1) & 1, code & 1))
    return tuple(bits)


def bit_states_to_uint_bit_width_codes(code_bits: tuple[int, ...]) -> tuple[int, ...]:
    if len(code_bits) % 3 != 0:
        raise ValueError("width-code bit-state carrier length must be divisible by 3")
    codes = []
    for offset in range(0, len(code_bits), 3):
        bit_2 = code_bits[offset]
        bit_1 = code_bits[offset + 1]
        bit_0 = code_bits[offset + 2]
        for bit in (bit_2, bit_1, bit_0):
            if bit not in (0, 1):
                raise ValueError("bit state must be 0 or 1")
        codes.append((bit_2 << 2) | (bit_1 << 1) | bit_0)
    return tuple(codes)


def flatten_minimal_uint_bit_state_carrier(
    minimal_carrier: tuple[tuple[int, ...], ...]
) -> tuple[int, ...]:
    bits = []
    for member_bits in minimal_carrier:
        if len(member_bits) == 0:
            raise ValueError("minimal uint bit-state member must not be empty")
        for bit in member_bits:
            if bit not in (0, 1):
                raise ValueError("bit state must be 0 or 1")
            bits.append(bit)
    return tuple(bits)
