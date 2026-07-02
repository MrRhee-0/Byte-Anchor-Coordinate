from pathlib import Path
import hashlib


def read_byte_carrier(path: Path) -> tuple[bytes, str]:
    with open(path, "rb") as handle:
        carrier = handle.read()
    return carrier, hashlib.sha256(carrier).hexdigest()
