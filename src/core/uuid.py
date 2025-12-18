import secrets
import time
import uuid


def uuid7() -> uuid.UUID:
    timestamp_ms = int(time.time() * 1000)
    rand_a = secrets.randbits(12)
    rand_b = secrets.randbits(62)

    raw = bytearray(16)
    raw[0:6] = timestamp_ms.to_bytes(6, "big")
    raw[6] = ((0x7 << 4) | (rand_a >> 8)) & 0xFF
    raw[7] = rand_a & 0xFF

    rand_b_bytes = bytearray(rand_b.to_bytes(8, "big"))
    rand_b_bytes[0] = (rand_b_bytes[0] & 0x3F) | 0x80
    raw[8:16] = rand_b_bytes

    return uuid.UUID(bytes=bytes(raw))
