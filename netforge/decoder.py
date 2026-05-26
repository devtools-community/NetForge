"""
netforge/decoder.py

Payload decoding utilities.
"""

import binascii


def decode_payload(raw_bytes):
    """
    Attempt decode raw packet payload into a readable string.
    """
    if not raw_bytes:
        return None

    try:
        text = raw_bytes.decode("utf-8", errors="strict")
        return text
    except UnicodeDecodeError:
        pass

    return binascii.hexlify(raw_bytes).decode("ascii")
