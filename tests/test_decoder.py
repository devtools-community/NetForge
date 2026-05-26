"""
tests/test_decoder.py
"""

from netforge.decoder import decode_payload


def test_utf8_payload():
    raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    result = decode_payload(raw)
    assert "GET" in result
    assert "HTTP" in result


def test_binary_falls_back_to_hex():
    raw = bytes([0x00, 0x01, 0xFF, 0xFE])
    result = decode_payload(raw)
    assert result == "0001fffe"


def test_empty_payload():
    result = decode_payload(b"")
    assert result is None


def test_ssh_banner():
    raw = b"SSH-2.0-OpenSSH_8.9p1"
    result = decode_payload(raw)
    assert result == "SSH-2.0-OpenSSH_8.9p1"
