"""
tests/test_analyzer.py
"""

import pytest
import os
from netforge import NetForge


SAMPLE_PCAP = os.path.join(os.path.dirname(__file__), "..", "samples", "c_sample.pcap")


def test_netforge_loads():
    if not os.path.exists(SAMPLE_PCAP):
        pytest.skip("sample pcap not found")
    nf = NetForge(SAMPLE_PCAP)
    assert nf is not None


def test_analyze_returns_list():
    if not os.path.exists(SAMPLE_PCAP):
        pytest.skip("sample pcap not found")
    nf = NetForge(SAMPLE_PCAP)
    packets = nf.analyze()
    assert isinstance(packets, list)


def test_packet_fields():
    if not os.path.exists(SAMPLE_PCAP):
        pytest.skip("sample pcap not found")
    nf = NetForge(SAMPLE_PCAP)
    packets = nf.analyze()
    for pkt in packets:
        assert hasattr(pkt, "src")
        assert hasattr(pkt, "dst")
        assert hasattr(pkt, "proto")


def test_filter_by_proto():
    if not os.path.exists(SAMPLE_PCAP):
        pytest.skip("sample pcap not found")
    nf = NetForge(SAMPLE_PCAP)
    packets = nf.analyze(filters={"proto": "tcp"})
    for pkt in packets:
        assert pkt.proto == "TCP"


def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        NetForge("/nonexistent/path.pcap")
