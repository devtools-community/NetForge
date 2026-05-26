"""
netforge/analyzer.py

Core packet extraction and analysis logic.
"""

from scapy.all import rdpcap, IP, TCP, UDP, ICMP, Raw
import os

from netforge.decoder import decode_payload
from netforge.filters import apply_filters
from netforge.exporters import export_text, export_json, export_csv


class PacketRecord:
    """Structured representation of a single packet."""

    def __init__(self, index, src, dst, proto, payload, raw_size):
        self.index = index
        self.src = src
        self.dst = dst
        self.proto = proto
        self.payload = payload
        self.raw_size = raw_size

    def __repr__(self):
        return f"PacketRecord(index={self.index}, src={self.src}, dst={self.dst}, proto={self.proto})"


class NetForge:
    """
    Main interface for pcap analysis.

    Usage:
        nf = NetForge("capture.pcap")
        packets = nf.analyze()
    """

    def __init__(self, pcap_path):
        if not os.path.exists(pcap_path):
            raise FileNotFoundError(f"pcap file not found: {pcap_path}")
        self.pcap_path = pcap_path
        self._packets = None

    def analyze(self, filters=None):
        """
        Parse the pcap and return a list of PacketRecord objects.

        Args:
            filters: dict of filter options (proto, src, dst, port, payload_only)

        Returns:
            list of PacketRecord
        """
        raw_packets = rdpcap(self.pcap_path)
        records = []

        for i, pkt in enumerate(raw_packets):
            record = self._extract(i, pkt)
            if record:
                records.append(record)

        if filters:
            records = apply_filters(records, filters)

        self._packets = records
        return records

    def _extract(self, index, pkt):
        src = dst = proto = payload = None
        raw_size = 0

        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst

            if TCP in pkt:
                proto = "TCP"
                src += f":{pkt[TCP].sport}"
                dst += f":{pkt[TCP].dport}"
            elif UDP in pkt:
                proto = "UDP"
                src += f":{pkt[UDP].sport}"
                dst += f":{pkt[UDP].dport}"
            elif ICMP in pkt:
                proto = "ICMP"
            else:
                proto = "IP"
        else:
            return None

        if Raw in pkt:
            raw_size = len(pkt[Raw].load)
            payload = decode_payload(pkt[Raw].load)

        return PacketRecord(index, src, dst, proto, payload, raw_size)

    def stats(self):
        """Return aggregate statistics for the analyzed capture."""
        if self._packets is None:
            self.analyze()

        proto_counts = {}
        src_counts = {}

        for r in self._packets:
            proto_counts[r.proto] = proto_counts.get(r.proto, 0) + 1
            base_src = r.src.split(":")[0] if r.src else "unknown"
            src_counts[base_src] = src_counts.get(base_src, 0) + 1

        return {
            "total_packets": len(self._packets),
            "protocols": proto_counts,
            "top_sources": sorted(src_counts.items(), key=lambda x: -x[1])[:10],
        }

    def export(self, fmt="text", output_path=None):
        """Export analyzed packets to text, JSON, or CSV."""
        if self._packets is None:
            self.analyze()

        if fmt == "json":
            return export_json(self._packets, output_path)
        elif fmt == "csv":
            return export_csv(self._packets, output_path)
        else:
            return export_text(self._packets, output_path)
