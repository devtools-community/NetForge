"""
examples/basic_analysis.py

Basic example: load a pcap and print a summary.
"""

from netforge import NetForge

nf = NetForge("../samples/c_sample.pcap")
packets = nf.analyze()

print(f"Loaded {len(packets)} packets\n")

for pkt in packets[:5]:
    print(f"  {pkt.proto:>4}  {pkt.src} → {pkt.dst}")
    if pkt.payload:
        print(f"        {pkt.payload[:60]}")
