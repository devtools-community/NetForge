"""
examples/filter_and_export.py

Filter TCP packets and export to JSON.
"""

from netforge import NetForge

nf = NetForge("../samples/c_sample.pcap")

# Only TCP packets with non-empty payloads
packets = nf.analyze(filters={
    "proto": "tcp",
    "payload_only": True,
})

print(f"Found {len(packets)} TCP packets with payloads")

# Export as JSON
nf.export(fmt="json", output_path="/tmp/tcp_packets.json")
print("Exported to /tmp/tcp_packets.json")
