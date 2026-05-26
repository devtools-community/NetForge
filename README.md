# NetForge

**Lightweight pcap analysis toolkit for network forensics and traffic inspection.**

NetForge wraps [Scapy](https://scapy.net/) to provide a clean, scriptable interface for extracting structured data from packet captures — source, destination, protocol, payload, and timing — without the boilerplate of working with Scapy directly.

Designed for security researchers, SOC analysts, and CTF participants who need quick, repeatable packet analysis without standing up a full SIEM.

---

## Features

- Parse `.pcap` and `.pcapng` files into structured Python objects
- Extract IP, TCP, UDP, ICMP fields with zero configuration
- Payload inspection with multi-encoding detection (UTF-8, hex, base64)
- Protocol-aware filtering (filter by port, IP range, protocol)
- Export to JSON, CSV, or plain text for downstream tooling
- CLI interface for one-liner analysis
- Designed to be imported as a library or run standalone

---

## Installation

```bash
git clone https://github.com/<your-account>/netforge.git
cd netforge
pip install -r requirements.txt
```

**Requirements:**
- Python 3.8+
- Scapy 2.5+

On macOS, Scapy requires libpcap:

```bash
brew install libpcap
```

---

## Quick Start

### CLI

```bash
# Summarize all packets in a capture
python3 -m netforge analyze capture.pcap

# Filter to TCP only, export as JSON
python3 -m netforge analyze capture.pcap --proto tcp --output json

# Show only packets with non-empty payloads
python3 -m netforge analyze capture.pcap --payload-only
```

### Library

```python
from netforge import NetForge

nf = NetForge("capture.pcap")
packets = nf.analyze()

for pkt in packets:
    print(pkt.src, "->", pkt.dst, "|", pkt.proto, "|", pkt.payload)
```

---

## CLI Reference

```
usage: python3 -m netforge [-h] {analyze,stats,export} pcap_file

Commands:
  analyze     Parse and display packet summary
  stats       Show aggregate statistics (top talkers, protocol breakdown)
  export      Export packets to JSON or CSV

Options:
  --proto       Filter by protocol: tcp, udp, icmp
  --src         Filter by source IP or CIDR
  --dst         Filter by destination IP or CIDR
  --port        Filter by port number
  --payload-only  Only show packets with non-empty payloads
  --output      Output format: text (default), json, csv
  --limit       Maximum packets to process
```

---

## Example Output

```
============================================================
  NetForge Packet Summary — 9 packets
============================================================

[   0]  TCP    192.168.1.10:54321 → 192.168.1.1:80
       Raw: GET / HTTP/1.1\r\nHost: internal.company.com

[   1]  TCP     192.168.1.1:80 → 192.168.1.10:54321
       Raw: HTTP/1.1 200 OK\r\nContent-Length: 13

[   3]  TCP    192.168.1.20:22 → 192.168.1.10:45678
       Raw: SSH-2.0-OpenSSH_8.9p1
```

---

## Project Structure

```
netforge/
├── netforge/
│   ├── __init__.py         # Public API
│   ├── analyzer.py         # Core packet extraction logic
│   ├── decoder.py          # Payload decoding utilities
│   ├── filters.py          # Protocol and field filters
│   └── exporters.py        # JSON/CSV export
├── tests/
│   ├── test_analyzer.py
│   └── test_decoder.py
├── examples/
│   ├── basic_analysis.py
│   └── filter_and_export.py
├── samples/
│   └── c_sample.pcap # Sample capture for testing
|	└── c_sample2...
|	└── c_sample3...
|	└── c_sample4...
├── requirements.txt
├── setup.py
└── README.md
```

---

## Known Issues

See the [Issues tab](../../issues) for open bugs and planned improvements.
Contributions welcome — PRs against `main` with tests included.

---

## License

MIT — see [LICENSE](LICENSE)

---

## Acknowledgements

Built on top of [Scapy](https://scapy.net/), the Python packet manipulation library.
Inspired by similar tools: [pyshark](https://github.com/KimiNewt/pyshark), [dpkt](https://github.com/kbandla/dpkt).
