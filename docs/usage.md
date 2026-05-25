# NetForge Usage Guide

## Installation

```bash
git clone https://github.com/<your-account>/netforge.git
cd netforge
pip install -r requirements.txt
```

## CLI Usage

### Analyze a pcap file

```bash
python3 -m netforge analyze capture.pcap
```

### Filter by protocol

```bash
python3 -m netforge analyze capture.pcap --proto tcp
```

### Show only packets with payloads

```bash
python3 -m netforge analyze capture.pcap --payload-only
```

### Export to JSON

```bash
python3 -m netforge analyze capture.pcap --output json > results.json
```

### Show statistics

```bash
python3 -m netforge stats capture.pcap
```

## Library Usage

```python
from netforge import NetForge

nf = NetForge("capture.pcap")
packets = nf.analyze()

for pkt in packets:
    if pkt.payload:
        print(f"{pkt.src} -> {pkt.dst}: {pkt.payload[:100]}")
```

## Filtering

```python
packets = nf.analyze(filters={
    "proto": "tcp",
    "src": "192.168.1.",
    "port": 443,
    "payload_only": True,
})
```
