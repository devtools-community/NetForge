"""
netforge/exporters.py

Export packet records to various formats.
"""

import json
import csv
import sys


def _record_to_dict(r):
    return {
        "index": r.index,
        "src": r.src,
        "dst": r.dst,
        "proto": r.proto,
        "payload": r.payload,
        "raw_size": r.raw_size,
    }


def export_text(records, output_path=None):
    lines = []
    lines.append(f"\n{'='*60}")
    lines.append(f"  NetForge Packet Summary — {len(records)} packets")
    lines.append(f"{'='*60}\n")

    for r in records:
        lines.append(f"[{r.index:>4}] {r.proto or '?':>4}  {r.src:>25} → {r.dst}")
        if r.payload:
            preview = r.payload[:80].replace("\n", "\\n").replace("\r", "\\r")
            lines.append(f"       Raw: {preview}")
        lines.append("")

    text = "\n".join(lines)

    if output_path:
        with open(output_path, "w") as f:
            f.write(text)
    else:
        print(text)

    return text


def export_json(records, output_path=None):
    data = [_record_to_dict(r) for r in records]
    text = json.dumps(data, indent=2)

    if output_path:
        with open(output_path, "w") as f:
            f.write(text)
    else:
        print(text)

    return text


def export_csv(records, output_path=None):
    fieldnames = ["index", "src", "dst", "proto", "payload", "raw_size"]

    if output_path:
        f = open(output_path, "w", newline="")
        close = True
    else:
        f = sys.stdout
        close = False

    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for r in records:
        writer.writerow(_record_to_dict(r))

    if close:
        f.close()
