"""
netforge/filters.py

Packet filtering utilities.
"""


def apply_filters(records, filters):
    """
    Filter a list of PacketRecord objects based on filter criteria.

    Supported filters:
        proto       : str  — 'tcp', 'udp', 'icmp'
        src         : str  — source IP (exact match or prefix)
        dst         : str  — destination IP (exact match or prefix)
        port        : int  — match src or dst port
        payload_only: bool — only include packets with non-empty payload
    """
    result = records

    if filters.get("proto"):
        p = filters["proto"].upper()
        result = [r for r in result if r.proto == p]

    if filters.get("src"):
        s = filters["src"]
        result = [r for r in result if r.src and r.src.startswith(s)]

    if filters.get("dst"):
        d = filters["dst"]
        result = [r for r in result if r.dst and r.dst.startswith(d)]

    if filters.get("port"):
        port = str(filters["port"])
        result = [r for r in result if r.src and (
            r.src.endswith(f":{port}") or (r.dst and r.dst.endswith(f":{port}"))
        )]

    if filters.get("payload_only"):
        result = [r for r in result if r.payload]

    return result
