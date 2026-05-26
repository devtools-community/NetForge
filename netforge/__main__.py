"""
netforge/__main__.py

CLI entry point.
Usage: python3 -m netforge analyze capture.pcap
"""

import argparse
import sys
from netforge import NetForge


def main():
    parser = argparse.ArgumentParser(
        prog="netforge",
        description="Lightweight pcap analysis toolkit"
    )
    subparsers = parser.add_subparsers(dest="command")

    # analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Parse and display packet summary")
    analyze_parser.add_argument("pcap", help="Path to pcap file")
    analyze_parser.add_argument("--proto", help="Filter by protocol: tcp, udp, icmp")
    analyze_parser.add_argument("--src", help="Filter by source IP")
    analyze_parser.add_argument("--dst", help="Filter by destination IP")
    analyze_parser.add_argument("--port", type=int, help="Filter by port number")
    analyze_parser.add_argument("--payload-only", action="store_true", help="Only show packets with payloads")
    analyze_parser.add_argument("--output", choices=["text", "json", "csv"], default="text")
    analyze_parser.add_argument("--limit", type=int, help="Max packets to process")

    # stats command
    stats_parser = subparsers.add_parser("stats", help="Show aggregate statistics")
    stats_parser.add_argument("pcap", help="Path to pcap file")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    nf = NetForge(args.pcap)

    if args.command == "analyze":
        filters = {}
        if args.proto:
            filters["proto"] = args.proto
        if args.src:
            filters["src"] = args.src
        if args.dst:
            filters["dst"] = args.dst
        if args.port:
            filters["port"] = args.port
        if args.payload_only:
            filters["payload_only"] = True

        packets = nf.analyze(filters or None)
        nf.export(fmt=args.output)

    elif args.command == "stats":
        stats = nf.stats()
        print(f"\nTotal packets : {stats['total_packets']}")
        print(f"\nProtocols:")
        for proto, count in stats["protocols"].items():
            print(f"  {proto:>6}: {count}")
        print(f"\nTop sources:")
        for src, count in stats["top_sources"]:
            print(f"  {src:>20}: {count} packets")


if __name__ == "__main__":
    main()
