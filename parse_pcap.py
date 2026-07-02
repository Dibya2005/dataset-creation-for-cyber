#!/usr/bin/env python3
"""
parse_pcap.py

Parses a .pcap file (captured via capture_traffic.sh / tcpdump) into a
structured CSV file, one row per packet.

Requires: scapy
    pip install scapy --break-system-packages

Usage:
    python3 parse_pcap.py input.pcap output.csv
"""

import sys
import csv
from datetime import datetime, timezone

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP
except ImportError:
    sys.exit("scapy is required. Install with: pip install scapy --break-system-packages")


FIELDNAMES = [
    "timestamp_utc",
    "src_ip",
    "dst_ip",
    "protocol",
    "src_port",
    "dst_port",
    "length",
    "tcp_flags",
    "ttl",
]


def flags_to_str(pkt):
    if TCP in pkt:
        f = pkt[TCP].flags
        return str(f)
    return ""


def parse_pcap(in_path, out_path):
    packets = rdpcap(in_path)
    rows = []

    for pkt in packets:
        if IP not in pkt:
            continue

        ip_layer = pkt[IP]
        ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).isoformat()

        proto = "OTHER"
        src_port = ""
        dst_port = ""
        tcp_flags = ""

        if TCP in pkt:
            proto = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            tcp_flags = flags_to_str(pkt)
        elif UDP in pkt:
            proto = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        elif ICMP in pkt:
            proto = "ICMP"

        rows.append({
            "timestamp_utc": ts,
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "protocol": proto,
            "src_port": src_port,
            "dst_port": dst_port,
            "length": len(pkt),
            "tcp_flags": tcp_flags,
            "ttl": ip_layer.ttl,
        })

    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[*] Parsed {len(rows)} packets -> {out_path}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("Usage: python3 parse_pcap.py input.pcap output.csv")
    parse_pcap(sys.argv[1], sys.argv[2])
