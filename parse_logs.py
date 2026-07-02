#!/usr/bin/env python3
"""
parse_logs.py

Parses Apache access.log and/or Linux auth.log (SSH login attempts) into
structured CSV files.

Usage:
    python3 parse_logs.py apache /var/log/apache2/access.log apache_parsed.csv
    python3 parse_logs.py auth   /var/log/auth.log auth_parsed.csv
"""

import sys
import csv
import re

APACHE_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d+) (?P<size>\S+)'
)

AUTH_RE = re.compile(
    r'^(?P<time>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}) \S+ sshd\[\d+\]: '
    r'(?P<result>Failed|Accepted) password for (?:invalid user )?(?P<user>\S+) '
    r'from (?P<ip>\S+) port (?P<port>\d+)'
)


def parse_apache(in_path, out_path):
    rows = []
    with open(in_path, "r", errors="ignore") as f:
        for line in f:
            m = APACHE_RE.search(line)
            if not m:
                continue
            rows.append({
                "timestamp": m.group("time"),
                "src_ip": m.group("ip"),
                "method": m.group("method"),
                "path": m.group("path"),
                "status": m.group("status"),
                "size": m.group("size"),
            })

    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "src_ip", "method", "path", "status", "size"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"[*] Parsed {len(rows)} Apache log lines -> {out_path}")


def parse_auth(in_path, out_path):
    rows = []
    with open(in_path, "r", errors="ignore") as f:
        for line in f:
            m = AUTH_RE.search(line)
            if not m:
                continue
            rows.append({
                "timestamp": m.group("time"),
                "result": m.group("result"),
                "user": m.group("user"),
                "src_ip": m.group("ip"),
                "port": m.group("port"),
            })

    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "result", "user", "src_ip", "port"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"[*] Parsed {len(rows)} auth log lines -> {out_path}")


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] not in ("apache", "auth"):
        sys.exit("Usage: python3 parse_logs.py [apache|auth] input_log output.csv")

    mode, in_path, out_path = sys.argv[1], sys.argv[2], sys.argv[3]
    if mode == "apache":
        parse_apache(in_path, out_path)
    else:
        parse_auth(in_path, out_path)
