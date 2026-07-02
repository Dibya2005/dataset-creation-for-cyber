#!/usr/bin/env python3
"""
build_dataset.py

One-command pipeline: parse every captured pcap, label each by its
filename (capture_traffic.sh already names files <label>_<timestamp>.pcap),
parse the Apache/auth logs and label them by time window, then combine
everything into final labeled dataset files.

Requires: scapy, pandas
    pip install scapy pandas --break-system-packages

Directory layout expected:
    captures/normal_20260701_100005.pcap
    captures/port_scan_20260701_100610.pcap
    captures/ssh_bruteforce_20260701_100920.pcap
    ...

Usage:
    python3 build_dataset.py \
        --captures-dir captures \
        --apache-log access.log \
        --auth-log auth.log \
        --windows windows.csv \
        --out-dir final

--apache-log, --auth-log, and --windows are all optional. If you only
have pcaps, just run:
    python3 build_dataset.py --captures-dir captures --out-dir final
"""

import argparse
import csv
import glob
import os
import re
import sys
from datetime import datetime, timezone

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP
except ImportError:
    sys.exit("scapy is required. Install with: pip install scapy --break-system-packages")

try:
    import pandas as pd
except ImportError:
    sys.exit("pandas is required. Install with: pip install pandas --break-system-packages")


PCAP_NAME_RE = re.compile(r"^(?P<label>.+)_\d{8}_\d{6}\.pcap$")

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


# ---------- pcap parsing ----------

def label_from_filename(path):
    name = os.path.basename(path)
    m = PCAP_NAME_RE.match(name)
    return m.group("label") if m else "unknown"


def parse_pcap_file(path):
    label = label_from_filename(path)
    packets = rdpcap(path)
    rows = []

    for pkt in packets:
        if IP not in pkt:
            continue
        ip_layer = pkt[IP]
        ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).isoformat()

        proto, src_port, dst_port, tcp_flags = "OTHER", "", "", ""
        if TCP in pkt:
            proto = "TCP"
            src_port, dst_port = pkt[TCP].sport, pkt[TCP].dport
            tcp_flags = str(pkt[TCP].flags)
        elif UDP in pkt:
            proto = "UDP"
            src_port, dst_port = pkt[UDP].sport, pkt[UDP].dport
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
            "label": label,
            "source_file": os.path.basename(path),
        })

    return rows


def build_pcap_dataset(captures_dir, out_dir):
    pcap_files = sorted(glob.glob(os.path.join(captures_dir, "*.pcap")))
    if not pcap_files:
        print(f"[!] No .pcap files found in {captures_dir}, skipping pcap dataset.")
        return

    all_rows = []
    print(f"[*] Found {len(pcap_files)} pcap file(s).")
    for f in pcap_files:
        rows = parse_pcap_file(f)
        label = label_from_filename(f)
        print(f"    - {os.path.basename(f)}: {len(rows)} packets, label='{label}'")
        all_rows.extend(rows)

    out_path = os.path.join(out_dir, "final_pcap_dataset.csv")
    fieldnames = ["timestamp_utc", "src_ip", "dst_ip", "protocol", "src_port",
                  "dst_port", "length", "tcp_flags", "ttl", "label", "source_file"]
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"[*] Wrote {len(all_rows)} total rows -> {out_path}")
    counts = pd.DataFrame(all_rows)["label"].value_counts()
    print("[*] Label distribution:")
    print(counts.to_string())


# ---------- log parsing ----------

def parse_apache_log(path):
    rows = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            m = APACHE_RE.search(line)
            if not m:
                continue
            rows.append({
                "timestamp_raw": m.group("time"),
                "src_ip": m.group("ip"),
                "method": m.group("method"),
                "path": m.group("path"),
                "status": m.group("status"),
                "size": m.group("size"),
            })
    return rows


def parse_auth_log(path, year):
    rows = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            m = AUTH_RE.search(line)
            if not m:
                continue
            rows.append({
                "timestamp_raw": f"{year} {m.group('time')}",
                "result": m.group("result"),
                "user": m.group("user"),
                "src_ip": m.group("ip"),
                "port": m.group("port"),
            })
    return rows


def load_windows(windows_path):
    windows = []
    with open(windows_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            windows.append({
                "label": row["label"],
                "start": datetime.fromisoformat(row["start_time"]),
                "end": datetime.fromisoformat(row["end_time"]),
            })
    return windows


def label_timestamp(ts, windows):
    if pd.isna(ts):
        return "unknown_timestamp_format"
    for w in windows:
        if w["start"] <= ts <= w["end"]:
            return w["label"]
    return "unlabeled"


def build_log_dataset(rows, ts_format, windows_path, out_path, dataset_name):
    if not rows:
        print(f"[!] No rows parsed for {dataset_name}, skipping.")
        return

    df = pd.DataFrame(rows)
    df["timestamp_iso"] = pd.to_datetime(
        df["timestamp_raw"], format=ts_format, errors="coerce"
    )
    # Normalize to timezone-naive UTC so it compares cleanly against
    # windows.csv timestamps (which are assumed to be naive UTC).
    if isinstance(df["timestamp_iso"].dtype, pd.DatetimeTZDtype):
        df["timestamp_iso"] = df["timestamp_iso"].dt.tz_convert("UTC").dt.tz_localize(None)

    if windows_path and os.path.exists(windows_path):
        windows = load_windows(windows_path)
        df["label"] = df["timestamp_iso"].apply(lambda ts: label_timestamp(ts, windows))
    else:
        df["label"] = "unlabeled"
        print(f"[!] No windows file given for {dataset_name} — all rows marked 'unlabeled'.")

    df.to_csv(out_path, index=False)
    print(f"[*] Wrote {len(df)} rows -> {out_path}")
    print(f"[*] Label distribution for {dataset_name}:")
    print(df["label"].value_counts().to_string())


# ---------- main ----------

def main():
    parser = argparse.ArgumentParser(description="Build labeled datasets from lab captures/logs.")
    parser.add_argument("--captures-dir", default="captures", help="Directory containing .pcap files")
    parser.add_argument("--apache-log", default=None, help="Path to Apache access.log")
    parser.add_argument("--auth-log", default=None, help="Path to auth.log")
    parser.add_argument("--windows", default=None, help="Path to windows.csv (used for log labeling)")
    parser.add_argument("--auth-log-year", default=str(datetime.now().year),
                         help="Year to assume for auth.log timestamps (they omit the year)")
    parser.add_argument("--out-dir", default="final", help="Output directory for final datasets")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    print("=== Building pcap dataset ===")
    build_pcap_dataset(args.captures_dir, args.out_dir)

    if args.apache_log:
        print("\n=== Building Apache log dataset ===")
        rows = parse_apache_log(args.apache_log)
        build_log_dataset(
            rows,
            ts_format="%d/%b/%Y:%H:%M:%S %z",
            windows_path=args.windows,
            out_path=os.path.join(args.out_dir, "final_apache_dataset.csv"),
            dataset_name="Apache log",
        )

    if args.auth_log:
        print("\n=== Building auth log dataset ===")
        rows = parse_auth_log(args.auth_log, args.auth_log_year)
        build_log_dataset(
            rows,
            ts_format=f"%Y %b %d %H:%M:%S",
            windows_path=args.windows,
            out_path=os.path.join(args.out_dir, "final_auth_dataset.csv"),
            dataset_name="auth log",
        )

    print(f"\n[*] Done. Final datasets in: {args.out_dir}/")


if __name__ == "__main__":
    main()
