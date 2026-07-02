#!/usr/bin/env python3
"""
label_data.py

Adds a 'label' column to a parsed pcap or log CSV, based on time windows
you define.

Step 1: Create a windows.csv file describing when each attack ran, e.g.:

    label,start_time,end_time
    normal,2026-07-01T10:00:00,2026-07-01T10:02:00
    port_scan,2026-07-01T10:02:00,2026-07-01T10:04:00
    ssh_bruteforce,2026-07-01T10:04:00,2026-07-01T10:09:00
    slowloris,2026-07-01T10:09:00,2026-07-01T10:14:00

Usage:
    python3 label_data.py parsed_pcap.csv windows.csv timestamp_utc labeled_pcap.csv
"""

import sys
import csv
from datetime import datetime


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


def label_for_timestamp(ts_str, windows):
    try:
        ts = datetime.fromisoformat(ts_str.replace("Z", ""))
    except ValueError:
        return "unknown_timestamp_format"

    for w in windows:
        if w["start"] <= ts <= w["end"]:
            return w["label"]
    return "unlabeled"


def label_file(in_path, windows_path, ts_column, out_path):
    windows = load_windows(windows_path)

    with open(in_path, "r", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames + ["label"]
        rows = list(reader)

    for row in rows:
        row["label"] = label_for_timestamp(row[ts_column], windows)

    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[*] Labeled {len(rows)} rows -> {out_path}")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit("Usage: python3 label_data.py input.csv windows.csv timestamp_column output.csv")
    label_file(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
