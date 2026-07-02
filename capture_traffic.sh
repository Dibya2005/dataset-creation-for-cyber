#!/bin/bash
# capture_traffic.sh
# Run this on the VICTIM or ATTACKER VM to capture traffic during a test run.
#
# Usage:
#   sudo ./capture_traffic.sh <label> <interface>
#
# Example:
#   sudo ./capture_traffic.sh ssh_bruteforce enp0s3
#
# Stop capture with Ctrl+C when the test is done.
# Output goes to ./captures/<label>_<timestamp>.pcap

set -e

LABEL="${1:-capture}"
IFACE="${2:-enp0s3}"
OUTDIR="./captures"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTFILE="${OUTDIR}/${LABEL}_${TIMESTAMP}.pcap"

mkdir -p "$OUTDIR"

echo "[*] Interface : $IFACE"
echo "[*] Label     : $LABEL"
echo "[*] Output    : $OUTFILE"
echo "[*] Start time: $(date -Iseconds)"
echo "[*] Press Ctrl+C to stop capture."
echo ""

# -i interface, -w write to file, -nn no name resolution (faster, cleaner)
sudo tcpdump -i "$IFACE" -w "$OUTFILE" -nn

echo ""
echo "[*] Stop time : $(date -Iseconds)"
echo "[*] Saved to  : $OUTFILE"
echo ""
echo "IMPORTANT: Note down the exact start/end timestamps printed above."
echo "You will need them later to label this capture's traffic window."
