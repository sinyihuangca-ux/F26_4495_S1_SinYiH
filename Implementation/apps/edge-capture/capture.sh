#!/bin/bash
# Rolling packet capture: writes one classic-pcap file every INTERVAL_SECONDS into
# CAPTURE_OUTPUT_DIR as <USER_ID>_<COMPUTER_ID>_<YYYYmmdd_HHMMSS>.pcap.
# sync_to_server.sh uploads the closed files (never the one being written).
set -euo pipefail

# ==========================================
# CONFIGURATION & ENVIRONMENT VARIABLES
# ==========================================
# Load .env next to this script if it exists, otherwise fall back to defaults
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/.env"
    set +a
fi

INTERFACE="${CAPTURE_INTERFACE:-eth0}"
OUTPUT_DIR="${CAPTURE_OUTPUT_DIR:-/var/captures}"
USER_ID="${USER_ID:-user_default}"
COMPUTER_ID="${COMPUTER_ID:-computer_default}"
INTERVAL_SECONDS="${INTERVAL_SECONDS:-10}"  # Rotate pcap every N seconds
# tcpdump drops root privileges after opening the interface; files are written as this user.
# It must be the user that runs sync_to_server.sh, so rsync --remove-source-files can delete them.
CAPTURE_USER="${CAPTURE_USER:-${SUDO_USER:-$(id -un)}}"

# Output dir must be writable by CAPTURE_USER (tcpdump creates each rotated file after dropping privileges)
sudo mkdir -p "$OUTPUT_DIR"
sudo chown "$CAPTURE_USER" "$OUTPUT_DIR"
sudo chmod 750 "$OUTPUT_DIR"

echo "=========================================="
echo " Starting Edge Packet Capture Service"
echo "=========================================="
echo " Interface   : $INTERFACE"
echo " Output Dir  : $OUTPUT_DIR"
echo " User ID     : $USER_ID"
echo " Computer ID : $COMPUTER_ID"
echo " Interval    : ${INTERVAL_SECONDS}s"
echo " Runs as     : $CAPTURE_USER"
echo "=========================================="

# Run tcpdump with rotation:
# -i <interface>  : Network interface to capture on
# -G <seconds>    : Rotate dump file every N seconds (on the first packet after the interval)
# -Z <user>       : User that owns the written files
# -w <pattern>    : Output filename pattern containing timestamp formatters (classic pcap, which
#                   CICFlowMeter requires; do not switch to pcapng)
# No -W: combined with -G it makes tcpdump *exit* after that many files. Local retention is
# handled by sync_to_server.sh (MAX_FILES).
exec sudo tcpdump -i "$INTERFACE" \
  -G "$INTERVAL_SECONDS" \
  -Z "$CAPTURE_USER" \
  -w "$OUTPUT_DIR/${USER_ID}_${COMPUTER_ID}_%Y%m%d_%H%M%S.pcap"
