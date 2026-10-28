#!/bin/bash

# ==========================================
# CONFIGURATION & ENVIRONMENT VARIABLES
# ==========================================
# Load local .env file if it exists, otherwise fall back to defaults
if [ -f .env ]; then
    export $(cat .env | grep -v '#' | xargs)
fi

INTERFACE="${CAPTURE_INTERFACE:-eth0}"
OUTPUT_DIR="${CAPTURE_OUTPUT_DIR:-/var/captures}"
USER_ID="${USER_ID:-user_default}"
COMPUTER_ID="${COMPUTER_ID:-computer_default}"
INTERVAL_SECONDS="${INTERVAL_SECONDS:-10}"  # Rotate pcap every 10 seconds
MAX_FILES="${MAX_FILES:-100}"              # Keep a max rolling window of files locally

# Ensure output directory exists with secure permissions
sudo mkdir -p "$OUTPUT_DIR"

echo "=========================================="
echo " Starting Edge Packet Capture Service"
echo "=========================================="
echo " Interface   : $INTERFACE"
echo " Output Dir  : $OUTPUT_DIR"
echo " User ID     : $USER_ID"
echo " Computer ID : $COMPUTER_ID"
echo " Interval    : ${INTERVAL_SECONDS}s"
echo "=========================================="

# Run tcpdump with rolling window parameters:
# -i <interface>  : Network interface to capture on
# -G <seconds>    : Rotate dump file every N seconds
# -W <files>      : Limit the number of files written (rolling buffer)
# -w <pattern>    : Output filename pattern containing timestamp formatters
sudo tcpdump -i "$INTERFACE" \
  -G "$INTERVAL_SECONDS" \
  -W "$MAX_FILES" \
  -w "$OUTPUT_DIR/${USER_ID}_${COMPUTER_ID}_%Y%m%d_%H%M%S.pcap"