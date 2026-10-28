#!/bin/bash

# ==========================================
# CONFIGURATION & ENVIRONMENT VARIABLES
# ==========================================
if [ -f .env ]; then
    export $(cat .env | grep -v '#' | xargs)
fi

SOURCE_DIR="${CAPTURE_OUTPUT_DIR:-/var/captures}"
SERVER_USER="${SERVER_USER:-pipeline}"
SERVER_IP="${SERVER_IP:-192.168.1.100}"
REMOTE_DIR="${REMOTE_DIR:-/var/data/incoming_pcaps/}"
SSH_KEY_PATH="${SSH_KEY_PATH:-~/.ssh/id_rsa}"

echo "[*] Starting synchronization of PCAP chunks to ${SERVER_USER}@${SERVER_IP}:${REMOTE_DIR}..."

# Sync closed .pcap files to the server
# -a : Archive mode (preserves permissions, timestamps)
# -v : Verbose output
# -z : Compress data during transfer
# --remove-source-files : Deletes local copy immediately after successful remote transfer
rsync -avz --remove-source-files \
  -e "ssh -i $SSH_KEY_PATH -o StrictHostKeyChecking=no" \
  --include="*.pcap" \
  --exclude="*inprogress*" \
  "$SOURCE_DIR/" "${SERVER_USER}@${SERVER_IP}:${REMOTE_DIR}"

if [ $? -eq 0 ]; then
    echo "[*] Sync cycle completed successfully."
else
    echo "[!] Error: rsync encountered an issue during transmission." >&2
    exit 1
fi