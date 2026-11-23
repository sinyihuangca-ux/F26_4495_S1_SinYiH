#!/bin/bash
# Uploads closed pcap chunks written by capture.sh to this computer's inbox on the server:
#   <REMOTE_USERS_ROOT>/<USER_ID>/comp/<COMPUTER_ID>/pcaps/
# where pcap-watcher picks them up. Run it periodically (e.g. from cron, see README.md).
#
# - The file tcpdump is currently writing (the newest one) is never uploaded.
# - rsync writes to a hidden temp file and renames it when complete, so the server
#   never sees a partial .pcap.
# - Uploaded files are deleted locally; if the server is unreachable, at most MAX_FILES
#   files are kept locally (oldest are deleted first).
set -euo pipefail

# ==========================================
# CONFIGURATION & ENVIRONMENT VARIABLES
# ==========================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/.env"
    set +a
fi

SOURCE_DIR="${CAPTURE_OUTPUT_DIR:-/var/captures}"
USER_ID="${USER_ID:-}"
COMPUTER_ID="${COMPUTER_ID:-}"
SERVER_USER="${SERVER_USER:-pipeline}"
SERVER_IP="${SERVER_IP:-}"
REMOTE_USERS_ROOT="${REMOTE_USERS_ROOT:-/srv/app/users}"
SSH_KEY_PATH="${SSH_KEY_PATH:-$HOME/.ssh/id_rsa}"
MAX_FILES="${MAX_FILES:-100}"   # 0 = never delete un-uploaded files

# IDs become part of the remote path, so only allow safe characters.
valid_id() { [[ "$1" =~ ^[A-Za-z0-9._-]+$ && "$1" != "." && "$1" != ".." ]]; }
if ! valid_id "$USER_ID" || ! valid_id "$COMPUTER_ID"; then
    echo "[!] USER_ID and COMPUTER_ID must be set and contain only letters, digits, '.', '_' or '-'." >&2
    exit 1
fi
if [ -z "$SERVER_IP" ]; then
    echo "[!] SERVER_IP must be set." >&2
    exit 1
fi
REMOTE_DIR="${REMOTE_DIR:-$REMOTE_USERS_ROOT/$USER_ID/comp/$COMPUTER_ID/pcaps/}"

# ==========================================
# SELECT CLOSED FILES
# ==========================================
shopt -s nullglob
# Names are <prefix>_<YYYYmmdd_HHMMSS>.pcap, so glob order (sorted by name) is capture order.
files=( "$SOURCE_DIR"/*.pcap )

# While tcpdump runs, the newest file is still open. tcpdump only rotates when a packet arrives
# after the interval, so an idle open file can look old: skip it by position, not by age.
if (( ${#files[@]} > 0 )) && pgrep -x tcpdump >/dev/null 2>&1; then
    unset 'files[${#files[@]}-1]'
fi

prune_local() {
    (( MAX_FILES > 0 )) || return 0
    local all=( "$SOURCE_DIR"/*.pcap )
    local excess=$(( ${#all[@]} - MAX_FILES ))
    if (( excess > 0 )); then
        echo "[!] ${excess} un-uploaded pcap file(s) over MAX_FILES=${MAX_FILES}; deleting the oldest." >&2
        rm -f -- "${all[@]:0:excess}"
    fi
}

if (( ${#files[@]} == 0 )); then
    echo "[*] No closed PCAP files to upload."
    exit 0
fi

# ==========================================
# UPLOAD
# ==========================================
list_file="$(mktemp)"
trap 'rm -f "$list_file"' EXIT
printf '%s\0' "${files[@]##*/}" > "$list_file"

echo "[*] Uploading ${#files[@]} PCAP file(s) to ${SERVER_USER}@${SERVER_IP}:${REMOTE_DIR}..."

# -a : Archive mode (preserves permissions, timestamps)
# -v : Verbose output
# -z : Compress data during transfer
# --from0 --files-from : upload exactly the selected closed files
# --remove-source-files : Deletes local copy only after a successful remote transfer
# --rsync-path : create the per-computer inbox on the server if it does not exist yet
# StrictHostKeyChecking=accept-new : trust the server key on first connect, reject if it changes
if rsync -avz --remove-source-files \
    --from0 --files-from="$list_file" \
    --rsync-path="mkdir -p '$REMOTE_DIR' && rsync" \
    -e "ssh -i \"$SSH_KEY_PATH\" -o StrictHostKeyChecking=accept-new -o BatchMode=yes" \
    "$SOURCE_DIR/" "${SERVER_USER}@${SERVER_IP}:${REMOTE_DIR}"; then
    echo "[*] Sync cycle completed successfully."
else
    status=$?
    echo "[!] Error: rsync exited with status ${status}." >&2
    prune_local
    exit 1
fi
