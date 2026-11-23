# Edge Packet Capture
This directory contains the lightweight capture and ingestion scripts deployed on user computers or remote machines.

Its primary purpose is to capture live bi-directional network traffic locally, split it into rolling PCAP chunks, attach host identity metadata, and  transmit the pcap files to the server.


## Directory Structure

```text
edge/
├── README.md               # Folder documentation
├── .env.example            # Environment configuration template
├── capture.sh              # Rolling packet capture script (tcpdump)
└── sync_to_server.sh       # Automated rsync streaming script over SSH
```

## Setup

1. `cp .env.example .env` and set `USER_ID`, `COMPUTER_ID`, `SERVER_IP` and `SSH_KEY_PATH`.
   Both scripts read the `.env` next to them, wherever they are run from.
2. Start the capture (needs sudo for tcpdump; it keeps running):

   ```bash
   ./capture.sh
   ```

   Files are written as the user who ran the script (`CAPTURE_USER`), so the sync below can delete them after upload.
3. Upload closed files periodically as the same user, e.g. every minute from `crontab -e`:

   ```cron
   * * * * * /path/to/edge-capture/sync_to_server.sh >> /tmp/pcap-sync.log 2>&1
   ```

## Where files go

Each closed chunk is uploaded to

```text
<REMOTE_USERS_ROOT>/<USER_ID>/comp/<COMPUTER_ID>/pcaps/     (default REMOTE_USERS_ROOT=/srv/app/users)
```

which is where the server's `pcap-watcher` converts it to a flow CSV. The directory is created on the
server if it does not exist, so `SERVER_USER` needs write access to `REMOTE_USERS_ROOT`.

- The file tcpdump is still writing is never uploaded.
- Uploaded files are deleted locally. If the server is unreachable, files accumulate up to `MAX_FILES`
  (default 100); beyond that the oldest are deleted.
- Captures are classic `.pcap` (CICFlowMeter does not read pcapng).
