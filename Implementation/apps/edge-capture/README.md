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
