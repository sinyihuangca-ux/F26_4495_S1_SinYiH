import re
import math

# Pre-compiled RegEx patterns for IP and Port extraction
IP_PATTERN = re.compile(r"SRC=(\d{1,3}(?:\.\d{1,3}){3})\s+DST=(\d{1,3}(?:\.\d{1,3}){3})")
PORT_PATTERN = re.compile(r"DPT=(\d+)")

SELECTED_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
    "ACK Flag Count"
]

def sanitize_numeric(val) -> float:
    """Replaces NaN or Infinite values with 0.0 to ensure ML model stability."""
    try:
        num = float(val)
        if math.isnan(num) or math.isinf(num):
            return 0.0
        return num
    except (ValueError, TypeError):
        return 0.0

def parse_log_batch(raw_logs: list) -> list:
    """
    Parses incoming log dictionaries using RegEx IP extraction and normalizes
    the 8 CIC-IDS-2017 numerical network flow features.
    """
    parsed_records = []
    for entry in raw_logs:
        raw_text = entry.get("raw_log", "")
        
        ip_match = IP_PATTERN.search(raw_text)
        src_ip = ip_match.group(1) if ip_match else "0.0.0.0"
        dst_ip = ip_match.group(2) if ip_match else "0.0.0.0"

        port_match = PORT_PATTERN.search(raw_text)
        dst_port = int(port_match.group(1)) if port_match else int(sanitize_numeric(entry.get("Destination Port", 80)))

        features = {feat: sanitize_numeric(entry.get(feat, 0.0)) for feat in SELECTED_FEATURES}
        features["Destination Port"] = float(dst_port)

        parsed_records.append({
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "destination_port": dst_port,
            "raw_log": raw_text,
            "true_label": entry.get("true_label", "Unknown"),
            "features": features
        })

    return parsed_records