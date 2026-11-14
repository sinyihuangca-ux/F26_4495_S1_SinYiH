import re
import math

# Pre-compiled Regular Expression patterns for extracting
# source IP, destination IP, and destination port from raw logs.
IP_PATTERN = re.compile(
    r"SRC=(\d{1,3}(?:\.\d{1,3}){3})\s+DST=(\d{1,3}(?:\.\d{1,3}){3})"
)

PORT_PATTERN = re.compile(r"DPT=(\d+)")

# Selected CIC-IDS-2017 network flow features used
# as machine learning input variables.
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
    """
    Converts a value to float and replaces invalid values
    such as NaN, Infinity, or non-numeric data with 0.0.

    This helps prevent machine learning model errors
    caused by malformed network traffic data.
    """
    try:
        num = float(val)

        # Replace NaN and Infinite values with zero
        if math.isnan(num) or math.isinf(num):
            return 0.0

        return num

    except (ValueError, TypeError):
        # Return zero for invalid inputs
        return 0.0


def parse_log_batch(raw_logs: list) -> list:
    """
    Parses a batch of incoming network log records.

    Responsibilities:
    1. Extract source and destination IP addresses.
    2. Extract destination port number.
    3. Normalize numerical feature values.
    4. Prepare structured records for machine learning analysis.

    Returns:
        List of standardized log dictionaries.
    """

    parsed_records = []

    # Process each log entry individually
    for entry in raw_logs:

        # Retrieve raw log text
        raw_text = entry.get("raw_log", "")

        # Extract source and destination IP addresses
        ip_match = IP_PATTERN.search(raw_text)

        # Use extracted IPs if found; otherwise use default values
        src_ip = ip_match.group(1) if ip_match else "0.0.0.0"
        dst_ip = ip_match.group(2) if ip_match else "0.0.0.0"

        # Extract destination port from the raw log
        port_match = PORT_PATTERN.search(raw_text)

        # Use extracted port if available;
        # otherwise use the provided feature value or default port 80
        dst_port = (
            int(port_match.group(1))
            if port_match
            else int(
                sanitize_numeric(
                    entry.get("Destination Port", 80)
                )
            )
        )

        # Normalize all selected ML feature values
        features = {
            feat: sanitize_numeric(entry.get(feat, 0.0))
            for feat in SELECTED_FEATURES
        }

        # Ensure destination port matches extracted value
        features["Destination Port"] = float(dst_port)

        # Create a structured record for ML processing
        parsed_records.append({
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "destination_port": dst_port,
            "raw_log": raw_text,

            # Ground-truth label (if available)
            "true_label": entry.get("true_label", "Unknown"),

            # Machine learning feature vector
            "features": features
        })

    # Return all parsed and normalized records
    return parsed_records