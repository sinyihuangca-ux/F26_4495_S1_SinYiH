"""Turns a CIC-IDS-2017 flow record into the numeric feature vector the models use."""
import math
from typing import Iterable

# Columns that identify a flow rather than describe its behaviour. They are not features.
ID_COLUMNS = {
    "Flow ID", "Source IP", "Source Port", "Destination IP", "Protocol", "Timestamp", "Label",
}


def clean_key(k: str) -> str:
    """CIC-IDS CSV headers often carry stray spaces (' Destination Port')."""
    return str(k).strip()


def normalise_record(row: dict) -> dict:
    return {clean_key(k): v for k, v in row.items()}


def _num(v) -> float:
    try:
        x = float(v)
    except (TypeError, ValueError):
        return 0.0
    if math.isnan(x) or math.isinf(x):
        return 0.0
    return x


def vectorise(row: dict, feature_names: Iterable[str]) -> list[float]:
    """Missing, non-numeric, NaN and infinite values become 0; negatives are clipped to 0
    (CIC-IDS has a few -1 sentinels). log1p tames the huge range of byte/packet rates."""
    return [math.log1p(max(_num(row.get(f)), 0.0)) for f in feature_names]


def flow_meta(row: dict) -> dict:
    """Identifying fields shown on the dashboard."""
    port = _num(row.get("Destination Port"))
    proto = row.get("Protocol")
    return {
        "src_ip": str(row.get("Source IP")) if row.get("Source IP") is not None else None,
        "dst_ip": str(row.get("Destination IP")) if row.get("Destination IP") is not None else None,
        "dst_port": int(port),
        "protocol": int(_num(proto)) if proto is not None else None,
        "flow_time": str(row["Timestamp"]) if row.get("Timestamp") is not None else None,
    }
