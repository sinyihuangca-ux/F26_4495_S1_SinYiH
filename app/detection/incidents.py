"""Groups flagged flows into incidents and summarises the evidence for each one.

Grouping ("both, auto-picked"):
  * a source that hits many different destination ports is a *scan* incident, keyed
    by that source (one incident instead of dozens of one-flow "incidents");
  * every other flagged flow is grouped by its *target* service (dst IP + port), which
    is how DDoS, brute force and web attacks show up.

The evidence is plain numbers (rates, sizes, flag patterns, ML/AI verdicts) that the
AI advisor reasons over. The dataset label is never included.
"""
import statistics
from collections import Counter, defaultdict
from typing import Optional

SCAN_MIN_PORTS = 10    # distinct lightly-touched ports from one source that make it a scan
SCAN_LIGHT_MAX = 3     # a port a source hits at most this often counts toward a scan;
                       # heavier traffic to one port (a flood, brute force) is its own incident
SESSION_GAP_S = 300    # a quiet gap this long starts a new incident on the same key

# Feature medians worth showing an analyst (CICFlowMeter names).
MEDIAN_FEATURES = {
    "Flow Duration": "flow_duration_us",
    "Total Fwd Packets": "fwd_packets",
    "Total Backward Packets": "bwd_packets",
    "Total Length of Fwd Packets": "fwd_bytes",
    "Total Length of Bwd Packets": "bwd_bytes",
    "Flow Packets/s": "packets_per_s",
    "Flow Bytes/s": "bytes_per_s",
    "Packet Length Mean": "packet_len_mean",
    "Init_Win_bytes_forward": "init_window_fwd",
}
FLAGS = ["SYN Flag Count", "ACK Flag Count", "PSH Flag Count", "RST Flag Count",
         "FIN Flag Count", "URG Flag Count"]


def is_flagged(f: dict) -> bool:
    return (f["final_verdict"] != "benign"
            or f["ml_verdict"] in ("suspicious", "malicious")
            or f["ai_verdict"] in ("suspicious", "malicious"))


def group(flows: list[dict]) -> dict[str, list[dict]]:
    """flows: flagged flows with their `features`. Returns key -> flows, where key is
    `scan:<src>@<start>` or `target:<dst ip>:<port>@<start>` (start = unix seconds)."""
    per_port = Counter((f.get("src_ip"), f.get("dst_ip"), f.get("dst_port")) for f in flows)
    light_ports: dict[str, set] = defaultdict(set)
    for (src, dst, port), n in per_port.items():
        if src and n <= SCAN_LIGHT_MAX:
            light_ports[src].add((dst, port))
    scanners = {s for s, ports in light_ports.items() if len(ports) >= SCAN_MIN_PORTS}

    base: dict[str, list[dict]] = defaultdict(list)
    for f in flows:
        src = f.get("src_ip")
        if src in scanners and per_port[(src, f.get("dst_ip"), f.get("dst_port"))] <= SCAN_LIGHT_MAX:
            base[f"scan:{src}"].append(f)
        else:
            base[f"target:{f.get('dst_ip') or '?'}:{f.get('dst_port')}"].append(f)

    # Split each group where traffic went quiet, so separate attack runs stay separate.
    groups: dict[str, list[dict]] = {}
    for key, fs in base.items():
        fs.sort(key=lambda f: f["received_at"])
        session = [fs[0]]
        for prev, cur in zip(fs, fs[1:]):
            if cur["received_at"] - prev["received_at"] > SESSION_GAP_S:
                groups[f"{key}@{int(session[0]['received_at'])}"] = session
                session = []
            session.append(cur)
        groups[f"{key}@{int(session[0]['received_at'])}"] = session
    return groups


def _median(values: list[float], digits: int = 1) -> Optional[float]:
    return round(statistics.median(values), digits) if values else None


def _top(counter: Counter, n: int = 3) -> list:
    return [k for k, _ in counter.most_common(n)]


def summarise(key: str, flows: list[dict]) -> dict:
    kind, _, rest = key.partition(":")
    rest = rest.rsplit("@", 1)[0]
    times = [f["received_at"] for f in flows]
    span = max(times) - min(times) if times else 0.0
    feats = [f.get("features") or {} for f in flows]
    n = len(flows)

    src = Counter(f.get("src_ip") for f in flows)
    dst = Counter(f"{f.get('dst_ip')}:{f.get('dst_port')}" for f in flows)
    dst_ports = {f.get("dst_port") for f in flows}
    ml_scores = [f["ml_score"] for f in flows if f.get("ml_score") is not None]
    ai_done = [f for f in flows if f.get("ai_status") == "done"]

    evidence = {
        "flows": n,
        "time_span_s": round(span, 1),
        "flows_per_s": round(n / span, 1) if span > 0 else None,
        "distinct_sources": len(src),
        "top_sources": _top(src),
        "distinct_targets": len(dst),
        "top_targets": _top(dst),
        "distinct_dst_ports": len(dst_ports),
        "sample_dst_ports": sorted(p for p in dst_ports if p is not None)[:15],
        "distinct_src_ports": len({fe["Source Port"] for fe in feats if "Source Port" in fe}) or None,
        "protocols": dict(Counter(f.get("protocol") for f in flows)),
        "medians": {
            label: _median([fe[col] for fe in feats if col in fe])
            for col, label in MEDIAN_FEATURES.items()
        },
        # Share of flows where each TCP flag appears at least once.
        "flag_share": {
            flag.split()[0]: round(sum(1 for fe in feats if fe.get(flag, 0) > 0) / n, 2)
            for flag in FLAGS if any(flag in fe for fe in feats)
        },
        "share_no_backward_packets": round(
            sum(1 for fe in feats if fe.get("Total Backward Packets", 1) == 0) / n, 2),
        "ml": {
            "verdicts": dict(Counter(f.get("ml_verdict") for f in flows)),
            "score_min": round(min(ml_scores), 2) if ml_scores else None,
            "score_median": _median(ml_scores, 2),
            "score_max": round(max(ml_scores), 2) if ml_scores else None,
            # The attack classifier's names for these flows (trained on labelled CIC-IDS-2017
            # attacks); a strong hint, but it only knows attack types it was trained on.
            "classifier_attack_types": dict(Counter(f["ml_attack_type"] for f in flows if f.get("ml_attack_type"))),
        },
        "per_flow_ai": {
            "reviewed": len(ai_done),
            "verdicts": dict(Counter(f.get("ai_verdict") for f in ai_done)),
            "attack_types_named": dict(Counter(f["ai_attack_type"] for f in ai_done if f.get("ai_attack_type"))),
        },
        "final_verdicts": dict(Counter(f["final_verdict"] for f in flows)),
        "analyst_feedback": dict(Counter(f["feedback"] for f in flows if f.get("feedback"))),
    }
    title = (f"Scan from {rest}" if kind == "scan"
             else f"Traffic to {rest}")
    return {
        "key": key,
        "kind": kind,
        "title": title,
        "flow_count": n,
        "max_flow_id": max(f["id"] for f in flows),
        "first_seen": min(times) if times else None,
        "last_seen": max(times) if times else None,
        "evidence": evidence,
    }


def build(flows: list[dict]) -> list[dict]:
    """Flagged flows -> incident summaries, largest first."""
    flagged = [f for f in flows if is_flagged(f)]
    incidents = [summarise(k, fs) for k, fs in group(flagged).items()]
    return sorted(incidents, key=lambda i: i["flow_count"], reverse=True)
