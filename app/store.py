"""SQLite storage for flows, analyst feedback and dashboard settings.

One file (threats.db in the project root), created on first run.
"""
import json
import sqlite3
import threading
import time
from copy import deepcopy
from typing import Any, Optional

from app.config import DB_PATH, DEFAULT_SETTINGS, RETIRED_MODELS

_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at   REAL NOT NULL,
    flow_time     TEXT,
    src_ip        TEXT,
    dst_ip        TEXT,
    dst_port      INTEGER,
    protocol      INTEGER,
    features      TEXT NOT NULL,       -- JSON of the model features, kept for AI review and retraining
    ground_truth  TEXT,                -- dataset label; used only to score accuracy
    ml_verdict    TEXT,                -- benign | suspicious | malicious | NULL (engine off)
    ml_score      REAL,                -- higher of anomaly score and classifier attack probability
    ml_anomaly    REAL,
    ml_attack_type TEXT,               -- classifier's best guess (DDoS, DoS Hulk, PortScan, ...)
    ml_attack_prob REAL,
    ai_status     TEXT NOT NULL DEFAULT 'skipped',   -- skipped | pending | done | failed
    ai_verdict    TEXT,
    ai_attack_type TEXT,
    ai_confidence REAL,
    ai_reason     TEXT,
    ai_provider   TEXT,
    final_verdict TEXT NOT NULL,
    agreement     TEXT,                -- agree | disagree | NULL (only one engine ran)
    feedback      TEXT                 -- false_positive | confirmed | NULL
);
CREATE INDEX IF NOT EXISTS idx_flows_final ON flows(final_verdict);
CREATE INDEX IF NOT EXISTS idx_flows_target ON flows(dst_ip, dst_port);
CREATE INDEX IF NOT EXISTS idx_flows_src ON flows(src_ip);
CREATE TABLE IF NOT EXISTS incident_briefs (
    key          TEXT PRIMARY KEY,     -- e.g. target:192.168.10.50:80 or scan:172.16.0.1
    flow_count   INTEGER NOT NULL,     -- incident size when it was briefed
    max_flow_id  INTEGER NOT NULL,
    brief        TEXT NOT NULL,        -- JSON from the AI advisor
    provider     TEXT,
    created_at   REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS allowlist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip     TEXT,
    dst_port   INTEGER,
    note       TEXT,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

FLOW_COLUMNS = [
    "id", "received_at", "flow_time", "src_ip", "dst_ip", "dst_port", "protocol",
    "ground_truth", "ml_verdict", "ml_score", "ml_anomaly", "ml_attack_type", "ml_attack_prob", "ai_status", "ai_verdict", "ai_attack_type",
    "ai_confidence", "ai_reason", "ai_provider", "final_verdict", "agreement", "feedback",
]


_local = threading.local()


def _db() -> sqlite3.Connection:
    """One connection per thread: FastAPI runs sync endpoints in a thread pool, and a
    shared connection gets corrupted results when two requests read at once."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        _local.conn = conn
    return conn


_db().executescript(SCHEMA)
# Databases created before the attack classifier existed lack its columns.
_have = {r["name"] for r in _db().execute("PRAGMA table_info(flows)")}
for _col, _type in (("ml_anomaly", "REAL"), ("ml_attack_type", "TEXT"), ("ml_attack_prob", "REAL")):
    if _col not in _have:
        _db().execute(f"ALTER TABLE flows ADD COLUMN {_col} {_type}")
_db().commit()


def _row(r: sqlite3.Row) -> dict:
    return {k: r[k] for k in FLOW_COLUMNS}


# ---------- flows ----------

def insert_flow(flow: dict) -> int:
    with _lock:
        cur = _db().execute(
            """INSERT INTO flows (received_at, flow_time, src_ip, dst_ip, dst_port, protocol, features,
                   ground_truth, ml_verdict, ml_score, ml_anomaly, ml_attack_type, ml_attack_prob,
                   ai_status, ai_reason, final_verdict, agreement)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                time.time(), flow.get("flow_time"), flow.get("src_ip"), flow.get("dst_ip"),
                flow.get("dst_port"), flow.get("protocol"), json.dumps(flow["features"]),
                flow.get("ground_truth"), flow.get("ml_verdict"), flow.get("ml_score"),
                flow.get("ml_anomaly"), flow.get("ml_attack_type"), flow.get("ml_attack_prob"),
                flow.get("ai_status", "skipped"), flow.get("ai_reason"), flow["final_verdict"],
                flow.get("agreement"),
            ),
        )
        _db().commit()
        return cur.lastrowid


def update_flow(flow_id: int, **fields: Any) -> None:
    if not fields:
        return
    cols = ", ".join(f"{k} = ?" for k in fields)
    with _lock:
        _db().execute(f"UPDATE flows SET {cols} WHERE id = ?", (*fields.values(), flow_id))
        _db().commit()


def get_flow(flow_id: int, with_features: bool = False) -> Optional[dict]:
    r = _db().execute("SELECT * FROM flows WHERE id = ?", (flow_id,)).fetchone()
    if not r:
        return None
    out = _row(r)
    if with_features:
        out["features"] = json.loads(r["features"])
    return out


def list_flows(limit: int = 200, verdict: Optional[str] = None, alerts_only: bool = False,
               search: Optional[str] = None) -> list[dict]:
    q = "SELECT * FROM flows WHERE 1=1"
    args: list = []
    if verdict:
        q += " AND final_verdict = ?"
        args.append(verdict)
    if alerts_only:
        q += f" AND {ALERT_SQL}"
    if search:
        like = f"%{search}%"
        q += (" AND (src_ip LIKE ? OR dst_ip LIKE ? OR CAST(dst_port AS TEXT) LIKE ?"
              " OR ai_attack_type LIKE ? OR ml_attack_type LIKE ? OR ground_truth LIKE ?)")
        args += [like] * 6
    q += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    return [_row(r) for r in _db().execute(q, args).fetchall()]


def clear_flows() -> None:
    with _lock:
        _db().execute("DELETE FROM flows")
        _db().execute("DELETE FROM incident_briefs")
        _db().commit()


ALERT_SQL = ("(final_verdict != 'benign' OR ml_verdict IN ('suspicious','malicious')"
             " OR ai_verdict IN ('suspicious','malicious'))")


def flagged_flows_with_features(limit: int = 20_000) -> list[dict]:
    rows = _db().execute(
        f"SELECT * FROM flows WHERE {ALERT_SQL} ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    out = []
    for r in rows:
        d = _row(r)
        d["features"] = json.loads(r["features"])
        out.append(d)
    return out


def flow_context(flow: dict, window_s: float = 600) -> dict:
    """How this flow fits with recent traffic: what the AI needs to recognise volume
    attacks (DDoS, brute force) and scans, which look ordinary one flow at a time."""
    c = _db()
    since = flow["received_at"] - window_s
    t = c.execute(
        """SELECT COUNT(*), COUNT(DISTINCT src_ip), MIN(received_at), MAX(received_at),
                  SUM(CASE WHEN ml_verdict IN ('suspicious','malicious') THEN 1 ELSE 0 END)
           FROM flows WHERE dst_ip IS ? AND dst_port IS ? AND received_at >= ?""",
        (flow["dst_ip"], flow["dst_port"], since)).fetchone()
    s = c.execute(
        """SELECT COUNT(*), COUNT(DISTINCT dst_port), COUNT(DISTINCT dst_ip)
           FROM flows WHERE src_ip IS ? AND received_at >= ?""",
        (flow["src_ip"], since)).fetchone()
    span = (t[3] or 0) - (t[2] or 0)
    return {
        "same_target_flows_10min": t[0],
        "same_target_distinct_sources": t[1],
        "same_target_span_s": round(span, 1),
        "same_target_ml_flagged": int(t[4] or 0),
        "same_source_flows_10min": s[0],
        "same_source_distinct_dst_ports": s[1],
        "same_source_distinct_dst_hosts": s[2],
    }


def get_briefs() -> dict[str, dict]:
    return {r["key"]: {**dict(r), "brief": json.loads(r["brief"])}
            for r in _db().execute("SELECT * FROM incident_briefs")}


def save_brief(key: str, flow_count: int, max_flow_id: int, brief: dict, provider: str) -> None:
    with _lock:
        _db().execute(
            """INSERT INTO incident_briefs (key, flow_count, max_flow_id, brief, provider, created_at)
               VALUES (?,?,?,?,?,?) ON CONFLICT(key) DO UPDATE SET flow_count=excluded.flow_count,
               max_flow_id=excluded.max_flow_id, brief=excluded.brief, provider=excluded.provider,
               created_at=excluded.created_at""",
            (key, flow_count, max_flow_id, json.dumps(brief), provider, time.time()))
        _db().commit()


def false_positive_features() -> list[dict]:
    """Features of flows an analyst marked as false positives (extra benign training data)."""
    rows = _db().execute("SELECT features FROM flows WHERE feedback = 'false_positive'").fetchall()
    return [json.loads(r["features"]) for r in rows]


def stats() -> dict:
    c = _db()
    total = c.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
    by_final = {r[0]: r[1] for r in c.execute(
        "SELECT final_verdict, COUNT(*) FROM flows GROUP BY final_verdict")}
    by_type = {r[0]: r[1] for r in c.execute(
        """SELECT COALESCE(ai_attack_type, ml_attack_type, CASE WHEN final_verdict='malicious' THEN 'Anomalous traffic'
                  ELSE 'Suspicious traffic' END), COUNT(*)
           FROM flows WHERE final_verdict != 'benign' GROUP BY 1""")}
    ai_status = {r[0]: r[1] for r in c.execute("SELECT ai_status, COUNT(*) FROM flows GROUP BY 1")}
    agreement = {r[0]: r[1] for r in c.execute(
        "SELECT agreement, COUNT(*) FROM flows WHERE agreement IS NOT NULL GROUP BY 1")}
    feedback = {r[0]: r[1] for r in c.execute(
        "SELECT feedback, COUNT(*) FROM flows WHERE feedback IS NOT NULL GROUP BY 1")}

    def confusion(col: str) -> Optional[dict]:
        """Accuracy of one engine against the dataset label (where a label exists).
        'suspicious' counts as a positive call."""
        rows = c.execute(
            f"""SELECT
                  SUM(CASE WHEN {col} != 'benign' AND ground_truth != 'BENIGN' THEN 1 ELSE 0 END),
                  SUM(CASE WHEN {col} != 'benign' AND ground_truth  = 'BENIGN' THEN 1 ELSE 0 END),
                  SUM(CASE WHEN {col}  = 'benign' AND ground_truth != 'BENIGN' THEN 1 ELSE 0 END),
                  SUM(CASE WHEN {col}  = 'benign' AND ground_truth  = 'BENIGN' THEN 1 ELSE 0 END)
                FROM flows WHERE {col} IS NOT NULL AND ground_truth IS NOT NULL"""
        ).fetchone()
        tp, fp, fn, tn = (int(x or 0) for x in rows)
        n = tp + fp + fn + tn
        if n == 0:
            return None
        return {
            "tp": tp, "fp": fp, "fn": fn, "tn": tn, "evaluated": n,
            "precision": round(tp / (tp + fp), 3) if tp + fp else None,
            "recall": round(tp / (tp + fn), 3) if tp + fn else None,
            "false_positive_rate": round(fp / (fp + tn), 3) if fp + tn else None,
        }

    return {
        "total_flows": total,
        "by_verdict": {k: by_final.get(k, 0) for k in ("benign", "suspicious", "malicious")},
        "by_type": by_type,
        "ai_status": ai_status,
        "agreement": agreement,
        "feedback": feedback,
        "accuracy": {
            "ml": confusion("ml_verdict"),
            # AI only sees a subset of flows, so its numbers cover those flows only.
            "ai": confusion("ai_verdict"),
            "combined": confusion("final_verdict"),
        },
    }


# ---------- allowlist ----------

def add_allow(src_ip: Optional[str], dst_port: Optional[int], note: str = "") -> int:
    with _lock:
        cur = _db().execute(
            "INSERT INTO allowlist (src_ip, dst_port, note, created_at) VALUES (?,?,?,?)",
            (src_ip, dst_port, note, time.time()),
        )
        _db().commit()
        return cur.lastrowid


def list_allow() -> list[dict]:
    return [dict(r) for r in _db().execute("SELECT * FROM allowlist ORDER BY id DESC")]


def delete_allow(rule_id: int) -> None:
    with _lock:
        _db().execute("DELETE FROM allowlist WHERE id = ?", (rule_id,))
        _db().commit()


def is_allowed(src_ip: Optional[str], dst_port: Optional[int]) -> bool:
    """A rule matches when each field it sets matches (NULL = wildcard)."""
    r = _db().execute(
        """SELECT 1 FROM allowlist
           WHERE (src_ip IS NULL OR src_ip = ?) AND (dst_port IS NULL OR dst_port = ?) LIMIT 1""",
        (src_ip, dst_port),
    ).fetchone()
    return r is not None


# ---------- settings ----------

def get_settings() -> dict:
    out = deepcopy(DEFAULT_SETTINGS)
    for r in _db().execute("SELECT key, value FROM settings"):
        if r["key"] in out:
            out[r["key"]] = json.loads(r["value"])
    # Providers retire model names; swap a saved retired name for its replacement.
    out["models"] = {p: RETIRED_MODELS.get(m, m) for p, m in out["models"].items()}
    return out


def save_settings(values: dict) -> dict:
    with _lock:
        for k, v in values.items():
            _db().execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (k, json.dumps(v)),
            )
        _db().commit()
    return get_settings()
