"""FastAPI app: ingest endpoint for the attack simulator, dashboard API and WebSocket.

Run from the project root:
    python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
"""
import csv
import io
import logging
import os
import random
from contextlib import asynccontextmanager
from typing import Any, Literal, Optional

from dotenv import set_key
from fastapi import Body, Depends, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field

from app import store
from app.auth import require_user
from app.config import CORS_ORIGINS, DEFAULT_SETTINGS, ENV_PATH, PROVIDERS, SECRET_KEYS
from app.detection.ai import ProviderError, ai_client, ai_reviewer, briefing_prompt, provider_key
from app.detection.features import ID_COLUMNS, _num, flow_meta, normalise_record
from app.detection.ml import ml_engine, ml_verdict
from app.detection.verdict import combine
from app.notify import notifier

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("api")


# ---------- WebSocket fan-out ----------

class ConnectionManager:
    def __init__(self):
        self.clients: set[WebSocket] = set()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.clients.add(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self.clients.discard(ws)

    async def broadcast(self, message: dict) -> None:
        dead = []
        for ws in list(self.clients):
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


async def apply_ai_result(flow_id: int, result: dict) -> None:
    """Called by the AI queue when a flow has been reviewed (or the review failed)."""
    flow = store.get_flow(flow_id)
    if not flow:
        return
    settings = store.get_settings()
    final, agreement = flow["final_verdict"], flow["agreement"]
    if result.get("ai_status") == "done":
        final, agreement = combine(
            flow["ml_verdict"], result["ai_verdict"], result["ai_confidence"],
            settings["ai_min_confidence"], store.is_allowed(flow["src_ip"], flow["dst_port"]),
        )
    store.update_flow(flow_id, **result, final_verdict=final, agreement=agreement)
    updated = store.get_flow(flow_id)
    await manager.broadcast({"type": "FLOW_UPDATED", "flow": updated})
    if final == "malicious" and flow["final_verdict"] != "malicious":
        await notifier.alert(updated["ai_attack_type"] or "Anomalous traffic",
                             updated["src_ip"], updated["dst_port"], settings)


@asynccontextmanager
async def lifespan(_: FastAPI):
    ai_reviewer.start(apply_ai_result)
    yield
    await ai_reviewer.stop()


app = FastAPI(
    title="AI Cyber Threat Mitigation Platform",
    description="ML + AI anomaly detection for streamed network flows, with a live WebSocket feed.",
    version="2.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- status ----------

@app.get("/")
def root():
    return {"status": "running", "platform": "AI Cyber Threat Mitigation", "docs": "/docs"}


@app.get("/api/health")
def health():
    settings = store.get_settings()
    return {
        "ml": {"enabled": settings["ml_enabled"], "model_loaded": ml_engine.ready,
               "trained_on": ml_engine.bundle["meta"] if ml_engine.ready else None},
        "ai": {"enabled": settings["ai_enabled"], "backlog": ai_reviewer.backlog,
               "providers": ai_client.status(settings["provider_order"])},
        "dashboards_connected": len(manager.clients),
    }


@app.websocket("/ws/alerts")
async def ws_alerts(ws: WebSocket):
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()  # clients may send pings; nothing else to do
    except WebSocketDisconnect:
        manager.disconnect(ws)


# ---------- ingestion (attack simulator posts here) ----------

@app.post("/api/logs/ingest")
async def ingest(logs: list[dict[str, Any]] = Body(...)):
    """Score a batch of CIC-IDS-2017 flow records with the ML engine, queue the ones the
    AI should review, store everything and push alerts to dashboards.

    The dataset's `Label` column is stored as ground truth for the accuracy panel only;
    it never influences a verdict."""
    settings = store.get_settings()
    rows = [normalise_record(r) for r in logs]
    use_ml = settings["ml_enabled"] and ml_engine.ready
    # With no key at all there is nothing to call, so don't queue flows just to fail them.
    has_key = any(provider_key(p) for p in settings["provider_order"])
    use_ai = settings["ai_enabled"] and has_key
    skip_reason = (None if use_ai else "AI engine is off" if not settings["ai_enabled"]
                   else "no AI key configured")
    scores = ml_engine.score(rows) if use_ml else [None] * len(rows)

    counts = {"benign": 0, "suspicious": 0, "malicious": 0}
    queued = 0
    for row, score in zip(rows, scores):
        meta = flow_meta(row)
        label = row.get("Label")
        features = {k: _num(v) for k, v in row.items() if k not in ID_COLUMNS}
        mv = (ml_verdict(score, settings["ml_suspicious_threshold"], settings["ml_malicious_threshold"])
              if use_ml else None)
        allowed = store.is_allowed(meta["src_ip"], meta["dst_port"])
        send_to_ai = use_ai and not allowed and (
            mv is None or mv != "benign" or random.random() < settings["ai_sample_rate"])
        final, agreement = combine(mv, None, None, settings["ai_min_confidence"], allowed)

        flow_id = store.insert_flow({
            **meta, "features": features,
            "ground_truth": str(label).strip().upper() if label is not None else None,
            "ml_verdict": mv, "ml_score": score,
            "ai_status": "pending" if send_to_ai else "skipped",
            "ai_reason": skip_reason or (None if send_to_ai else
                                         "allowlisted" if allowed else "not in the AI sample"),
            "final_verdict": final, "agreement": agreement,
        })
        if send_to_ai:
            ai_reviewer.enqueue(flow_id)
            queued += 1
        counts[final] += 1
        if final != "benign" or send_to_ai:
            await manager.broadcast({"type": "FLOW", "flow": store.get_flow(flow_id)})
        if final == "malicious":
            await notifier.alert("Anomalous traffic", meta["src_ip"], meta["dst_port"], settings)

    await manager.broadcast({"type": "STATS", "stats": store.stats()})
    return {
        "status": "success",
        "processed": len(rows),
        "verdicts": counts,
        "anomalies_flagged": counts["suspicious"] + counts["malicious"],  # kept for the old simulator
        "queued_for_ai": queued,
        "engines": {"ml": use_ml, "ai": use_ai},
    }


# ---------- flows / alerts ----------

@app.get("/api/flows")
def list_flows(limit: int = Query(200, le=5000), verdict: Optional[str] = None,
               alerts_only: bool = False, q: Optional[str] = None):
    return store.list_flows(limit, verdict, alerts_only, q)


@app.get("/api/stats")
def stats():
    return store.stats()


@app.get("/api/flows/export.csv")
def export_csv(alerts_only: bool = True):
    rows = store.list_flows(100_000, alerts_only=alerts_only)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=store.FLOW_COLUMNS)
    w.writeheader()
    w.writerows(rows)
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=threat_log.csv"})


class Feedback(BaseModel):
    feedback: Optional[Literal["false_positive", "confirmed"]]
    allowlist: bool = Field(False, description="Also stop alerting on this source IP + port")


@app.post("/api/flows/{flow_id}/feedback")
async def set_feedback(flow_id: int, body: Feedback, user=Depends(require_user)):
    flow = store.get_flow(flow_id)
    if not flow:
        raise HTTPException(404, "flow not found")
    store.update_flow(flow_id, feedback=body.feedback)
    if body.allowlist and body.feedback == "false_positive":
        store.add_allow(flow["src_ip"], flow["dst_port"], note=f"from flow #{flow_id}")
    updated = store.get_flow(flow_id)
    await manager.broadcast({"type": "FLOW_UPDATED", "flow": updated})
    return updated


@app.delete("/api/flows")
async def clear_flows(user=Depends(require_user)):
    store.clear_flows()
    await manager.broadcast({"type": "STATS", "stats": store.stats()})
    return {"status": "cleared"}


# ---------- allowlist ----------

class AllowRule(BaseModel):
    src_ip: Optional[str] = None
    dst_port: Optional[int] = None
    note: str = ""


@app.get("/api/allowlist")
def get_allowlist():
    return store.list_allow()


@app.post("/api/allowlist")
def add_allowlist(rule: AllowRule, user=Depends(require_user)):
    if rule.src_ip is None and rule.dst_port is None:
        raise HTTPException(400, "set a source IP, a port, or both")
    return {"id": store.add_allow(rule.src_ip, rule.dst_port, rule.note)}


@app.delete("/api/allowlist/{rule_id}")
def delete_allowlist(rule_id: int, user=Depends(require_user)):
    store.delete_allow(rule_id)
    return {"status": "deleted"}


# ---------- settings ----------

def mask(value: str) -> Optional[str]:
    if not value:
        return None
    return f"{value[:3]}…{value[-4:]}" if len(value) > 10 else "…" + value[-2:]


def settings_view() -> dict:
    return {
        "settings": store.get_settings(),
        "secrets": {name: mask(os.environ.get(env, "")) for name, env in SECRET_KEYS.items()},
    }


class SettingsUpdate(BaseModel):
    settings: dict[str, Any] = {}
    # Provider name -> new key. An empty string removes the key; omitted = unchanged.
    secrets: dict[str, str] = {}


@app.get("/api/settings")
def get_settings(user=Depends(require_user)):
    return settings_view()


@app.put("/api/settings")
def update_settings(body: SettingsUpdate, user=Depends(require_user)):
    clean = {}
    for k, v in body.settings.items():
        if k not in DEFAULT_SETTINGS:
            raise HTTPException(400, f"unknown setting: {k}")
        default = DEFAULT_SETTINGS[k]
        if isinstance(default, bool):
            if not isinstance(v, bool):
                raise HTTPException(400, f"{k} must be true/false")
        elif isinstance(default, (int, float)):
            if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0:
                raise HTTPException(400, f"{k} must be a non-negative number")
        elif k == "provider_order":
            if not isinstance(v, list) or sorted(v) != sorted(PROVIDERS):
                raise HTTPException(400, f"provider_order must list each of {PROVIDERS} once")
        elif k == "models":
            if not isinstance(v, dict) or not all(isinstance(m, str) and m for m in v.values()):
                raise HTTPException(400, "models must map provider -> model name")
            v = {**store.get_settings()["models"], **{p: m for p, m in v.items() if p in PROVIDERS}}
        clean[k] = v
    merged = {**store.get_settings(), **clean}
    if merged["ml_suspicious_threshold"] > merged["ml_malicious_threshold"]:
        raise HTTPException(400, "the suspicious threshold must not be above the malicious threshold")
    for k in ("ml_suspicious_threshold", "ml_malicious_threshold", "ai_sample_rate", "ai_min_confidence"):
        if merged[k] > 1:
            raise HTTPException(400, f"{k} must be between 0 and 1")
    if merged["ai_batch_size"] < 1:
        raise HTTPException(400, "ai_batch_size must be at least 1")
    if clean:
        store.save_settings(clean)

    for name, value in body.secrets.items():
        if name not in SECRET_KEYS:
            raise HTTPException(400, f"unknown key: {name}")
        env = SECRET_KEYS[name]
        value = value.strip()
        ENV_PATH.touch(exist_ok=True)
        set_key(str(ENV_PATH), env, value, quote_mode="never")
        if value:
            os.environ[env] = value
        else:
            os.environ.pop(env, None)
    if body.secrets:
        ai_client.reset_cooldowns()
    return settings_view()


# ---------- AI threat briefing ----------

@app.post("/api/analyze-threats")
async def analyze_threats(threat_counts: Optional[dict[str, int]] = Body(None, embed=True)):
    """Severity-ranked briefing with mitigation advice. Uses the current threat counts
    from the database unless the request supplies its own."""
    counts = threat_counts or store.stats()["by_type"]
    if not counts:
        raise HTTPException(400, "No threats detected yet - run the attack simulator first.")
    try:
        data, provider = await ai_client.generate(briefing_prompt(counts), store.get_settings())
    except ProviderError as e:
        raise HTTPException(502, f"AI briefing failed: {e}")
    items = data.get("results", data) if isinstance(data, dict) else data
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    items = sorted([i for i in items if isinstance(i, dict)],
                   key=lambda i: order.get(str(i.get("severity", "")).upper(), 9))
    return {"provider_used": provider, "result": items}


# ---------- RSS feed of malicious flows ----------

@app.get("/api/rss")
def rss():
    from email.utils import formatdate
    from xml.sax.saxutils import escape

    items = []
    for f in store.list_flows(200):
        if f["final_verdict"] != "malicious":
            continue
        title = escape(f"{f['ai_attack_type'] or 'Anomalous traffic'} detected")
        desc = escape(f"Flow #{f['id']} from {f['src_ip'] or 'unknown'} to port {f['dst_port']}")
        items.append(
            f"<item><title>{title}</title><description>{desc}</description>"
            f'<guid isPermaLink="false">flow-{f["id"]}</guid>'
            f"<pubDate>{formatdate(f['received_at'])}</pubDate></item>"
        )
        if len(items) == 50:
            break
    xml = ('<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel>'
           "<title>AI Threat Mitigation alerts</title><link>http://localhost:3000/logs</link>"
           "<description>Malicious flows detected</description>" + "".join(items) +
           "</channel></rss>")
    return Response(xml, media_type="application/rss+xml")
