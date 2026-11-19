"""Backend tests. Run from the project root:  python -m pytest -q"""
import os
import tempfile
import time
from pathlib import Path

import pandas as pd
import pytest

_tmp = tempfile.mkdtemp()
os.environ["THREAT_DB_PATH"] = str(Path(_tmp) / "test.db")
os.environ["THREAT_ENV_FILE"] = str(Path(_tmp) / ".env")
for k in ("GEMINI_API_KEY", "GROQ_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "NTFY_TOPIC",
          "CLERK_PUBLISHABLE_KEY", "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY", "CLERK_JWKS_URL"):
    os.environ.pop(k, None)

from fastapi.testclient import TestClient  # noqa: E402

from app import store  # noqa: E402
from app.detection import ai as ai_mod  # noqa: E402
from app.detection.verdict import combine  # noqa: E402
from app.main import app  # noqa: E402

DATA = Path(__file__).resolve().parent.parent / "data"


def sample_rows(n=40):
    df = pd.read_csv(DATA / "mixed_monday_benign_friday_ddos_500.csv")
    df.columns = df.columns.str.strip()
    df = pd.concat([df[df["Label"] == "BENIGN"].head(n // 2), df[df["Label"] != "BENIGN"].head(n // 2)])
    return df.to_dict(orient="records")


@pytest.fixture(autouse=True)
def fresh_db():
    store.clear_flows()
    store._db().execute("DELETE FROM settings")
    store._db().execute("DELETE FROM allowlist")
    store._db().execute("DELETE FROM incident_briefs")
    store._db().commit()
    yield


# ---------- verdict rules ----------

@pytest.mark.parametrize("ml, ai, conf, expected", [
    ("suspicious", "benign", 0.9, "benign"),        # AI clears a likely false positive
    ("suspicious", "benign", 0.3, "suspicious"),    # ...but not when it is unsure
    ("malicious", "benign", 0.95, "suspicious"),    # strong disagreement -> analyst review
    ("malicious", "malicious", 0.9, "malicious"),
    ("benign", "malicious", 0.9, "suspicious"),     # AI caught what ML missed
    ("benign", "benign", 0.9, "benign"),
    ("suspicious", "malicious", 0.4, "suspicious"), # unsure AI can't escalate
    ("suspicious", "malicious", 0.9, "malicious"),
    (None, "malicious", 0.9, "malicious"),          # ML switched off
    ("malicious", None, None, "malicious"),         # AI switched off / pending
])
def test_combine(ml, ai, conf, expected):
    assert combine(ml, ai, conf, 0.6)[0] == expected


def test_combine_agreement_and_allowlist():
    assert combine("malicious", "benign", 0.9, 0.6)[1] == "disagree"
    assert combine("suspicious", "malicious", 0.9, 0.6)[1] == "agree"
    assert combine("malicious", None, None, 0.6) == ("malicious", None)
    assert combine("malicious", "malicious", 1.0, 0.6, allowlisted=True)[0] == "benign"


# ---------- ingest ----------

def test_label_never_decides():
    """A flow with an attack label but perfectly benign-looking features is not flagged
    just because of its label (the old shortcut)."""
    rows = [r for r in sample_rows() if r["Label"] == "BENIGN"][:5]
    for r in rows:
        r["Label"] = "DDoS"
    with TestClient(app) as c:
        c.put("/api/settings", json={"settings": {"ai_enabled": False}})
        out = c.post("/api/logs/ingest", json=rows).json()
    assert out["processed"] == 5
    flows = store.list_flows()
    assert all(f["ground_truth"] == "DDOS" for f in flows)
    # Benign traffic should mostly stay benign even though the label says DDoS.
    assert sum(f["final_verdict"] == "benign" for f in flows) >= 3


def test_ingest_ml_only_and_stats():
    with TestClient(app) as c:
        c.put("/api/settings", json={"settings": {"ai_enabled": False}})
        out = c.post("/api/logs/ingest", json=sample_rows()).json()
        assert out["processed"] == 40 and out["queued_for_ai"] == 0
        stats = c.get("/api/stats").json()
    acc = stats["accuracy"]["ml"]
    assert acc["evaluated"] == 40
    assert acc["recall"] > 0.5  # most DDoS flows caught
    assert stats["accuracy"]["ai"] is None


def test_engines_can_be_switched_off():
    with TestClient(app) as c:
        c.put("/api/settings", json={"settings": {"ai_enabled": False, "ml_enabled": False}})
        out = c.post("/api/logs/ingest", json=sample_rows(4)).json()
    assert out["engines"] == {"ml": False, "ai": False}
    assert all(f["ml_verdict"] is None and f["final_verdict"] == "benign" for f in store.list_flows())


def test_ai_reviews_uncertain_and_clears_false_positive(monkeypatch):
    calls = []

    async def fake_generate(self, prompt, settings):
        import json, re
        ids = [int(i) for i in re.findall(r'"id":(\d+)', prompt)]
        calls.append(ids)
        assert "Label" not in prompt and "DDoS" not in prompt.split("Flows:")[1]
        return {"results": [{"id": i, "verdict": "benign", "confidence": 0.95, "reason": "normal"}
                            for i in ids]}, "groq"

    monkeypatch.setattr(ai_mod.AIClient, "generate", fake_generate)
    monkeypatch.setenv("GROQ_API_KEY", "test")
    with TestClient(app) as c:
        c.put("/api/settings", json={"settings": {"ai_sample_rate": 0.0, "ai_min_interval": 0}})
        out = c.post("/api/logs/ingest", json=sample_rows()).json()
        flagged = out["verdicts"]["suspicious"] + out["verdicts"]["malicious"]
        assert out["queued_for_ai"] == flagged > 0
        for _ in range(50):
            if not any(f["ai_status"] == "pending" for f in store.list_flows()):
                break
            time.sleep(0.05)
    flows = store.list_flows()
    reviewed = [f for f in flows if f["ai_status"] == "done"]
    assert len(reviewed) == flagged
    for f in reviewed:
        assert f["ai_provider"] == "groq"
        # ML suspicious + confident AI benign -> benign; ML malicious + AI benign -> suspicious
        assert f["final_verdict"] == ("benign" if f["ml_verdict"] == "suspicious" else "suspicious")
        assert f["agreement"] == "disagree"


def test_no_keys_means_ai_skipped():
    with TestClient(app) as c:
        out = c.post("/api/logs/ingest", json=sample_rows(10)).json()
    assert out["engines"]["ai"] is False
    assert all(f["ai_status"] == "skipped" for f in store.list_flows())


def test_ai_failure_keeps_ml_verdict(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "bad")

    async def failing(self, prompt, settings):
        raise ai_mod.ProviderError("groq rejected the API key (401)")

    monkeypatch.setattr(ai_mod.AIClient, "generate", failing)
    with TestClient(app) as c:
        c.put("/api/settings", json={"settings": {"ai_min_interval": 0}})
        c.post("/api/logs/ingest", json=sample_rows(10))
        for _ in range(50):
            if not any(f["ai_status"] == "pending" for f in store.list_flows()):
                break
            time.sleep(0.05)
    for f in store.list_flows():
        if f["ai_status"] == "failed":
            assert "rejected" in f["ai_reason"]
            assert f["final_verdict"] == (f["ml_verdict"] or "benign")


# ---------- feedback, allowlist, settings ----------

def test_feedback_and_allowlist():
    with TestClient(app) as c:
        c.put("/api/settings", json={"settings": {"ai_enabled": False}})
        c.post("/api/logs/ingest", json=sample_rows())
        flagged = store.list_flows(alerts_only=True)[0]
        r = c.post(f"/api/flows/{flagged['id']}/feedback",
                   json={"feedback": "false_positive", "allowlist": True})
        assert r.json()["feedback"] == "false_positive"
        assert store.is_allowed(flagged["src_ip"], flagged["dst_port"])
        assert len(store.false_positive_features()) == 1


def test_settings_keys_are_masked_and_written_to_env():
    with TestClient(app) as c:
        r = c.put("/api/settings", json={"secrets": {"groq": "gsk_abcdefghijklmnop1234"}})
        assert r.json()["secrets"]["groq"] == "gsk…1234"
        assert "gsk_abcdefghijklmnop1234" not in r.text
        assert "GROQ_API_KEY=gsk_abcdefghijklmnop1234" in Path(os.environ["THREAT_ENV_FILE"]).read_text()
        r = c.put("/api/settings", json={"secrets": {"groq": ""}})
        assert r.json()["secrets"]["groq"] is None


def test_settings_validation():
    with TestClient(app) as c:
        assert c.put("/api/settings", json={"settings": {"nope": 1}}).status_code == 400
        assert c.put("/api/settings", json={"settings": {"ml_enabled": "yes"}}).status_code == 400
        bad = {"ml_suspicious_threshold": 0.99, "ml_malicious_threshold": 0.5}
        assert c.put("/api/settings", json={"settings": bad}).status_code == 400
        ok = c.put("/api/settings", json={"settings": {"provider_order": ["claude", "groq", "gemini", "openai"]}})
        assert ok.json()["settings"]["provider_order"][0] == "claude"


def test_settings_blocked_from_network_without_clerk():
    with TestClient(app, client=("192.168.1.80", 5000)) as c:
        assert c.get("/api/settings").status_code == 403
        assert c.post("/api/logs/ingest", json=sample_rows(2)).status_code == 200  # simulator still works


def test_parse_results_tolerates_messy_output():
    data = ai_mod.extract_json('```json\n{"results":[{"id":1,"verdict":"MALICIOUS","confidence":"0.8",'
                               '"attack_type":"DDoS"},{"id":99,"verdict":"benign"},{"id":2,"verdict":"maybe"}]}\n```')
    out = ai_mod.parse_results(data, {1, 2})
    assert out == {1: {"ai_verdict": "malicious", "ai_confidence": 0.8, "ai_attack_type": "DDoS", "ai_reason": ""}}


# ---------- incidents & AI advisor ----------

from app.detection import incidents as incident_mod  # noqa: E402


def _flow(i, src, dst, port, t=0.0):
    return {"id": i, "src_ip": src, "dst_ip": dst, "dst_port": port, "protocol": 6, "received_at": t,
            "final_verdict": "suspicious", "ml_verdict": "suspicious", "ml_score": 0.9, "ai_verdict": None,
            "ai_status": "skipped", "ai_attack_type": None, "feedback": None,
            "features": {"Flow Duration": 100, "SYN Flag Count": 1, "Total Backward Packets": 0}}


def test_incident_grouping_target_and_scan():
    # One attacker (like CIC-IDS-2017's 172.16.0.1) floods :80, scans 20 ports, then
    # comes back to :80 an hour later.
    flows = [_flow(i, "10.0.0.5", "192.168.1.10", 80, t=i) for i in range(30)]
    flows += [_flow(100 + p, "10.0.0.5", "192.168.1.10", p, t=40 + p) for p in range(20, 40)]
    flows += [_flow(200 + i, "10.0.0.5", "192.168.1.10", 80, t=3600 + i) for i in range(8)]
    incs = {i["key"].rsplit("@", 1)[0] + "@" + i["key"].rsplit("@", 1)[1]: i for i in incident_mod.build(flows)}
    assert set(incs) == {"target:192.168.1.10:80@0", "scan:10.0.0.5@60", "target:192.168.1.10:80@3600"}
    flood = incs["target:192.168.1.10:80@0"]["evidence"]
    assert flood["flows"] == 30 and flood["distinct_sources"] == 1
    assert flood["flag_share"]["SYN"] == 1.0 and flood["share_no_backward_packets"] == 1.0
    scan = incs["scan:10.0.0.5@60"]
    assert scan["evidence"]["distinct_dst_ports"] == 20 and scan["title"] == "Scan from 10.0.0.5"
    assert "Label" not in str(incs) and "ground_truth" not in str(scan["evidence"])


def test_advisor_skips_incidents_it_already_read(monkeypatch):
    sent = []

    async def fake_generate(self, prompt, settings):
        import json as _j
        payload = _j.loads(prompt.split("Incidents:\n", 1)[1])
        sent.append([p["key"] for p in payload])
        return {"incidents": [{"key": p["key"], "assessment": "HTTP flood (DDoS)", "confidence": 0.8,
                               "severity": "CRITICAL", "summary": "s", "evidence": ["e"],
                               "actions": ["a"], "verify": ["v"]} for p in payload]}, "gemini"

    monkeypatch.setattr(ai_mod.AIClient, "generate", fake_generate)
    with TestClient(app) as c:
        c.put("/api/settings", json={"settings": {"ai_enabled": False}})
        c.post("/api/logs/ingest", json=sample_rows())
        first = c.post("/api/analyze-threats", json={}).json()
        assert first["analysed"] >= 1 and first["incidents"][0]["brief"]["assessment"] == "HTTP flood (DDoS)"
        second = c.post("/api/analyze-threats", json={}).json()
        assert second["analysed"] == 0 and second["reused"] == first["analysed"]
        assert len(sent) == 1  # no second AI call
        key = first["incidents"][0]["key"]
        third = c.post("/api/analyze-threats", json={"force_keys": [key]}).json()
        assert third["analysed"] == 1 and sent[-1] == [key]
        listed = c.get("/api/incidents").json()
        assert listed[0]["brief"] is not None


def test_per_flow_prompt_includes_context(monkeypatch):
    prompts = []

    async def fake_generate(self, prompt, settings):
        import re
        prompts.append(prompt)
        ids = [int(i) for i in re.findall(r'"id":(\d+)', prompt)]
        return {"results": [{"id": i, "verdict": "malicious", "attack_type": "DDoS", "confidence": 0.9}
                            for i in ids]}, "gemini"

    monkeypatch.setattr(ai_mod.AIClient, "generate", fake_generate)
    monkeypatch.setenv("GEMINI_API_KEY", "x")
    with TestClient(app) as c:
        c.put("/api/settings", json={"settings": {"ai_min_interval": 0, "ai_sample_rate": 0.0}})
        c.post("/api/logs/ingest", json=sample_rows())
        for _ in range(50):
            if not any(f["ai_status"] == "pending" for f in store.list_flows()):
                break
            time.sleep(0.05)
    assert prompts and '"same_target_flows_10min"' in prompts[0]
    assert any(f["ai_attack_type"] == "DDoS" for f in store.list_flows())


def test_retired_groq_model_is_migrated():
    store.save_settings({"models": {"gemini": "gemini-2.5-flash", "groq": "llama-3.3-70b-versatile",
                                    "openai": "gpt-4o-mini", "claude": "claude-haiku-4-5"}})
    assert store.get_settings()["models"]["groq"] == "openai/gpt-oss-120b"
