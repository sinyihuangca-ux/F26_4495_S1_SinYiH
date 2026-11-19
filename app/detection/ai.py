"""AI engine: an LLM reviews flows and gives its own verdict, with provider failover.

Which flows it sees (to stay inside free-tier rate limits):
  * every flow the ML engine calls suspicious or malicious, and
  * a random sample (Settings -> ai_sample_rate) of flows ML calls benign, so the AI
    can catch attacks the ML misses.
If the ML engine is switched off, the AI reviews every flow.

Requests go through one background queue, at most one call every `ai_min_interval`
seconds. Providers are tried in the order set in Settings; one that rate-limits
(HTTP 429) or rejects its key is skipped for a while and the next one is used.
"""
import asyncio
import json
import logging
import os
import re
import time
from typing import Awaitable, Callable, Optional

import httpx

from app import store
from app.config import SECRET_KEYS

log = logging.getLogger("ai")

# A readable subset of CIC-IDS-2017 features. Enough for an LLM to reason about the
# flow's shape without flooding the prompt.
AI_FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Bwd Packet Length Max", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Packet Length Mean", "Average Packet Size", "Down/Up Ratio", "SYN Flag Count",
    "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
]

VERDICTS = {"benign", "suspicious", "malicious"}


class ProviderError(Exception):
    def __init__(self, msg: str, cooldown: float = 0.0):
        super().__init__(msg)
        self.cooldown = cooldown


def provider_key(provider: str) -> str:
    return os.environ.get(SECRET_KEYS[provider], "").strip()


async def _call(client: httpx.AsyncClient, provider: str, key: str, model: str, prompt: str) -> str:
    if provider == "gemini":
        r = await client.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            headers={"x-goog-api-key": key},
            json={
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"},
            },
        )
        _raise_for(provider, r)
        return r.json()["candidates"][0]["content"]["parts"][0]["text"]

    if provider in ("groq", "openai"):
        url = ("https://api.groq.com/openai/v1/chat/completions" if provider == "groq"
               else "https://api.openai.com/v1/chat/completions")
        r = await client.post(
            url,
            headers={"Authorization": f"Bearer {key}"},
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "response_format": {"type": "json_object"},
            },
        )
        _raise_for(provider, r)
        return r.json()["choices"][0]["message"]["content"]

    if provider == "claude":
        r = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
            json={
                "model": model,
                "max_tokens": 2048,
                "temperature": 0.1,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        _raise_for(provider, r)
        return "".join(b.get("text", "") for b in r.json()["content"])

    raise ProviderError(f"unknown provider {provider}")


def _raise_for(provider: str, r: httpx.Response) -> None:
    if r.status_code == 200:
        return
    detail = r.text[:200].replace("\n", " ")
    if r.status_code == 429:
        retry = r.headers.get("retry-after")
        wait = float(retry) if retry and retry.replace(".", "", 1).isdigit() else 60.0
        raise ProviderError(f"{provider} rate-limited (429)", cooldown=wait)
    if r.status_code in (401, 403):
        raise ProviderError(f"{provider} rejected the API key ({r.status_code})", cooldown=3600)
    if r.status_code >= 500:
        raise ProviderError(f"{provider} unavailable ({r.status_code})", cooldown=30)
    raise ProviderError(f"{provider} error {r.status_code}: {detail}")


def extract_json(text: str):
    """Parse model output, tolerating ```json fences or chatter around the JSON."""
    text = re.sub(r"```(?:json)?", "", text).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = re.search(r"(\{.*\}|\[.*\])", text, re.S)
    if not m:
        raise ValueError("no JSON in model output")
    return json.loads(m.group(1))


class AIClient:
    """Failover across providers, remembering which ones are cooling down."""

    def __init__(self):
        self.cooldown_until: dict[str, float] = {}
        self.last_error: Optional[str] = None
        self.last_provider: Optional[str] = None

    def reset_cooldowns(self) -> None:
        self.cooldown_until.clear()

    def available(self, order: list[str]) -> list[str]:
        now = time.time()
        return [p for p in order if provider_key(p) and self.cooldown_until.get(p, 0) <= now]

    def status(self, order: list[str]) -> dict:
        now = time.time()
        return {
            p: ("no key" if not provider_key(p)
                else f"cooling down {int(self.cooldown_until[p] - now)}s" if self.cooldown_until.get(p, 0) > now
                else "ready")
            for p in order
        } | {"last_error": self.last_error, "last_provider": self.last_provider}

    async def generate(self, prompt: str, settings: dict) -> tuple[object, str]:
        order = settings["provider_order"]
        candidates = self.available(order)
        if not candidates:
            if not any(provider_key(p) for p in order):
                raise ProviderError("no AI keys configured (add one in Settings)")
            raise ProviderError("all AI providers are cooling down after errors")
        errors = []
        async with httpx.AsyncClient(timeout=45.0) as client:
            for p in candidates:
                try:
                    text = await _call(client, p, provider_key(p), settings["models"][p], prompt)
                    data = extract_json(text)
                    self.last_provider, self.last_error = p, None
                    return data, p
                except ProviderError as e:
                    if e.cooldown:
                        self.cooldown_until[p] = time.time() + e.cooldown
                    errors.append(str(e))
                except (httpx.HTTPError, ValueError, KeyError, IndexError) as e:
                    errors.append(f"{p}: {type(e).__name__}: {e}")
                log.warning("AI provider failed, trying next: %s", errors[-1])
        self.last_error = errors[-1] if errors else "unknown"
        raise ProviderError("; ".join(errors))


ai_client = AIClient()


def flow_prompt(flows: list[dict]) -> str:
    items = []
    for f in flows:
        feats = f["features"]
        items.append({
            "id": f["id"],
            "protocol": f.get("protocol"),
            **{k: feats[k] for k in AI_FEATURES if k in feats},
        })
    return (
        "You are a SOC analyst reviewing network flow records (CICFlowMeter features, "
        "CIC-IDS-2017 style). For each flow, decide whether it looks benign, suspicious "
        "or malicious. Not everything is clear-cut: use 'suspicious' when the evidence is "
        "mixed, and give an honest confidence between 0 and 1. Ordinary web, DNS and "
        "background traffic is normal; do not flag a flow only because a value is large.\n\n"
        "Return ONLY a JSON object of the form "
        '{"results": [{"id": <id>, "verdict": "benign|suspicious|malicious", '
        '"attack_type": "<e.g. DDoS, PortScan, Brute Force, XSS, SQL Injection, Infiltration, or null>", '
        '"confidence": <0-1>, "reason": "<one short sentence>"}]}\n\n'
        f"Flows:\n{json.dumps(items, separators=(',', ':'))}"
    )


def parse_results(data, ids: set[int]) -> dict[int, dict]:
    rows = data.get("results", data) if isinstance(data, dict) else data
    out = {}
    for r in rows if isinstance(rows, list) else []:
        try:
            fid = int(r["id"])
        except (KeyError, TypeError, ValueError):
            continue
        verdict = str(r.get("verdict", "")).lower()
        if fid not in ids or verdict not in VERDICTS:
            continue
        try:
            conf = min(max(float(r.get("confidence", 0.5)), 0.0), 1.0)
        except (TypeError, ValueError):
            conf = 0.5
        attack = r.get("attack_type")
        out[fid] = {
            "ai_verdict": verdict,
            "ai_confidence": round(conf, 3),
            "ai_attack_type": (str(attack)[:60] if attack and str(attack).lower() not in ("null", "none", "benign")
                               and verdict != "benign" else None),
            "ai_reason": str(r.get("reason", ""))[:300],
        }
    return out


class AIReviewer:
    """Background queue that sends flows to the AI in batches and reports results."""

    def __init__(self):
        self.queue: Optional[asyncio.Queue] = None
        self.task: Optional[asyncio.Task] = None
        self.on_result: Optional[Callable[[int, dict], Awaitable[None]]] = None
        self._last_call = 0.0

    def start(self, on_result: Callable[[int, dict], Awaitable[None]]) -> None:
        self.on_result = on_result
        if self.task is None or self.task.done():
            self.queue = asyncio.Queue()  # bound to the running event loop
            self.task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass

    def enqueue(self, flow_id: int) -> None:
        if self.queue is not None:
            self.queue.put_nowait(flow_id)

    @property
    def backlog(self) -> int:
        return self.queue.qsize() if self.queue else 0

    async def _run(self) -> None:
        while True:
            first = await self.queue.get()
            settings = store.get_settings()
            batch = [first]
            while len(batch) < settings["ai_batch_size"] and not self.queue.empty():
                batch.append(self.queue.get_nowait())
            wait = settings["ai_min_interval"] - (time.time() - self._last_call)
            if wait > 0:
                await asyncio.sleep(wait)
            try:
                await self._review(batch, settings)
            except Exception:  # never let one bad batch kill the worker
                log.exception("AI review batch failed")
            finally:
                self._last_call = time.time()

    async def _review(self, ids: list[int], settings: dict) -> None:
        flows = [f for f in (store.get_flow(i, with_features=True) for i in ids) if f]
        if not flows:
            return
        try:
            data, provider = await ai_client.generate(flow_prompt(flows), settings)
            results = parse_results(data, {f["id"] for f in flows})
        except ProviderError as e:
            log.warning("AI review skipped for %d flows: %s", len(flows), e)
            for f in flows:
                await self.on_result(f["id"], {"ai_status": "failed", "ai_reason": str(e)[:300]})
            return
        for f in flows:
            r = results.get(f["id"])
            if r:
                await self.on_result(f["id"], {**r, "ai_status": "done", "ai_provider": provider})
            else:
                await self.on_result(f["id"], {"ai_status": "failed",
                                               "ai_reason": "AI response did not include this flow"})


ai_reviewer = AIReviewer()


def briefing_prompt(threat_counts: dict) -> str:
    return (
        "You are a senior SOC analyst. These are counts of network threats detected in the "
        f"last monitoring window:\n{json.dumps(threat_counts, indent=2)}\n\n"
        "Rank them by operational risk and give a concrete mitigation for each. Return ONLY "
        'a JSON object: {"results": [{"attack_type": str, "severity": "CRITICAL|HIGH|MEDIUM|LOW", '
        '"count": int, "advice": str}]}, sorted CRITICAL first.'
    )
