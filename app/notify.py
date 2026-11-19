"""Push notifications through ntfy.sh for malicious flows.

Runs in the background and never blocks ingestion. To avoid flooding your phone
during a DDoS, at most one push goes out per cooldown window; alerts that arrive in
between are counted and summarised in the next push.
"""
import logging
import os
import time
from collections import Counter

import httpx

log = logging.getLogger("notify")


class Notifier:
    def __init__(self):
        self.last_sent = 0.0
        self.pending: Counter = Counter()

    async def alert(self, attack_type: str, src_ip: str | None, dst_port: int | None,
                    settings: dict) -> None:
        topic = os.environ.get("NTFY_TOPIC", "").strip()
        if not settings.get("notify_enabled") or not topic:
            return
        self.pending[attack_type] += 1
        if time.time() - self.last_sent < settings.get("notify_cooldown", 30):
            return
        summary = ", ".join(f"{n}x {t}" for t, n in self.pending.most_common())
        total = sum(self.pending.values())
        self.pending.clear()
        self.last_sent = time.time()
        body = (f"{attack_type} from {src_ip or 'unknown'} to port {dst_port}."
                if total == 1 else f"{total} malicious flows: {summary}.")
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(
                    f"https://ntfy.sh/{topic}",
                    content=body.encode(),
                    headers={"Title": f"Threat detected: {attack_type}", "Priority": "5",
                             "Tags": "rotating_light,shield"},
                )
        except httpx.HTTPError as e:
            log.warning("ntfy push failed: %s", e)


notifier = Notifier()
