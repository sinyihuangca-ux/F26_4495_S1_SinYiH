"""Windows notifications for incoming attacks, raised by the backend itself.

They appear on the PC running uvicorn, even with the browser closed. Clicking one opens
Threats & Logs in the default browser.

Same rules as the dashboard's in-page banners (web-frontend lib/notify.tsx):
  * one notification per incident: the first qualifying flow to a target (dst IP +
    port) notifies at once; further flows within the cooldown are rolled into one
    "+N more" update when it ends;
  * a source that hits 3+ different targets within a minute is one port-scan incident;
  * Settings decide whether it's on, which verdicts notify (malicious, or malicious +
    suspicious) and the cooldown.
Notifications for the same incident replace each other in the Action Center.

On non-Windows machines, or without the `windows-toasts` package, nothing is shown
(the decisions are still made, so tests can check them).
"""
import asyncio
import hashlib
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

log = logging.getLogger("winnotify")

RANK = {"benign": 0, "suspicious": 1, "malicious": 2}
SCAN_TARGETS = 3        # distinct targets from one source that make it a scan
SCAN_WINDOW_S = 60.0    # ...within this long
APP_NAME = "AI Threat Mitigation"
DASHBOARD_URL = os.getenv("DASHBOARD_URL", "http://localhost:3000/logs")


def _windows_toaster():
    """Returns a function that shows (tag, title, body), or None if unavailable."""
    if sys.platform != "win32":
        return None
    try:
        from windows_toasts import InteractableWindowsToaster, Toast
    except ImportError:
        log.warning("windows-toasts isn't installed - run: python -m pip install windows-toasts")
        return None

    def show(tag: str, title: str, body: str) -> None:
        # Created per call: WinRT objects are tied to the thread that made them.
        toaster = InteractableWindowsToaster(APP_NAME)
        toast = Toast(text_fields=[title, body], launch_action=DASHBOARD_URL)
        # Windows limits tags to 64 characters; same tag = replace the earlier one.
        toast.tag = hashlib.sha1(tag.encode()).hexdigest()[:32]
        toast.group = "threats"
        toaster.show_toast(toast)

    return show


@dataclass
class _Incident:
    last_shown: float
    pending: int = 0
    last: Optional[dict] = None
    timer: Optional[asyncio.TimerHandle] = None


@dataclass
class WindowsNotifier:
    show_fn: Optional[Callable[[str, str, str], None]] = field(default_factory=_windows_toaster)
    incidents: dict = field(default_factory=dict)
    targets_by_source: dict = field(default_factory=dict)
    notified: set = field(default_factory=set)
    sent: list = field(default_factory=list)  # (tag, title, body) history, newest last

    @property
    def available(self) -> bool:
        return self.show_fn is not None

    def _emit(self, tag: str, title: str, body: str) -> None:
        self.sent = (self.sent + [(tag, title, body)])[-50:]
        if self.show_fn is None:
            return
        try:
            loop = asyncio.get_running_loop()
            # Showing a toast is a blocking WinRT call; keep it off the event loop.
            loop.run_in_executor(None, self._safe_show, tag, title, body)
        except RuntimeError:  # no running loop (e.g. called from a script)
            self._safe_show(tag, title, body)

    def _safe_show(self, tag: str, title: str, body: str) -> None:
        try:
            self.show_fn(tag, title, body)
        except Exception as e:  # a notification failing must never break ingestion
            log.warning("Windows notification failed: %s", e)

    def test(self) -> bool:
        self._emit("test", "Test notification",
                   "Windows notifications are working. Click to open Threats & Logs.")
        return self.available

    def consider(self, flow: dict, settings: dict, previous_verdict: Optional[str] = None) -> None:
        """Call for every new or updated flow."""
        if not settings.get("notify_enabled", True) or flow["id"] in self.notified:
            return
        min_rank = RANK.get(settings.get("notify_min_verdict", "malicious"), 2)
        if RANK.get(flow["final_verdict"], 0) < min_rank:
            return
        if previous_verdict is not None and RANK.get(previous_verdict, 0) >= min_rank:
            return  # already counted at that level
        self.notified.add(flow["id"])

        now = time.time()
        key = f"{flow.get('dst_ip') or '?'}:{flow.get('dst_port')}"
        scan = False
        src = flow.get("src_ip")
        if src:
            seen = self.targets_by_source.setdefault(src, {})
            seen[key] = now
            for t, at in list(seen.items()):
                if now - at > SCAN_WINDOW_S:
                    del seen[t]
            if len(seen) >= SCAN_TARGETS:
                key, scan = f"scan from {src}", True

        cooldown = max(float(settings.get("notify_cooldown", 30)), 0.0)
        inc = self.incidents.get(key)
        attack = flow.get("ai_attack_type") or flow.get("ml_attack_type") or (
            "Attack" if flow["final_verdict"] == "malicious" else "Suspicious traffic")
        if inc is None or now - inc.last_shown >= cooldown:
            if inc and inc.timer:
                inc.timer.cancel()
            self.incidents[key] = _Incident(last_shown=now, last=flow)
            title = f"Possible port scan from {src}" if scan else f"{attack} detected on {key}"
            score = f" · ML score {flow['ml_score']:.2f}" if flow.get("ml_score") is not None else ""
            self._emit(key, title, f"{flow['final_verdict'].capitalize()} traffic from {src or 'unknown'}{score}")
            return

        inc.pending += 1
        inc.last = flow
        if inc.timer is None:
            delay = max(cooldown - (now - inc.last_shown), 0.0)
            try:
                inc.timer = asyncio.get_running_loop().call_later(delay, self._flush, key)
            except RuntimeError:
                pass

    def _flush(self, key: str) -> None:
        inc = self.incidents.get(key)
        if not inc:
            return
        inc.timer = None
        if inc.pending == 0:
            return
        f = inc.last
        scan = key.startswith("scan from ")
        attack = f.get("ai_attack_type") or f.get("ml_attack_type") or "Attack"
        if scan:
            title, body = f"Port scan continuing from {f.get('src_ip')}", \
                f"+{inc.pending} more probed ports on {f.get('dst_ip') or 'the target'}"
        else:
            s = "" if inc.pending == 1 else "s"
            title, body = f"{attack} continuing on {key}", \
                f"+{inc.pending} more {f['final_verdict']} flow{s} from {f.get('src_ip') or 'unknown'}"
        self._emit(key, title, body)
        inc.pending = 0
        inc.last_shown = time.time()


windows_notifier = WindowsNotifier()
