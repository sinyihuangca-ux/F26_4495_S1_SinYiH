"use client";

// Attack notifications raised by the dashboard itself (no ntfy app needed).
//
// * One popup per incident: the first qualifying flow to a target (dst IP + port)
//   notifies straight away; more flows to the same target within the cooldown are
//   counted and rolled into one "+N more" update when it ends. A source that hits
//   several different ports in a short time is treated as one scan incident, so a
//   port scan gives one popup instead of one per port.
// * Shown as in-page banners. Windows notifications (outside the browser) come from
//   the backend itself (app/winnotify.py), so they work even with the browser closed.
// * Which verdicts notify, and the cooldown, come from Settings via /api/health.

import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { ShieldAlert, X } from "lucide-react";
import { api, Flow } from "./api";

export interface NotifySettings {
  notify_enabled: boolean;
  notify_min_verdict: "malicious" | "suspicious";
  notify_cooldown: number;
  windows?: boolean; // backend can show Windows notifications
}

interface Toast {
  id: number;
  key: string;
  title: string;
  body: string;
  severe: boolean;
}

interface NotifyState {
  settings: NotifySettings;
  reloadSettings: () => void;
  // Called by the live feed for every flow it receives.
  consider: (flow: Flow, previousVerdict?: Flow["final_verdict"]) => void;
}

const DEFAULTS: NotifySettings = { notify_enabled: true, notify_min_verdict: "malicious", notify_cooldown: 30 };
const NotifyContext = createContext<NotifyState | null>(null);
const RANK = { benign: 0, suspicious: 1, malicious: 2 } as const;
const TOAST_MS = 8000;
const SCAN_TARGETS = 3;       // distinct targets from one source that make it a scan
const SCAN_WINDOW_MS = 60000; // ...within this long

const targetOf = (f: Flow) => `${f.dst_ip ?? "?"}:${f.dst_port ?? "?"}`;
const attackOf = (f: Flow) => f.ai_attack_type ?? f.ml_attack_type ?? (f.final_verdict === "malicious" ? "Attack" : "Suspicious traffic");

export function NotifyProvider({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [settings, setSettings] = useState<NotifySettings>(DEFAULTS);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const settingsRef = useRef(settings);
  useEffect(() => {
    settingsRef.current = settings;
  }, [settings]);
  const notified = useRef(new Set<number>()); // flow ids already counted
  const incidents = useRef(new Map<string, { lastShown: number; pending: number; last: Flow; timer?: ReturnType<typeof setTimeout> }>());
  const nextId = useRef(1);
  const targetsBySource = useRef(new Map<string, Map<string, number>>()); // src -> target -> last seen

  const reloadSettings = useCallback(() => {
    api<{ notifications?: NotifySettings }>("/api/health")
      .then((h) => h.notifications && setSettings(h.notifications))
      .catch(() => {});
  }, []);

  useEffect(() => {
    reloadSettings();
    const t = setInterval(reloadSettings, 30000);
    return () => clearInterval(t);
  }, [reloadSettings]);

  const show = useCallback((key: string, title: string, body: string, severe: boolean) => {
    const id = nextId.current++;
    setToasts((t) => [...t.filter((x) => x.key !== key), { id, key, title, body, severe }].slice(-4));
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), TOAST_MS);
  }, []);

  const flush = useCallback((key: string) => {
    const inc = incidents.current.get(key);
    if (!inc) return;
    inc.timer = undefined;
    if (inc.pending === 0) return;
    const f = inc.last;
    const scan = key.startsWith("scan from ");
    show(key, scan ? `Port scan continuing from ${f.src_ip}` : `${attackOf(f)} continuing on ${key}`,
      scan ? `+${inc.pending} more probed ports on ${f.dst_ip ?? "the target"}`
        : `+${inc.pending} more ${f.final_verdict} flow${inc.pending === 1 ? "" : "s"} from ${f.src_ip ?? "unknown"}`,
      f.final_verdict === "malicious");
    inc.pending = 0;
    inc.lastShown = Date.now();
  }, [show]);

  const consider = useCallback((flow: Flow, previousVerdict?: Flow["final_verdict"]) => {
    const s = settingsRef.current;
    if (!s.notify_enabled || notified.current.has(flow.id)) return;
    const min = RANK[s.notify_min_verdict];
    if (RANK[flow.final_verdict] < min) return;
    if (previousVerdict && RANK[previousVerdict] >= min) return; // already counted at that level
    notified.current.add(flow.id);

    const now = Date.now();
    // Scan detection: many different targets from one source -> one incident for the source.
    let key = targetOf(flow);
    let scan = false;
    if (flow.src_ip) {
      const seen = targetsBySource.current.get(flow.src_ip) ?? new Map<string, number>();
      seen.set(key, now);
      for (const [t, at] of seen) if (now - at > SCAN_WINDOW_MS) seen.delete(t);
      targetsBySource.current.set(flow.src_ip, seen);
      if (seen.size >= SCAN_TARGETS) {
        key = `scan from ${flow.src_ip}`;
        scan = true;
      }
    }
    const cooldownMs = Math.max(s.notify_cooldown, 0) * 1000;
    const inc = incidents.current.get(key);
    if (!inc || now - inc.lastShown >= cooldownMs) {
      if (inc?.timer) clearTimeout(inc.timer);
      incidents.current.set(key, { lastShown: now, pending: 0, last: flow });
      show(key, scan ? `Possible port scan from ${flow.src_ip}` : `${attackOf(flow)} detected on ${key}`,
        `${flow.final_verdict === "malicious" ? "Malicious" : "Suspicious"} traffic from ${flow.src_ip ?? "unknown"}` +
        (flow.ml_score != null ? ` · ML score ${flow.ml_score.toFixed(2)}` : ""),
        flow.final_verdict === "malicious");
      return;
    }
    inc.pending += 1;
    inc.last = flow;
    if (!inc.timer) inc.timer = setTimeout(() => flush(key), Math.max(cooldownMs - (now - inc.lastShown), 0));
  }, [show, flush]);

  return (
    <NotifyContext.Provider value={{ settings, reloadSettings, consider }}>
      {children}
      <div className="pointer-events-none fixed right-4 top-20 z-[100] flex w-80 flex-col gap-2">
        {toasts.map((t) => (
          <div key={t.id} role="alert"
            className={`pointer-events-auto cursor-pointer rounded-xl border p-3 shadow-2xl backdrop-blur ${t.severe
              ? "border-red-500/50 bg-red-950/90" : "border-amber-500/50 bg-amber-950/90"}`}
            onClick={() => { router.push("/logs"); setToasts((x) => x.filter((y) => y.id !== t.id)); }}>
            <div className="flex items-start gap-2">
              <ShieldAlert size={18} className={t.severe ? "mt-0.5 text-red-400" : "mt-0.5 text-amber-300"} />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold text-white">{t.title}</p>
                <p className="mt-0.5 text-xs text-slate-300">{t.body}</p>
              </div>
              <button aria-label="Dismiss" className="text-slate-400 hover:text-white"
                onClick={(e) => { e.stopPropagation(); setToasts((x) => x.filter((y) => y.id !== t.id)); }}>
                <X size={14} />
              </button>
            </div>
          </div>
        ))}
      </div>
    </NotifyContext.Provider>
  );
}

export function useNotify() {
  const ctx = useContext(NotifyContext);
  if (!ctx) throw new Error("useNotify must be used inside <NotifyProvider>");
  return ctx;
}
