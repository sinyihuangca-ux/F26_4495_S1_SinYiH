"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { ArrowDown, ArrowUp, Save, Settings as SettingsIcon, Trash2 } from "lucide-react";
import { api, setServer, Settings, SettingsView } from "@/lib/api";
import { useLive } from "@/lib/live";
import { useNotify } from "@/lib/notify";

const PROVIDER_NAMES: Record<string, string> = {
  gemini: "Google Gemini",
  groq: "Groq (free tier)",
  openai: "OpenAI",
  claude: "Anthropic Claude",
};

interface Health {
  ml: { enabled: boolean; model_loaded: boolean; trained_on: { source: string; benign_rows: number } | null };
  ai: { enabled: boolean; backlog: number; providers: Record<string, string | null> };
}

interface AllowRule {
  id: number;
  src_ip: string | null;
  dst_port: number | null;
  note: string;
}

function Section({ title, hint, children }: { title: string; hint?: string; children: React.ReactNode }) {
  return (
    <section className="rounded-xl border border-slate-800 bg-slate-900/60 p-5">
      <h2 className="font-semibold text-white">{title}</h2>
      {hint && <p className="mt-0.5 text-xs text-slate-500">{hint}</p>}
      <div className="mt-4 space-y-4">{children}</div>
    </section>
  );
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex cursor-pointer items-center justify-between gap-4 text-sm">
      <span className="text-slate-300">{label}</span>
      <button type="button" onClick={() => onChange(!checked)}
        className={`relative h-6 w-11 rounded-full transition ${checked ? "bg-sky-600" : "bg-slate-700"}`}>
        <span className={`absolute top-0.5 h-5 w-5 rounded-full bg-white transition ${checked ? "left-5" : "left-0.5"}`} />
      </button>
    </label>
  );
}

function Slider({ label, value, onChange, min = 0, max = 1, step = 0.01, format }: {
  label: string;
  value: number;
  onChange: (v: number) => void;
  min?: number;
  max?: number;
  step?: number;
  format?: (v: number) => string;
}) {
  return (
    <label className="block text-sm">
      <div className="flex justify-between text-slate-300">
        <span>{label}</span>
        <span className="font-mono text-sky-300">{format ? format(value) : value}</span>
      </div>
      <input type="range" min={min} max={max} step={step} value={value}
        onChange={(e) => onChange(Number(e.target.value))} className="mt-1 w-full accent-sky-500" />
    </label>
  );
}

const input = "w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-white focus:border-sky-500 focus:outline-none";
const pct = (v: number) => `${Math.round(v * 100)}%`;

export default function SettingsPage() {
  const { getToken } = useAuth();
  const { reconnect, status, server } = useLive();
  const { permission, requestPermission, reloadSettings } = useNotify();
  const serverInput = useRef<HTMLInputElement>(null);
  const [view, setView] = useState<SettingsView | null>(null);
  const [draft, setDraft] = useState<Settings | null>(null);
  const [keys, setKeys] = useState<Record<string, string>>({});
  const [health, setHealth] = useState<Health | null>(null);
  const [allow, setAllow] = useState<AllowRule[]>([]);
  const [newRule, setNewRule] = useState({ src_ip: "", dst_port: "" });
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    try {
      const token = await getToken();
      const [v, h, a] = await Promise.all([
        api<SettingsView>("/api/settings", {}, token),
        api<Health>("/api/health"),
        api<AllowRule[]>("/api/allowlist"),
      ]);
      setView(v);
      setDraft(v.settings);
      setHealth(h);
      setAllow(a);
    } catch (e) {
      setMessage({ ok: false, text: (e as Error).message });
    }
  }, [getToken]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- initial data fetch
    load();
  }, [load]);

  const set = <K extends keyof Settings>(k: K, v: Settings[K]) => setDraft((d) => (d ? { ...d, [k]: v } : d));

  const save = async () => {
    if (!draft) return;
    setSaving(true);
    setMessage(null);
    try {
      const secrets = Object.fromEntries(Object.entries(keys).filter(([, v]) => v.trim() !== ""));
      const v = await api<SettingsView>("/api/settings", {
        method: "PUT",
        body: JSON.stringify({ settings: draft, secrets }),
      }, await getToken());
      setView(v);
      setDraft(v.settings);
      setKeys({});
      setMessage({ ok: true, text: "Saved. Keys are stored in the backend's .env file." });
      reloadSettings();
      setHealth(await api<Health>("/api/health"));
    } catch (e) {
      setMessage({ ok: false, text: (e as Error).message });
    } finally {
      setSaving(false);
    }
  };

  const removeKey = async (name: string) => {
    try {
      const v = await api<SettingsView>("/api/settings", {
        method: "PUT",
        body: JSON.stringify({ secrets: { [name]: "" } }),
      }, await getToken());
      setView(v);
    } catch (e) {
      setMessage({ ok: false, text: (e as Error).message });
    }
  };

  const move = (i: number, dir: -1 | 1) => {
    if (!draft) return;
    const order = [...draft.provider_order];
    const j = i + dir;
    if (j < 0 || j >= order.length) return;
    [order[i], order[j]] = [order[j], order[i]];
    set("provider_order", order);
  };

  const addRule = async () => {
    try {
      await api("/api/allowlist", {
        method: "POST",
        body: JSON.stringify({
          src_ip: newRule.src_ip.trim() || null,
          dst_port: newRule.dst_port.trim() ? Number(newRule.dst_port) : null,
        }),
      }, await getToken());
      setNewRule({ src_ip: "", dst_port: "" });
      setAllow(await api<AllowRule[]>("/api/allowlist"));
    } catch (e) {
      setMessage({ ok: false, text: (e as Error).message });
    }
  };

  const deleteRule = async (id: number) => {
    await api(`/api/allowlist/${id}`, { method: "DELETE" }, await getToken()).catch(() => {});
    setAllow(await api<AllowRule[]>("/api/allowlist"));
  };

  return (
    <div className="max-w-3xl space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="flex items-center gap-2 text-2xl font-bold tracking-tight">
          <SettingsIcon className="text-sky-400" /> Settings
        </h1>
        <button onClick={save} disabled={!draft || saving}
          className="flex items-center gap-2 rounded-lg bg-sky-600 px-4 py-2 text-sm font-medium hover:bg-sky-500 disabled:bg-slate-800">
          <Save size={16} /> {saving ? "Saving…" : "Save changes"}
        </button>
      </div>
      {message && (
        <p className={`rounded-lg border px-3 py-2 text-sm ${message.ok
          ? "border-emerald-800 bg-emerald-950/40 text-emerald-300"
          : "border-red-800 bg-red-950/40 text-red-300"}`}>{message.text}</p>
      )}

      <Section title="Backend server" hint="Where FastAPI runs. Saved in this browser only.">
        <div className="flex gap-2">
          <input ref={serverInput} key={server} className={input} defaultValue={server}
            placeholder="localhost:8000 or 192.168.1.50:8000" />
          <button onClick={() => { setServer(serverInput.current?.value ?? ""); reconnect(); load(); }}
            className="rounded-lg bg-slate-800 px-4 text-sm hover:bg-slate-700">Connect</button>
        </div>
        <p className="text-xs text-slate-500">Live feed: {status}</p>
      </Section>

      {draft && view && (
        <>
          <Section title="Detection engines"
            hint="Both engines judge each flow on their own; the dashboard shows their verdicts side by side.">
            <Toggle label="ML engine (Isolation Forest + One-Class SVM)" checked={draft.ml_enabled}
              onChange={(v) => set("ml_enabled", v)} />
            {health && !health.ml.model_loaded && (
              <p className="text-xs text-amber-300">No model file found. Run <code>python -m app.train</code> on the backend.</p>
            )}
            {health?.ml.trained_on && (
              <p className="text-xs text-slate-500">
                Trained on {health.ml.trained_on.benign_rows.toLocaleString()} benign flows from {health.ml.trained_on.source}.
              </p>
            )}
            <Slider label="ML score for “suspicious”" value={draft.ml_suspicious_threshold} format={(v) => v.toFixed(2)}
              onChange={(v) => set("ml_suspicious_threshold", Math.min(v, draft.ml_malicious_threshold))} />
            <Slider label="ML score for “malicious”" value={draft.ml_malicious_threshold} format={(v) => v.toFixed(2)}
              onChange={(v) => set("ml_malicious_threshold", Math.max(v, draft.ml_suspicious_threshold))} />
            <p className="text-xs text-slate-500">
              A score of 0.90 means the flow is more unusual than 90% of normal traffic seen in training.
              Lower thresholds catch more attacks but raise more false positives for the AI to sort out.
            </p>
            <hr className="border-slate-800" />
            <Toggle label="AI engine (LLM review)" checked={draft.ai_enabled} onChange={(v) => set("ai_enabled", v)} />
            <Slider label="Also review this share of ML-benign flows" value={draft.ai_sample_rate}
              max={0.5} format={pct} onChange={(v) => set("ai_sample_rate", v)} />
            <Slider label="Minimum AI confidence to clear or escalate" value={draft.ai_min_confidence}
              format={pct} onChange={(v) => set("ai_min_confidence", v)} />
            <div className="grid grid-cols-2 gap-4">
              <label className="text-sm text-slate-300">Seconds between AI calls
                <input type="number" min={0} step={0.5} className={`${input} mt-1`} value={draft.ai_min_interval}
                  onChange={(e) => set("ai_min_interval", Number(e.target.value))} />
              </label>
              <label className="text-sm text-slate-300">Flows per AI call
                <input type="number" min={1} max={50} className={`${input} mt-1`} value={draft.ai_batch_size}
                  onChange={(e) => set("ai_batch_size", Number(e.target.value))} />
              </label>
            </div>
          </Section>

          <Section title="AI providers"
            hint="Tried top to bottom. A provider that rate-limits or rejects its key is skipped and the next one is used.">
            {draft.provider_order.map((p, i) => (
              <div key={p} className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                <div className="mb-2 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-slate-500">{i + 1}.</span>
                    <span className="text-sm font-medium text-white">{PROVIDER_NAMES[p] ?? p}</span>
                    <span className="text-[11px] text-slate-500">{health?.ai.providers[p]}</span>
                  </div>
                  <div className="flex gap-1">
                    <button onClick={() => move(i, -1)} className="rounded p-1 hover:bg-slate-800" title="Move up"><ArrowUp size={14} /></button>
                    <button onClick={() => move(i, 1)} className="rounded p-1 hover:bg-slate-800" title="Move down"><ArrowDown size={14} /></button>
                  </div>
                </div>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  <div className="flex gap-2">
                    <input type="password" autoComplete="off" className={input}
                      placeholder={view.secrets[p] ? `Saved: ${view.secrets[p]}` : "Paste API key"}
                      value={keys[p] ?? ""} onChange={(e) => setKeys((k) => ({ ...k, [p]: e.target.value }))} />
                    {view.secrets[p] && (
                      <button onClick={() => removeKey(p)} className="rounded-lg px-2 text-slate-500 hover:bg-slate-800 hover:text-red-400" title="Remove key">
                        <Trash2 size={14} />
                      </button>
                    )}
                  </div>
                  <input className={input} value={draft.models[p] ?? ""} placeholder="model name"
                    onChange={(e) => set("models", { ...draft.models, [p]: e.target.value })} />
                </div>
              </div>
            ))}
            {health?.ai.providers.last_error && (
              <p className="text-xs text-amber-300">Last AI error: {health.ai.providers.last_error}</p>
            )}
          </Section>

          <Section title="Attack notifications"
            hint="The dashboard pops up an alert when attacks come in: a banner on the page, or a Windows notification when the tab is in the background. One popup per attacked target, then a roll-up of further flows.">
            <Toggle label="Show attack notifications" checked={draft.notify_enabled} onChange={(v) => set("notify_enabled", v)} />
            <label className="block text-sm text-slate-300">Notify on
              <select className={`${input} mt-1`} value={draft.notify_min_verdict}
                onChange={(e) => set("notify_min_verdict", e.target.value as Settings["notify_min_verdict"])}>
                <option value="malicious">Malicious flows only</option>
                <option value="suspicious">Malicious and suspicious flows</option>
              </select>
            </label>
            <label className="block text-sm text-slate-300">At most one popup per target every (seconds)
              <input type="number" min={0} className={`${input} mt-1`} value={draft.notify_cooldown}
                onChange={(e) => set("notify_cooldown", Number(e.target.value))} />
            </label>
            <div className="flex items-center justify-between gap-4 rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-sm">
              <span className="text-slate-300">
                Windows notifications:{" "}
                <span className={permission === "granted" ? "text-emerald-400" : permission === "denied" ? "text-red-400" : "text-amber-300"}>
                  {permission === "granted" ? "allowed" : permission === "denied" ? "blocked in browser settings"
                    : permission === "unsupported" ? "not supported by this browser" : "not enabled yet"}
                </span>
              </span>
              {permission === "default" && (
                <button onClick={requestPermission} className="rounded-lg bg-sky-600 px-3 py-1.5 text-xs font-medium hover:bg-sky-500">
                  Enable browser notifications
                </button>
              )}
            </div>
            {permission === "denied" && (
              <p className="text-xs text-slate-500">
                Click the lock icon next to the address bar, set Notifications to Allow, then reload. In-page banners still work meanwhile.
              </p>
            )}
          </Section>
        </>
      )}

      <Section title="Allowlist" hint="Flows matching a rule are never alerted on. Leave a field empty to match anything.">
        <div className="flex gap-2">
          <input className={input} placeholder="Source IP" value={newRule.src_ip}
            onChange={(e) => setNewRule((r) => ({ ...r, src_ip: e.target.value }))} />
          <input className={input} placeholder="Destination port" value={newRule.dst_port}
            onChange={(e) => setNewRule((r) => ({ ...r, dst_port: e.target.value.replace(/\D/g, "") }))} />
          <button onClick={addRule} className="rounded-lg bg-slate-800 px-4 text-sm hover:bg-slate-700">Add</button>
        </div>
        {allow.length > 0 && (
          <ul className="divide-y divide-slate-800 text-sm">
            {allow.map((r) => (
              <li key={r.id} className="flex items-center justify-between py-2">
                <span className="font-mono text-slate-300">
                  {r.src_ip ?? "any IP"} → port {r.dst_port ?? "any"}
                  {r.note && <span className="ml-2 font-sans text-xs text-slate-500">{r.note}</span>}
                </span>
                <button onClick={() => deleteRule(r.id)} className="text-slate-500 hover:text-red-400"><Trash2 size={14} /></button>
              </li>
            ))}
          </ul>
        )}
      </Section>
    </div>
  );
}
