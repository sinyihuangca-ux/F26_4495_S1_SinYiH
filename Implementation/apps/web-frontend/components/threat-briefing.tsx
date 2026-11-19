"use client";

import { useState } from "react";
import { ShieldAlert, Sparkles } from "lucide-react";
import { api } from "@/lib/api";
import { useLive } from "@/lib/live";

interface Ranked {
  attack_type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  count: number;
  advice: string;
}

const SEVERITY: Record<string, string> = {
  CRITICAL: "bg-red-500/20 text-red-400 border-red-500/30",
  HIGH: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  MEDIUM: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  LOW: "bg-blue-500/20 text-blue-400 border-blue-500/30",
};

// Severity-ranked mitigation advice from whichever AI provider is available.
export function ThreatBriefing() {
  const { stats } = useLive();
  const [items, setItems] = useState<Ranked[]>([]);
  const [provider, setProvider] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const hasThreats = Object.keys(stats?.by_type ?? {}).length > 0;

  const run = async () => {
    setLoading(true);
    setError("");
    try {
      const res = await api<{ provider_used: string; result: Ranked[] }>("/api/analyze-threats", {
        method: "POST",
        body: JSON.stringify({}),
      });
      setItems(res.result);
      setProvider(res.provider_used);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h3 className="font-semibold text-white">AI threat briefing</h3>
          <p className="text-[11px] text-slate-500">
            {provider ? `Ranked by ${provider}` : "Threats ranked by operational risk, with mitigations"}
          </p>
        </div>
        <button
          onClick={run}
          disabled={loading || !hasThreats}
          className="flex items-center gap-2 rounded-lg bg-purple-600 px-3 py-1.5 text-xs font-medium hover:bg-purple-500 disabled:bg-slate-800 disabled:text-slate-500"
        >
          <Sparkles size={14} /> {loading ? "Analysing…" : "Analyse priority"}
        </button>
      </div>
      {error && <p className="mb-3 text-xs text-red-400">{error}</p>}
      {items.length === 0 ? (
        <div className="rounded-lg border border-dashed border-slate-800 py-8 text-center">
          <ShieldAlert size={32} className="mx-auto mb-2 text-slate-600" />
          <p className="text-xs text-slate-500">
            {hasThreats ? "Click “Analyse priority” for a briefing." : "Stream some traffic first."}
          </p>
        </div>
      ) : (
        <ol className="space-y-3">
          {items.map((it, i) => (
            <li key={i} className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`rounded-full border px-2 py-0.5 text-[11px] font-bold ${SEVERITY[it.severity] ?? SEVERITY.LOW}`}>
                  #{i + 1} {it.severity}
                </span>
                <span className="font-semibold text-white">{it.attack_type}</span>
                <span className="text-[11px] text-slate-500">{it.count} flows</span>
              </div>
              <p className="mt-2 text-xs text-slate-300">{it.advice}</p>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}
