"use client";

import { useCallback, useEffect, useState } from "react";
import { RefreshCw, ShieldAlert, Sparkles } from "lucide-react";
import { api } from "@/lib/api";
import { useLive } from "@/lib/live";

interface Brief {
  assessment: string;
  confidence: number;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  summary: string;
  evidence: string[];
  alternatives: string[];
  actions: string[];
  verify: string[];
}

interface Incident {
  key: string;
  kind: "target" | "scan";
  title: string;
  flow_count: number;
  first_seen: number;
  last_seen: number;
  stats: {
    flows_per_s: number | null;
    time_span_s: number;
    distinct_sources: number;
    top_sources: string[];
    distinct_dst_ports: number;
    ml_score_median: number | null;
  };
  brief: Brief | null;
  provider: string | null;
  briefed_at: number | null;
  new_flows_since_brief: number | null;
  stale: boolean;
  fresh: boolean;
}

interface AnalyzeResponse {
  provider_used: string | null;
  analysed: number;
  reused: number;
  error: string | null;
  incidents: Incident[];
}

const SEVERITY: Record<string, string> = {
  CRITICAL: "bg-red-500/20 text-red-400 border-red-500/30",
  HIGH: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  MEDIUM: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  LOW: "bg-blue-500/20 text-blue-400 border-blue-500/30",
};

function List({ title, items, ordered = false }: { title: string; items: string[]; ordered?: boolean }) {
  if (!items.length) return null;
  const Tag = ordered ? "ol" : "ul";
  return (
    <div className="mt-3">
      <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">{title}</p>
      <Tag className={`mt-1 space-y-1 pl-4 text-xs text-slate-300 ${ordered ? "list-decimal" : "list-disc"}`}>
        {items.map((x, i) => <li key={i}>{x}</li>)}
      </Tag>
    </div>
  );
}

function IncidentCard({ inc, rank, onRefresh, busy }: {
  inc: Incident;
  rank: number;
  onRefresh: () => void;
  busy: boolean;
}) {
  const b = inc.brief;
  const s = inc.stats;
  const meta = [
    `${inc.flow_count} flows`,
    s.flows_per_s ? `${s.flows_per_s}/s` : null,
    inc.kind === "scan" ? `${s.distinct_dst_ports} ports` : `from ${s.top_sources.slice(0, 2).join(", ")}${s.distinct_sources > 2 ? ` +${s.distinct_sources - 2}` : ""}`,
    s.ml_score_median != null ? `ML score ~${s.ml_score_median.toFixed(2)}` : null,
  ].filter(Boolean).join(" · ");

  return (
    <li className="rounded-lg border border-slate-800 bg-slate-950 p-3">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            {b && (
              <span className={`rounded-full border px-2 py-0.5 text-[11px] font-bold ${SEVERITY[b.severity]}`}>
                #{rank} {b.severity}
              </span>
            )}
            <span className="font-semibold text-white">{b ? b.assessment : inc.title}</span>
            {b && <span className="text-[11px] text-slate-400">{Math.round(b.confidence * 100)}% confident</span>}
          </div>
          <p className="mt-1 font-mono text-[11px] text-slate-500">{inc.title} · {meta}</p>
        </div>
        <button onClick={onRefresh} disabled={busy} title="Re-analyse this incident"
          className="shrink-0 rounded p-1 text-slate-500 hover:bg-slate-800 hover:text-slate-300 disabled:opacity-40">
          <RefreshCw size={13} className={busy ? "animate-spin" : ""} />
        </button>
      </div>

      {b ? (
        <>
          <p className="mt-2 text-xs text-slate-200">{b.summary}</p>
          <List title="Why I think so" items={b.evidence} />
          <List title="What to do" items={b.actions} ordered />
          <List title="To confirm" items={b.verify} />
          <List title="Could also be" items={b.alternatives} />
          <p className="mt-3 text-[10px] text-slate-600">
            {inc.fresh ? "Just analysed" : "Saved briefing"} by {inc.provider}
            {inc.new_flows_since_brief ? ` · ${inc.new_flows_since_brief} new flows since` : ""}
          </p>
        </>
      ) : (
        <p className="mt-2 text-xs text-slate-500">Not analysed yet.</p>
      )}
    </li>
  );
}

// AI advisor: one assessment per incident. Incidents it has already read are reused,
// so clicking again only spends tokens on new or grown incidents.
export function ThreatBriefing() {
  const { stats } = useLive();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [note, setNote] = useState("");
  const [loading, setLoading] = useState<string | null>(null); // "all" or an incident key
  const [error, setError] = useState("");
  // Reload saved incidents as traffic arrives, but not on every single batch.
  const total = Math.floor((stats?.total_flows ?? 0) / 200);

  const loadSaved = useCallback(() => {
    api<Incident[]>("/api/incidents").then(setIncidents).catch(() => {});
  }, []);

  useEffect(() => {
    loadSaved();
  }, [loadSaved, total]);

  const run = async (forceKey?: string) => {
    setLoading(forceKey ?? "all");
    setError("");
    try {
      const res = await api<AnalyzeResponse>("/api/analyze-threats", {
        method: "POST",
        body: JSON.stringify(forceKey ? { force_keys: [forceKey] } : {}),
      });
      setIncidents(res.incidents);
      setNote(res.analysed === 0 && res.reused > 0
        ? "Nothing new since the last briefing, so no AI call was made."
        : `Analysed ${res.analysed} incident${res.analysed === 1 ? "" : "s"}${res.reused ? `, reused ${res.reused} saved` : ""}${res.provider_used ? ` (${res.provider_used})` : ""}.`);
      if (res.error) setError(res.error);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(null);
    }
  };

  const pending = incidents.filter((i) => i.stale).length;
  let rank = 0;

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="mb-3 flex items-center justify-between gap-2">
        <div>
          <h3 className="font-semibold text-white">AI threat advisor</h3>
          <p className="text-[11px] text-slate-500">
            {incidents.length ? `${incidents.length} incidents · ${pending} to analyse` : "What each incident probably is, and what to do"}
          </p>
        </div>
        <button onClick={() => run()} disabled={loading !== null || incidents.length === 0}
          className="flex shrink-0 items-center gap-2 rounded-lg bg-purple-600 px-3 py-1.5 text-xs font-medium hover:bg-purple-500 disabled:bg-slate-800 disabled:text-slate-500">
          <Sparkles size={14} /> {loading === "all" ? "Analysing…" : "Analyse priority"}
        </button>
      </div>
      {note && <p className="mb-2 text-[11px] text-slate-400">{note}</p>}
      {error && <p className="mb-3 text-xs text-red-400">{error}</p>}
      {incidents.length === 0 ? (
        <div className="rounded-lg border border-dashed border-slate-800 py-8 text-center">
          <ShieldAlert size={32} className="mx-auto mb-2 text-slate-600" />
          <p className="text-xs text-slate-500">No incidents yet. Stream some traffic first.</p>
        </div>
      ) : (
        <ol className="space-y-3">
          {incidents.map((inc) => (
            <IncidentCard key={inc.key} inc={inc} rank={inc.brief ? ++rank : 0}
              onRefresh={() => run(inc.key)} busy={loading === inc.key} />
          ))}
        </ol>
      )}
    </div>
  );
}
