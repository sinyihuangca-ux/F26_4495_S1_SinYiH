"use client";

import { useEffect, useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { Download, Search, ShieldAlert, Trash2 } from "lucide-react";
import { AccuracyPanel } from "@/components/dashboard-charts";
import { FlowTable } from "@/components/flow-table";
import { ThreatBriefing } from "@/components/threat-briefing";
import { api, Flow, httpBase } from "@/lib/api";
import { useLive } from "@/lib/live";

// Threats and the audit log on one page: what was detected, the AI advisor's take,
// and every flagged flow with analyst feedback controls.

const FILTERS = [
  { id: "review", label: "Needs review" },
  { id: "alerts", label: "All alerts" },
  { id: "malicious", label: "Malicious" },
  { id: "suspicious", label: "Suspicious" },
  { id: "disagree", label: "ML ≠ AI" },
  { id: "all", label: "All flows" },
] as const;
type FilterId = (typeof FILTERS)[number]["id"];

// Where a human is most useful: the engines disagree, or the call is only "suspicious",
// and nobody has marked it yet.
const needsReview = (f: Flow) =>
  !f.feedback && f.final_verdict !== "benign" && (f.agreement === "disagree" || f.final_verdict === "suspicious");

export default function ThreatsAndLogsPage() {
  const { getToken } = useAuth();
  const { alerts, stats, refresh } = useLive();
  const [filter, setFilter] = useState<FilterId>("review");
  const [search, setSearch] = useState("");
  const [flows, setFlows] = useState<Flow[]>([]);
  const [error, setError] = useState("");

  const types = Object.entries(stats?.by_type ?? {}).sort((a, b) => b[1] - a[1]);

  // Re-query whenever the filter changes or new data arrives over the live feed.
  const liveVersion = `${stats?.total_flows ?? 0}-${alerts.length}-${alerts[0]?.id ?? 0}`;
  useEffect(() => {
    const params = new URLSearchParams({ limit: "1000" });
    if (["review", "alerts", "disagree"].includes(filter)) params.set("alerts_only", "true");
    if (filter === "malicious" || filter === "suspicious") params.set("verdict", filter);
    if (search) params.set("q", search);
    const t = setTimeout(() => {
      api<Flow[]>(`/api/flows?${params}`)
        .then((rows) => {
          setFlows(
            filter === "disagree" ? rows.filter((r) => r.agreement === "disagree")
              : filter === "review" ? rows.filter(needsReview)
              : rows,
          );
          setError("");
        })
        .catch((e) => setError(e.message));
    }, 300);
    return () => clearTimeout(t);
  }, [filter, search, liveVersion]);

  // Show AI updates and feedback for rows already on screen without waiting for the next query.
  const merged = flows.map((f) => alerts.find((a) => a.id === f.id) ?? f);
  const shown = filter === "review" ? merged.filter(needsReview) : merged;

  const clearAll = async () => {
    if (!confirm("Delete every stored flow, alert and AI briefing? This can't be undone.")) return;
    try {
      await api("/api/flows", { method: "DELETE" }, await getToken());
      setFlows([]);
      refresh();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold tracking-tight">
            <ShieldAlert className="text-red-400" /> Threats &amp; logs
          </h1>
          <p className="text-sm text-slate-400">
            What was detected, what the AI thinks it is, and every flagged flow. Mark false positives to improve the next training run.
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={clearAll}
            className="flex items-center gap-2 rounded-lg border border-red-800/60 bg-red-950/40 px-3 py-2 text-sm text-red-400 hover:bg-red-900/40">
            <Trash2 size={16} /> Clear
          </button>
          <a href={`${httpBase()}/api/flows/export.csv?alerts_only=${filter !== "all"}`}
            className="flex items-center gap-2 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium hover:bg-blue-500">
            <Download size={16} /> Export CSV
          </a>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
          <h3 className="mb-3 font-semibold text-white">Active threat types</h3>
          {types.length === 0 ? (
            <p className="text-xs text-slate-500">None detected.</p>
          ) : (
            <ul className="space-y-2">
              {types.map(([name, n]) => (
                <li key={name} className="flex items-center justify-between text-sm">
                  <span className="text-slate-300">{name}</span>
                  <span className="font-mono text-red-400">{n}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
        <AccuracyPanel />
      </div>

      <ThreatBriefing />

      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <div className="mb-4 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <h3 className="font-semibold text-white">Audit log</h3>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <div className="flex flex-wrap gap-1">
              {FILTERS.map((f) => (
                <button key={f.id} onClick={() => setFilter(f.id)}
                  className={`rounded-lg px-3 py-1.5 text-xs ${filter === f.id
                    ? "border border-sky-500/40 bg-sky-600/20 text-sky-300"
                    : "border border-slate-800 text-slate-400 hover:bg-slate-900"}`}>
                  {f.label}{f.id === filter && shown.length > 0 ? ` (${shown.length})` : ""}
                </button>
              ))}
            </div>
            <div className="relative sm:w-64">
              <Search className="absolute left-3 top-2.5 text-slate-500" size={15} />
              <input value={search} onChange={(e) => setSearch(e.target.value)}
                placeholder="IP, port, attack type or label…"
                className="w-full rounded-lg border border-slate-800 bg-slate-950 py-2 pl-9 pr-3 text-sm placeholder-slate-500 focus:border-blue-500 focus:outline-none" />
            </div>
          </div>
        </div>
        {filter === "review" && (
          <p className="mb-3 text-[11px] text-slate-500">
            Suspicious flows and flows where ML and AI disagree that nobody has marked yet. Your decision is saved and used when you retrain.
          </p>
        )}
        {error && <p className="mb-2 text-sm text-red-400">{error}</p>}
        <FlowTable flows={shown} />
      </div>
    </div>
  );
}
