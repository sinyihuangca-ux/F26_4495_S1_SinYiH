"use client";

import { useEffect, useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { Download, FileText, Search, Trash2 } from "lucide-react";
import { FlowTable } from "@/components/flow-table";
import { api, Flow, httpBase } from "@/lib/api";
import { useLive } from "@/lib/live";

const FILTERS = [
  { id: "alerts", label: "Alerts" },
  { id: "malicious", label: "Malicious" },
  { id: "suspicious", label: "Suspicious" },
  { id: "disagree", label: "ML ≠ AI" },
  { id: "all", label: "All flows" },
] as const;

export default function LogsPage() {
  const { getToken } = useAuth();
  const { alerts, stats, refresh } = useLive();
  const [filter, setFilter] = useState<(typeof FILTERS)[number]["id"]>("alerts");
  const [search, setSearch] = useState("");
  const [flows, setFlows] = useState<Flow[]>([]);
  const [error, setError] = useState("");

  // Re-query whenever the filter changes or new data arrives over the live feed.
  const liveVersion = `${stats?.total_flows ?? 0}-${alerts.length}-${alerts[0]?.id ?? 0}`;
  useEffect(() => {
    const params = new URLSearchParams({ limit: "1000" });
    if (filter === "alerts" || filter === "disagree") params.set("alerts_only", "true");
    if (filter === "malicious" || filter === "suspicious") params.set("verdict", filter);
    if (search) params.set("q", search);
    const t = setTimeout(() => {
      api<Flow[]>(`/api/flows?${params}`)
        .then((rows) => {
          setFlows(filter === "disagree" ? rows.filter((r) => r.agreement === "disagree") : rows);
          setError("");
        })
        .catch((e) => setError(e.message));
    }, 300);
    return () => clearTimeout(t);
  }, [filter, search, liveVersion]);

  // Show AI updates for rows already on screen without waiting for the next query.
  const merged = flows.map((f) => alerts.find((a) => a.id === f.id) ?? f);

  const clearAll = async () => {
    if (!confirm("Delete every stored flow and alert? This can't be undone.")) return;
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
            <FileText className="text-blue-400" /> Security audit log
          </h1>
          <p className="text-sm text-slate-400">Stored on the backend. Mark false positives to improve the next training run.</p>
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

      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="flex flex-wrap gap-1">
          {FILTERS.map((f) => (
            <button key={f.id} onClick={() => setFilter(f.id)}
              className={`rounded-lg px-3 py-1.5 text-xs ${filter === f.id
                ? "border border-sky-500/40 bg-sky-600/20 text-sky-300"
                : "border border-slate-800 text-slate-400 hover:bg-slate-900"}`}>
              {f.label}
            </button>
          ))}
        </div>
        <div className="relative max-w-sm flex-1">
          <Search className="absolute left-3 top-2.5 text-slate-500" size={15} />
          <input value={search} onChange={(e) => setSearch(e.target.value)}
            placeholder="IP, port, attack type or label…"
            className="w-full rounded-lg border border-slate-800 bg-slate-900 py-2 pl-9 pr-3 text-sm placeholder-slate-500 focus:border-blue-500 focus:outline-none" />
        </div>
      </div>

      {error && <p className="text-sm text-red-400">{error}</p>}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <FlowTable flows={merged} />
      </div>
    </div>
  );
}
