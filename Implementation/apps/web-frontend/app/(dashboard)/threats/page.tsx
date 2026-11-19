"use client";

import { ShieldAlert } from "lucide-react";
import { AccuracyPanel } from "@/components/dashboard-charts";
import { FlowTable } from "@/components/flow-table";
import { ThreatBriefing } from "@/components/threat-briefing";
import { useLive } from "@/lib/live";

export default function ThreatsPage() {
  const { stats, alerts } = useLive();
  const types = Object.entries(stats?.by_type ?? {}).sort((a, b) => b[1] - a[1]);
  // Where a human is most useful: the engines disagree, or the call is only "suspicious".
  const review = alerts.filter(
    (f) => !f.feedback && f.final_verdict !== "benign" && (f.agreement === "disagree" || f.final_verdict === "suspicious"),
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-bold tracking-tight">
          <ShieldAlert className="text-red-400" /> Threats
        </h1>
        <p className="text-sm text-slate-400">What was detected, and what still needs a human decision.</p>
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
        <h3 className="font-semibold text-white">Needs review ({review.length})</h3>
        <p className="mb-3 text-[11px] text-slate-500">
          Suspicious flows and flows where ML and AI disagree. Your decision is saved and used when you retrain.
        </p>
        <FlowTable flows={review.slice(0, 100)} />
      </div>
    </div>
  );
}
