"use client";

import { Activity, AlertTriangle, FileText, ShieldQuestion } from "lucide-react";
import { useLive } from "@/lib/live";

function Card({ icon: Icon, label, value, tone, sub }: {
  icon: React.ElementType;
  label: string;
  value: string;
  tone: string;
  sub: string;
}) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <div className="flex items-center gap-3">
        <div className={`flex h-10 w-10 items-center justify-center rounded-lg border ${tone}`}>
          <Icon className="h-5 w-5" />
        </div>
        <div>
          <p className="text-xs font-medium text-slate-400">{label}</p>
          <h3 className="text-2xl font-bold tracking-tight text-white">{value}</h3>
        </div>
      </div>
      <p className="mt-3 text-xs text-slate-500">{sub}</p>
    </div>
  );
}

export function KpiCards() {
  const { stats, status } = useLive();
  const v = stats?.by_verdict ?? { benign: 0, suspicious: 0, malicious: 0 };
  const pendingAi = stats?.ai_status?.pending ?? 0;
  const disagreements = stats?.agreement?.disagree ?? 0;

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <Card icon={FileText} label="Flows analysed" value={(stats?.total_flows ?? 0).toLocaleString()}
        tone="border-sky-500/20 bg-sky-500/10 text-sky-400"
        sub={`${pendingAi} waiting for AI review`} />
      <Card icon={AlertTriangle} label="Malicious" value={v.malicious.toLocaleString()}
        tone="border-red-500/20 bg-red-500/10 text-red-400"
        sub="Final verdict after both engines" />
      <Card icon={ShieldQuestion} label="Suspicious" value={v.suspicious.toLocaleString()}
        tone="border-amber-500/20 bg-amber-500/10 text-amber-300"
        sub={`${disagreements} where ML and AI disagree`} />
      <Card icon={Activity} label="System status"
        value={status === "connected" ? (v.malicious > 0 ? "Under attack" : "Monitoring") : "Offline"}
        tone="border-emerald-500/20 bg-emerald-500/10 text-emerald-400"
        sub={status === "connected" ? "Live feed connected" : "Backend not reachable"} />
    </div>
  );
}
