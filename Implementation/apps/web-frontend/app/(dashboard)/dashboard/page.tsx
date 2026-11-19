"use client";

import Link from "next/link";
import { DashboardCharts } from "@/components/dashboard-charts";
import { FlowTable } from "@/components/flow-table";
import { KpiCards } from "@/components/kpi-cards";
import { ThreatBriefing } from "@/components/threat-briefing";
import { useLive } from "@/lib/live";

export default function DashboardPage() {
  const { alerts } = useLive();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Threat overview</h1>
        <p className="text-sm text-slate-400">
          Every flow is scored by the ML models; the AI double-checks the uncertain ones and a sample of the rest.
        </p>
      </div>

      <KpiCards />
      <DashboardCharts />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4 xl:col-span-2">
          <div className="mb-3 flex items-center justify-between">
            <h3 className="font-semibold text-white">Live alerts · ML vs AI</h3>
            <Link href="/logs" className="text-xs text-sky-400 hover:underline">
              Full log →
            </Link>
          </div>
          <FlowTable flows={alerts.slice(0, 15)} showTruth={false} />
        </div>
        <ThreatBriefing />
      </div>
    </div>
  );
}
