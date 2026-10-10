import { KpiCards } from "@/components/kpi-cards";
import { LogFeed } from "@/components/log-feed";
import { DashboardCharts } from "@/components/dashboard-charts";
import { ActionBanner } from "@/components/action-banner";

export default function DashboardPage() {
  return (
    <main className="p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">
            Dashboard
          </h1>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <span>2026-10-09 14:32:18</span>
          <span className="flex items-center gap-1.5 text-emerald-400">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
            Live
          </span>
        </div>
      </div>

      {/* Grid Stack */}
      <KpiCards />
      <LogFeed />
      <DashboardCharts />
      <ActionBanner />
    </main>
  );
}
