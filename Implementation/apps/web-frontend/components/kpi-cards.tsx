import {
  FileText,
  AlertTriangle,
  Shield,
  Activity,
  TrendingUp,
} from "lucide-react";

export function KpiCards() {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      {/* Total Logs Parsed */}
      <div className="relative overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-sky-500/20 bg-sky-500/10 text-sky-400">
              <FileText className="h-5 w-5" />
            </div>
            <div>
              <p className="text-xs font-medium text-slate-400">
                Total Logs Parsed
              </p>
              <h3 className="text-2xl font-bold tracking-tight text-white">
                1,284,532
              </h3>
            </div>
          </div>
        </div>
        <div className="mt-3 flex items-center justify-between">
          <div className="flex items-center text-xs font-medium text-emerald-400">
            <TrendingUp className="mr-1 h-3.5 w-3.5" />
            +12.5%
          </div>
          {/* Mini Decorative Bar Graphic */}
          <div className="flex items-end gap-1">
            <span className="h-2 w-1.5 rounded-sm bg-sky-500/30" />
            <span className="h-3 w-1.5 rounded-sm bg-sky-500/50" />
            <span className="h-2.5 w-1.5 rounded-sm bg-sky-500/40" />
            <span className="h-4 w-1.5 rounded-sm bg-sky-500/70" />
            <span className="h-5 w-1.5 rounded-sm bg-sky-500" />
          </div>
        </div>
      </div>

      {/* Anomalies Detected */}
      <div className="relative overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-red-500/20 bg-red-500/10 text-red-400">
            <AlertTriangle className="h-5 w-5" />
          </div>
          <div>
            <p className="text-xs font-medium text-slate-400">
              Anomalies Detected
            </p>
            <h3 className="text-2xl font-bold tracking-tight text-red-500">
              1,328
            </h3>
          </div>
        </div>
        <div className="mt-3 flex items-center justify-between">
          <div className="flex items-center text-xs font-medium text-emerald-400">
            <TrendingUp className="mr-1 h-3.5 w-3.5" />
            +8.7%
          </div>
          {/* Mini Red Bar Graphic */}
          <div className="flex items-end gap-1">
            <span className="h-2 w-1.5 rounded-sm bg-red-500/30" />
            <span className="h-3 w-1.5 rounded-sm bg-red-500/40" />
            <span className="h-4 w-1.5 rounded-sm bg-red-500/60" />
            <span className="h-3.5 w-1.5 rounded-sm bg-red-500/80" />
            <span className="h-5 w-1.5 rounded-sm bg-red-500" />
          </div>
        </div>
      </div>

      {/* Threat Severity */}
      <div className="relative overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-amber-500/20 bg-amber-500/10 text-amber-400">
            <Shield className="h-5 w-5" />
          </div>
          <div>
            <p className="text-xs font-medium text-slate-400">
              Threat Severity
            </p>
            <h3 className="text-2xl font-bold tracking-tight text-red-500">
              Critical
            </h3>
          </div>
        </div>
        <div className="mt-3 flex items-center justify-between">
          <p className="text-xs text-slate-500">Highest severity in last 24h</p>
          <div className="flex items-end gap-1">
            <span className="h-2 w-1.5 rounded-sm bg-red-500/40" />
            <span className="h-3 w-1.5 rounded-sm bg-red-500/60" />
            <span className="h-4.5 w-1.5 rounded-sm bg-red-500/80" />
            <span className="h-5 w-1.5 rounded-sm bg-red-500" />
          </div>
        </div>
      </div>

      {/* System Status */}
      <div className="relative overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-emerald-500/20 bg-emerald-500/10 text-emerald-400">
              <Activity className="h-5 w-5" />
            </div>
            <div>
              <p className="text-xs font-medium text-slate-400">
                System Status
              </p>
              <h3 className="text-2xl font-bold tracking-tight text-emerald-400">
                Protected
              </h3>
            </div>
          </div>
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-emerald-500/20 text-emerald-400">
            <Shield className="h-5 w-5 fill-emerald-500/30" />
          </div>
        </div>
        <div className="mt-3">
          <p className="text-xs text-slate-500">All systems operational</p>
        </div>
      </div>
    </div>
  );
}
