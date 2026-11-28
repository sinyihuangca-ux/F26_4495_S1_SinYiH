import { Flow, Verdict } from "@/lib/api";

const STYLES: Record<Verdict, string> = {
  malicious: "border-red-500/40 bg-red-500/15 text-red-400",
  suspicious: "border-amber-500/40 bg-amber-500/15 text-amber-300",
  benign: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
};

export function VerdictBadge({ verdict }: { verdict: Verdict | null }) {
  if (!verdict) return <span className="text-xs text-slate-600">off</span>;
  return (
    <span className={`inline-block rounded-full border px-2 py-0.5 text-[11px] font-semibold uppercase ${STYLES[verdict]}`}>
      {verdict}
    </span>
  );
}

export function MlCell({ flow }: { flow: Flow }) {
  return (
    <div className="space-y-0.5"
      title={flow.ml_anomaly != null ? `anomaly ${flow.ml_anomaly.toFixed(2)}${flow.ml_attack_prob != null ? ` · classifier ${flow.ml_attack_prob.toFixed(2)}` : ""}` : ""}>
      <div className="flex items-center gap-2">
        <VerdictBadge verdict={flow.ml_verdict} />
        {flow.ml_score != null && <span className="font-mono text-[11px] text-slate-500">{flow.ml_score.toFixed(2)}</span>}
      </div>
      {flow.ml_attack_type && flow.ml_verdict !== "benign" && (
        <div className="text-[11px] text-slate-400">{flow.ml_attack_type}</div>
      )}
    </div>
  );
}

export function AiCell({ flow }: { flow: Flow }) {
  if (flow.ai_status === "pending") return <span className="text-xs text-sky-400 animate-pulse">reviewing…</span>;
  if (flow.ai_status === "skipped") {
    const off = flow.ai_reason === "AI engine is off" || flow.ai_reason === "no AI key configured";
    return <span className="text-xs text-slate-600" title={flow.ai_reason ?? ""}>{off ? "AI off" : "not sampled"}</span>;
  }
  if (flow.ai_status === "failed")
    return (
      <span className="text-xs text-slate-500" title={flow.ai_reason ?? ""}>
        unavailable
      </span>
    );
  return (
    <div className="space-y-0.5" title={flow.ai_reason ?? ""}>
      <div className="flex items-center gap-2">
        <VerdictBadge verdict={flow.ai_verdict} />
        {flow.ai_confidence != null && (
          <span className="font-mono text-[11px] text-slate-500">{Math.round(flow.ai_confidence * 100)}%</span>
        )}
      </div>
      {flow.ai_attack_type && <div className="text-[11px] text-slate-400">{flow.ai_attack_type}</div>}
    </div>
  );
}

export function AgreementBadge({ value }: { value: Flow["agreement"] }) {
  if (!value) return <span className="text-xs text-slate-600">—</span>;
  return value === "agree" ? (
    <span className="text-xs text-emerald-400">agree</span>
  ) : (
    <span className="text-xs font-semibold text-amber-300">disagree</span>
  );
}

export const portLabel = (f: Flow) => (f.dst_port != null ? String(f.dst_port) : "—");

export function timeLabel(f: Flow) {
  return new Date(f.received_at * 1000).toLocaleTimeString();
}
