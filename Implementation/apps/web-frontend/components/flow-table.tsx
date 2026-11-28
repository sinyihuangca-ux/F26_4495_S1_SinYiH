"use client";

import { useState } from "react";
import { useAuth } from "@clerk/nextjs";
import { Check, ShieldOff, Undo2 } from "lucide-react";
import { api, Flow } from "@/lib/api";
import { useLive } from "@/lib/live";
import { AgreementBadge, AiCell, MlCell, VerdictBadge, portLabel, timeLabel } from "./verdict";

// ML and AI verdicts side by side, the combined verdict, and analyst feedback controls.
export function FlowTable({ flows, showTruth = true, compact = false }: {
  flows: Flow[];
  showTruth?: boolean;
  compact?: boolean;
}) {
  const { getToken } = useAuth();
  const { upsert } = useLive();
  const [busy, setBusy] = useState<number | null>(null);
  const [error, setError] = useState("");

  const sendFeedback = async (flow: Flow, feedback: Flow["feedback"], allowlist = false) => {
    setBusy(flow.id);
    setError("");
    try {
      const updated = await api<Flow>(
        `/api/flows/${flow.id}/feedback`,
        { method: "POST", body: JSON.stringify({ feedback, allowlist }) },
        await getToken(),
      );
      upsert(updated);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  if (flows.length === 0) {
    return (
      <p className="py-12 text-center text-sm text-slate-500">
        Nothing yet. Run the attack simulator to stream traffic.
      </p>
    );
  }

  return (
    <div className="overflow-x-auto">
      {error && <p className="mb-2 text-xs text-red-400">{error}</p>}
      <table className="w-full text-left text-xs">
        <thead className="text-[11px] uppercase text-slate-500">
          <tr className="border-b border-slate-800">
            <th className="p-2">Time</th>
            <th className="p-2">Source → Port</th>
            <th className="p-2">ML</th>
            <th className="p-2">AI</th>
            <th className="p-2">Engines</th>
            <th className="p-2">Final</th>
            {showTruth && <th className="p-2">Dataset label</th>}
            {!compact && <th className="p-2 text-right">Analyst</th>}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60">
          {flows.map((f) => (
            <tr key={f.id} className={f.final_verdict === "malicious" ? "bg-red-950/15" : ""}>
              <td className="p-2 font-mono text-slate-400 whitespace-nowrap">{timeLabel(f)}</td>
              <td className="p-2 font-mono text-slate-300 whitespace-nowrap">
                {f.src_ip ?? "?"} → {portLabel(f)}
              </td>
              <td className="p-2"><MlCell flow={f} /></td>
              <td className="p-2"><AiCell flow={f} /></td>
              <td className="p-2"><AgreementBadge value={f.agreement} /></td>
              <td className="p-2"><VerdictBadge verdict={f.final_verdict} /></td>
              {showTruth && (
                <td className={`p-2 text-[11px] ${f.ground_truth === "BENIGN" ? "text-slate-500" : "text-slate-300"}`}>
                  {f.ground_truth ?? "—"}
                </td>
              )}
              {!compact && (
                <td className="p-2 text-right whitespace-nowrap">
                  {f.feedback ? (
                    <span className="inline-flex items-center gap-2">
                      <span className={f.feedback === "confirmed" ? "text-red-400" : "text-emerald-400"}>
                        {f.feedback === "confirmed" ? "confirmed" : "false positive"}
                      </span>
                      <button
                        disabled={busy === f.id}
                        onClick={() => sendFeedback(f, null)}
                        className="text-slate-500 hover:text-slate-300"
                        title="Undo"
                      >
                        <Undo2 size={13} />
                      </button>
                    </span>
                  ) : (
                    <span className="inline-flex gap-1">
                      <button
                        disabled={busy === f.id}
                        onClick={() => sendFeedback(f, "confirmed")}
                        className="rounded border border-red-800/60 px-1.5 py-0.5 text-red-400 hover:bg-red-950/40"
                        title="Confirm this is a real threat"
                      >
                        <Check size={12} className="inline" /> Threat
                      </button>
                      <button
                        disabled={busy === f.id}
                        onClick={() => sendFeedback(f, "false_positive")}
                        className="rounded border border-emerald-800/60 px-1.5 py-0.5 text-emerald-400 hover:bg-emerald-950/40"
                        title="Mark as a false positive (used as benign data next time you retrain)"
                      >
                        False +
                      </button>
                      <button
                        disabled={busy === f.id}
                        onClick={() => sendFeedback(f, "false_positive", true)}
                        className="rounded border border-slate-700 px-1.5 py-0.5 text-slate-400 hover:bg-slate-800"
                        title="False positive, and stop alerting on this source IP + port"
                      >
                        <ShieldOff size={12} className="inline" /> Allow
                      </button>
                    </span>
                  )}
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
