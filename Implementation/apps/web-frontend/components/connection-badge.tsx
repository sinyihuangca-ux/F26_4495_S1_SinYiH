"use client";

import { useLive } from "@/lib/live";

export function ConnectionBadge() {
  const { status, server } = useLive();
  const color = status === "connected" ? "bg-emerald-500 animate-pulse" : status === "connecting" ? "bg-amber-400" : "bg-red-500";
  const label = status === "connected" ? "Connected (live)" : status === "connecting" ? "Connecting…" : "Disconnected";
  return (
    <span className="flex items-center gap-2 rounded-full border border-slate-800 bg-slate-900 px-3 py-1 font-mono text-xs text-slate-300">
      <span className={`h-2 w-2 rounded-full ${color}`} />
      {label} · {server}
    </span>
  );
}
