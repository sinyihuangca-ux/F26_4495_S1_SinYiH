"use client";

import { useState } from "react";
import Link from "next/link";
import { Bell, ShieldAlert, X } from "lucide-react";
import { useLive } from "@/lib/live";
import { VerdictBadge, timeLabel } from "@/components/verdict";

export default function NotificationBell() {
  const { alerts, unread, markRead, status } = useLive();
  const [open, setOpen] = useState(false);
  const recent = alerts.filter((a) => a.final_verdict !== "benign").slice(0, 20);

  const toggle = () => {
    setOpen((o) => !o);
    markRead();
  };

  return (
    <div className="relative">
      <button onClick={toggle} aria-label="Notifications"
        className="relative rounded-full p-2 text-slate-400 transition hover:bg-slate-800 hover:text-white">
        <Bell className="h-6 w-6" />
        {unread > 0 && (
          <span className="absolute right-1 top-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500 px-1 text-[10px] font-bold text-white">
            {unread > 99 ? "99+" : unread}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 z-50 mt-2 w-80 overflow-hidden rounded-xl border border-slate-800 bg-slate-900 shadow-2xl sm:w-96">
          <div className="flex items-center justify-between border-b border-slate-800 bg-slate-950 px-4 py-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-red-500" />
              <span className="text-sm font-semibold text-white">Threat alerts</span>
            </div>
            <div className="flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${status === "connected" ? "bg-emerald-500" : "bg-red-500"}`} />
              <button onClick={() => setOpen(false)} className="text-slate-400 hover:text-white"><X className="h-4 w-4" /></button>
            </div>
          </div>
          <div className="max-h-80 divide-y divide-slate-800/50 overflow-y-auto">
            {recent.length === 0 ? (
              <div className="py-8 text-center text-sm text-slate-500">No threats detected.</div>
            ) : (
              recent.map((a) => (
                <div key={a.id} className="p-3 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-slate-200">{a.ai_attack_type ?? "Anomalous traffic"}</span>
                    <span className="text-[10px] text-slate-500">{timeLabel(a)}</span>
                  </div>
                  <div className="mt-1 flex items-center gap-2 text-slate-400">
                    <VerdictBadge verdict={a.final_verdict} />
                    <span className="font-mono">{a.src_ip ?? "?"} → {a.dst_port}</span>
                  </div>
                </div>
              ))
            )}
          </div>
          <Link href="/logs" onClick={() => setOpen(false)}
            className="block border-t border-slate-800 py-2 text-center text-xs text-sky-400 hover:bg-slate-800">
            Open audit log
          </Link>
        </div>
      )}
    </div>
  );
}
