"use client";

import { useState } from "react";
import {
  LayoutDashboard,
  FileText,
  ShieldAlert,
  Box,
  RotateCcw,
  Settings,
  Shield,
} from "lucide-react";

const NAV_ITEMS = [
  { label: "Dashboard", icon: LayoutDashboard, href: "#", active: true },
  { label: "Logs", icon: FileText, href: "#", active: false },
  { label: "Threats", icon: ShieldAlert, href: "#", active: false },
  { label: "Containers", icon: Box, href: "#", active: false },
  { label: "Settings", icon: Settings, href: "#", active: false },
];

export function Sidebar() {
  const [activeTab, setActiveTab] = useState("Dashboard");

  return (
    <aside className="flex h-screen w-60 flex-col border-r border-slate-800 bg-slate-950/80 p-4 text-slate-300">
      {/* Brand Header */}
      <div className="mb-8 flex items-center gap-3 px-2">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-sky-500 to-blue-700 shadow-lg shadow-sky-950/50">
          <Shield className="h-6 w-6 text-white fill-white/20" />
        </div>
        <div>
          <span className="font-bold text-white tracking-wide">AI</span>
          <span className="text-xs text-sky-400 block font-medium">
            Fortress
          </span>
        </div>
      </div>

      {/* Nav Links */}
      <nav className="flex-1 space-y-1.5">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.label;

          return (
            <button
              key={item.label}
              onClick={() => setActiveTab(item.label)}
              className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-xs font-medium transition-all ${
                isActive
                  ? "bg-sky-600/20 text-sky-400 border border-sky-500/30 shadow-sm"
                  : "text-slate-400 hover:bg-slate-900 hover:text-slate-200"
              }`}
            >
              <Icon
                className={`h-4 w-4 ${isActive ? "text-sky-400" : "text-slate-400"}`}
              />
              {item.label}
            </button>
          );
        })}
      </nav>
    </aside>
  );
}
