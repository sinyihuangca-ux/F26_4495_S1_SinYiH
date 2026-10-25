"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  FileText,
  ShieldAlert,
  Box,
  Settings,
  Shield,
} from "lucide-react";

const NAV_ITEMS = [
  { label: "Dashboard", icon: LayoutDashboard, href: "/dashboard" },
  { label: "Logs", icon: FileText, href: "/logs" },
  { label: "Threats", icon: ShieldAlert, href: "/threats" },
  { label: "Containers", icon: Box, href: "/containers" },
  { label: "Settings", icon: Settings, href: "/settings" },
];

export function Sidebar() {
  const pathname = usePathname();

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
            {process.env.NEXT_PUBLIC_APP_NAME}
          </span>
        </div>
      </div>

      {/* Nav Links */}
      <nav className="flex-1 space-y-1.5">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive = pathname === item.href;

          return (
            <Link
              key={item.label}
              href={item.href}
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
            </Link>
          );
        })}
      </nav>
    </aside>
  );
}
