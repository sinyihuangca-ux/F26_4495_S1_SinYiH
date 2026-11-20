import type { Metadata } from "next";
import { Suspense } from "react";
import { SignInButton, SignUpButton, UserButton, Show } from "@clerk/nextjs";
import { Sidebar } from "@/components/sidebar";
import { LiveProvider } from "@/lib/live";
import { NotifyProvider } from "@/lib/notify";
import { ConnectionBadge } from "@/components/connection-badge";
import NotificationBell from "./components/NotificationBell";

export const metadata: Metadata = {
  title: "AI Cyber Threat Mitigation Dashboard",
  description: "Real-time ML + AI anomaly detection",
};

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <NotifyProvider>
    <LiveProvider>
      <div className="flex min-h-screen bg-[#0B0F19] text-white">
        <Sidebar />
        <div className="flex flex-1 flex-col overflow-y-auto">
          <header className="flex h-16 items-center justify-between border-b border-slate-800 bg-[#0B0F19]/50 px-6 backdrop-blur-md">
            <ConnectionBadge />
            <div className="flex items-center gap-4">
              <NotificationBell />
              {/* Auth state is read per request, so it streams in behind Suspense. */}
              <Suspense fallback={<div className="h-9 w-9 rounded-full bg-slate-800" />}>
              <Show when="signed-out">
                <SignInButton mode="modal">
                  <button className="rounded-md border border-slate-700 bg-slate-800 px-4 py-2 text-sm hover:bg-slate-700">Sign in</button>
                </SignInButton>
                <SignUpButton mode="modal">
                  <button className="rounded-md bg-purple-600 px-4 py-2 text-sm hover:bg-purple-500">Sign up</button>
                </SignUpButton>
              </Show>
              <Show when="signed-in">
                <UserButton appearance={{ elements: { avatarBox: "w-9 h-9 border border-slate-700" } }} />
              </Show>
              </Suspense>
            </div>
          </header>
          <main className="flex-1 p-6">{children}</main>
        </div>
      </div>
    </LiveProvider>
    </NotifyProvider>
  );
}
