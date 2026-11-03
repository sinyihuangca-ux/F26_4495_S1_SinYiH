import type { Metadata } from "next";
import "@/app/globals.css";
import { Sidebar } from "@/components/sidebar";

// Global metadata configuration for Next.js App Router
export const metadata: Metadata = {
  title: "AI Cybersecurity Threat Mitigation Platform",
  description: "Real-time NIDS with Machine Learning Anomaly Detection",
};

// Root layout component providing theme container and navigation shell
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="flex min-h-screen bg-[#0B0F19] text-white antialiased">
        {/* Persistent SOC Left Sidebar Navigation */}
        <Sidebar />

        {/* Main Application Canvas Container */}
        <div className="flex-1 flex flex-col overflow-y-auto">
          {/* Header Bar simplified to avoid SSR runtime authentication errors */}
          <header className="flex justify-between items-center p-4 border-b border-gray-800 bg-[#0B0F19]/50 backdrop-blur-md h-16">
            <div className="font-semibold text-sm text-gray-400">
              SOC Security Operations Center
            </div>
            
            {/* System Live Health Indicator Badge */}
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono px-3 py-1 bg-emerald-950/40 border border-emerald-800 text-emerald-400 rounded-full flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
                System Live (No Auth Lockout)
              </span>
            </div>
          </header>

          {/* Dynamic Page Component Viewport */}
          <main className="flex-1 p-6">{children}</main>
        </div>
      </body>
    </html>
  );
}