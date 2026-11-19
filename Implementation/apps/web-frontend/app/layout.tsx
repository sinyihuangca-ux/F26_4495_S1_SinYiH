import type { Metadata } from "next";
import { ClerkProvider } from "@clerk/nextjs";
import "./globals.css";

export const metadata: Metadata = {
  title: "AI Cyber Threat Mitigation Platform",
  description: "Real-time ML + AI threat detection for network traffic",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <ClerkProvider>
      <html lang="en" className="dark">
        <body className="min-h-screen bg-[#0B0F19] text-slate-100 antialiased">{children}</body>
      </html>
    </ClerkProvider>
  );
}
