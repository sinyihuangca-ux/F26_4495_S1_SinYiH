"use client";

import { useState } from "react";
import Link from "next/link";
import {
  Shield,
  ArrowRight,
  Activity,
  Cpu,
  Lock,
  Terminal,
  CheckCircle2,
  Bell,
  Check,
  Building,
  Users,
  Server,
  Star,
  ChevronRight,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Header } from "@/components/marketing/header";

export default function LandingPage() {
  const [activeUseCase, setActiveUseCase] = useState("soc");

  return (
    <div className="min-h-screen bg-[#0B0F19] text-slate-100 flex flex-col font-sans selection:bg-sky-500 selection:text-white">
      {/* 1. Sticky Header / Navigation Bar */}
      <Header />

      {/* 2. Hero Section */}
      <section className="relative overflow-hidden pt-20 pb-16 md:pt-28 md:pb-24 border-b border-slate-800/60">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[300px] bg-sky-600/10 blur-[120px] rounded-full pointer-events-none" />
        <div className="mx-auto max-w-7xl px-6 flex flex-col items-center text-center">
          <Badge
            variant="outline"
            className="mb-6 border-sky-500/30 bg-sky-500/10 text-sky-400 px-3 py-1 text-xs rounded-full backdrop-blur-md"
          >
            <Shield className="mr-1.5 h-3.5 w-3.5" />
            Trusted by 500+ Security Teams & SOC Analysts
          </Badge>

          <h1 className="max-w-4xl text-4xl font-extrabold tracking-tight text-white sm:text-6xl lg:text-7xl">
            Real-Time AI Log Analysis &{" "}
            <span className="bg-gradient-to-r from-sky-400 to-blue-500 bg-clip-text text-transparent">
              Automated Threat Mitigation
            </span>
          </h1>

          <p className="mt-6 max-w-2xl text-base text-slate-400 sm:text-lg leading-relaxed">
            Detect anomalies in milliseconds, map attacks against MITRE ATT&CK
            frameworks, and isolate compromised containers automatically before
            breaches happen.
          </p>

          <div className="mt-8 flex flex-col sm:flex-row items-center gap-4 w-full sm:w-auto">
            <Button
              asChild
              size="lg"
              className="w-full sm:w-auto bg-sky-600 hover:bg-sky-500 text-white font-medium px-8 shadow-lg shadow-sky-950/50"
            >
              <Link href="/register">
                Start Free Trial
                <ArrowRight className="ml-2 h-4 w-4" />
              </Link>
            </Button>
          </div>

          {/* Interactive Mock UI Preview */}
          <div className="mt-14 w-full max-w-5xl rounded-2xl border border-slate-800 bg-slate-950/70 p-3 backdrop-blur-xl shadow-2xl shadow-sky-950/20">
            <div className="flex items-center justify-between border-b border-slate-800/80 px-4 py-2.5">
              <div className="flex items-center gap-2">
                <span className="h-3 w-3 rounded-full bg-red-500/80" />
                <span className="h-3 w-3 rounded-full bg-amber-500/80" />
                <span className="h-3 w-3 rounded-full bg-emerald-500/80" />
                <span className="ml-2 text-xs font-mono text-slate-500">
                  ai-shield-telemetry // live-feed
                </span>
              </div>
              <div className="flex items-center gap-2 text-[10px] font-mono text-emerald-400">
                <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                SYSTEM PROTECTED
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 p-3">
              <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-4 text-left font-mono">
                <p className="text-[10px] text-slate-400">LOG PARSER RATE</p>
                <p className="text-xl font-bold text-white mt-1">
                  1,284,532 /s
                </p>
                <div className="mt-2 text-[10px] text-emerald-400 flex items-center">
                  +12.5% vs baseline
                </div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-4 text-left font-mono">
                <p className="text-[10px] text-slate-400">ACTIVE ANOMALIES</p>
                <p className="text-xl font-bold text-red-500 mt-1">
                  1 CRITICAL
                </p>
                <div className="mt-2 text-[10px] text-red-400">
                  MITRE T1486 Detected
                </div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-4 text-left font-mono">
                <p className="text-[10px] text-slate-400">MITIGATION STATUS</p>
                <p className="text-xl font-bold text-sky-400 mt-1">
                  AUTO ISOLATED
                </p>
                <div className="mt-2 text-[10px] text-slate-400">
                  Container web-app-1
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 3. Core Features Section */}
      <section
        id="features"
        className="py-20 border-b border-slate-800/60 bg-slate-950/40"
      >
        <div className="mx-auto max-w-7xl px-6">
          <div className="text-center max-w-3xl mx-auto">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-sky-400">
              Capabilities
            </h2>
            <p className="mt-2 text-3xl font-bold text-white sm:text-4xl">
              Engineered for Automated Defense
            </p>
            <p className="mt-4 text-sm text-slate-400">
              Full-stack security telemetry powered by custom real-time neural
              log processors.
            </p>
          </div>

          <div className="mt-16 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
            {[
              {
                icon: Cpu,
                title: "AI Anomaly Detection",
                desc: "Real-time log parsing trained on your server baseline behavior to catch zero-day exploits.",
              },
              {
                icon: Terminal,
                title: "MITRE ATT&CK Mapping",
                desc: "Automated tagging of attack vectors like T1486 Data Encryption or T1110 Brute Force.",
              },
              {
                icon: Lock,
                title: "1-Click Container Isolation",
                desc: "Trigger snapshot recovery and isolate compromised pods instantly through automated webhooks.",
              },
              {
                icon: Activity,
                title: "Live Telemetry & Metrics",
                desc: "Sub-second stream graphs comparing normal vs. anomaly traffic volumes across clusters.",
              },
              {
                icon: Bell,
                title: "Automated SOC Workflows",
                desc: "Custom webhooks, PagerDuty escalations, and rich Slack/Teams context cards.",
              },
              {
                icon: CheckCircle2,
                title: "Compliance Ready",
                desc: "Immutable log archiving structured for SOC2 Type II, HIPAA, and GDPR audit standards.",
              },
            ].map((feature, idx) => (
              <div
                key={idx}
                className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 transition-all hover:border-sky-500/40 hover:bg-slate-900/80"
              >
                <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-sky-500/20 bg-sky-500/10 text-sky-400">
                  <feature.icon className="h-5 w-5" />
                </div>
                <h3 className="mt-4 font-semibold text-white">
                  {feature.title}
                </h3>
                <p className="mt-2 text-xs text-slate-400 leading-relaxed">
                  {feature.desc}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* 4. Key Benefits Section */}
      <section id="benefits" className="py-20 border-b border-slate-800/60">
        <div className="mx-auto max-w-7xl px-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
            <div>
              <h2 className="text-xs font-semibold uppercase tracking-wider text-sky-400">
                Why AI {process.env.NEXT_PUBLIC_APP_NAME}
              </h2>
              <p className="mt-2 text-3xl font-bold text-white sm:text-4xl">
                Replace Alert Fatigue with Immediate Action
              </p>
              <p className="mt-4 text-sm text-slate-400 leading-relaxed">
                Legacy SIEM systems flood your security analysts with tens of
                thousands of unprioritized alerts daily. AI{" "}
                {process.env.NEXT_PUBLIC_APP_NAME} filters noise at ingestion
                level.
              </p>

              <div className="mt-8 space-y-6">
                {[
                  {
                    title: "99.9% Noise Reduction",
                    desc: "Filter out false positives with context-aware baseline AI models.",
                  },
                  {
                    title: "Sub-Second Response Times",
                    desc: "Execute containment actions automatically without human intervention delays.",
                  },
                  {
                    title: "Zero-Setup Telemetry",
                    desc: "Plug directly into Kubernetes, AWS CloudWatch, and Docker in under 5 minutes.",
                  },
                ].map((benefit, idx) => (
                  <div key={idx} className="flex gap-4">
                    <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-emerald-500/20 text-emerald-400">
                      <Check className="h-3.5 w-3.5" />
                    </div>
                    <div>
                      <h4 className="font-semibold text-white text-sm">
                        {benefit.title}
                      </h4>
                      <p className="text-xs text-slate-400 mt-0.5">
                        {benefit.desc}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 backdrop-blur-md">
              <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800">
                <span className="text-xs font-mono text-slate-400">
                  THREAT MITIGATION LATENCY
                </span>
                <Badge
                  variant="outline"
                  className="border-emerald-500/40 bg-emerald-500/10 text-emerald-400 text-[10px]"
                >
                  BENCHMARK
                </Badge>
              </div>

              <div className="space-y-4 font-mono text-xs">
                <div>
                  <div className="flex justify-between text-slate-400 mb-1">
                    <span>Traditional SIEM + Manual Review</span>
                    <span>42 mins</span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-slate-800">
                    <div className="h-2 rounded-full bg-red-500 w-full" />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-slate-400 mb-1">
                    <span>Standard Automation Rules</span>
                    <span>8 mins</span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-slate-800">
                    <div className="h-2 rounded-full bg-amber-500 w-1/4" />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-emerald-400 font-bold mb-1">
                    <span>
                      AI {process.env.NEXT_PUBLIC_APP_NAME} Automated Engine
                    </span>
                    <span>0.4 seconds</span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-slate-800">
                    <div className="h-2 rounded-full bg-sky-400 w-[2%]" />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* 5. Use Cases Section */}
      <section
        id="use-cases"
        className="py-20 border-b border-slate-800/60 bg-slate-950/40"
      >
        <div className="mx-auto max-w-7xl px-6">
          <div className="text-center max-w-3xl mx-auto">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-sky-400">
              Tailored Defense
            </h2>
            <p className="mt-2 text-3xl font-bold text-white sm:text-4xl">
              Built for Modern Technical Teams
            </p>
          </div>

          <div className="mt-10 flex justify-center gap-2">
            {[
              { id: "soc", label: "SOC Analysts", icon: Users },
              { id: "devsecops", label: "DevSecOps Teams", icon: Server },
              { id: "enterprise", label: "Enterprise Infra", icon: Building },
            ].map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveUseCase(tab.id)}
                  className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium transition-all ${
                    activeUseCase === tab.id
                      ? "bg-sky-600 text-white shadow-md shadow-sky-950"
                      : "bg-slate-900 border border-slate-800 text-slate-400 hover:text-white"
                  }`}
                >
                  <Icon className="h-4 w-4" />
                  {tab.label}
                </button>
              );
            })}
          </div>

          <div className="mt-8 max-w-4xl mx-auto rounded-xl border border-slate-800 bg-slate-900/60 p-8 backdrop-blur-md">
            {activeUseCase === "soc" && (
              <div>
                <h3 className="text-lg font-bold text-white">
                  Streamline Alert Triage for Security Operations
                </h3>
                <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                  Automatically consolidate millions of raw log entries into
                  structured threat context cards mapped to MITRE frameworks.
                  Allow analysts to pivot from detection to response in one
                  click.
                </p>
              </div>
            )}
            {activeUseCase === "devsecops" && (
              <div>
                <h3 className="text-lg font-bold text-white">
                  Automate Kubernetes & CI/CD Pipeline Security
                </h3>
                <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                  Embed runtime anomaly detection directly into your deployment
                  environments. Automatically quarantine anomalous pods or
                  trigger snapshot rollbacks when threats are detected.
                </p>
              </div>
            )}
            {activeUseCase === "enterprise" && (
              <div>
                <h3 className="text-lg font-bold text-white">
                  Protect Hybrid Cloud Infrastructures
                </h3>
                <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                  Unified visibility across AWS, Azure, GCP, and on-premise
                  infrastructure with zero performance overhead on production
                  servers.
                </p>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* 6. Testimonials Section */}
      <section id="testimonials" className="py-20 border-b border-slate-800/60">
        <div className="mx-auto max-w-7xl px-6">
          <div className="text-center max-w-3xl mx-auto">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-sky-400">
              Testimonials
            </h2>
            <p className="mt-2 text-3xl font-bold text-white sm:text-4xl">
              Validated by Industry Leaders
            </p>
          </div>

          <div className="mt-16 grid grid-cols-1 md:grid-cols-3 gap-6">
            {[
              {
                quote:
                  "The 1-click container isolation feature stopped an active ransomware encryption vector in our staging cluster before it could move laterally.",
                author: "Sarah Jenkins",
                role: "Chief Information Security Officer",
              },
              {
                quote:
                  "We reduced our incident response time from 40 minutes down to sub-seconds. AI {process.env.NEXT_PUBLIC_APP_NAME} handles our baseline parsing without false alarm noise.",
                author: "David Chen",
                role: "Lead DevOps Engineer",
              },
              {
                quote:
                  "The automated MITRE ATT&CK tagging gives our junior analysts instant context on complex multi-stage attack vectors.",
                author: "Marcus Vance",
                role: "Security Operations Manager",
              },
            ].map((t, idx) => (
              <div
                key={idx}
                className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 flex flex-col justify-between"
              >
                <div>
                  <div className="flex gap-1 text-amber-400 mb-4">
                    {[...Array(5)].map((_, i) => (
                      <Star key={i} className="h-4 w-4 fill-amber-400" />
                    ))}
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed italic">
                    &quot;{t.quote}&quot;
                  </p>
                </div>
                <div className="mt-6 pt-4 border-t border-slate-800/80">
                  <p className="text-xs font-semibold text-white">{t.author}</p>
                  <p className="text-[10px] text-slate-400">{t.role}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* 7. CTA Banner & Footer Section */}
      <section className="py-20 bg-gradient-to-b from-[#0B0F19] to-slate-950">
        <div className="mx-auto max-w-5xl px-6">
          <div className="rounded-2xl border border-slate-800 bg-slate-900/80 p-8 md:p-12 text-center relative overflow-hidden backdrop-blur-xl">
            <div className="absolute top-0 right-0 w-64 h-64 bg-sky-500/10 blur-[80px] rounded-full pointer-events-none" />
            <h2 className="text-2xl font-bold text-white sm:text-3xl">
              Ready to Secure Your Cloud Infrastructure?
            </h2>
            <p className="mt-3 text-xs text-slate-400 max-w-xl mx-auto">
              Deploy AI {process.env.NEXT_PUBLIC_APP_NAME} telemetry agents in
              under 5 minutes and get instant real-time log analysis.
            </p>

            <form
              onSubmit={(e) => e.preventDefault()}
              className="mt-8 flex flex-col sm:flex-row gap-3 max-w-md mx-auto"
            >
              <Input
                type="email"
                placeholder="Enter your work email"
                className="h-10 border-slate-700 bg-slate-950/80 text-xs text-slate-200 placeholder:text-slate-500 focus-visible:ring-sky-500"
              />
              <Button
                type="submit"
                className="h-10 bg-sky-600 hover:bg-sky-500 text-xs text-white px-6 font-medium"
              >
                Get Started
                <ChevronRight className="ml-1 h-4 w-4" />
              </Button>
            </form>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950 px-6 py-12 text-xs text-slate-400">
        <div className="mx-auto max-w-7xl grid grid-cols-2 md:grid-cols-5 gap-8">
          <div className="col-span-2">
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-sky-400" />
              <span className="font-bold text-white">
                AI {process.env.NEXT_PUBLIC_APP_NAME}
              </span>
            </div>
            <p className="mt-3 text-[11px] text-slate-500 leading-relaxed max-w-xs">
              Automated AI log telemetry & container mitigation platform for
              enterprise SOC teams.
            </p>
          </div>

          <div>
            <h4 className="font-semibold text-white mb-3">Product</h4>
            <ul className="space-y-2 text-[11px]">
              <li>
                <a href="#features" className="hover:text-slate-200">
                  Features
                </a>
              </li>
              <li>
                <a href="#benefits" className="hover:text-slate-200">
                  Telemetry
                </a>
              </li>
              <li>
                <a href="#pricing" className="hover:text-slate-200">
                  Pricing
                </a>
              </li>
            </ul>
          </div>

          <div>
            <h4 className="font-semibold text-white mb-3">Resources</h4>
            <ul className="space-y-2 text-[11px]">
              <li>
                <a href="#" className="hover:text-slate-200">
                  Documentation
                </a>
              </li>
              <li>
                <a href="#" className="hover:text-slate-200">
                  API Reference
                </a>
              </li>
              <li>
                <a href="#" className="hover:text-slate-200">
                  MITRE Library
                </a>
              </li>
            </ul>
          </div>

          <div>
            <h4 className="font-semibold text-white mb-3">Company</h4>
            <ul className="space-y-2 text-[11px]">
              <li>
                <a href="#" className="hover:text-slate-200">
                  About Us
                </a>
              </li>
              <li>
                <a href="#" className="hover:text-slate-200">
                  Privacy Policy
                </a>
              </li>
              <li>
                <a href="#" className="hover:text-slate-200">
                  Contact
                </a>
              </li>
            </ul>
          </div>
        </div>

        <div className="mx-auto max-w-7xl mt-12 pt-6 border-t border-slate-800/60 flex flex-col sm:flex-row justify-between items-center text-[10px] text-slate-500">
          <p>
            © 2026 AI {process.env.NEXT_PUBLIC_APP_NAME} Inc. All rights
            reserved.
          </p>
        </div>
      </footer>
    </div>
  );
}
