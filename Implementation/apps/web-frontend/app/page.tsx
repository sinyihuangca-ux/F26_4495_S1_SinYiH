"use client";

import { useEffect, useState } from "react";
import {
  Bot,
  Key,
  ShieldAlert,
  Sparkles,
  Server,
  FileText,
  Download,
  Trash2,
  Search,
  Shield,
  Settings,
  Cpu,
  X,
} from "lucide-react";

interface LogEntry {
  id: string;
  timestamp: string;
  label: string;
  destination_port: number;
  score: number;
  model?: string;
}

interface RankedAttack {
  attack_type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  count: number;
  advice: string;
}

export default function UnifiedCommandCenter() {
  const [connectionStatus, setConnectionStatus] = useState("Disconnected");
  const [serverIp, setServerIp] = useState<string>("localhost:8000");

  // Unified Settings drawer state (contains Configure AI Keys & Server IP)
  const [showSettings, setShowSettings] = useState(false);

  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [rawThreatCounts, setRawThreatCounts] = useState<Record<string, number>>({});
  const [search, setSearch] = useState("");

  const [geminiKey, setGeminiKey] = useState("");
  const [groqKey, setGroqKey] = useState("");
  const [openaiKey, setOpenaiKey] = useState("");

  const [rankedAttacks, setRankedAttacks] = useState<RankedAttack[]>([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  // Safe Host Resolver Helper to guarantee valid URLs
  const getCleanHost = () => {
    const raw = serverIp || localStorage.getItem("SECURITY_BACKEND_IP") || "localhost:8000";
    const cleaned = raw.replace(/^https?:\/\//, "").replace(/^ws:\/\//, "").trim();
    return cleaned !== "" ? cleaned : "localhost:8000";
  };

  useEffect(() => {
    const savedIp = localStorage.getItem("SECURITY_BACKEND_IP") || "localhost:8000";
    setServerIp(savedIp);

    setGeminiKey(localStorage.getItem("GEMINI_API_KEY") || "");
    setGroqKey(localStorage.getItem("GROQ_API_KEY") || "");
    setOpenaiKey(localStorage.getItem("OPENAI_API_KEY") || "");

    const savedLogs: LogEntry[] = JSON.parse(localStorage.getItem("SECURITY_LOG_HISTORY") || "[]");
    setLogs(savedLogs);

    const counts: Record<string, number> = {};
    savedLogs.forEach((log: LogEntry) => {
      counts[log.label] = (counts[log.label] || 0) + 1;
    });
    setRawThreatCounts(counts);
  }, []);

  // Robust Auto-Reconnecting WebSocket Effect
  useEffect(() => {
    let ws: WebSocket | null = null;
    let reconnectTimer: NodeJS.Timeout;
    let isMounted = true;

    const connectWebSocket = () => {
      if (!isMounted) return;

      const hostToUse = getCleanHost();
      const wsUrl = `ws://${hostToUse}/ws/alerts`;

      setConnectionStatus("Connecting...");
      ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        if (isMounted) setConnectionStatus(`Connected (${hostToUse})`);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === "ATTACK_DETECTED") {
            const type = data.label || "Unknown Threat";
            const newLog: LogEntry = {
              id: Math.random().toString(36).substring(2, 9),
              timestamp: data.timestamp || new Date().toLocaleTimeString(),
              label: type,
              destination_port: data.destination_port ?? 80,
              score: data.score ?? 0,
              model: data.model || "ML Anomaly Model",
            };

            setRawThreatCounts((prev) => ({ ...prev, [type]: (prev[type] || 0) + 1 }));
            setLogs((prev) => {
              const updated = [newLog, ...prev];
              localStorage.setItem("SECURITY_LOG_HISTORY", JSON.stringify(updated));
              return updated;
            });
          }
        } catch (err) {
          console.error("Failed to parse incoming WebSocket message:", err);
        }
      };

      ws.onerror = () => {
        // Suppress noisy repeating console logs if connection is down
      };

      ws.onclose = () => {
        if (isMounted) {
          setConnectionStatus("Disconnected (Reconnecting...)");
          reconnectTimer = setTimeout(connectWebSocket, 3000);
        }
      };
    };

    connectWebSocket();

    return () => {
      isMounted = false;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (ws) ws.close();
    };
  }, [serverIp]);

  const saveConfig = () => {
    localStorage.setItem("SECURITY_BACKEND_IP", serverIp.trim() || "localhost:8000");
    localStorage.setItem("GEMINI_API_KEY", geminiKey.trim());
    localStorage.setItem("GROQ_API_KEY", groqKey.trim());
    localStorage.setItem("OPENAI_API_KEY", openaiKey.trim());
    setShowSettings(false);
  };

  const runAiAdvisorAnalysis = async () => {
    const keys = [
      { provider: "groq", key: groqKey },
      { provider: "gemini", key: geminiKey },
      { provider: "openai", key: openaiKey },
    ].filter((k) => k.key.trim() !== "");

    if (keys.length === 0) {
      setShowSettings(true);
      return;
    }

    setIsAnalyzing(true);
    try {
      const hostToUse = getCleanHost();
      const res = await fetch(`http://${hostToUse}/api/analyze-threats`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          threat_counts: rawThreatCounts,
          keys: keys,
        }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to analyze threats");

      const cleanedJson = data.result.replace(/```json|```/g, "").trim();
      const parsed: RankedAttack[] = JSON.parse(cleanedJson);
      setRankedAttacks(parsed);
    } catch (err: any) {
      console.error("AI Analysis failed:", err);
      alert(`Failover Simulation Error: ${err.message}`);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const clearLogs = () => {
    if (confirm("Are you sure you want to clear all audit logs?")) {
      setLogs([]);
      setRawThreatCounts({});
      setRankedAttacks([]);
      localStorage.removeItem("SECURITY_LOG_HISTORY");
    }
  };

  const exportToCSV = () => {
    if (logs.length === 0) return;
    const headers = ["Timestamp", "Attack Type", "Destination Port", "Anomaly Score"];
    const rows = logs.map((log) => [
      `"${log.timestamp}"`,
      `"${log.label}"`,
      log.destination_port,
      log.score.toFixed(4),
    ]);
    const csvContent =
      "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map((e) => e.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `security_audit_logs_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const filteredLogs = logs.filter(
    (log) => log.label.toLowerCase().includes(search.toLowerCase()) || log.destination_port.toString().includes(search)
  );

  const totalThreats = Object.values(rawThreatCounts).reduce((a, b) => a + b, 0);
  const activeKeysCount = [geminiKey, groqKey, openaiKey].filter((k) => k.trim() !== "").length;

  return (
    <div className="p-8 space-y-8 bg-slate-950 min-h-screen text-slate-100">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between border-b border-slate-800 pb-4 gap-4">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight flex items-center gap-2">
            <Shield className="text-sky-400" /> AI Fortress Security Command Center
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Unified real-time threat detection, multi-model AI failover, and audit logs
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Unified Settings Button (Contains Configure AI Keys & Backend IP) */}
          <button
            onClick={() => setShowSettings(!showSettings)}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs transition border ${
              activeKeysCount > 0
                ? "bg-slate-800 hover:bg-slate-700 border-emerald-800/70 text-emerald-300"
                : "bg-slate-800 hover:bg-slate-700 border-slate-700 text-slate-200"
            }`}
          >
            <Settings size={14} className="text-sky-400" /> Settings
            {activeKeysCount > 0 && (
              <span className="text-[11px] font-mono text-emerald-400">
                ({activeKeysCount} AI Key{activeKeysCount > 1 ? "s" : ""})
              </span>
            )}
          </button>

          <button
            onClick={runAiAdvisorAnalysis}
            disabled={isAnalyzing || totalThreats === 0}
            className="flex items-center gap-2 bg-purple-600 hover:bg-purple-500 disabled:bg-slate-800 px-4 py-1.5 rounded-lg text-xs font-medium transition"
          >
            <Sparkles size={14} /> {isAnalyzing ? "Failover Analyzing..." : "Run Multi-Model Advisor"}
          </button>

          <span className="text-xs font-mono px-3 py-1 bg-slate-900 border border-slate-800 rounded-full flex items-center gap-2">
            <span
              className={`h-2 w-2 rounded-full ${
                connectionStatus.includes("Connected") ? "bg-emerald-500 animate-pulse" : "bg-red-500"
              }`}
            />
            {connectionStatus}
          </span>
        </div>
      </div>

      {/* Settings Panel: Configure AI Keys & FastAPI Backend Host */}
      {showSettings && (
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-5 shadow-xl">
          <div className="flex justify-between items-center border-b border-slate-800 pb-3">
            <div>
              <h3 className="font-bold text-sm text-white flex items-center gap-2">
                <Settings size={16} className="text-sky-400" /> Platform Settings — Configure AI Keys & Backend Host
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Cycles automatically through Groq (Free Tier), Gemini, and OpenAI.
              </p>
            </div>
            <button
              onClick={() => setShowSettings(false)}
              className="text-slate-400 hover:text-white"
              aria-label="Close Settings"
            >
              <X size={16} />
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="text-xs text-slate-400 flex items-center gap-1.5 mb-1">
                <Server size={13} className="text-sky-400" /> FastAPI Host
              </label>
              <input
                type="text"
                value={serverIp}
                onChange={(e) => setServerIp(e.target.value)}
                placeholder="localhost:8000"
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500 font-mono"
              />
            </div>

            <div>
              <label className="text-xs text-slate-400 flex items-center gap-1.5 mb-1">
                <Key size={13} className="text-purple-400" /> Groq API Key (Free Tier)
              </label>
              <input
                type="password"
                placeholder="gsk_..."
                value={groqKey}
                onChange={(e) => setGroqKey(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-purple-500 font-mono"
              />
            </div>

            <div>
              <label className="text-xs text-slate-400 flex items-center gap-1.5 mb-1">
                <Key size={13} className="text-purple-400" /> Gemini API Key
              </label>
              <input
                type="password"
                placeholder="AIza..."
                value={geminiKey}
                onChange={(e) => setGeminiKey(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-purple-500 font-mono"
              />
            </div>

            <div>
              <label className="text-xs text-slate-400 flex items-center gap-1.5 mb-1">
                <Key size={13} className="text-purple-400" /> OpenAI / Codex API Key
              </label>
              <input
                type="password"
                placeholder="sk-..."
                value={openaiKey}
                onChange={(e) => setOpenaiKey(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-purple-500 font-mono"
              />
            </div>
          </div>

          <div className="flex justify-end gap-3">
            <button
              onClick={() => setShowSettings(false)}
              className="bg-slate-800 hover:bg-slate-700 px-4 py-2 rounded-lg text-xs font-medium text-slate-300 transition"
            >
              Cancel
            </button>
            <button
              onClick={saveConfig}
              className="bg-purple-600 hover:bg-purple-500 px-5 py-2 rounded-lg text-xs font-medium text-white transition"
            >
              Save Settings
            </button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Severity-Ranked Threat Briefing split into ML Detected Results & AI Detection Results */}
        <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800 rounded-xl p-6 shadow-xl backdrop-blur-sm space-y-6">
          <div className="flex justify-between items-center border-b border-slate-800/80 pb-4">
            <div>
              <h2 className="text-lg font-bold flex items-center gap-2">
                <Bot className="text-purple-400" /> Severity-Ranked Threat Briefing
              </h2>
              <p className="text-xs text-slate-400">
                Separated view of actual ML detections and AI detection / failover recommendations
              </p>
            </div>
            <span className="text-xs font-mono bg-purple-950/60 border border-purple-800 text-purple-300 px-3 py-1 rounded-md">
              {totalThreats} Total Events Processed
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            {/* Left: ML Detected Results (Actual ML Model Detections) */}
            <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 space-y-3.5">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
                <h3 className="text-sm font-bold text-emerald-300 flex items-center gap-2">
                  <Cpu size={15} className="text-emerald-400" /> ML Detected Results
                </h3>
                <span className="text-[11px] font-mono text-slate-400">{logs.length} detected</span>
              </div>

              {logs.length === 0 ? (
                <div className="text-center py-14 border border-dashed border-slate-800 rounded-lg px-3">
                  <ShieldAlert size={34} className="mx-auto mb-2.5 text-slate-600" />
                  <p className="text-xs text-slate-400 font-medium">No ML anomalies detected yet.</p>
                  <p className="text-[11px] text-slate-500 mt-1">
                    Stream traffic from simulator to view actual ML detections.
                  </p>
                </div>
              ) : (
                <div className="space-y-2.5 max-h-[360px] overflow-y-auto pr-1">
                  {logs.slice(0, 20).map((item) => (
                    <div
                      key={item.id}
                      className="p-3 bg-slate-900 border border-slate-800 rounded-lg space-y-1.5"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-bold text-red-400 flex items-center gap-1.5">
                          <ShieldAlert size={13} /> {item.label}
                        </span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/70 text-emerald-300 border border-emerald-800/60">
                          {item.model || "ML Model"}
                        </span>
                      </div>
                      <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] font-mono text-slate-400">
                        <span>Port: {item.destination_port}</span>
                        <span>Score: {item.score.toFixed(4)}</span>
                        <span>{item.timestamp}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Right: AI Detection Results (AI Detection / Severity Ranking & Advice) */}
            <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-4 space-y-3.5">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
                <h3 className="text-sm font-bold text-purple-300 flex items-center gap-2">
                  <Sparkles size={15} className="text-purple-400" /> AI Detection Results
                </h3>
                <span className="text-[11px] font-mono text-slate-400">{rankedAttacks.length} ranked</span>
              </div>

              {rankedAttacks.length === 0 ? (
                <div className="text-center py-14 border border-dashed border-slate-800 rounded-lg px-3">
                  <Bot size={34} className="mx-auto mb-2.5 text-slate-600" />
                  <p className="text-xs text-slate-400 font-medium">No AI severity analysis generated yet.</p>
                  <p className="text-[11px] text-slate-500 mt-1">
                    Configure your API keys in <strong>Settings</strong> and click{" "}
                    <strong>"Run Multi-Model Advisor"</strong>.
                  </p>
                </div>
              ) : (
                <div className="space-y-2.5 max-h-[360px] overflow-y-auto pr-1">
                  {rankedAttacks.map((item, idx) => (
                    <div
                      key={idx}
                      className="p-3 bg-slate-900 border border-slate-800 rounded-lg space-y-2"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="px-2 py-0.5 rounded-full text-[11px] font-bold border bg-red-500/20 text-red-400 border-red-500/30">
                          #{idx + 1} {item.severity}
                        </span>
                        <h4 className="font-bold text-sm text-white">{item.attack_type}</h4>
                        <span className="text-[11px] font-mono text-slate-400">
                          ({item.count} occurrences)
                        </span>
                      </div>
                      <p className="text-xs text-slate-300 font-mono bg-slate-950 p-2.5 rounded border border-slate-800">
                        💡 <strong>Mitigation:</strong> {item.advice}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 shadow-xl backdrop-blur-sm space-y-4">
          <h3 className="text-base font-bold flex items-center gap-2">
            <ShieldAlert className="text-sky-400" /> Live Threat Distribution
          </h3>
          <div className="space-y-2 max-h-[350px] overflow-y-auto pr-1">
            {Object.keys(rawThreatCounts).length === 0 ? (
              <p className="text-xs text-slate-500 text-center py-10">Awaiting incoming stream data...</p>
            ) : (
              Object.entries(rawThreatCounts).map(([type, count]) => (
                <div
                  key={type}
                  className="flex justify-between items-center p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono"
                >
                  <span className="text-slate-300">{type}</span>
                  <span className="px-2 py-0.5 bg-sky-950 text-sky-400 border border-sky-800 rounded font-bold">
                    {count}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 shadow-xl space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h2 className="text-lg font-bold flex items-center gap-2">
              <FileText className="text-blue-400" /> Persistent Audit Log Ledger
            </h2>
            <p className="text-xs text-slate-400">All captured security events synchronized in real time</p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={clearLogs}
              disabled={logs.length === 0}
              className="flex items-center gap-2 bg-red-950/40 border border-red-800/60 hover:bg-red-900/40 text-red-400 disabled:opacity-50 px-3 py-2 rounded-lg text-xs font-medium transition"
            >
              <Trash2 size={14} /> Clear Logs
            </button>
            <button
              onClick={exportToCSV}
              disabled={logs.length === 0}
              className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 disabled:text-slate-600 px-4 py-2 rounded-lg text-xs font-medium transition"
            >
              <Download size={14} /> Export to CSV ({logs.length})
            </button>
          </div>
        </div>

        <div className="relative max-w-md">
          <Search className="absolute left-3 top-3 text-slate-500" size={16} />
          <input
            type="text"
            placeholder="Filter logs by attack type or port..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="overflow-hidden rounded-xl border border-slate-800">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-800/50 text-slate-400 uppercase text-xs font-mono">
              <tr>
                <th className="p-4">Timestamp</th>
                <th className="p-4">Attack Type</th>
                <th className="p-4">Destination Port</th>
                <th className="p-4">Anomaly Score</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {filteredLogs.length === 0 ? (
                <tr>
                  <td colSpan={4} className="p-12 text-center text-slate-500 font-medium">
                    No log entries recorded yet. Start your backend anomaly simulator!
                  </td>
                </tr>
              ) : (
                filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-800/30 transition">
                    <td className="p-4 text-slate-400 font-mono text-xs">{log.timestamp}</td>
                    <td className="p-4 font-bold text-red-400 flex items-center gap-2">
                      <ShieldAlert size={14} /> {log.label}
                    </td>
                    <td className="p-4 font-mono">{log.destination_port}</td>
                    <td className="p-4 font-mono text-slate-300">{log.score.toFixed(4)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}