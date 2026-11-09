"use client";

import { useEffect, useState } from "react";
import { Bot, Key, ShieldAlert, Sparkles, Server, FileText, Download, Trash2, Search, Shield } from "lucide-react";

interface LogEntry {
  id: string;
  timestamp: string;
  label: string;
  destination_port: number;
  score: number;
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
  const [showIpInput, setShowIpInput] = useState(false);
  
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [rawThreatCounts, setRawThreatCounts] = useState<Record<string, number>>({});
  const [search, setSearch] = useState("");

  const [showKeyConfig, setShowKeyConfig] = useState(false);
  const [geminiKey, setGeminiKey] = useState("");
  const [claudeKey, setClaudeKey] = useState("");
  const [openaiKey, setOpenaiKey] = useState("");

  const [rankedAttacks, setRankedAttacks] = useState<RankedAttack[]>([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  useEffect(() => {
    const savedIp = localStorage.getItem("SECURITY_BACKEND_IP") || "localhost:8000";
    setServerIp(savedIp);

    setGeminiKey(localStorage.getItem("GEMINI_API_KEY") || "");
    setClaudeKey(localStorage.getItem("CLAUDE_API_KEY") || "");
    setOpenaiKey(localStorage.getItem("OPENAI_API_KEY") || "");

    const savedLogs = JSON.parse(localStorage.getItem("SECURITY_LOG_HISTORY") || "[]");
    setLogs(savedLogs);

    const counts: Record<string, number> = {};
    savedLogs.forEach((log: LogEntry) => {
      counts[log.label] = (counts[log.label] || 0) + 1;
    });
    setRawThreatCounts(counts);
  }, []);

  useEffect(() => {
    if (!serverIp) return;
    const formattedHost = serverIp.replace(/^https?:\/\//, "").replace(/^ws:\/\//, "").trim();
    const wsUrl = `ws://${formattedHost}/ws/alerts`;

    const ws = new WebSocket(wsUrl);

    ws.onopen = () => setConnectionStatus(`Connected (${formattedHost})`);
    
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === "ATTACK_DETECTED") {
        const type = data.label || "Unknown Threat";
        const newLog: LogEntry = {
          id: Math.random().toString(36).substring(2, 9),
          timestamp: new Date().toLocaleTimeString(),
          label: type,
          destination_port: data.destination_port ?? 80,
          score: data.score ?? 0,
        };

        setRawThreatCounts((prev) => ({ ...prev, [type]: (prev[type] || 0) + 1 }));
        setLogs((prev) => {
          const updated = [newLog, ...prev];
          localStorage.setItem("SECURITY_LOG_HISTORY", JSON.stringify(updated));
          return updated;
        });
      }
    };

    ws.onclose = () => setConnectionStatus("Disconnected");

    return () => ws.close();
  }, [serverIp]);

  const saveConfig = () => {
    localStorage.setItem("SECURITY_BACKEND_IP", serverIp);
    localStorage.setItem("GEMINI_API_KEY", geminiKey);
    localStorage.setItem("CLAUDE_API_KEY", claudeKey);
    localStorage.setItem("OPENAI_API_KEY", openaiKey);
    setShowKeyConfig(false);
    setShowIpInput(false);
  };

  const runAiAdvisorAnalysis = async () => {
    const keys = [
      { provider: "gemini", key: geminiKey },
      { provider: "claude", key: claudeKey },
      { provider: "openai", key: openaiKey },
    ].filter((k) => k.key.trim() !== "");

    if (keys.length === 0) {
      setShowKeyConfig(true);
      return;
    }

    setIsAnalyzing(true);
    try {
      const formattedHost = serverIp.replace(/^https?:\/\//, "").trim();
      const res = await fetch(`http://${formattedHost}/api/analyze-threats`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          threat_counts: rawThreatCounts,
          keys: keys,
        }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Failed to analyze threats");

      console.log(`[+] Successfully analyzed using provider: ${data.provider_used}`);

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
      localStorage.removeItem("SECURITY_LOG_HISTORY");
    }
  };

  const exportToCSV = () => {
    if (logs.length === 0) return;
    const headers = ["Timestamp", "Attack Type", "Destination Port", "Anomaly Score"];
    const rows = logs.map((log) => [`"${log.timestamp}"`, `"${log.label}"`, log.destination_port, log.score.toFixed(4)]);
    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map((e) => e.join(","))].join("\n");
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
  const activeKeysCount = [geminiKey, claudeKey, openaiKey].filter((k) => k.trim() !== "").length;

  return (
    <div className="p-8 space-y-8 bg-slate-950 min-h-screen text-slate-100">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between border-b border-slate-800 pb-4 gap-4">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight flex items-center gap-2">
            <Shield className="text-sky-400" /> AI Fortress Security Command Center
          </h1>
          <p className="text-sm text-slate-400 mt-1">Unified real-time threat detection, multi-model AI failover, and audit logs</p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={() => { setShowIpInput(!showIpInput); setShowKeyConfig(false); }}
            className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded-lg text-xs transition border border-slate-700 font-mono"
          >
            <Server size={14} className="text-sky-400" /> IP: {serverIp}
          </button>

          <button
            onClick={() => { setShowKeyConfig(!showKeyConfig); setShowIpInput(false); }}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs transition border ${
              activeKeysCount > 0 ? "bg-emerald-950/40 border-emerald-800 text-emerald-400" : "bg-slate-800 border-slate-700 text-slate-300"
            }`}
          >
            <Key size={14} /> {activeKeysCount > 0 ? `${activeKeysCount} AI Key(s) Active` : "Configure AI Keys"}
          </button>

          <button
            onClick={runAiAdvisorAnalysis}
            disabled={isAnalyzing || totalThreats === 0}
            className="flex items-center gap-2 bg-purple-600 hover:bg-purple-500 disabled:bg-slate-800 px-4 py-1.5 rounded-lg text-xs font-medium transition"
          >
            <Sparkles size={14} /> {isAnalyzing ? "Failover Analyzing..." : "Run Multi-Model Advisor"}
          </button>

          <span className="text-xs font-mono px-3 py-1 bg-slate-900 border border-slate-800 rounded-full flex items-center gap-2">
            <span className={`h-2 w-2 rounded-full ${connectionStatus.includes("Connected") ? "bg-emerald-500 animate-pulse" : "bg-red-500"}`} />
            {connectionStatus}
          </span>
        </div>
      </div>

      {showIpInput && (
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl flex gap-3 items-center">
          <label className="text-xs text-slate-400 font-mono whitespace-nowrap">FastAPI Host:</label>
          <input
            type="text"
            value={serverIp}
            onChange={(e) => setServerIp(e.target.value)}
            className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-white focus:outline-none focus:border-sky-500 font-mono"
          />
          <button onClick={saveConfig} className="bg-sky-600 hover:bg-sky-500 px-4 py-2 rounded-lg text-sm font-medium transition">
            Save IP
          </button>
        </div>
      )}

      {showKeyConfig && (
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="font-bold text-sm text-white flex items-center gap-2">
              <Key size={16} className="text-purple-400" /> Configure Multi-Model Failover Keys
            </h3>
            <span className="text-xs text-slate-400">Cycles automatically on errors, invalid keys, or high-demand limits (429/503).</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="text-xs text-slate-400 block mb-1">Gemini API Key</label>
              <input
                type="password"
                placeholder="AIza..."
                value={geminiKey}
                onChange={(e) => setGeminiKey(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-purple-500 font-mono"
              />
            </div>
            <div>
              <label className="text-xs text-slate-400 block mb-1">Claude API Key (Anthropic)</label>
              <input
                type="password"
                placeholder="sk-ant-..."
                value={claudeKey}
                onChange={(e) => setClaudeKey(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-purple-500 font-mono"
              />
            </div>
            <div>
              <label className="text-xs text-slate-400 block mb-1">OpenAI / Codex API Key</label>
              <input
                type="password"
                placeholder="sk-..."
                value={openaiKey}
                onChange={(e) => setOpenaiKey(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-purple-500 font-mono"
              />
            </div>
          </div>
          <div className="flex justify-end">
            <button onClick={saveConfig} className="bg-purple-600 hover:bg-purple-500 px-5 py-2 rounded-lg text-xs font-medium transition">
              Save All Keys
            </button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800 rounded-xl p-6 shadow-xl backdrop-blur-sm space-y-6">
          <div className="flex justify-between items-center">
            <div>
              <h2 className="text-lg font-bold flex items-center gap-2">
                <Bot className="text-purple-400" /> Severity-Ranked Threat Briefing
              </h2>
              <p className="text-xs text-slate-400">Multi-model failover advisor recommendations ordered by operational risk</p>
            </div>
            <span className="text-xs font-mono bg-purple-950/60 border border-purple-800 text-purple-300 px-3 py-1 rounded-md">
              {totalThreats} Total Events Processed
            </span>
          </div>

          <div className="space-y-4">
            {rankedAttacks.length === 0 ? (
              <div className="text-center py-20 border border-dashed border-slate-800 rounded-lg">
                <ShieldAlert size={40} className="mx-auto mb-3 text-slate-600" />
                <p className="text-sm text-slate-400 font-medium">No AI severity analysis generated yet.</p>
                <p className="text-xs text-slate-500 mt-1">Configure your API keys and click <strong>"Run Multi-Model Advisor"</strong>.</p>
              </div>
            ) : (
              rankedAttacks.map((item, idx) => (
                <div key={idx} className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
                  <div className="flex items-center gap-3">
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-bold border bg-red-500/20 text-red-400 border-red-500/30">
                      #{idx + 1} {item.severity}
                    </span>
                    <h3 className="font-bold text-base text-white">{item.attack_type}</h3>
                    <span className="text-xs font-mono text-slate-400">({item.count} occurrences)</span>
                  </div>
                  <p className="text-xs text-slate-300 font-mono bg-slate-900 p-2.5 rounded border border-slate-800">
                    💡 <strong>Mitigation:</strong> {item.advice}
                  </p>
                </div>
              ))
            )}
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
                <div key={type} className="flex justify-between items-center p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono">
                  <span className="text-slate-300">{type}</span>
                  <span className="px-2 py-0.5 bg-sky-950 text-sky-400 border border-sky-800 rounded font-bold">{count}</span>
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