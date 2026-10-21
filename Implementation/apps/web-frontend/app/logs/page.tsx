"use client";

import { useEffect, useState } from "react";
import { Download, FileText, Search, ShieldAlert } from "lucide-react";

interface LogEntry {
  id: string;
  timestamp: string;
  label: string;
  destination_port: number;
  score: number;
}

export default function LogsPage() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [search, setSearch] = useState("");

  useEffect(() => {
    const savedIp = localStorage.getItem("SECURITY_BACKEND_IP") || "localhost:8000";
    const formattedHost = savedIp.replace(/^https?:\/\//, "").replace(/^ws:\/\//, "").trim();
    const wsUrl = `ws://${formattedHost}/ws/alerts`;

    const ws = new WebSocket(wsUrl);

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === "ATTACK_DETECTED") {
        const newLog: LogEntry = {
          id: Math.random().toString(36).substring(2, 9),
          timestamp: data.timestamp || new Date().toLocaleString(),
          label: data.label || "Anomaly",
          destination_port: data.destination_port ?? 80,
          score: data.score ?? 0,
        };
        setLogs((prev) => [newLog, ...prev]);
      }
    };

    return () => ws.close();
  }, []);

  const exportToCSV = () => {
    if (logs.length === 0) return;

    const headers = ["Timestamp", "Attack Type", "Destination Port", "Anomaly Score"];
    const rows = logs.map((log) => [
      `"${log.timestamp}"`,
      `"${log.label}"`,
      log.destination_port,
      log.score.toFixed(4),
    ]);

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
    (log) =>
      log.label.toLowerCase().includes(search.toLowerCase()) ||
      log.destination_port.toString().includes(search)
  );

  return (
    <div className="p-8 space-y-8 bg-slate-950 min-h-screen text-slate-100">
      {/* Header & Export Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight flex items-center gap-2">
            <FileText className="text-blue-400" /> Security Audit Logs
          </h1>
          <p className="text-sm text-slate-400 mt-1">Persistent event ledger for audit tracking and export</p>
        </div>
        <div className="mt-4 sm:mt-0 flex items-center gap-3">
          <button
            onClick={exportToCSV}
            disabled={logs.length === 0}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 disabled:text-slate-600 px-4 py-2 rounded-lg text-sm font-medium transition"
          >
            <Download size={16} /> Export to CSV ({logs.length})
          </button>
        </div>
      </div>

      {/* Search Filter */}
      <div className="relative max-w-md">
        <Search className="absolute left-3 top-3 text-slate-500" size={16} />
        <input
          type="text"
          placeholder="Filter logs by attack type or port..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
        />
      </div>

      {/* Logs Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <table className="w-full text-left text-sm text-slate-300">
          <thead className="bg-slate-800/50 text-slate-400 uppercase text-xs">
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
                  No log entries recorded yet.
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
  );
}