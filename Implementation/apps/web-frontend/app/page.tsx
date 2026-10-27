"use client";

import { useState, useEffect } from "react";
import { Download, Search, ShieldAlert, FileText } from "lucide-react";

interface LogEntry {
  id: string;
  timestamp: string;
  attack_type: string;
  dest_port: number;
  anomaly_score: number;
}

export default function LogsPage() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [search, setSearch] = useState("");

  useEffect(() => {
    const ws = new WebSocket("ws://localhost:8000/ws/alerts");

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === "ATTACK_DETECTED") {
        const newLog: LogEntry = {
          id: Math.random().toString(36).substring(2, 9),
          timestamp: data.timestamp || new Date().toLocaleString(),
          attack_type: data.attack_type || "Anomaly Detected",
          dest_port: data.dest_port ?? 80,
          anomaly_score: data.anomaly_score ?? 0,
        };
        setLogs((prev) => [newLog, ...prev]);
      }
    };

    return () => ws.close();
  }, []);

  const exportToCSV = () => {
    if (logs.length === 0) return;

    const headers = ["ID", "Timestamp", "Attack Type", "Destination Port", "Anomaly Score"];
    const rows = logs.map((log) => [
      log.id,
      `"${log.timestamp}"`,
      `"${log.attack_type}"`,
      log.dest_port,
      log.anomaly_score,
    ]);

    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map((e) => e.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `threat_logs_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const filteredLogs = logs.filter(
    (log) =>
      log.attack_type.toLowerCase().includes(search.toLowerCase()) ||
      log.dest_port.toString().includes(search)
  );

  return (
    <div className="p-8 text-white min-h-screen bg-slate-950">
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <FileText className="text-blue-500" /> Security Audit Logs
          </h1>
          <p className="text-slate-400">Complete raw historical events captured by Isolation Forest</p>
        </div>

        <button
          onClick={exportToCSV}
          disabled={logs.length === 0}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 disabled:text-slate-500 px-4 py-2 rounded-lg font-medium transition"
        >
          <Download size={18} /> Export to CSV ({logs.length})
        </button>
      </div>

      <div className="mb-6 relative max-w-md">
        <Search className="absolute left-3 top-3 text-slate-500" size={18} />
        <input
          type="text"
          placeholder="Filter by attack type or port..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-10 pr-4 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
        />
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
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
                <td colSpan={4} className="p-8 text-center text-slate-500">
                  No threat events logged yet.
                </td>
              </tr>
            ) : (
              filteredLogs.map((log) => (
                <tr key={log.id} className="hover:bg-slate-800/30">
                  <td className="p-4 text-slate-400">{log.timestamp}</td>
                  <td className="p-4 font-semibold text-red-400 flex items-center gap-2">
                    <ShieldAlert size={16} /> {log.attack_type}
                  </td>
                  <td className="p-4">{log.dest_port}</td>
                  <td className="p-4 font-mono">{log.anomaly_score.toFixed(4)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}