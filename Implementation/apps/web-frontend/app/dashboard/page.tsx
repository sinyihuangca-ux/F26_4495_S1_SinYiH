"use client";

import { useEffect, useState } from "react";

export default function DashboardPage() {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [connectionStatus, setConnectionStatus] = useState("Disconnected");

  useEffect(() => {
    // Connect to FastAPI WebSocket server 
    // (If viewing from another PC, replace 'localhost' with your server PC IP)
    const ws = new WebSocket("ws://localhost:8000/ws/alerts");

    ws.onopen = () => {
      setConnectionStatus("Connected (Live)");
      console.log("[+] Connected to Security WebSocket stream");
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === "ATTACK_DETECTED") {
        // Prepend new alert to the top of the feed (keeping max 20 recent alerts)
        setAlerts((prev) => [data, ...prev.slice(0, 19)]);
      }
    };

    ws.onclose = () => {
      setConnectionStatus("Disconnected");
      console.log("[-] Disconnected from WebSocket stream");
    };

    return () => {
      ws.close();
    };
  }, []);

  return (
    <div className="p-8 space-y-8 bg-slate-950 min-h-screen text-slate-100">
      {/* Header & Status Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight">Security Command Dashboard</h1>
          <p className="text-sm text-slate-400 mt-1">Real-Time AI Anomaly Detection & Threat Mitigation</p>
        </div>
        <div className="mt-4 sm:mt-0 flex items-center gap-3">
          <span className="text-xs font-mono px-3 py-1 bg-slate-900 border border-slate-800 rounded-full flex items-center gap-2">
            <span className={`h-2 w-2 rounded-full ${connectionStatus.includes("Connected") ? "bg-emerald-500 animate-pulse" : "bg-red-500"}`} />
            {connectionStatus}
          </span>
        </div>
      </div>

      {/* Live Threat Feed Section */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 shadow-xl backdrop-blur-sm">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h2 className="text-lg font-bold">Live Threat Log Feed</h2>
            <p className="text-xs text-slate-400">Incoming network flow anomalies flagged by Isolation Forest ML Engine</p>
          </div>
          <span className="text-xs font-mono bg-red-950/60 border border-red-800 text-red-400 px-3 py-1 rounded-md">
            {alerts.length} Threats Captured
          </span>
        </div>

        <div className="space-y-3 max-h-[600px] overflow-y-auto pr-2">
          {alerts.length === 0 ? (
            <div className="text-center py-16 border border-dashed border-slate-800 rounded-lg">
              <p className="text-sm text-slate-500 font-medium">No active threats detected. System secure.</p>
              <p className="text-xs text-slate-600 mt-1">Run your attack simulator on PC #2 to stream traffic.</p>
            </div>
          ) : (
            alerts.map((alert, idx) => (
              <div 
                key={idx} 
                className="p-4 bg-red-950/20 border border-red-900/40 rounded-lg flex flex-col sm:flex-row justify-between sm:items-center gap-4 transition-all hover:bg-red-950/30"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 bg-red-600 text-white text-xs font-bold rounded">ALERT</span>
                    <span className="font-bold text-red-400 tracking-wide">{alert.label}</span>
                  </div>
                  <p className="text-xs text-slate-400 font-mono">
                    Destination Port: <span className="text-slate-200">{alert.destination_port}</span> | Anomaly Score: <span className="text-slate-200">{alert.score.toFixed(3)}</span>
                  </p>
                </div>
                <div className="text-right">
                  <span className="text-xs font-mono text-slate-500">{alert.timestamp}</span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}