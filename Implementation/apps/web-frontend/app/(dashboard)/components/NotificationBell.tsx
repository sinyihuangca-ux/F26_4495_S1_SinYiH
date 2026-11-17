"use client";

import { useState, useEffect } from "react";
import { Bell, ShieldAlert, X } from "lucide-react";

interface Alert {
  type: string;
  label: string;
  score: number;
  destination_port: number;
  timestamp: string;
}

export default function NotificationBell() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [isOpen, setIsOpen] = useState(false);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    // Connect to FastAPI WebSocket endpoint
    const ws = new WebSocket("ws://localhost:8000/ws/alerts");

    ws.onopen = () => {
      setIsConnected(true);
      console.log("[*] Connected to security WebSocket stream");
    };

    ws.onmessage = (event) => {
      try {
        const data: Alert = JSON.parse(event.data);
        if (data.type === "ATTACK_DETECTED") {
          setAlerts((prev) => [data, ...prev.slice(0, 19)]); // Keep last 20 alerts
          setIsOpen(true); // Auto-open dropdown on critical alert
        }
      } catch (err) {
        console.error("Failed to parse WebSocket message", err);
      }
    };

    ws.onclose = () => {
      setIsConnected(false);
      console.log("[-] Disconnected from security WebSocket stream");
    };

    return () => {
      ws.close();
    };
  }, []);

  return (
    <div className="relative">
      {/* Bell Button with Badge */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="relative p-2 text-gray-400 hover:text-white transition rounded-full hover:bg-gray-800 focus:outline-none"
        aria-label="Notifications"
      >
        <Bell className="w-6 h-6" />
        {alerts.length > 0 && (
          <span className="absolute top-1 right-1 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-[10px] font-bold text-white animate-pulse">
            {alerts.length}
          </span>
        )}
      </button>

      {/* Dropdown Menu */}
      {isOpen && (
        <div className="absolute right-0 mt-2 w-80 sm:w-96 bg-gray-900 border border-gray-800 rounded-xl shadow-2xl z-50 overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 bg-gray-950 border-b border-gray-800">
            <div className="flex items-center space-x-2">
              <ShieldAlert className="w-5 h-5 text-red-500" />
              <span className="font-semibold text-white text-sm">Security Threat Alerts</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className={`h-2 w-2 rounded-full ${isConnected ? "bg-green-500" : "bg-red-500"}`} />
              <button
                onClick={() => setIsOpen(false)}
                className="text-gray-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          <div className="max-h-80 overflow-y-auto divide-y divide-gray-800/50">
            {alerts.length === 0 ? (
              <div className="py-8 text-center text-sm text-gray-500">
                No active threats detected. System secure.
              </div>
            >
            ) : (
              alerts.map((alert, index) => (
                <div key={index} className="p-4 hover:bg-gray-800/50 transition">
                  <div className="flex justify-between items-start">
                    <span className="text-xs font-medium text-red-400 bg-red-500/10 px-2 py-0.5 rounded">
                      {alert.label}
                    </span>
                    <span className="text-[10px] text-gray-500">{alert.timestamp}</span>
                  </div>
                  <div className="mt-2 text-xs text-gray-300">
                    <p>Target Port: <span className="font-mono text-white">{alert.destination_port}</span></p>
                    <p>Anomaly Score: <span className="font-mono text-white">{alert.score.toFixed(3)}</span></p>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}