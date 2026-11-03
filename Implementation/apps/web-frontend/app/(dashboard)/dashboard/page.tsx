"use client";

import { useEffect, useState } from "react";
import { Bot, Key, ShieldAlert, Sparkles, CheckCircle2, Server, Play } from "lucide-react";

interface RankedAttack {
  attack_type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  count: number;
  advice: string;
}

export default function DashboardPage() {
  const [connectionStatus, setConnectionStatus] = useState("Disconnected");
  const [rawThreatCounts, setRawThreatCounts] = useState<Record<string, number>>({});
  
  // Backend server address and Gemini key configuration state
  const [serverIp, setServerIp] = useState<string>("localhost:8000");
  const [tempIpInput, setTempIpInput] = useState<string>("");
  const [showIpInput, setShowIpInput] = useState(false);

  const [apiKey, setApiKey] = useState<string>("");
  const [tempKeyInput, setTempKeyInput] = useState<string>("");
  const [showKeyInput, setShowKeyInput] = useState(false);

  // Gemini AI Advisory state (Used as secondary validation)
  const [rankedAttacks, setRankedAttacks] = useState<RankedAttack[]>([]);
  const [isAiAnalyzing, setIsAiAnalyzing] = useState(false);

  // Local trained machine learning model execution state
  const [isModelRunning, setIsModelRunning] = useState(false);
  const [mlSummary, setMlSummary] = useState<string>("");

  // Initialize saved configurations & WebSocket stream listener
  useEffect(() => {
    const savedIp = localStorage.getItem("SECURITY_BACKEND_IP") || "localhost:8000";
    setServerIp(savedIp);
    setTempIpInput(savedIp);

    const savedKey = localStorage.getItem("GEMINI_API_KEY") || "";
    if (savedKey) {
      setApiKey(savedKey);
      setTempKeyInput(savedKey);
    }
  }, []);

  // Connect to live threat WebSocket feed
  useEffect(() => {
    if (!serverIp) return;

    const formattedHost = serverIp.replace(/^https?:\/\//, "").replace(/^ws:\/\//, "").trim();
    const wsUrl = `ws://${formattedHost}/ws/alerts`;

    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      setConnectionStatus(`Connected (${formattedHost})`);
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === "ATTACK_DETECTED") {
        const type = data.label || "Unknown Threat";
        setRawThreatCounts((prev) => ({
          ...prev,
          [type]: (prev[type] || 0) + 1,
        }));

        // Append to persistent log ledger in localStorage
        const existingLogs = JSON.parse(localStorage.getItem("SECURITY_LOG_HISTORY") || "[]");
        const newLogEntry = {
          id: Math.random().toString(36).substring(2, 9),
          timestamp: data.timestamp || new Date().toLocaleString(),
          label: type,
          destination_port: data.destination_port ?? 80,
          score: data.score ?? 0,
        };
        localStorage.setItem("SECURITY_LOG_HISTORY", JSON.stringify([newLogEntry, ...existingLogs]));
      }
    };

    ws.onclose = () => setConnectionStatus("Disconnected");
    return () => ws.close();
  }, [serverIp]);

  // Primary Action: Execute local trained machine learning pipeline (Isolation Forest / One-SVM)
  const runTrainedModelAnalysis = async () => {
    setIsModelRunning(true);
    setMlSummary("Executing local ML model pipeline...");

    try {
      const formattedHost = serverIp.replace(/^https?:\/\//, "").replace(/^ws:\/\//, "").trim();
      const response = await fetch(`http://${formattedHost}/analyze-logs`, {
        method: "POST",
      });

      const data = await response.json();

      if (data.status === "success") {
        setMlSummary(`[+] Execution Complete: Model analyzed ${data.total_parsed} incoming traffic logs successfully.`);
      } else {
        setMlSummary("[-] Execution failed: Backend returned non-success response.");
      }
    } catch (err) {
      console.error("Local ML analysis execution error:", err);
      setMlSummary("[-] Connection Error: Could not reach backend server endpoint.");
    } finally {
      setIsModelRunning(false);
    }
  };

  // Secondary Action: Run Gemini AI as secondary advisor / verification
  const runAiAdvisorAnalysis = async () => {
    const activeKey = apiKey || localStorage.getItem("GEMINI_API_KEY");
    if (!activeKey) {
      setShowKeyInput(true);
      return;
    }

    setIsAiAnalyzing(true);
    try {
      const prompt = `You are a Senior Cybersecurity AI Advisor. Analyze these active network threats captured in real time: ${JSON.stringify(rawThreatCounts)}. 
      Return ONLY a raw valid JSON array sorted strictly by severity (CRITICAL first, then HIGH, MEDIUM, LOW):
      [
        {
          "attack_type": "DDoS",
          "severity": "CRITICAL",
          "count": 15,
          "advice": "Apply rate-limiting rules at firewall and enable cloud scrubbing."
        }
      ]`;

      const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent?key=${activeKey}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: { temperature: 0.2 }
        }),
      });

      const data = await res.json();
      if (data.error) {
        alert(`Gemini API Error: ${data.error.message}`);
        return;
      }

      const textResponse = data.candidates[0].content.parts[0].text;
      const cleanedJson = textResponse.replace(/```json|```/g, "").trim();
      setRankedAttacks(JSON.parse(cleanedJson));
    } catch (err) {
      console.error("Gemini AI Analysis failed:", err);
    } finally {
      setIsAiAnalyzing(false);
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "CRITICAL": return "bg-red-500/20 text-red-400 border-red-500/30";
      case "HIGH": return "bg-orange-500/20 text-orange-400 border-orange-500/30";
      case "MEDIUM": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
      default: return "bg-blue-500/20 text-blue-400 border-blue-500/30";
    }
  };

  const totalThreats = Object.values(rawThreatCounts).reduce((a, b) => a + b, 0);

  return (
    <div className="p-8 space-y-8 bg-slate-950 min-h-screen text-slate-100">
      {/* Header & Main Operation Control Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight flex items-center gap-2">
            <ShieldAlert className="text-emerald-400" /> AI Cybersecurity SOC Dashboard
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Primary analysis driven by trained Isolation Forest & One-SVM models
          </p>
        </div>

        <div className="mt-4 sm:mt-0 flex items-center gap-3">
          {/* PRIMARY BUTTON: Run Local Trained ML Model */}
          <button
            onClick={runTrainedModelAnalysis}
            disabled={isModelRunning}
            className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-800 px-4 py-2 rounded-lg text-xs font-bold transition shadow-lg shadow-emerald-950/40"
          >
            <Play size={14} /> {isModelRunning ? "Analyzing..." : "Run Trained ML Model"}
          </button>

          {/* SECONDARY BUTTON: Gemini AI Advisory */}
          <button
            onClick={runAiAdvisorAnalysis}
            disabled={isAiAnalyzing || totalThreats === 0}
            className="flex items-center gap-2 bg-purple-900/60 hover:bg-purple-800 border border-purple-700 text-purple-200 disabled:bg-slate-800 px-3 py-2 rounded-lg text-xs font-medium transition"
          >
            <Sparkles size={14} /> {isAiAnalyzing ? "Verifying..." : "AI Verification"}
          </button>

          {/* Server IP Config Toggle Button */}
          <button
            onClick={() => setShowIpInput(!showIpInput)}
            className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 px-3 py-2 rounded-lg text-xs transition border border-slate-700"
          >
            <Server size={14} className="text-sky-400" /> {serverIp}
          </button>

          {/* Connection Status Indicator */}
          <span className="text-xs font-mono px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg flex items-center gap-2">
            <span className={`h-2 w-2 rounded-full ${connectionStatus.includes("Connected") ? "bg-emerald-500 animate-pulse" : "bg-red-500"}`} />
            {connectionStatus}
          </span>
        </div>
      </div>

      {/* Input Drawer for Server IP Configuration */}
      {showIpInput && (
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl flex gap-3 items-center">
          <label className="text-xs text-slate-400 font-mono">FastAPI Host:</label>
          <input
            type="text"
            value={tempIpInput}
            onChange={(e) => setTempIpInput(e.target.value)}
            className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-white"
          />
          <button
            onClick={() => {
              setServerIp(tempIpInput.trim());
              localStorage.setItem("SECURITY_BACKEND_IP", tempIpInput.trim());
              setShowIpInput(false);
            }}
            className="bg-sky-600 hover:bg-sky-500 px-4 py-2 rounded-lg text-sm font-medium"
          >
            Save IP
          </button>
        </div>
      )}

      {/* Trained Model Execution Results Notification Banner */}
      {mlSummary && (
        <div className="p-4 bg-emerald-950/40 border border-emerald-800 rounded-xl text-emerald-300 text-xs font-mono">
          {mlSummary}
        </div>
      )}

      {/* Threat Briefing & Verification Panel */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 shadow-xl backdrop-blur-sm">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h2 className="text-lg font-bold">Model Threat Analysis Briefing</h2>
            <p className="text-xs text-slate-400">Live network threat streams and secondary AI validation</p>
          </div>
          <span className="text-xs font-mono bg-slate-800 border border-slate-700 text-slate-300 px-3 py-1 rounded-md">
            {totalThreats} Streamed Events Captured
          </span>
        </div>

        <div className="space-y-4">
          {rankedAttacks.length === 0 ? (
            <div className="text-center py-16 border border-dashed border-slate-800 rounded-lg">
              <ShieldAlert size={40} className="mx-auto mb-3 text-slate-600" />
              <p className="text-sm text-slate-400 font-medium">Ready for real-time model inference.</p>
              <p className="text-xs text-slate-500 mt-1">
                Click <strong>"Run Trained ML Model"</strong> above to perform primary anomaly detection.
              </p>
            </div>
          ) : (
            rankedAttacks.map((item, idx) => (
              <div key={idx} className="p-4 bg-slate-950 border border-slate-800 rounded-xl flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                <div className="space-y-2">
                  <div className="flex items-center gap-3">
                    <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${getSeverityBadge(item.severity)}`}>
                      #{idx + 1} {item.severity}
                    </span>
                    <h3 className="font-bold text-lg text-white">{item.attack_type}</h3>
                    <span className="text-xs font-mono text-slate-400">({item.count} occurrences)</span>
                  </div>
                  <p className="text-xs text-slate-300 font-mono bg-slate-900 p-2.5 rounded border border-slate-800">
                    💡 <strong>Secondary AI Verification:</strong> {item.advice}
                  </p>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}