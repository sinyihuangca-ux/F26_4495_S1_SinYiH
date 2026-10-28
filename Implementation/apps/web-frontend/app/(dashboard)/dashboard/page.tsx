"use client";

import { useEffect, useState } from "react";
import {
  Bot,
  Key,
  ShieldAlert,
  Sparkles,
  CheckCircle2,
  Server,
} from "lucide-react";

interface RankedAttack {
  attack_type: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  count: number;
  advice: string;
}

export default function DashboardPage() {
  const [connectionStatus, setConnectionStatus] = useState("Disconnected");
  const [rawThreatCounts, setRawThreatCounts] = useState<
    Record<string, number>
  >({});

  // IP and API Key configuration state
  const [serverIp, setServerIp] = useState<string>("localhost:8000");
  const [tempIpInput, setTempIpInput] = useState<string>("");
  const [showIpInput, setShowIpInput] = useState(false);

  const [apiKey, setApiKey] = useState<string>("");
  const [tempKeyInput, setTempKeyInput] = useState<string>("");
  const [showKeyInput, setShowKeyInput] = useState(false);

  const [rankedAttacks, setRankedAttacks] = useState<RankedAttack[]>([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  // Initialize saved configurations & WebSocket connection
  useEffect(() => {
    const savedIp =
      localStorage.getItem("SECURITY_BACKEND_IP") || "localhost:8000";
    setServerIp(savedIp);
    setTempIpInput(savedIp);

    const savedKey = localStorage.getItem("GEMINI_API_KEY") || "";
    if (savedKey) {
      setApiKey(savedKey);
      setTempKeyInput(savedKey);
    }
  }, []);

  // Connect to WebSocket whenever serverIp changes
  useEffect(() => {
    if (!serverIp) return;

    // Clean IP string (remove protocol if included by accident)
    const formattedHost = serverIp
      .replace(/^https?:\/\//, "")
      .replace(/^ws:\/\//, "")
      .trim();
    const wsUrl = `ws://${formattedHost}/ws/alerts`;

    console.log(`[+] Attempting WebSocket connection to: ${wsUrl}`);
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      setConnectionStatus(`Connected (${formattedHost})`);
      console.log("[+] Connected to Security WebSocket stream");
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === "ATTACK_DETECTED") {
        const type = data.label || "Unknown Threat";
        setRawThreatCounts((prev) => ({
          ...prev,
          [type]: (prev[type] || 0) + 1,
        }));

        // Save incoming alert to global persistent log history in localStorage
        const existingLogs = JSON.parse(
          localStorage.getItem("SECURITY_LOG_HISTORY") || "[]",
        );
        const newLogEntry = {
          id: Math.random().toString(36).substring(2, 9),
          timestamp: data.timestamp || new Date().toLocaleString(),
          label: type,
          destination_port: data.destination_port ?? 80,
          score: data.score ?? 0,
        };
        localStorage.setItem(
          "SECURITY_LOG_HISTORY",
          JSON.stringify([newLogEntry, ...existingLogs]),
        );
      }
    };

    ws.onclose = () => {
      setConnectionStatus("Disconnected");
      console.log("[-] Disconnected from WebSocket stream");
    };

    return () => {
      ws.close();
    };
  }, [serverIp]);

  const saveServerIp = (ip: string) => {
    const trimmed = ip.trim();
    if (!trimmed) return;
    setServerIp(trimmed);
    localStorage.setItem("SECURITY_BACKEND_IP", trimmed);
    setShowIpInput(false);
  };

  const saveApiKey = (key: string) => {
    const trimmed = key.trim();
    if (!trimmed) return;
    setApiKey(trimmed);
    localStorage.setItem("GEMINI_API_KEY", trimmed);
    setShowKeyInput(false);
  };

  const runAiAdvisorAnalysis = async () => {
    const activeKey = apiKey || localStorage.getItem("GEMINI_API_KEY");
    if (!activeKey) {
      setShowKeyInput(true);
      return;
    }

    setIsAnalyzing(true);
    try {
      const prompt = `You are a Senior Cybersecurity AI Advisor. Analyze these active network threats captured in real time: ${JSON.stringify(rawThreatCounts)}. 
      Return ONLY a raw valid JSON array (no markdown code blocks, no backticks) sorted strictly by severity (CRITICAL first, then HIGH, MEDIUM, LOW) in this exact structure:
      [
        {
          "attack_type": "DDoS",
          "severity": "CRITICAL",
          "count": 15,
          "advice": "Apply rate-limiting rules at firewall and enable cloud scrubbing."
        }
      ]`;

      const res = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent?key=${activeKey}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            contents: [{ parts: [{ text: prompt }] }],
            generationConfig: {
              temperature: 0.2,
            },
          }),
        },
      );

      const data = await res.json();

      if (data.error) {
        alert(`Gemini API Error: ${data.error.message}`);
        setIsAnalyzing(false);
        return;
      }

      const textResponse = data.candidates[0].content.parts[0].text;
      const cleanedJson = textResponse.replace(/```json|```/g, "").trim();
      const parsed: RankedAttack[] = JSON.parse(cleanedJson);

      setRankedAttacks(parsed);
    } catch (err) {
      console.error("Gemini AI Analysis failed:", err);
      alert(
        "Failed to analyze threats. Check the browser console for details.",
      );
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "CRITICAL":
        return "bg-red-500/20 text-red-400 border-red-500/30";
      case "HIGH":
        return "bg-orange-500/20 text-orange-400 border-orange-500/30";
      case "MEDIUM":
        return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
      default:
        return "bg-blue-500/20 text-blue-400 border-blue-500/30";
    }
  };

  const totalThreats = Object.values(rawThreatCounts).reduce(
    (a, b) => a + b,
    0,
  );

  return (
    <div className="p-8 space-y-8 bg-slate-950 min-h-screen text-slate-100">
      {/* Header & Control Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between border-b border-slate-800 pb-4">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight flex items-center gap-2">
            <Bot className="text-purple-400" /> AI Security Advisor Dashboard
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Powered by Gemini AI threat intelligence & advisory briefings
          </p>
        </div>
        <div className="mt-4 sm:mt-0 flex items-center gap-3">
          {/* Server IP Config Button */}
          <button
            onClick={() => {
              setShowIpInput(!showIpInput);
              setShowKeyInput(false);
            }}
            className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 px-3 py-1.5 rounded-lg text-xs transition border border-slate-700"
          >
            <Server size={14} className="text-sky-400" /> Server IP: {serverIp}
          </button>

          {/* Gemini API Key Button */}
          <button
            onClick={() => {
              setShowKeyInput(!showKeyInput);
              setShowIpInput(false);
            }}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs transition border ${
              apiKey
                ? "bg-emerald-950/40 border-emerald-800 text-emerald-400"
                : "bg-slate-800 border-slate-700 text-slate-300 hover:bg-slate-700"
            }`}
          >
            {apiKey ? <CheckCircle2 size={14} /> : <Key size={14} />}
            {apiKey ? "Gemini Key Active" : "Add Gemini Key"}
          </button>

          <button
            onClick={runAiAdvisorAnalysis}
            disabled={isAnalyzing || totalThreats === 0}
            className="flex items-center gap-2 bg-purple-600 hover:bg-purple-500 disabled:bg-slate-800 px-4 py-1.5 rounded-lg text-xs font-medium transition"
          >
            <Sparkles size={14} />{" "}
            {isAnalyzing ? "Analyzing..." : "Analyze Priority"}
          </button>

          <span className="text-xs font-mono px-3 py-1 bg-slate-900 border border-slate-800 rounded-full flex items-center gap-2">
            <span
              className={`h-2 w-2 rounded-full ${connectionStatus.includes("Connected") ? "bg-emerald-500 animate-pulse" : "bg-red-500"}`}
            />
            {connectionStatus}
          </span>
        </div>
      </div>

      {/* Input Drawer for Server IP */}
      {showIpInput && (
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl flex gap-3 items-center">
          <label className="text-xs text-slate-400 font-mono whitespace-nowrap">
            FastAPI Host:
          </label>
          <input
            type="text"
            placeholder="e.g. 192.168.1.75:8000 or localhost:8000"
            value={tempIpInput}
            onChange={(e) => setTempIpInput(e.target.value)}
            className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-white focus:outline-none focus:border-sky-500"
          />
          <button
            onClick={() => saveServerIp(tempIpInput)}
            className="bg-sky-600 hover:bg-sky-500 px-4 py-2 rounded-lg text-sm font-medium transition"
          >
            Save IP
          </button>
        </div>
      )}

      {/* Input Drawer for Gemini API Key */}
      {showKeyInput && (
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl flex gap-3 items-center">
          <input
            type="password"
            placeholder="Enter your Gemini API key (AIza...)"
            value={tempKeyInput}
            onChange={(e) => setTempKeyInput(e.target.value)}
            className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2 text-sm text-white focus:outline-none focus:border-purple-500"
          />
          <button
            onClick={() => saveApiKey(tempKeyInput)}
            className="bg-purple-600 hover:bg-purple-500 px-4 py-2 rounded-lg text-sm font-medium transition"
          >
            Save Key
          </button>
        </div>
      )}

      {/* AI Security Advisor Advisory List */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 shadow-xl backdrop-blur-sm">
        <div className="flex justify-between items-center mb-6">
          <div>
            <h2 className="text-lg font-bold">
              Severity-Ranked Threat Briefing
            </h2>
            <p className="text-xs text-slate-400">
              Gemini advisor recommendations ordered by operational risk
            </p>
          </div>
          <span className="text-xs font-mono bg-purple-950/60 border border-purple-800 text-purple-300 px-3 py-1 rounded-md">
            {totalThreats} Total Events Processed
          </span>
        </div>

        <div className="space-y-4">
          {rankedAttacks.length === 0 ? (
            <div className="text-center py-16 border border-dashed border-slate-800 rounded-lg">
              <ShieldAlert size={40} className="mx-auto mb-3 text-slate-600" />
              <p className="text-sm text-slate-400 font-medium">
                No Gemini AI severity analysis generated yet.
              </p>
              <p className="text-xs text-slate-500 mt-1">
                {!apiKey
                  ? "Please add your Gemini API key using the button above, then click"
                  : "Stream live threats and click"}{" "}
                <strong>"Analyze Priority"</strong>.
              </p>
            </div>
          ) : (
            rankedAttacks.map((item, idx) => (
              <div
                key={idx}
                className="p-4 bg-slate-950 border border-slate-800 rounded-xl flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4"
              >
                <div className="space-y-2">
                  <div className="flex items-center gap-3">
                    <span
                      className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${getSeverityBadge(item.severity)}`}
                    >
                      #{idx + 1} {item.severity}
                    </span>
                    <h3 className="font-bold text-lg text-white">
                      {item.attack_type}
                    </h3>
                    <span className="text-xs font-mono text-slate-400">
                      ({item.count} occurrences)
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 font-mono bg-slate-900 p-2.5 rounded border border-slate-800">
                    💡 <strong>Advisor Mitigation:</strong> {item.advice}
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
