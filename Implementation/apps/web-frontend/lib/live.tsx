"use client";

// One WebSocket connection to the backend, shared by every dashboard page and the
// notification bell. Reconnects automatically and refreshes data when it does.
// New or escalated flows are passed to the notifier (lib/notify.tsx).

import { createContext, useCallback, useContext, useEffect, useRef, useState, useSyncExternalStore } from "react";
import { api, Flow, getServer, Stats, wsUrl } from "./api";
import { useNotify } from "./notify";

type Status = "connecting" | "connected" | "disconnected";

interface LiveState {
  status: Status;
  server: string;
  stats: Stats | null;
  alerts: Flow[]; // newest first; flows that any engine flagged or that the AI is reviewing
  unread: number;
  markRead: () => void;
  upsert: (flow: Flow) => void;
  refresh: () => Promise<void>;
  reconnect: () => void;
}

const LiveContext = createContext<LiveState | null>(null);
const MAX_ALERTS = 500;

export function isAlert(f: Flow) {
  return f.final_verdict !== "benign" || f.ml_verdict === "suspicious" || f.ml_verdict === "malicious" ||
    f.ai_verdict === "suspicious" || f.ai_verdict === "malicious" || f.ai_status === "pending";
}

export function LiveProvider({ children }: { children: React.ReactNode }) {
  const [status, setStatus] = useState<Status>("connecting");
  const [stats, setStats] = useState<Stats | null>(null);
  const [alerts, setAlerts] = useState<Flow[]>([]);
  const [unread, setUnread] = useState(0);
  const [generation, setGeneration] = useState(0);
  const retry = useRef(0);
  const { consider } = useNotify();
  // Last known verdict per flow, so an AI review that escalates a flow can notify.
  const verdicts = useRef(new Map<number, Flow["final_verdict"]>());
  // Read from localStorage on the client only; re-read whenever we reconnect.
  const server = useSyncExternalStore(
    useCallback((cb: () => void) => { window.addEventListener("storage", cb); return () => window.removeEventListener("storage", cb); }, []),
    () => `${getServer()}#${generation}`,
    () => "",
  ).split("#")[0];

  const upsert = useCallback((flow: Flow) => {
    setAlerts((prev) => {
      const i = prev.findIndex((f) => f.id === flow.id);
      if (i >= 0) {
        const next = prev.slice();
        next[i] = flow;
        return next;
      }
      return [flow, ...prev].slice(0, MAX_ALERTS);
    });
  }, []);

  const refresh = useCallback(async () => {
    try {
      const [s, flows] = await Promise.all([
        api<Stats>("/api/stats"),
        api<Flow[]>(`/api/flows?alerts_only=true&limit=${MAX_ALERTS}`),
      ]);
      setStats(s);
      setAlerts(flows);
    } catch {
      // backend unreachable; the status badge already says so
    }
  }, []);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let closed = false;

    const connect = () => {
      setStatus("connecting");
      ws = new WebSocket(wsUrl());
      ws.onopen = () => {
        retry.current = 0;
        setStatus("connected");
        refresh();
      };
      ws.onmessage = (ev) => {
        let msg: { type: string; flow?: Flow; stats?: Stats };
        try {
          msg = JSON.parse(ev.data);
        } catch {
          return;
        }
        if (msg.type === "STATS" && msg.stats) setStats(msg.stats);
        if ((msg.type === "FLOW" || msg.type === "FLOW_UPDATED") && msg.flow) {
          consider(msg.flow, verdicts.current.get(msg.flow.id));
          verdicts.current.set(msg.flow.id, msg.flow.final_verdict);
          upsert(msg.flow);
          if (msg.type === "FLOW" && msg.flow.final_verdict !== "benign") setUnread((n) => n + 1);
        }
      };
      ws.onclose = () => {
        setStatus("disconnected");
        if (closed) return;
        const delay = Math.min(1000 * 2 ** retry.current, 15000);
        retry.current += 1;
        timer = setTimeout(connect, delay);
      };
    };
    connect();
    // AI reviews update individual flows over the socket; refresh stats now and then too.
    const poll = setInterval(() => api<Stats>("/api/stats").then(setStats).catch(() => {}), 10000);

    return () => {
      closed = true;
      clearTimeout(timer);
      clearInterval(poll);
      ws?.close();
    };
  }, [generation, refresh, upsert, consider]);

  const value: LiveState = {
    status,
    server,
    stats,
    alerts,
    unread,
    markRead: () => setUnread(0),
    upsert,
    refresh,
    reconnect: () => setGeneration((g) => g + 1),
  };
  return <LiveContext.Provider value={value}>{children}</LiveContext.Provider>;
}

export function useLive() {
  const ctx = useContext(LiveContext);
  if (!ctx) throw new Error("useLive must be used inside <LiveProvider>");
  return ctx;
}
