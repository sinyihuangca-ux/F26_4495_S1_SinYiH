// Talks to the FastAPI backend. The address comes from (in order): the value saved in
// Settings on this browser, NEXT_PUBLIC_API_URL, or localhost:8000.

export type Verdict = "benign" | "suspicious" | "malicious";

export interface Flow {
  id: number;
  received_at: number;
  flow_time: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  protocol: number | null;
  ground_truth: string | null;
  ml_verdict: Verdict | null;
  ml_score: number | null;
  ai_status: "skipped" | "pending" | "done" | "failed";
  ai_verdict: Verdict | null;
  ai_attack_type: string | null;
  ai_confidence: number | null;
  ai_reason: string | null;
  ai_provider: string | null;
  final_verdict: Verdict;
  agreement: "agree" | "disagree" | null;
  feedback: "false_positive" | "confirmed" | null;
}

export interface Confusion {
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  evaluated: number;
  precision: number | null;
  recall: number | null;
  false_positive_rate: number | null;
}

export interface Stats {
  total_flows: number;
  by_verdict: Record<Verdict, number>;
  by_type: Record<string, number>;
  ai_status: Record<string, number>;
  agreement: Record<string, number>;
  feedback: Record<string, number>;
  accuracy: { ml: Confusion | null; ai: Confusion | null; combined: Confusion | null };
}

export interface Settings {
  ml_enabled: boolean;
  ai_enabled: boolean;
  ml_suspicious_threshold: number;
  ml_malicious_threshold: number;
  ai_sample_rate: number;
  ai_min_confidence: number;
  ai_min_interval: number;
  ai_batch_size: number;
  provider_order: string[];
  models: Record<string, string>;
  notify_enabled: boolean;
  notify_min_verdict: "malicious" | "suspicious";
  notify_cooldown: number;
}

export interface SettingsView {
  settings: Settings;
  secrets: Record<string, string | null>;
}

const STORAGE_KEY = "SECURITY_BACKEND_IP";

export function getServer(): string {
  let saved = "";
  try {
    saved = localStorage.getItem(STORAGE_KEY) || "";
  } catch {
    // storage unavailable (private mode / SSR)
  }
  const raw = saved || process.env.NEXT_PUBLIC_API_URL || "localhost:8000";
  return raw.replace(/^(https?|wss?):\/\//, "").replace(/\/+$/, "").trim() || "localhost:8000";
}

export function setServer(host: string) {
  try {
    localStorage.setItem(STORAGE_KEY, host.trim());
  } catch {
    // ignore
  }
}

export const httpBase = () => `http://${getServer()}`;
export const wsUrl = () => `ws://${getServer()}/ws/alerts`;

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

// `token` is the Clerk session token; needed for endpoints that change settings or data.
export async function api<T>(path: string, init: RequestInit = {}, token?: string | null): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);
  let res: Response;
  try {
    res = await fetch(`${httpBase()}${path}`, { ...init, headers });
  } catch {
    throw new ApiError(0, `Can't reach the backend at ${getServer()}. Is uvicorn running?`);
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail ?? body);
    } catch {
      // non-JSON error
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}
