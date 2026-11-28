"use client";

import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Confusion } from "@/lib/api";
import { useLive } from "@/lib/live";

const COLORS = { benign: "#10b981", suspicious: "#f59e0b", malicious: "#ef4444" };
const tooltip = {
  contentStyle: { backgroundColor: "#0f172a", borderColor: "#334155", borderRadius: 8, fontSize: 12 },
};

export function DashboardCharts() {
  const { stats } = useLive();
  const v = stats?.by_verdict ?? { benign: 0, suspicious: 0, malicious: 0 };
  const total = v.benign + v.suspicious + v.malicious;
  const donut = (Object.keys(COLORS) as (keyof typeof COLORS)[]).map((k) => ({ name: k, value: v[k] }));
  const types = Object.entries(stats?.by_type ?? {})
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <h3 className="mb-2 font-semibold text-white">Traffic by final verdict</h3>
        <div className="flex h-52 items-center justify-around">
          <div className="relative h-40 w-40">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={total ? donut : [{ name: "none", value: 1 }]} innerRadius={50} outerRadius={70}
                  paddingAngle={total ? 3 : 0} dataKey="value">
                  {(total ? donut : [{ name: "none" }]).map((d) => (
                    <Cell key={d.name} fill={COLORS[d.name as keyof typeof COLORS] ?? "#1e293b"} stroke="#0B0F19" />
                  ))}
                </Pie>
                {total > 0 && <Tooltip {...tooltip} />}
              </PieChart>
            </ResponsiveContainer>
            <div className="pointer-events-none absolute inset-0 flex items-center justify-center text-lg font-bold">
              {total ? `${Math.round((v.benign / total) * 100)}%` : "—"}
            </div>
          </div>
          <ul className="space-y-2 text-xs">
            {donut.map((d) => (
              <li key={d.name} className="flex items-center gap-2">
                <span className="h-3 w-3 rounded-full" style={{ background: COLORS[d.name as keyof typeof COLORS] }} />
                <span className="capitalize text-slate-400">{d.name}</span>
                <span className="font-semibold text-white">{d.value.toLocaleString()}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <h3 className="mb-2 font-semibold text-white">Threats by type</h3>
        <div className="h-52">
          {types.length ? (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={types} layout="vertical" margin={{ left: 10 }}>
                <XAxis type="number" stroke="#64748b" fontSize={10} />
                <YAxis type="category" dataKey="name" stroke="#64748b" fontSize={10} width={110} />
                <Tooltip {...tooltip} cursor={{ fill: "#1e293b" }} />
                <Bar dataKey="count" fill="#ef4444" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <p className="pt-20 text-center text-xs text-slate-500">No threats yet</p>
          )}
        </div>
      </div>

      <AccuracyPanel />
    </div>
  );
}

const pct = (x: number | null | undefined) => (x == null ? "—" : `${Math.round(x * 100)}%`);

function Row({ name, c }: { name: string; c: Confusion | null }) {
  return (
    <tr className="border-t border-slate-800/60">
      <td className="py-2 font-medium text-slate-300">{name}</td>
      <td className="py-2 font-mono">{pct(c?.recall)}</td>
      <td className="py-2 font-mono">{pct(c?.precision)}</td>
      <td className="py-2 font-mono">{pct(c?.false_positive_rate)}</td>
      <td className="py-2 font-mono text-slate-500">{c?.evaluated ?? 0}</td>
    </tr>
  );
}

// Scored against the dataset's Label column, which never affects the verdicts themselves.
export function AccuracyPanel() {
  const { stats } = useLive();
  const a = stats?.accuracy;
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      <h3 className="font-semibold text-white">Detection accuracy</h3>
      <p className="mb-2 text-[11px] text-slate-500">Against the dataset labels · suspicious counts as a detection</p>
      <table className="w-full text-left text-xs">
        <thead className="text-[11px] uppercase text-slate-500">
          <tr>
            <th className="pb-1">Engine</th>
            <th className="pb-1" title="Share of real attacks caught">Caught</th>
            <th className="pb-1" title="Share of alerts that were real attacks">Precision</th>
            <th className="pb-1" title="Share of normal flows wrongly flagged">False +</th>
            <th className="pb-1">Flows</th>
          </tr>
        </thead>
        <tbody>
          <Row name="ML" c={a?.ml ?? null} />
          <Row name="AI (reviewed only)" c={a?.ai ?? null} />
          <Row name="Combined" c={a?.combined ?? null} />
        </tbody>
      </table>
    </div>
  );
}
