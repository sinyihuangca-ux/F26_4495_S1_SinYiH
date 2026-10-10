"use client";

import { PieChart as PieIcon, LineChart as LineIcon } from "lucide-react";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
} from "recharts";

const DONUT_DATA = [
  { name: "Normal Traffic", value: 1283204, color: "#0088FE" },
  { name: "Anomaly Traffic", value: 13328, color: "#FF4D4D" },
];

const TIME_SERIES_DATA = [
  { time: "14:00", normal: 2100, anomaly: 200 },
  { time: "14:05", normal: 3100, anomaly: 180 },
  { time: "14:10", normal: 3800, anomaly: 1200 },
  { time: "14:15", normal: 2600, anomaly: 150 },
  { time: "14:20", normal: 3200, anomaly: 220 },
  { time: "14:25", normal: 2900, anomaly: 850 },
  { time: "14:30", normal: 2700, anomaly: 180 },
];

export function DashboardCharts() {
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      {/* Donut Chart: Traffic Ratio */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <div className="flex items-center gap-2 mb-4">
          <PieIcon className="h-5 w-5 text-sky-400" />
          <h3 className="font-semibold text-white">
            Normal vs. Anomaly Traffic
          </h3>
        </div>

        <div className="flex flex-col sm:flex-row items-center justify-around h-56">
          <div className="relative h-44 w-44">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={DONUT_DATA}
                  innerRadius={55}
                  outerRadius={75}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {DONUT_DATA.map((entry, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={entry.color}
                      stroke="#0B0F19"
                      strokeWidth={2}
                    />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-xl font-bold text-white">98.9%</span>
            </div>
          </div>

          <div className="flex flex-col gap-3 text-xs">
            <div className="flex items-center gap-2">
              <span className="h-3 w-3 rounded-full bg-[#0088FE]" />
              <div>
                <p className="text-slate-400">Normal Traffic</p>
                <p className="font-bold text-white">1,283,204 (98.9%)</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <span className="h-3 w-3 rounded-full bg-[#FF4D4D]" />
              <div>
                <p className="text-slate-400">Anomaly Traffic</p>
                <p className="font-bold text-white">13,328 (1.1%)</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Line Chart: Flow Rate over Time */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <LineIcon className="h-5 w-5 text-sky-400" />
            <h3 className="font-semibold text-white">Flow Rate over Time</h3>
          </div>
          <div className="flex items-center gap-4 text-xs">
            <span className="flex items-center gap-1.5 text-sky-400">
              <span className="h-0.5 w-3 bg-[#0088FE]" /> Normal Traffic
            </span>
            <span className="flex items-center gap-1.5 text-red-400">
              <span className="h-0.5 w-3 bg-[#FF4D4D]" /> Anomaly Traffic
            </span>
          </div>
        </div>

        <div className="h-56 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={TIME_SERIES_DATA}>
              <XAxis
                dataKey="time"
                stroke="#64748b"
                fontSize={10}
                tickLine={false}
              />
              <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#0f172a",
                  borderColor: "#334155",
                  borderRadius: "8px",
                  fontSize: "12px",
                }}
              />
              <Line
                type="monotone"
                dataKey="normal"
                stroke="#0088FE"
                strokeWidth={2}
                dot={false}
              />
              <Line
                type="monotone"
                dataKey="anomaly"
                stroke="#FF4D4D"
                strokeWidth={2}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
