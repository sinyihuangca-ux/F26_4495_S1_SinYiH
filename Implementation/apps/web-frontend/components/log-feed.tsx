"use client";

import { useState } from "react";
import { Search, ListFilter } from "lucide-react";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

const LOG_DATA = [
  {
    time: "2025-04-26 14:32:17",
    source: "192.168.1.15",
    message: "User login successful for admin",
    is_anomaly: false,
    attack: "-",
    severity: "Info",
  },
  {
    time: "2025-04-26 14:32:14",
    source: "10.0.0.23",
    message: "Suspicious encryption activity detected",
    is_anomaly: true,
    attack: "T1486 Data Encrypted",
    severity: "Critical",
  },
  {
    time: "2025-04-26 14:32:10",
    source: "172.16.0.8",
    message: "Container started: web-app-1",
    is_anomaly: false,
    attack: "-",
    severity: "Info",
  },
  {
    time: "2025-04-26 14:32:07",
    source: "10.0.0.45",
    message: "Multiple failed login attempts",
    is_anomaly: true,
    attack: "T1110 Brute Force",
    severity: "High",
  },
  {
    time: "2025-04-26 14:32:03",
    source: "192.168.1.20",
    message: "File accessed: /etc/passwd",
    is_anomaly: false,
    attack: "-",
    severity: "Info",
  },
  {
    time: "2025-04-26 14:31:58",
    source: "172.16.0.12",
    message: "Scheduled backup completed",
    is_anomaly: false,
    attack: "-",
    severity: "Info",
  },
  {
    time: "2025-04-26 14:31:55",
    source: "10.0.0.9",
    message: "Kubernetes API anomaly request",
    is_anomaly: true,
    attack: "T1190 Exploit Public-Facing App",
    severity: "High",
  },
  {
    time: "2025-04-26 14:31:51",
    source: "192.168.1.33",
    message: "User logout",
    is_anomaly: false,
    attack: "-",
    severity: "Info",
  },
];

export function LogFeed() {
  const [onlyAnomalies, setOnlyAnomalies] = useState(false);
  const [search, setSearch] = useState("");

  const filteredLogs = LOG_DATA.filter((log) => {
    if (onlyAnomalies && !log.is_anomaly) return false;
    if (
      search &&
      !log.message.toLowerCase().includes(search.toLowerCase()) &&
      !log.source.includes(search)
    )
      return false;
    return true;
  });

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
      {/* Table Controls */}
      <div className="mb-4 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2">
          <ListFilter className="h-5 w-5 text-sky-400" />
          <h2 className="font-semibold text-white">Live Log Feed & Alerts</h2>
          <span className="ml-2 flex items-center gap-1.5 text-xs text-red-500">
            <span className="h-2 w-2 rounded-full bg-red-500 animate-pulse" />
            Live
          </span>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <Switch
              id="anomalies-toggle"
              checked={onlyAnomalies}
              onCheckedChange={setOnlyAnomalies}
            />
            <label
              htmlFor="anomalies-toggle"
              className="text-xs text-slate-400 cursor-pointer"
            >
              Show only anomalies
            </label>
          </div>
          <div className="relative w-48 sm:w-64">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-slate-500" />
            <Input
              placeholder="Search logs..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="h-9 border-slate-800 bg-slate-950/50 pl-8 text-xs text-slate-300 placeholder:text-slate-600 focus-visible:ring-sky-500"
            />
          </div>
        </div>
      </div>

      {/* Data Table */}
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow className="border-slate-800 hover:bg-transparent">
              <TableHead className="text-xs font-semibold text-slate-400">
                Time
              </TableHead>
              <TableHead className="text-xs font-semibold text-slate-400">
                Source
              </TableHead>
              <TableHead className="text-xs font-semibold text-slate-400">
                Log Message
              </TableHead>
              <TableHead className="text-xs font-semibold text-slate-400">
                is_anomaly
              </TableHead>
              <TableHead className="text-xs font-semibold text-slate-400">
                MITRE ATT&CK
              </TableHead>
              <TableHead className="text-xs font-semibold text-slate-400 text-right">
                Severity
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filteredLogs.map((log, index) => (
              <TableRow
                key={index}
                className={`border-slate-800/60 font-mono text-xs ${
                  log.is_anomaly
                    ? "bg-red-950/20 text-red-400 hover:bg-red-950/30"
                    : "text-slate-300 hover:bg-slate-800/40"
                }`}
              >
                <TableCell className="whitespace-nowrap">{log.time}</TableCell>
                <TableCell>{log.source}</TableCell>
                <TableCell className="max-w-xs truncate font-sans">
                  {log.message}
                </TableCell>
                <TableCell>{log.is_anomaly ? "true" : "false"}</TableCell>
                <TableCell>{log.attack}</TableCell>
                <TableCell className="text-right">
                  <Badge
                    variant="outline"
                    className={`text-[10px] uppercase font-sans font-medium px-2 py-0.5 ${
                      log.severity === "Critical"
                        ? "border-red-500/40 bg-red-500/20 text-red-400"
                        : log.severity === "High"
                          ? "border-amber-500/40 bg-amber-500/20 text-amber-400"
                          : "border-sky-500/40 bg-sky-500/20 text-sky-400"
                    }`}
                  >
                    {log.severity}
                  </Badge>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
