import React from "react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend
} from "recharts";
import { Activity } from "lucide-react";

function AlertTrendChart({ logs = [], analytics = null }) {
  let chartData = [];

  // 1. PIPELINE A: IF API DATA EXISTS (analytics.events_per_hour)
  if (analytics?.events_per_hour && typeof analytics.events_per_hour === "object") {
    chartData = Object.entries(analytics.events_per_hour).map(([time, value]) => {
      let formattedTime = String(time).trim();
      if (!formattedTime.includes(":")) {
        formattedTime = `${formattedTime.padStart(2, "0")}:00`;
      }

      if (typeof value === "object" && value !== null) {
        return {
          time: formattedTime,
          // Robust mapping parameters handle any variation your Python backend transmits
          Critical: value.Critical || value.critical || value.crit || value.CRITICAL || 0,
          High: value.High || value.high || value.HIGH || 0,
          
          // Captures Medium events and guards against common alternate strings like warning or mod
          Medium: value.Medium || value.medium || value.MEDIUM || value.warning || value.warn || value.mod || 0,
          
          Low: value.Low || value.low || value.LOW || 0,
          Informational: value.Informational || value.informational || value.Info || value.info || value.INFO || 0
        };
      }
      
      // Fallback if events_per_hour contains flat numbers instead of nested metric objects
      return { time: formattedTime, Critical: 0, High: 0, Medium: 0, Low: 0, Informational: Number(value) || 0 };
    });
  } 
  // 2. PIPELINE B: CLIENT-SIDE LOCAL LOG PARSING FALLBACK
  else {
    const timeBuckets = {};
    for (let h = 0; h < 24; h++) {
      const label = `${String(h).padStart(2, "0")}:00`;
      timeBuckets[label] = { time: label, Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
    }

    logs.forEach((log) => {
      try {
        const timeVal = log?.event?.time;
        if (!timeVal) return;
        const date = new Date(timeVal);
        if (Number.isNaN(date.getTime())) return;
        const label = `${String(date.getHours()).padStart(2, "0")}:00`;
        
        // Convert log string completely to lowercase to eliminate matching sensitivity bugs
        let rawSev = log?.detection?.severity || "Informational";
        rawSev = rawSev.trim().toLowerCase();
        
        let normalizedSev = "Informational";
        if (rawSev === "critical") normalizedSev = "Critical";
        else if (rawSev === "high") normalizedSev = "High";
        else if (rawSev === "medium") normalizedSev = "Medium";
        else if (rawSev === "low") normalizedSev = "Low";
        else if (["informational", "info"].includes(rawSev)) normalizedSev = "Informational";

        if (timeBuckets[label]) {
          timeBuckets[label][normalizedSev] += 1;
        }
      } catch (err) {
        console.error("Error processing fallback log stream metrics:", err);
      }
    });
    chartData = Object.values(timeBuckets);
  }

  // Ensure chronological timeline alignment from left to right
  chartData.sort((a, b) => String(a.time).localeCompare(String(b.time)));

  // Custom SOC-themed Overlay Tooltip
  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      const total = payload.reduce((sum, entry) => sum + (entry.value || 0), 0);
      return (
        <div className="bg-slate-950/95 border border-slate-800 rounded-xl p-3 shadow-2xl backdrop-blur-md font-mono text-[11px] min-w-[170px] pointer-events-none z-50">
          <div className="text-slate-500 font-bold uppercase text-[9px] mb-2 tracking-wider">
            TIMESTAMP: {label}
          </div>
          <div className="space-y-1">
            {payload.map((entry) => (
              <div key={entry.name} className="flex justify-between items-center gap-4">
                <span className="flex items-center gap-1.5" style={{ color: entry.color }}>
                  <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: entry.color }} />
                  {entry.name}:
                </span>
                <span className="font-bold text-white text-right">{entry.value}</span>
              </div>
            ))}
          </div>
          <div className="border-t border-slate-800/60 mt-2 pt-1.5 flex justify-between items-center text-cyan-400 font-bold text-[10px]">
            <span>Total Streams:</span>
            <span>{total} events</span>
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="w-full h-full bg-transparent p-2 flex flex-col justify-between select-none">
      
      {/* Chart Header */}
      <div className="flex justify-between items-center mb-4 px-2 shrink-0">
        <div className="flex items-center gap-2">
          <Activity size={14} className="text-cyan-400 animate-pulse" />
          <h2 className="text-xs font-bold uppercase tracking-wider text-white">
            Cyber Threat Horizon Stream
          </h2>
        </div>
        <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 font-mono">
          24H Synchronized
        </span>
      </div>

      {/* Main Graph Layout Panel */}
      {chartData.length === 0 ? (
        <div className="flex-1 flex items-center justify-center text-xs font-medium text-slate-600">
          No active telemetry stream available.
        </div>
      ) : (
        <div className="flex-1 min-h-0 w-full relative">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData} margin={{ top: 10, right: 15, left: -25, bottom: -5 }}>
              <defs>
                <linearGradient id="colorCrit" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#ef4444" stopOpacity={0.4}/><stop offset="95%" stopColor="#ef4444" stopOpacity={0}/></linearGradient>
                <linearGradient id="colorHigh" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#f97316" stopOpacity={0.3}/><stop offset="95%" stopColor="#f97316" stopOpacity={0}/></linearGradient>
                <linearGradient id="colorMed" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#eab308" stopOpacity={0.25}/><stop offset="95%" stopColor="#eab308" stopOpacity={0}/></linearGradient>
                <linearGradient id="colorLow" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#22c55e" stopOpacity={0.2}/><stop offset="95%" stopColor="#22c55e" stopOpacity={0}/></linearGradient>
                <linearGradient id="colorInfo" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4}/><stop offset="95%" stopColor="#3b82f6" stopOpacity={0.05}/></linearGradient>
              </defs>

              <CartesianGrid stroke="#1e293b" strokeOpacity={0.25} strokeDasharray="4 4" vertical={false} />
              <XAxis dataKey="time" stroke="#475569" tick={{ fontSize: 9, fontFamily: "monospace", fontWeight: 600 }} tickLine={false} axisLine={false} dy={6} />
              <YAxis stroke="#475569" tick={{ fontSize: 9, fontFamily: "monospace", fontWeight: 600 }} tickLine={false} axisLine={false} dx={-4} />
              <Tooltip content={<CustomTooltip />} />
              
              <Legend 
                verticalAlign="top" 
                height={24}
                iconType="circle"
                iconSize={8}
                wrapperStyle={{ fontSize: '9px', fontFamily: 'monospace', textTransform: 'uppercase', fontWeight: 700, paddingBottom: '10px' }}
              />

              {/* Explicit independent area tracks */}
              <Area type="monotone" dataKey="Critical" name="Critical" stroke="#ef4444" strokeWidth={2.5} fill="url(#colorCrit)" />
              <Area type="monotone" dataKey="High" name="High" stroke="#f97316" strokeWidth={2} fill="url(#colorHigh)" />
              <Area type="monotone" dataKey="Medium" name="Medium" stroke="#eab308" strokeWidth={2} fill="url(#colorMed)" />
              <Area type="monotone" dataKey="Low" name="Low" stroke="#22c55e" strokeWidth={2} fill="url(#colorLow)" />
              <Area type="monotone" dataKey="Informational" name="Informational" stroke="#3b82f6" strokeWidth={2.5} fill="url(#colorInfo)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
}

export default AlertTrendChart;