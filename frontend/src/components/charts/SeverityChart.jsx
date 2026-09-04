import React from "react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import { ShieldAlert } from "lucide-react";

function SeverityChart({ logs = [], analytics = null }) {
  // 1. Strict Color Mapping by Name Key
  const SEVERITY_COLORS = {
    Critical: "#ef4444",      // Vibrant Red
    High: "#f97316",          // Orange Alert
    Medium: "#eab308",        // Tactical Yellow
    Low: "#22c55e",           // Success Green
    Informational: "#3b82f6", // Infrastructure Blue
  };

  // 2. FIXED TREND ORDER SEQUENCE: Critical -> High -> Informational -> Low -> Medium
  const PREFERRED_ORDER = ["Critical", "High", "Informational", "Low", "Medium"];
  
  let baseCounts = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };

  // Parse analytics data
  if (analytics?.severity && typeof analytics.severity === "object") {
    const sev = analytics.severity;
    baseCounts.Critical = sev.Critical || sev.critical || 0;
    baseCounts.High = sev.High || sev.high || 0;
    baseCounts.Medium = sev.Medium || sev.medium || 0;
    baseCounts.Low = sev.Low || sev.low || 0;
    baseCounts.Informational = sev.Informational || sev.informational || sev.Info || sev.info || 0;
  } 
  // Parse raw fallback logs
  else {
    logs.forEach((log) => {
      let rawSev = log?.detection?.severity || "Informational";
      rawSev = rawSev.trim().toLowerCase();
      
      if (rawSev === "critical") baseCounts.Critical += 1;
      else if (rawSev === "high") baseCounts.High += 1;
      else if (rawSev === "medium") baseCounts.Medium += 1;
      else if (rawSev === "low") baseCounts.Low += 1;
      else if (["informational", "info"].includes(rawSev)) {
        baseCounts.Informational += 1;
      }
    });
  }

  // Stable 5-item array structure so Recharts indexing properties remain aligned
  const chartData = PREFERRED_ORDER.map((name) => ({
    name,
    value: baseCounts[name],
  }));

  // Clean Legend layout labels without visible numeric count tokens
  const customLegendPayload = chartData.map((item) => ({
    value: item.name,
    type: "circle", // Force type definition directly on individual entries
    id: item.name,
    color: SEVERITY_COLORS[item.name],
  }));

  return (
    <div className="w-full h-full bg-transparent p-2 flex flex-col justify-between select-none">
      
      {/* Header Container */}
      <div className="flex justify-between items-center mb-4 px-2 shrink-0">
        <div className="flex items-center gap-2">
          <ShieldAlert size={14} className="text-cyan-400" />
          <h2 className="text-xs font-bold uppercase tracking-wider text-white">
            Severity Distribution
          </h2>
        </div>
        
        <div className="flex items-center gap-1.5 text-slate-500 text-[9px] font-bold uppercase tracking-wider font-mono bg-slate-900/40 px-2 py-0.5 rounded-md">
          <span className="w-1 h-1 rounded-full bg-cyan-500 animate-ping" />
          <span>System Synchronized</span>
        </div>
      </div>

      {/* Chart Render Core */}
      <div className="flex-1 min-h-0 w-full relative">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              dataKey="value"
              nameKey="name"
              innerRadius="55%"
              outerRadius="78%"
              paddingAngle={3}
              cx="50%"
              cy="42%"
            >
              {/* Loop directly over stable 5-item array */}
              {chartData.map((entry) => (
                <Cell
                  key={entry.name}
                  fill={SEVERITY_COLORS[entry.name]}
                  stroke={entry.value > 0 ? "rgba(15, 23, 42, 0.8)" : "none"}
                  strokeWidth={entry.value > 0 ? 2 : 0}
                  fillOpacity={entry.value > 0 ? 1 : 0} // Hides 0-value items cleanly
                />
              ))}
            </Pie>

            <Tooltip
              contentStyle={{
                background: "rgba(15, 23, 42, 0.95)",
                border: "none",
                borderRadius: "8px",
                backdropFilter: "blur(4px)",
                fontSize: "11px",
                color: "#f8fafc",
                boxShadow: "0 10px 15px -3px rgba(0, 0, 0, 0.5)",
                fontFamily: "monospace"
              }}
              itemStyle={{ fontWeight: "bold" }}
              filterNull={true}
              formatter={(value, name) => value > 0 ? [value, name] : null}
            />

            <Legend
              verticalAlign="bottom"
              payload={customLegendPayload}
              iconType="circle" // Ensures clean circle markers render
              iconSize={8}      // Increases dot size to match the prominent trend layout dots
              wrapperStyle={{
                color: "#94a3b8",
                fontSize: "9px",
                fontWeight: 700,
                fontFamily: "monospace",
                textTransform: "uppercase",
                paddingTop: "0px",
                bottom: "0px",
              }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

export default SeverityChart;