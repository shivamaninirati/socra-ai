import { useEffect, useState, useMemo } from "react";
import { useLiveSOC } from "../context/LiveSOCContext";
import StatCard from "../components/StatCard";
import TopHostsCard from "../components/dashboard/TopHostsCard";
import CollectorStatusCard from "../components/dashboard/CollectorStatusCard";
import RecentAlerts from "../components/dashboard/RecentAlerts";
import AlertTrendChart from "../components/charts/AlertTrendChart";
import SeverityChart from "../components/charts/SeverityChart";
import PageHeader from "../components/ui/PageHeader";
import DashboardSkeleton from "../components/ui/DashboardSkeleton";
import EventDetailsDrawer from "../components/Events/EventDetailsDrawer";

const SEVERITY_HIGH_VALUES = new Set(["high", "critical"]);

const parseEventTime = (log) => {
  const value = log?.event?.time;
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
};

const getSeverity = (log) => String(log?.detection?.severity || "").toLowerCase();

const buildTodayDashboardAnalytics = (todayLogs = [], analytics = null) => {
  const severity = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
  const topHostMap = {};
  const hosts = new Set();
  const now = new Date();
  const currentHour = now.getHours();
  const eventsPerHour = {};
  for (let h = 0; h <= currentHour; h++) {
    const label = `${String(h).padStart(2, "0")}:00`;
    eventsPerHour[label] = { time: label, Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
  }
  const rollingWindowMs = 60 * 1000;
  let rollingCount = 0;
  const timestampNow = now.getTime();

  todayLogs.forEach((log) => {
    let rawSev = log?.detection?.severity || "Informational";
    rawSev = rawSev.trim().toLowerCase();
    let normalizedSevName = "Informational";
    if (rawSev === "critical") normalizedSevName = "Critical";
    else if (rawSev === "high") normalizedSevName = "High";
    else if (rawSev === "medium") normalizedSevName = "Medium";
    else if (rawSev === "low") normalizedSevName = "Low";
    if (severity[normalizedSevName] !== undefined) severity[normalizedSevName] += 1;
    const host = log?.event?.host || log?.event?.computer || "";
    if (host) { hosts.add(host); topHostMap[host] = (topHostMap[host] || 0) + 1; }
    const logTime = parseEventTime(log);
    if (logTime) {
      const logHour = logTime.getHours();
      if (logHour <= currentHour) {
        const label = `${String(logHour).padStart(2, "0")}:00`;
        if (eventsPerHour[label]) eventsPerHour[label][normalizedSevName] += 1;
      }
      if (timestampNow - logTime.getTime() <= rollingWindowMs) rollingCount += 1;
    }
  });

  if (analytics?.summary) {
    return {
      summary: {
        high: analytics.summary.high ?? todayLogs.filter((log) => SEVERITY_HIGH_VALUES.has(getSeverity(log))).length,
        critical: analytics.summary.critical ?? (severity.Critical || 0),
        hosts: analytics.summary.hosts ?? hosts.size,
        eps: analytics.summary.eps ?? Number((rollingCount / 60).toFixed(2)),
      },
      severity: analytics.severity ?? severity,
      // Use full-dataset analytics from accumulator, fall back to local computation
      events_per_hour: Object.keys(analytics.events_per_hour || {}).length > 0 ? analytics.events_per_hour : eventsPerHour,
      top_hosts: analytics?.top_hosts?.length ? analytics.top_hosts : Object.entries(topHostMap).sort((a, b) => b[1] - a[1]).slice(0, 8),
      collector: analytics.collector ?? { live_events: todayLogs.length, history_events: todayLogs.length },
    };
  }

  return {
    summary: {
      high: todayLogs.filter((log) => SEVERITY_HIGH_VALUES.has(getSeverity(log))).length,
      critical: severity.Critical || 0, hosts: hosts.size,
      eps: Number((rollingCount / 60).toFixed(2)),
    },
    severity, events_per_hour: eventsPerHour,
    top_hosts: Object.entries(topHostMap).sort((a, b) => b[1] - a[1]).slice(0, 8),
    collector: { live_events: todayLogs.length, history_events: todayLogs.length },
  };
};

function Dashboard({ globalSearchQuery = { tokens: {}, keywords: [], raw: "" } }) {
  const { analytics: contextAnalytics, connected, connectionState, analyticsLoading: contextLoading } = useLiveSOC();
  const [lastUpdated, setLastUpdated] = useState(null);
  const [selectedLog, setSelectedLog] = useState(null);

  // All dashboard metrics come from the server-side analytics API (/analytics/dashboard),
  // which LiveSOCContext fetches on mount and keeps fresh via WebSocket + periodic resync.
  // Recent critical alerts are served by that same endpoint (recent_critical_alerts, bounded)
  // plus live WebSocket events — no bulk event download is needed for the charts.

  // Update timestamp when context analytics changes (from WebSocket)
  useEffect(() => { if (contextAnalytics) setLastUpdated(new Date()); }, [contextAnalytics]);

  // ALL HOOKS MUST BE CALLED BEFORE ANY EARLY RETURN - React Rules of Hooks
  const todayStart = new Date();
  todayStart.setHours(0, 0, 0, 0);
  const todayLogs = useMemo(() => {
    const alerts = contextAnalytics?.recentAlerts || [];
    const startMs = todayStart.getTime();
    return alerts.filter((log) => {
      const time = parseEventTime(log);
      return time && time.getTime() >= startMs;
    });
  }, [contextAnalytics?.recentAlerts]);

  const derivedAnalytics = useMemo(() => {
    const useContextAnalytics = contextAnalytics && !contextLoading;
    return useContextAnalytics ? buildTodayDashboardAnalytics(todayLogs, contextAnalytics) : buildTodayDashboardAnalytics(todayLogs);
  }, [todayLogs, contextAnalytics, contextLoading]);

  const restSummary = derivedAnalytics?.summary || {};
  const hasData = contextAnalytics || todayLogs.length > 0;
  const isEmpty = !hasData && !contextLoading;
  const totalEventsCount = contextAnalytics?.summary?.total_events ?? todayLogs.length;
  const highSeverityCount = restSummary.high || 0;
  const windowsHostsCount = restSummary.hosts || 0;
  const eventsPerSecCount = restSummary.eps || 0;
  const critical = restSummary.critical || 0;

  // Unified source: use context analytics accumulator if available (has ALL events),
  // fall back to todayLogs computation
  const recentCriticalAlerts = useMemo(() => {
    // When context analytics has recentAlerts, use them as the primary source
    // (the accumulator tracks all high/critical events without artificial limits)
    if (contextAnalytics?.recentAlerts && contextAnalytics.recentAlerts.length > 0 && !contextLoading) {
      return contextAnalytics.recentAlerts;
    }
    // Fallback: compute from todayLogs
    return todayLogs
      .filter((log) => SEVERITY_HIGH_VALUES.has(getSeverity(log)))
      .sort((a, b) => (parseEventTime(b)?.getTime() || 0) - (parseEventTime(a)?.getTime() || 0));
  }, [todayLogs, contextAnalytics, contextLoading]);

  // Now it's safe to have the early return AFTER all hooks are called
  if (!contextAnalytics || contextLoading) return <DashboardSkeleton />;

  let health = "GOOD", dot = "bg-green-400", text = "text-green-400", bg = "bg-green-500/10", border = "border-green-500/20";
  if (connectionState === "reconnecting") {
    health = "RECONNECTING"; dot = "bg-yellow-400"; text = "text-yellow-400"; bg = "bg-yellow-500/10"; border = "border-yellow-500/20";
  } else if (connectionState === "disconnected" || connectionState === "connecting") {
    health = connectionState === "connecting" ? "CONNECTING" : "DISCONNECTED";
    dot = "bg-slate-400"; text = "text-slate-400"; bg = "bg-slate-500/10"; border = "border-slate-500/20";
  } else if (critical > 0 || highSeverityCount > 20) {
    health = "CRITICAL"; dot = "bg-red-400"; text = "text-red-400"; bg = "bg-red-500/10"; border = "border-red-500/20";
  } else if (highSeverityCount >= 5) {
    health = "WARNING"; dot = "bg-yellow-400"; text = "text-yellow-400"; bg = "bg-yellow-500/10"; border = "border-yellow-500/20";
  }

  return (
    <div className="space-y-6 select-none">
      <div className="flex justify-between items-center bg-slate-900/10 p-2 rounded-xl border border-slate-900/40">
        <PageHeader title="Dashboard" subtitle="Monitor your SOC environment in real time." />
        <div className="flex items-center gap-4">
          <div className="text-right hidden sm:block">
            <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Real-Time Pulse</p>
            <p className="text-xs font-mono text-slate-300 mt-1">{lastUpdated ? lastUpdated.toLocaleTimeString("en-GB", { hour12: false }) : "--:--:--"}</p>
          </div>
          <div className={`flex items-center gap-2 px-3 py-2 rounded-lg border ${bg} ${border} shadow-sm font-mono`}>
            <div className={`w-2 h-2 rounded-full animate-pulse ${dot}`} />
            <span className={`text-xs font-bold tracking-wide uppercase ${text}`}>{health}</span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard title="Total Events (Today)" value={contextLoading ? "Loading..." : totalEventsCount} color="#3b82f6" />
        <StatCard title="High Severity (Today)" value={contextLoading ? "Loading..." : highSeverityCount} color="#f97316" />
        <StatCard title="Windows Hosts (Today)" value={contextLoading ? "Loading..." : windowsHostsCount} color="#22c55e" />
        <StatCard title="Events / Sec (Live)" value={contextLoading ? "Loading..." : eventsPerSecCount} color="#8b5cf6" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
        <div className="xl:col-span-8 bg-slate-900/20 border border-slate-800 rounded-xl p-4 min-h-[350px] flex items-center justify-center">
          {isEmpty ? <p className="text-slate-400 text-lg">No events collected today</p> : <AlertTrendChart logs={todayLogs} analytics={derivedAnalytics} />}
        </div>
        <div className="xl:col-span-4 bg-slate-900/20 border border-slate-800 rounded-xl p-4 min-h-[350px] flex items-center justify-center">
          {isEmpty ? <p className="text-slate-400 text-lg">No events collected today</p> : <SeverityChart logs={todayLogs} analytics={derivedAnalytics} />}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-slate-900/20 border border-slate-800 rounded-xl p-4 flex items-center justify-center min-h-[200px]">
          {isEmpty ? <p className="text-slate-400">No data available</p> : <TopHostsCard analytics={derivedAnalytics} />}
        </div>
        <div className="bg-slate-900/20 border border-slate-800 rounded-xl p-4 flex items-center justify-center min-h-[200px]">
          {isEmpty ? <p className="text-slate-400">No data available</p> : <CollectorStatusCard analytics={derivedAnalytics} connected={connected} connectionState={connectionState} />}
        </div>
      </div>

      <div className="bg-slate-900/20 border border-slate-800 rounded-xl p-4">
        <div className="flex items-center justify-between mb-4 border-b border-slate-800/60 pb-3">
          <h3 className="text-xs font-bold uppercase text-slate-400 tracking-wider font-mono">Recent Critical Alerts (Today Window)</h3>
          <span className="text-[10px] font-mono text-slate-500 font-bold bg-slate-900/60 px-2 py-0.5 rounded border border-slate-800">
            {isEmpty ? "No data" : `${recentCriticalAlerts.length} High/Crit Alerts Logged`}
          </span>
        </div>
        {isEmpty ? <div className="flex items-center justify-center py-8 text-slate-400">No critical alerts to display</div> : <RecentAlerts logs={recentCriticalAlerts} onInvestigate={setSelectedLog} />}
      </div>

      <EventDetailsDrawer log={selectedLog} onClose={() => setSelectedLog(null)} />
    </div>
  );
}

export default Dashboard;