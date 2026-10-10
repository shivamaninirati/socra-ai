
import { useEffect, useState, useMemo } from "react";
import { motion } from "motion/react";

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

const getSeverity = (log) =>
  String(log?.detection?.severity || "").toLowerCase();

const buildTodayDashboardAnalytics = (todayLogs = [], analytics = null) => {
  const severity = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Informational: 0,
  };

  const topHostMap = {};
  const hosts = new Set();
  const now = new Date();
  const currentHour = now.getHours();
  const eventsPerHour = {};

  for (let h = 0; h <= currentHour; h++) {
    const label = `${String(h).padStart(2, "0")}:00`;

    eventsPerHour[label] = {
      time: label,
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
      Informational: 0,
    };
  }

  const rollingWindowMs = 60 * 1000;
  let rollingCount = 0;
  const timestampNow = now.getTime();

  todayLogs.forEach((log) => {
    const rawSev = String(
      log?.detection?.severity || "Informational"
    ).trim().toLowerCase();

    let normalizedSevName = "Informational";

    if (rawSev === "critical") normalizedSevName = "Critical";
    else if (rawSev === "high") normalizedSevName = "High";
    else if (rawSev === "medium") normalizedSevName = "Medium";
    else if (rawSev === "low") normalizedSevName = "Low";

    if (severity[normalizedSevName] !== undefined) {
      severity[normalizedSevName] += 1;
    }

    const host = log?.event?.host || log?.event?.computer || "";

    if (host) {
      hosts.add(host);
      topHostMap[host] = (topHostMap[host] || 0) + 1;
    }

    const logTime = parseEventTime(log);

    if (logTime) {
      const logHour = logTime.getHours();

      if (logHour <= currentHour) {
        const label = `${String(logHour).padStart(2, "0")}:00`;

        if (eventsPerHour[label]) {
          eventsPerHour[label][normalizedSevName] += 1;
        }
      }

      const age = timestampNow - logTime.getTime();

      if (age >= 0 && age <= rollingWindowMs) {
        rollingCount += 1;
      }
    }
  });

  if (analytics?.summary) {
    return {
      summary: {
        high:
          analytics.summary.high ??
          todayLogs.filter((log) =>
            SEVERITY_HIGH_VALUES.has(getSeverity(log))
          ).length,
        critical: analytics.summary.critical ?? severity.Critical,
        hosts: analytics.summary.hosts ?? hosts.size,
        eps:
          analytics.summary.eps ??
          Number((rollingCount / 60).toFixed(2)),
      },

      severity: analytics.severity ?? severity,

      events_per_hour:
        Object.keys(analytics.events_per_hour || {}).length > 0
          ? analytics.events_per_hour
          : eventsPerHour,

      top_hosts: analytics.top_hosts?.length
        ? analytics.top_hosts
        : Object.entries(topHostMap)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 8),

      collector: analytics.collector ?? {
        live_events: todayLogs.length,
        history_events: todayLogs.length,
      },
    };
  }

  return {
    summary: {
      high: todayLogs.filter((log) =>
        SEVERITY_HIGH_VALUES.has(getSeverity(log))
      ).length,
      critical: severity.Critical,
      hosts: hosts.size,
      eps: Number((rollingCount / 60).toFixed(2)),
    },

    severity,
    events_per_hour: eventsPerHour,

    top_hosts: Object.entries(topHostMap)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8),

    collector: {
      live_events: todayLogs.length,
      history_events: todayLogs.length,
    },
  };
};

function Dashboard({
  globalSearchQuery = { tokens: {}, keywords: [], raw: "" },
}) {
  const {
    analytics: contextAnalytics,
    connected,
    connectionState,
    analyticsLoading: contextLoading,
  } = useLiveSOC();

  const [lastUpdated, setLastUpdated] = useState(null);
  const [selectedLog, setSelectedLog] = useState(null);

  useEffect(() => {
    if (contextAnalytics) {
      setLastUpdated(new Date());
    }
  }, [contextAnalytics]);

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

    return useContextAnalytics
      ? buildTodayDashboardAnalytics(todayLogs, contextAnalytics)
      : buildTodayDashboardAnalytics(todayLogs);
  }, [todayLogs, contextAnalytics, contextLoading]);

  const restSummary = derivedAnalytics?.summary || {};
  const hasData = Boolean(contextAnalytics || todayLogs.length > 0);
  const isEmpty = !hasData && !contextLoading;

  const totalEventsCount =
    contextAnalytics?.summary?.total_events ?? todayLogs.length;

  const highSeverityCount = restSummary.high || 0;
  const windowsHostsCount = restSummary.hosts || 0;
  const eventsPerSecCount = restSummary.eps || 0;
  const critical = restSummary.critical || 0;

  const recentCriticalAlerts = useMemo(() => {
    if (
      contextAnalytics?.recentAlerts?.length > 0 &&
      !contextLoading
    ) {
      return contextAnalytics.recentAlerts;
    }

    return todayLogs
      .filter((log) =>
        SEVERITY_HIGH_VALUES.has(getSeverity(log))
      )
      .sort(
        (a, b) =>
          (parseEventTime(b)?.getTime() || 0) -
          (parseEventTime(a)?.getTime() || 0)
      );
  }, [todayLogs, contextAnalytics, contextLoading]);

  if (!contextAnalytics || contextLoading) {
    return <DashboardSkeleton />;
  }

  let health = "GOOD";
  let dot = "bg-green-400";
  let text = "text-green-400";
  let bg = "bg-green-500/10";
  let border = "border-green-500/20";

  if (connectionState === "reconnecting") {
    health = "RECONNECTING";
    dot = "bg-yellow-400";
    text = "text-yellow-400";
    bg = "bg-yellow-500/10";
    border = "border-yellow-500/20";
  } else if (
    connectionState === "disconnected" ||
    connectionState === "connecting"
  ) {
    health =
      connectionState === "connecting"
        ? "CONNECTING"
        : "DISCONNECTED";
    dot = "bg-slate-400";
    text = "text-slate-400";
    bg = "bg-slate-500/10";
    border = "border-slate-500/20";
  } else if (critical > 0 || highSeverityCount > 20) {
    health = "CRITICAL";
    dot = "bg-red-400";
    text = "text-red-400";
    bg = "bg-red-500/10";
    border = "border-red-500/20";
  } else if (highSeverityCount >= 5) {
    health = "WARNING";
    dot = "bg-orange-400";
    text = "text-orange-400";
    bg = "bg-orange-500/10";
    border = "border-orange-500/20";
  }

  const cardVariants = {
    hidden: { opacity: 0, y: 10 },
    visible: {
      opacity: 1,
      y: 0,
      transition: { duration: 0.3, ease: "easeOut" },
    },
  };

  return (
    <motion.div
      className="space-y-6 select-none"
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, ease: "easeOut" }}
    >
      {/* Dashboard header */}
      <div className="flex justify-between items-center bg-slate-900/10 p-2 rounded-xl border border-slate-900/40">
        <PageHeader
          title="Dashboard"
          subtitle="Monitor your SOC environment in real time."
        />

        <div className="flex items-center gap-4">
          <div className="text-right hidden sm:block">
            <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500">
              Real-Time Pulse
            </p>

            <p className="text-xs font-mono text-slate-300 mt-1">
              {lastUpdated
                ? lastUpdated.toLocaleTimeString("en-GB", {
                    hour12: false,
                  })
                : "--:--:--"}
            </p>
          </div>

          <div
            className={`flex items-center gap-2 px-3 py-2 rounded-lg border ${bg} ${border} shadow-sm font-mono`}
          >
            <div className={`w-2 h-2 rounded-full animate-pulse ${dot}`} />

            <span
              className={`text-xs font-bold tracking-wide uppercase ${text}`}
            >
              {health}
            </span>
          </div>
        </div>
      </div>

      {/* Metric cards */}
      <motion.div
        className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4"
        initial="hidden"
        animate="visible"
        transition={{ staggerChildren: 0.08 }}
      >
        <motion.div
          variants={cardVariants}
          whileHover={{ y: -3 }}
          transition={{ duration: 0.2 }}
        >
          <StatCard
            title="Total Events (Today)"
            value={contextLoading ? "Loading..." : totalEventsCount}
            color="#06b6d4"
          />
        </motion.div>

        <motion.div
          variants={cardVariants}
          whileHover={{ y: -3 }}
          transition={{ duration: 0.2 }}
        >
          <StatCard
            title="High Severity (Today)"
            value={contextLoading ? "Loading..." : highSeverityCount}
            color="#f97316"
          />
        </motion.div>

        <motion.div
          variants={cardVariants}
          whileHover={{ y: -3 }}
          transition={{ duration: 0.2 }}
        >
          <StatCard
            title="Windows Hosts (Today)"
            value={contextLoading ? "Loading..." : windowsHostsCount}
            color="#22c55e"
          />
        </motion.div>

        <motion.div
          variants={cardVariants}
          whileHover={{ y: -3 }}
          transition={{ duration: 0.2 }}
        >
          <StatCard
            title="Events / Sec (Live)"
            value={contextLoading ? "Loading..." : eventsPerSecCount}
            color="#3b82f6"
          />
        </motion.div>
      </motion.div>

      {/* Charts */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-4">
        <motion.div
          className="xl:col-span-8 bg-slate-900/20 border border-slate-800 rounded-xl p-4 min-h-[350px] flex items-center justify-center"
          variants={cardVariants}
          initial="hidden"
          animate="visible"
          whileHover={{ y: -2 }}
        >
          {isEmpty ? (
            <p className="text-slate-400 text-lg">
              No events collected today
            </p>
          ) : (
            <AlertTrendChart
              logs={todayLogs}
              analytics={derivedAnalytics}
            />
          )}
        </motion.div>

        <motion.div
          className="xl:col-span-4 bg-slate-900/20 border border-slate-800 rounded-xl p-4 min-h-[350px] flex items-center justify-center"
          variants={cardVariants}
          initial="hidden"
          animate="visible"
          whileHover={{ y: -2 }}
        >
          {isEmpty ? (
            <p className="text-slate-400 text-lg">
              No events collected today
            </p>
          ) : (
            <SeverityChart
              logs={todayLogs}
              analytics={derivedAnalytics}
            />
          )}
        </motion.div>
      </div>

      {/* Top hosts and collector status */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <motion.div
          className="bg-slate-900/20 border border-slate-800 rounded-xl p-4 flex items-center justify-center min-h-[200px]"
          variants={cardVariants}
          initial="hidden"
          animate="visible"
          whileHover={{ y: -2 }}
        >
          {isEmpty ? (
            <p className="text-slate-400">No data available</p>
          ) : (
            <TopHostsCard analytics={derivedAnalytics} />
          )}
        </motion.div>

        <motion.div
          className="bg-slate-900/20 border border-slate-800 rounded-xl p-4 flex items-center justify-center min-h-[200px]"
          variants={cardVariants}
          initial="hidden"
          animate="visible"
          whileHover={{ y: -2 }}
        >
          {isEmpty ? (
            <p className="text-slate-400">No data available</p>
          ) : (
            <CollectorStatusCard
              analytics={derivedAnalytics}
              connected={connected}
              connectionState={connectionState}
            />
          )}
        </motion.div>
      </div>

      {/* Recent critical alerts */}
      <motion.div
        className="bg-slate-900/20 border border-slate-800 rounded-xl p-4"
        variants={cardVariants}
        initial="hidden"
        animate="visible"
      >
        <div className="flex items-center justify-between mb-4 border-b border-slate-800/60 pb-3">
          <h3 className="text-xs font-bold uppercase text-slate-400 tracking-[0.2em]">
            Recent Critical Alerts (Today Window)
          </h3>

          <span className="text-[10px] font-mono text-slate-500 font-bold bg-slate-900/60 px-2 py-0.5 rounded border border-slate-800">
            {isEmpty
              ? "No data"
              : `${recentCriticalAlerts.length} High/Crit Alerts Logged`}
          </span>
        </div>

        {isEmpty ? (
          <div className="flex items-center justify-center py-8 text-slate-400">
            No critical alerts to display
          </div>
        ) : (
          <RecentAlerts
            logs={recentCriticalAlerts}
            onInvestigate={setSelectedLog}
          />
        )}
      </motion.div>

      <EventDetailsDrawer
        log={selectedLog}
        onClose={() => setSelectedLog(null)}
      />
    </motion.div>
  );
}

export default Dashboard;
