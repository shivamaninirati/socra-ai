import {
  Database,
  Activity,
  ShieldCheck,
  Cpu,
  Wifi,
  WifiOff,
  RefreshCw,
  ShieldAlert,
  CircleSlash,
} from "lucide-react";

function CollectorStatusCard({
  analytics,
  connected = false,
  connectionState = "disconnected",
}) {
  const collector = analytics?.collector || {};

  const wsStatus = (() => {
    if (connected && connectionState === "connected") {
      return {
        color: "text-emerald-400",
        dot: "bg-emerald-400",
        label: "CONNECTED",
        icon: <Wifi size={12} />,
      };
    }

    if (connectionState === "reconnecting") {
      return {
        color: "text-amber-400",
        dot: "bg-amber-400",
        label: "RECONNECTING",
        icon: <RefreshCw size={12} className="animate-spin" />,
      };
    }

    return {
      color: "text-red-400",
      dot: "bg-red-400",
      label: "OFFLINE",
      icon: <WifiOff size={12} />,
    };
  })();

  // Runtime status is reported by the backend.
  const running =
    collector.running === true ||
    String(collector.status || "").toLowerCase() === "running";

  const privilegeBlocked =
    running && collector.security_log_accessible === false;

  const profileBadge = running
    ? {
        color: "text-emerald-400",
        bg: "bg-emerald-500/10",
      }
    : {
        color: "text-red-400",
        bg: "bg-red-500/10",
      };

  const status = [
    {
      icon: <ShieldCheck size={14} />,
      name: "Collector Profile",
      value: running ? "Running" : "Stopped",
      isBadge: true,
      badgeColor: profileBadge,
    },
    {
      icon: <Database size={14} />,
      name: "Live Store (today)",
      value: collector.live_events ?? 0,
      title:
        "Events in the live in-memory store (today's persisted events + new events)",
    },
    {
      icon: <Database size={14} />,
      name: "Persisted History (all time)",
      value: collector.history_events ?? 0,
      title: "Total rows persisted in the SQLite events table",
    },
    {
      icon: <Activity size={14} />,
      name: "Throughput (EPS)",
      value: analytics?.summary?.eps ?? 0,
    },
  ];

  return (
    <div className="flex h-full w-full flex-col rounded-xl border border-slate-800/80 bg-slate-950/60 p-4 transition-colors duration-200 hover:border-slate-700/80">
      {/* Header */}
      <div className="mb-4 flex items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-slate-800 bg-slate-900/80">
            <Cpu size={15} className="text-slate-300" />
          </div>

          <div className="min-w-0">
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-100">
              Collector Status
            </h2>
            <p className="mt-0.5 text-[10px] text-slate-500">
              Telemetry & runtime health
            </p>
          </div>
        </div>

        <div
          className={`flex shrink-0 items-center gap-1.5 rounded-md border border-slate-800/80 bg-slate-900/60 px-2 py-1 text-[9px] font-bold tracking-wider ${wsStatus.color}`}
        >
          <span
            className={`h-1.5 w-1.5 rounded-full ${wsStatus.dot} ${
              connectionState === "reconnecting" ? "" : "animate-pulse"
            }`}
          />
          {wsStatus.icon}
          <span>{wsStatus.label}</span>
        </div>
      </div>

      {/* Collector warnings */}
      {!running && (
        <div className="mb-3 flex items-start gap-2 rounded-lg border border-red-500/15 bg-red-500/[0.04] px-3 py-2.5">
          <CircleSlash
            size={13}
            className="mt-0.5 shrink-0 text-red-400"
          />

          <div className="min-w-0">
            <p className="text-[10px] font-semibold text-red-300">
              Collector unavailable
            </p>
            <p className="mt-0.5 break-words text-[10px] leading-4 text-slate-400">
              {collector.message ||
                "No collector is running. Events will not be collected."}
            </p>
          </div>
        </div>
      )}

      {privilegeBlocked && (
        <div className="mb-3 flex items-start gap-2 rounded-lg border border-amber-500/15 bg-amber-500/[0.04] px-3 py-2.5">
          <ShieldAlert
            size={13}
            className="mt-0.5 shrink-0 text-amber-400"
          />

          <div className="min-w-0">
            <p className="text-[10px] font-semibold text-amber-300">
              Restricted log access
            </p>
            <p className="mt-0.5 break-words text-[10px] leading-4 text-slate-400">
              {collector.privilege_error ||
                collector.message ||
                "Security channel collection requires Administrator privileges."}
            </p>
          </div>
        </div>
      )}

      {/* Status metrics */}
      <div className="flex flex-1 flex-col justify-between gap-1">
        {status.map((item, index) => (
          <div
            key={index}
            title={item.title}
            className="group flex items-center justify-between gap-3 rounded-lg border border-transparent px-2.5 py-2 transition-colors duration-150 hover:border-slate-800/70 hover:bg-slate-900/50"
          >
            <div className="flex min-w-0 items-center gap-2.5">
              <span
                className={`shrink-0 ${
                  item.isBadge
                    ? running
                      ? "text-emerald-400"
                      : "text-red-400"
                    : "text-slate-500"
                }`}
              >
                {item.icon}
              </span>

              <span className="truncate text-[11px] font-medium text-slate-400 transition-colors group-hover:text-slate-200">
                {item.name}
              </span>
            </div>

            <span
              className={`shrink-0 rounded-md px-2.5 py-1 font-mono text-[11px] font-semibold tabular-nums ${
                item.isBadge
                  ? `${item.badgeColor.bg} ${item.badgeColor.color} text-[9px] uppercase tracking-wider`
                  : "border border-slate-800/70 bg-slate-900/70 text-slate-200"
              }`}
            >
              {item.value}
            </span>
          </div>
        ))}
      </div>

      {/* Footer */}
      <div className="mt-4 flex items-center justify-between border-t border-slate-800/70 pt-3">
        <div className="flex items-center gap-1.5">
          <span
            className={`h-1.5 w-1.5 rounded-full ${
              running ? "bg-emerald-400" : "bg-red-400"
            }`}
          />
          <span className="text-[9px] font-medium uppercase tracking-wider text-slate-500">
            Runtime
          </span>
        </div>

        <span
          className={`text-[9px] font-semibold uppercase tracking-wider ${
            running ? "text-emerald-400" : "text-red-400"
          }`}
        >
          {running ? "Operational" : "Unavailable"}
        </span>
      </div>
    </div>
  );
}

export default CollectorStatusCard;