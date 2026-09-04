import { Database, Activity, ShieldCheck, Cpu, Wifi, WifiOff, RefreshCw, ShieldAlert, CircleSlash } from "lucide-react";

function CollectorStatusCard({ analytics, connected = false, connectionState = "disconnected" }) {
  const collector = analytics?.collector || {};

  const wsStatus = (() => {
    if (connected && connectionState === "connected") {
      return { color: "text-green-400", dot: "bg-green-400", label: "CONNECTED", icon: <Wifi size={12} /> };
    }
    if (connectionState === "reconnecting") {
      return { color: "text-yellow-400", dot: "bg-yellow-400", label: "RECONNECTING", icon: <RefreshCw size={12} className="animate-spin" /> };
    }
    return { color: "text-red-400", dot: "bg-red-400", label: "OFFLINE", icon: <WifiOff size={12} /> };
  })();

  // Collector runtime comes from the backend (single source of truth). The
  // status is NEVER assumed: it is "Running" only when a collector process
  // (standalone or in-process) is actually reporting.
  const running = collector.running === true || String(collector.status || "").toLowerCase() === "running";
  const privilegeBlocked = running && collector.security_log_accessible === false;

  const profileBadge = running
    ? { color: "text-emerald-400", bg: "bg-emerald-500/10" }
    : { color: "text-red-400", bg: "bg-red-500/10" };

  const status = [
    { icon: <ShieldCheck size={14} className="text-emerald-400" />, name: "Collector Profile", value: running ? "Running" : "Stopped", isBadge: true, badgeColor: profileBadge },
    { icon: <Database size={14} />, name: "Live Store (today)", value: collector.live_events ?? 0, title: "Events in the live in-memory store (today's persisted events + new events)" },
    { icon: <Database size={14} />, name: "Persisted History (all time)", value: collector.history_events ?? 0, title: "Total rows persisted in the SQLite events table" },
    { icon: <Activity size={14} />, name: "Throughput (EPS)", value: analytics?.summary?.eps ?? 0 },
  ];

  return (
    <div className="w-full bg-transparent h-full p-4 flex flex-col border border-slate-800/80 rounded-xl">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Cpu size={16} className="text-cyan-400" />
          <h2 className="text-sm font-bold uppercase tracking-wider text-white">Collector Status</h2>
        </div>
        <div className={`flex items-center gap-1.5 ${wsStatus.color} text-[10px] font-bold tracking-wider`}>
          <span className={`w-1.5 h-1.5 rounded-full ${wsStatus.dot} ${connectionState === "reconnecting" ? "" : "animate-pulse"}`} />
          {wsStatus.icon}
          <span>{wsStatus.label}</span>
        </div>
      </div>

      {!running && (
        <div className="flex items-start gap-2 mb-3 px-2 py-2 bg-red-500/5 border border-red-500/20 rounded-lg">
          <CircleSlash size={13} className="text-red-400 shrink-0 mt-0.5" />
          <p className="text-[10px] text-red-300/90 leading-4">
            {collector.message || "No collector is running. Events will not be collected."}
          </p>
        </div>
      )}

      {privilegeBlocked && (
        <div className="flex items-start gap-2 mb-3 px-2 py-2 bg-amber-500/5 border border-amber-500/20 rounded-lg">
          <ShieldAlert size={13} className="text-amber-400 shrink-0 mt-0.5" />
          <p className="text-[10px] text-amber-300/90 leading-4">
            {collector.privilege_error || collector.message || "Security channel collection requires Administrator privileges."}
          </p>
        </div>
      )}

      <div className="space-y-1 flex-1 flex flex-col justify-between">
        {status.map((item, index) => (
          <div key={index} title={item.title} className="flex justify-between items-center py-1.5 border-none hover:bg-slate-900/40 px-2 rounded-lg transition-colors duration-100">
            <div className="flex items-center gap-2.5 text-xs font-semibold text-slate-300">
              <span className="text-slate-500">{item.icon}</span>
              <span>{item.name}</span>
            </div>
            <span className={`font-mono text-xs font-bold px-2.5 py-0.5 rounded-md ${
              item.isBadge
                ? `${item.badgeColor.bg} ${item.badgeColor.color} uppercase tracking-wide text-[10px]`
                : "bg-cyan-500/5 text-cyan-400"
            }`}>
              {item.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default CollectorStatusCard;
