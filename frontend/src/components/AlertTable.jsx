import { ArrowUpRight, Cpu, Monitor } from "lucide-react";

import SeverityBadge from "./SeverityBadge";

const ROW_HEIGHT = 56;

// Real alert triage lifecycle (Task 17) — one visual treatment per status so
// the queue reads at a glance. Colors are display-only; the status itself is
// the persisted analyst-set value served by the backend.
const STATUS_STYLES = {
  New: "border-cyan-500/10 bg-cyan-500/5 text-cyan-400",
  Investigating: "border-amber-500/20 bg-amber-500/10 text-amber-400",
  Contained: "border-violet-500/20 bg-violet-500/10 text-violet-400",
  Resolved: "border-emerald-500/20 bg-emerald-500/10 text-emerald-400",
  Closed: "border-slate-600/40 bg-slate-700/20 text-slate-400",
};

function AlertTable({ logs = [], onSelect, onInvestigate, totalCount = 0 }) {
  const formatTime = (time) => {
    if (!time) {
      return { clock: "-", date: "" };
    }

    try {
      const parsed = new Date(time);
      return {
        clock: parsed.toLocaleTimeString("en-GB", { hour12: false }),
        date: parsed.toLocaleDateString("en-GB", { day: "2-digit", month: "short" }),
      };
    } catch {
      return { clock: time, date: "" };
    }
  };

  const getMitre = (log) => {
    const mitre = log?.detection?.mitre;

    // Canonical detection.mitre is a list of blocks (single technique = one
    // element list); legacy rows may carry a plain dict or string. Show the
    // first mapped technique when multiple exist.
    let block = mitre;
    if (Array.isArray(mitre)) {
      block = mitre.length > 0 ? mitre[0] : null;
    }

    if (block && typeof block === "object") {
      return {
        id: block?.id || "-",
        tactic: block?.tactic || "",
      };
    }

    return {
      id: block || "-",
      tactic: "",
    };
  };

  // Events with no process / PID / MITRE information carry explicit sentinels
  // from the backend normalization layer (never fabricated values).
  const isUnmappedMitre = (id) =>
    !id || id === "-" || id === "N/A" || id === "Unknown" || id === "Unmapped";

  return (
    <div className="w-full">
      <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
        <div>
          <h2 className="text-sm font-bold uppercase tracking-wider text-white">Alert Queue</h2>
          <p className="mt-0.5 text-xs text-slate-500">
            {totalCount.toLocaleString()} matching Windows security events
          </p>
        </div>
      </div>

      <table className="w-full min-w-[1100px] table-fixed border-collapse">
        <thead>
          <tr className="border-b border-slate-800 text-left text-[11px] font-bold uppercase tracking-wider text-slate-500">
            <th className="w-[138px] px-4 py-3">Time</th>
            <th className="w-[116px] px-4 py-3 text-center">Severity</th>
            <th className="w-[160px] px-4 py-3">Host</th>
            <th className="w-[92px] px-4 py-3 text-center">Event ID</th>
            <th className="px-4 py-3">Process</th>
            <th className="w-[110px] px-4 py-3 text-center">PID</th>
            <th className="w-[138px] px-4 py-3 text-center">MITRE</th>
            <th className="w-[92px] px-4 py-3 text-center">Status</th>
            <th className="w-[126px] px-4 py-3 text-right">Action</th>
          </tr>
        </thead>

        <tbody className="divide-y divide-slate-900/80">
          {logs.length === 0 ? (
            <tr>
              <td colSpan={9} className="px-4 py-16 text-center">
                <p className="text-sm font-semibold text-slate-400">No alerts match the active filters.</p>
                <p className="mt-1 text-xs text-slate-600">Adjust the filter row or wait for new live telemetry.</p>
              </td>
            </tr>
          ) : (
            logs.map((log, index) => {
              const event = log.event || {};
              const detection = log.detection || {};
              const time = formatTime(event.time);
              const processName = event.process_name || "Not available in event";
              const processId = event.process_id || "Not available";
              const host = event.host || event.computer || "-";
              const mitre = getMitre(log);
              const status = event.status || detection.status || "New";
              const key = log?.metadata?.fingerprint ||
                `${event.time}-${event.event_id}-${event.record_number || index}`;

              return (
                <tr
                  key={key}
                  onClick={() => onSelect?.(log)}
                  className="cursor-pointer bg-slate-950/10 transition hover:bg-slate-900/50"
                >
                  <td className="px-4 py-3 align-middle">
                    <div className="font-mono text-sm font-semibold text-slate-200">{time.clock}</div>
                    <div className="text-xs text-slate-500">{time.date}</div>
                  </td>

                  <td className="px-4 py-3 text-center align-middle">
                    <div className="inline-flex scale-95">
                      <SeverityBadge severity={detection.severity} />
                    </div>
                  </td>

                  <td className="px-4 py-3 align-middle">
                    <div className="flex min-w-0 items-center gap-2">
                      <Monitor size={14} className="shrink-0 text-slate-600" />
                      <span title={host} className="truncate text-sm font-semibold text-slate-200">
                        {host}
                      </span>
                    </div>
                  </td>

                  <td className="px-4 py-3 text-center align-middle font-mono text-sm font-bold text-cyan-400">
                    {event.event_id || "-"}
                  </td>

                  <td className="px-4 py-3 align-middle">
                    <div className="flex min-w-0 items-center gap-2">
                      <Cpu size={14} className="shrink-0 text-slate-600" />
                      <span title={processName} className={"truncate font-mono text-sm " +
                        (processName === "Not available in event" ? "text-slate-600" : "text-slate-300")}>
                        {processName}
                      </span>
                    </div>
                  </td>

                  {/* Real PID from telemetry, kept as a separate field from the
                      process name (never combined, never synthesized). */}
                  <td className="px-4 py-3 text-center align-middle">
                    <span
                      title={processId}
                      className={"font-mono text-sm " +
                        (processId === "Not available" ? "text-slate-600" : "text-slate-400")}
                    >
                      {processId}
                    </span>
                  </td>

                  <td className="px-4 py-3 text-center align-middle">
                    {isUnmappedMitre(mitre.id) ? (
                      <span className="text-slate-600">Unmapped</span>
                    ) : (
                      <div className="min-w-0">
                        <div title={mitre.id} className="truncate font-mono text-sm font-bold text-purple-400">
                          {mitre.id}
                        </div>
                        {mitre.tactic && (
                          <div title={mitre.tactic} className="truncate text-[10px] font-bold uppercase tracking-wider text-slate-500">
                            {mitre.tactic}
                          </div>
                        )}
                      </div>
                    )}
                  </td>

                  <td className="px-4 py-3 text-center align-middle">
                    <span
                      title={log?._status_changed_by ? `Changed by ${log._status_changed_by}` : status}
                      className={`inline-flex rounded-md border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide ${STATUS_STYLES[status] || STATUS_STYLES.New}`}
                    >
                      {status}
                    </span>
                  </td>

                  <td className="px-4 py-3 text-right align-middle">
                    <button
                      onClick={(event) => {
                        event.stopPropagation();
                        onInvestigate?.(log);
                      }}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-1.5 text-xs font-bold text-slate-300 transition hover:border-cyan-500/40 hover:text-white"
                    >
                      Investigate
                      <ArrowUpRight size={13} />
                    </button>
                  </td>
                </tr>
              );
            })
          )}
        </tbody>
      </table>
    </div>
  );
}

export default AlertTable;
export { ROW_HEIGHT };
