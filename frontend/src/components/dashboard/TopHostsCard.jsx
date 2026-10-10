import { Monitor, HelpCircle } from "lucide-react";

function TopHostsCard({ analytics }) {
  const hosts = analytics?.top_hosts || [];

  return (
    <div className="flex h-full w-full flex-col justify-between rounded-xl border border-slate-800/80 bg-slate-950/60 p-4">
      <div>
        {/* Header */}
        <div className="mb-4 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Monitor size={16} className="text-slate-400" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-100">
              Top Hosts
            </h2>
          </div>

          <span className="whitespace-nowrap font-mono text-[10px] font-semibold uppercase tracking-wider text-slate-500">
            Live Connection
          </span>
        </div>

        {/* Host List */}
        {hosts.length > 0 && (
          <div className="space-y-1">
            {hosts.slice(0, 8).map((host, index) => (
              <div
                key={host?.[0] || index}
                className="flex items-center justify-between gap-3 rounded-lg px-2 py-2 transition-colors duration-150 hover:bg-slate-900/70"
              >
                <div className="min-w-0">
                  <p className="truncate text-xs font-semibold text-slate-200">
                    {host?.[0] || "Unknown"}
                  </p>
                  <p className="mt-0.5 text-[10px] font-medium text-slate-500">
                    Windows Endpoint
                  </p>
                </div>

                <span className="shrink-0 rounded-md border border-slate-800 bg-slate-900 px-2.5 py-1 font-mono text-xs font-semibold tabular-nums text-slate-300">
                  {host?.[1] ?? 0}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Empty State */}
      {hosts.length === 0 && (
        <div className="flex min-h-[144px] flex-1 flex-col items-center justify-center rounded-xl px-4 text-center">
          <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-xl border border-slate-800 bg-slate-900/70">
            <HelpCircle size={20} className="text-slate-500" />
          </div>

          <p className="text-xs font-semibold tracking-wide text-slate-300">
            No Hosts Available
          </p>

          <p className="mt-1 max-w-[240px] text-[11px] leading-relaxed text-slate-500">
            Waiting for endpoint metrics from the backend analytics pipeline.
          </p>
        </div>
      )}
    </div>
  );
}

export default TopHostsCard;