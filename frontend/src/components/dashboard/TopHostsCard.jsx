import { Monitor, HelpCircle } from "lucide-react";

function TopHostsCard({ analytics }) {
  const hosts = analytics?.top_hosts || [];

  return (
    <div className="w-full bg-transparent h-full p-4 flex flex-col justify-between border border-slate-800/80 rounded-xl">
      <div>
        {/* Seamless Header Row */}
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Monitor size={16} className="text-cyan-400" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-white">
              Top Hosts
            </h2>
          </div>
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 font-mono">
            Live Connection
          </span>
        </div>

        {/* High-Density Row Matrix */}
        {hosts.length > 0 && (
          <div className="space-y-1">
            {hosts.slice(0, 8).map((host, index) => (
              <div
                key={index}
                className="flex items-center justify-between py-1.5 border-none hover:bg-slate-900/40 px-2 rounded-lg transition-colors duration-100"
              >
                <div>
                  <p className="text-xs font-semibold text-slate-200">
                    {host[0] || "Unknown"}
                  </p>
                  <p className="text-[10px] text-slate-500 font-medium">
                    Windows Endpoint
                  </p>
                </div>
                <span className="px-2.5 py-0.5 rounded-md bg-cyan-500/5 text-cyan-400 font-mono text-xs font-bold">
                  {host[1]}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Vibrant Empty State */}
      {hosts.length === 0 && (
        <div className="flex-1 flex flex-col items-center justify-center text-center px-4 rounded-xl bg-slate-900/10 min-h-[144px]">
          <HelpCircle size={22} className="text-slate-600 mb-2" />
          <p className="text-xs font-bold text-slate-400 tracking-wide">
            No Hosts Available
          </p>
          <p className="text-[11px] text-slate-500 max-w-[240px] mt-0.5 leading-relaxed">
            Backend analytics pipe is waiting for asset metric collection frames.
          </p>
        </div>
      )}
    </div>
  );
}

export default TopHostsCard;