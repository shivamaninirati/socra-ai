import SeverityBadge from "./SeverityBadge";

function HuntResultsTable({ results = [] }) {
    if (!results.length) {
        return (
            <div className="rounded-xl border border-slate-800/80 bg-slate-950/60 p-10 text-center">
                <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-xl border border-slate-800 bg-slate-900">
                    <svg
                        xmlns="http://www.w3.org/2000/svg"
                        width="22"
                        height="22"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="1.7"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        className="text-slate-500"
                    >
                        <circle cx="11" cy="11" r="8" />
                        <path d="m21 21-4.35-4.35" />
                    </svg>
                </div>
                <p className="text-sm font-medium text-slate-300">
                    No hunt results
                </p>
                <p className="mt-1 text-xs text-slate-500">
                    Run a threat hunt to discover matching security events.
                </p>
            </div>
        );
    }

    return (
        <div className="overflow-hidden rounded-xl border border-slate-800/80 bg-slate-950/60">
            <div className="flex items-center justify-between border-b border-slate-800/80 px-5 py-4">
                <div>
                    <h3 className="text-sm font-semibold text-slate-100">
                        Hunt Results
                    </h3>
                    <p className="mt-1 text-xs text-slate-500">
                        Matching security events from your hunt
                    </p>
                </div>

                <span className="rounded-md border border-slate-700/70 bg-slate-900 px-2.5 py-1 text-xs font-medium text-slate-300">
                    {results.length} {results.length === 1 ? "event" : "events"}
                </span>
            </div>

            <div className="overflow-x-auto">
                <table className="w-full min-w-[720px] text-left">
                    <thead className="border-b border-slate-800 bg-slate-900/70">
                        <tr>
                            <th className="px-5 py-3 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                                Time
                            </th>
                            <th className="px-5 py-3 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                                Host
                            </th>
                            <th className="px-5 py-3 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                                Event / Process
                            </th>
                            <th className="px-5 py-3 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                                Severity
                            </th>
                        </tr>
                    </thead>

                    <tbody className="divide-y divide-slate-800/70">
                        {results.map((log, index) => (
                            <tr
                                key={log.event?.event_id ?? `${log.event?.time}-${index}`}
                                className="transition-colors duration-150 hover:bg-slate-900/60"
                            >
                                <td className="whitespace-nowrap px-5 py-4 text-xs text-slate-400">
                                    {log.event?.time
                                        ? new Date(log.event.time).toLocaleString()
                                        : "—"}
                                </td>

                                <td className="px-5 py-4">
                                    <span
                                        className="inline-block max-w-[180px] truncate rounded-md border border-slate-700/70 bg-slate-900 px-2 py-1 text-xs font-medium text-slate-300"
                                        title={log.event?.host || "Unknown host"}
                                    >
                                        {log.event?.host || "Unknown host"}
                                    </span>
                                </td>

                                <td className="max-w-[360px] px-5 py-4">
                                    <p
                                        className="truncate text-sm font-medium text-slate-200"
                                        title={log.event?.process_name || "Unknown process"}
                                    >
                                        {log.event?.process_name || "Unknown process"}
                                    </p>
                                </td>

                                <td className="whitespace-nowrap px-5 py-4">
                                    <SeverityBadge
                                        severity={log.detection?.severity || "Informational"}
                                    />
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            <div className="border-t border-slate-800/80 bg-slate-900/30 px-5 py-3">
                <p className="text-xs text-slate-500">
                    Showing {results.length} matching{" "}
                    {results.length === 1 ? "event" : "events"}
                </p>
            </div>
        </div>
    );
}

export default HuntResultsTable;