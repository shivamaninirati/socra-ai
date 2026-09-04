import { useState, useMemo, useEffect } from "react";
import { ChevronLeft, ChevronRight, AlertTriangle } from "lucide-react";
import SeverityBadge from "../SeverityBadge";

const ROWS_PER_PAGE = 50;

function RecentAlerts({ logs = [], onInvestigate }) {
  const [currentPage, setCurrentPage] = useState(1);

  const alerts = useMemo(() => {
    return logs
      .filter((log) => {
        const s = (log?.detection?.severity || "").toLowerCase();
        return s === "high" || s === "critical";
      })
      .sort((a, b) => {
        const tA = new Date(a?.event?.time || a?.time || 0);
        const tB = new Date(b?.event?.time || b?.time || 0);
        return tB - tA;
      });
  }, [logs]);

  const totalAlerts = alerts.length;
  const totalPages = Math.max(1, Math.ceil(totalAlerts / ROWS_PER_PAGE));
  const startIndex = (currentPage - 1) * ROWS_PER_PAGE;
  const endIndex = Math.min(startIndex + ROWS_PER_PAGE, totalAlerts);
  const paginatedAlerts = alerts.slice(startIndex, endIndex);

  // Reset to page 1 if current page exceeds total pages (e.g., after data change)
  useEffect(() => {
    if (currentPage > totalPages) setCurrentPage(1);
  }, [totalPages, currentPage]);

  const goToPage = (page) => {
    setCurrentPage(Math.max(1, Math.min(page, totalPages)));
  };

  // Generate page numbers for pagination bar
  const getPageNumbers = () => {
    const pages = [];
    const maxVisible = 7;
    if (totalPages <= maxVisible) {
      for (let i = 1; i <= totalPages; i++) pages.push(i);
    } else {
      pages.push(1);
      let start = Math.max(2, currentPage - 2);
      let end = Math.min(totalPages - 1, currentPage + 2);
      if (currentPage <= 3) { start = 2; end = Math.min(5, totalPages - 1); }
      if (currentPage >= totalPages - 2) { start = Math.max(2, totalPages - 4); end = totalPages - 1; }
      if (start > 2) pages.push("...");
      for (let i = start; i <= end; i++) pages.push(i);
      if (end < totalPages - 1) pages.push("...");
      pages.push(totalPages);
    }
    return pages;
  };

  return (
    <div className="w-full bg-transparent">
      
      {/* Seamless Header Block */}
      <div className="px-4 py-2 flex items-center justify-between">
        <div>
          <h2 className="text-sm font-bold uppercase tracking-wider text-white">
            Recent Critical Alerts
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            High-priority security events — {totalAlerts} total
          </p>
        </div>
        {totalAlerts > 0 && (
          <div className="flex items-center gap-1.5 text-[11px] font-mono text-slate-500 font-bold bg-slate-900/60 px-2.5 py-1 rounded-lg border border-slate-800/60">
            <AlertTriangle size={12} className="text-cyan-400" />
            <span>Showing {startIndex + 1}–{endIndex} of {totalAlerts}</span>
          </div>
        )}
      </div>

      {/* High-Density Borderless Logging Matrix */}
      <div className="overflow-x-auto w-full">
        <table className="w-full border-collapse">
          <thead>
            <tr className="text-slate-500 text-[11px] font-bold uppercase tracking-wider border-none">
              <th className="text-left px-4 py-2">Time</th>
              <th className="text-left px-4 py-2">Host</th>
              <th className="text-center px-4 py-2">Event</th>
              <th className="text-center px-4 py-2">Severity</th>
              <th className="text-right px-4 py-2">Action</th>
            </tr>
          </thead>
          
          <tbody className="divide-none">
            {paginatedAlerts.length === 0 ? (
              <tr className="border-none">
                <td
                  colSpan={5}
                  className="py-8 text-center text-sm font-medium text-slate-600"
                >
                  No critical alerts.
                </td>
              </tr>
            ) : (
              paginatedAlerts.map((log, index) => (
                <tr
                  key={log?.metadata?.fingerprint || `alert-${startIndex + index}`}
                  className="border-none hover:bg-slate-900/40 transition-colors duration-100"
                >
                  {/* Event Timestamp */}
                  <td className="px-4 py-2 text-xs font-mono text-slate-400 whitespace-nowrap">
                    {new Date(log.event?.time).toLocaleString("en-GB", {
                      hour12: false,
                    })}
                  </td>

                  {/* Targeted Endpoint Host */}
                  <td className="px-4 py-2 text-xs font-semibold text-slate-200">
                    {log.event?.host}
                  </td>

                  {/* Windows Event ID String */}
                  <td className="px-4 py-2 text-center font-mono text-xs font-bold text-cyan-500/90">
                    {log.event?.event_id}
                  </td>

                  {/* Severity Badge Asset */}
                  <td className="px-4 py-2 text-center transform scale-95 origin-center">
                    <SeverityBadge severity={log.detection?.severity} />
                  </td>

                  {/* Micro Session Action Triage Trigger */}
                  <td className="px-4 py-2 text-right">
                    <button
                      onClick={() => onInvestigate?.(log)}
                      className="px-2.5 py-1 text-xs font-bold rounded bg-slate-800 text-slate-300 hover:bg-cyan-600 hover:text-white transition-all duration-150"
                    >
                      Open
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Enterprise Pagination Controls */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between px-4 py-3 border-t border-slate-800/40">
          <div className="flex items-center gap-1 text-[10px] font-mono text-slate-600 font-bold">
            <span>{ROWS_PER_PAGE} rows per page</span>
          </div>

          <div className="flex items-center gap-1">
            <button
              onClick={() => goToPage(currentPage - 1)}
              disabled={currentPage <= 1}
              className="p-1.5 rounded-lg text-slate-500 hover:text-white hover:bg-slate-800/80 disabled:opacity-30 disabled:cursor-not-allowed transition-all"
              title="Previous page"
            >
              <ChevronLeft size={14} />
            </button>

            {getPageNumbers().map((page, idx) =>
              page === "..." ? (
                <span key={`ellipsis-${idx}`} className="px-1.5 text-[10px] text-slate-600 font-bold">...</span>
              ) : (
                <button
                  key={`page-${page}`}
                  onClick={() => goToPage(page)}
                  className={`min-w-[28px] h-7 px-1.5 rounded-lg text-[11px] font-bold font-mono transition-all ${
                    currentPage === page
                      ? "bg-cyan-600/20 text-cyan-400 border border-cyan-500/30"
                      : "text-slate-500 hover:text-slate-300 hover:bg-slate-800/60 border border-transparent"
                  }`}
                >
                  {page}
                </button>
              )
            )}

            <button
              onClick={() => goToPage(currentPage + 1)}
              disabled={currentPage >= totalPages}
              className="p-1.5 rounded-lg text-slate-500 hover:text-white hover:bg-slate-800/80 disabled:opacity-30 disabled:cursor-not-allowed transition-all"
              title="Next page"
            >
              <ChevronRight size={14} />
            </button>
          </div>

          <div className="text-[10px] font-mono text-slate-600 font-bold">
            Page {currentPage} of {totalPages}
          </div>
        </div>
      )}
    </div>
  );
}

export default RecentAlerts;