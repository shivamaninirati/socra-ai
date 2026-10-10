import { useState, useMemo, useEffect } from "react";
import {
  ChevronLeft,
  ChevronRight,
  AlertTriangle,
  ShieldAlert,
} from "lucide-react";
import { motion, AnimatePresence, useReducedMotion } from "motion/react";
import SeverityBadge from "../SeverityBadge";

const ROWS_PER_PAGE = 50;

const containerVariants = {
  hidden: { opacity: 0, y: 8 },
  visible: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.35,
      ease: "easeOut",
      when: "beforeChildren",
      staggerChildren: 0.045,
    },
  },
};

const rowVariants = {
  hidden: { opacity: 0, y: 5 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.22, ease: "easeOut" },
  },
  exit: {
    opacity: 0,
    y: -3,
    transition: { duration: 0.12, ease: "easeIn" },
  },
};

function RecentAlerts({ logs = [], onInvestigate }) {
  const [currentPage, setCurrentPage] = useState(1);
  const shouldReduceMotion = useReducedMotion();

  const alerts = useMemo(() => {
    return logs
      .filter((log) => {
        const severity = (
          log?.detection?.severity || ""
        ).toLowerCase();

        return severity === "high" || severity === "critical";
      })
      .sort((a, b) => {
        const timeA = new Date(
          a?.event?.time || a?.time || 0
        ).getTime();

        const timeB = new Date(
          b?.event?.time || b?.time || 0
        ).getTime();

        return timeB - timeA;
      });
  }, [logs]);

  const totalAlerts = alerts.length;
  const totalPages = Math.max(
    1,
    Math.ceil(totalAlerts / ROWS_PER_PAGE)
  );

  const startIndex = (currentPage - 1) * ROWS_PER_PAGE;
  const endIndex = Math.min(
    startIndex + ROWS_PER_PAGE,
    totalAlerts
  );

  const paginatedAlerts = alerts.slice(startIndex, endIndex);

  useEffect(() => {
    if (currentPage > totalPages) {
      setCurrentPage(1);
    }
  }, [currentPage, totalPages]);

  const goToPage = (page) => {
    setCurrentPage(Math.max(1, Math.min(page, totalPages)));
  };

  const getPageNumbers = () => {
    const pages = [];
    const maxVisible = 7;

    if (totalPages <= maxVisible) {
      for (let page = 1; page <= totalPages; page++) {
        pages.push(page);
      }
    } else {
      pages.push(1);

      let start = Math.max(2, currentPage - 2);
      let end = Math.min(totalPages - 1, currentPage + 2);

      if (currentPage <= 3) {
        start = 2;
        end = Math.min(5, totalPages - 1);
      }

      if (currentPage >= totalPages - 2) {
        start = Math.max(2, totalPages - 4);
        end = totalPages - 1;
      }

      if (start > 2) {
        pages.push("...");
      }

      for (let page = start; page <= end; page++) {
        pages.push(page);
      }

      if (end < totalPages - 1) {
        pages.push("...");
      }

      pages.push(totalPages);
    }

    return pages;
  };

  const formatTimestamp = (log) => {
    const timestamp = log?.event?.time || log?.time;

    if (!timestamp) return "—";

    const date = new Date(timestamp);

    if (Number.isNaN(date.getTime())) return "—";

    return date.toLocaleString("en-GB", {
      hour12: false,
    });
  };

  const animationProps = shouldReduceMotion
    ? {
        initial: false,
        animate: { opacity: 1 },
        transition: { duration: 0 },
      }
    : {
        variants: containerVariants,
        initial: "hidden",
        animate: "visible",
      };

  return (
    <motion.div
      {...animationProps}
      className="relative w-full overflow-hidden bg-transparent"
    >
      {/* Subtle ambient highlight */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-500/20 to-transparent"
      />

      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
        <div className="flex min-w-0 items-center gap-3">
          <motion.div
            initial={shouldReduceMotion ? false : { opacity: 0, scale: 0.88 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.3, ease: "easeOut" }}
            className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-900/80 text-cyan-400 ring-1 ring-inset ring-slate-800/80"
          >
            <ShieldAlert size={17} strokeWidth={1.7} />
          </motion.div>

          <div className="min-w-0">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-100">
              Recent Critical Alerts
            </h2>

            <p className="mt-1 text-xs text-slate-500">
              High-priority security events
              <span className="mx-1.5 text-slate-700">/</span>
              <span className="font-mono tabular-nums text-slate-400">
                {totalAlerts.toLocaleString()}
              </span>{" "}
              total
            </p>
          </div>
        </div>

        {totalAlerts > 0 && (
          <motion.div
            initial={shouldReduceMotion ? false : { opacity: 0, x: 8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.3, delay: 0.08 }}
            className="flex items-center gap-2 rounded-md bg-slate-900/70 px-2.5 py-1.5 font-mono text-[11px] text-slate-400 ring-1 ring-inset ring-slate-800/70"
          >
            <AlertTriangle
              size={12}
              className="text-cyan-400"
            />

            <span className="tabular-nums">
              Showing {startIndex + 1}–{endIndex} of {totalAlerts}
            </span>
          </motion.div>
        )}
      </div>

      {/* Table */}
      <div className="w-full overflow-x-auto">
        <table className="w-full border-collapse text-left">
          <thead>
            <tr className="border-y border-slate-800/60 bg-slate-950/30 text-[10px] font-bold uppercase tracking-[0.13em] text-slate-500">
              <th className="whitespace-nowrap px-4 py-3 font-semibold">
                Time
              </th>
              <th className="px-4 py-3 font-semibold">
                Host
              </th>
              <th className="px-4 py-3 text-center font-semibold">
                Event
              </th>
              <th className="px-4 py-3 text-center font-semibold">
                Severity
              </th>
              <th className="px-4 py-3 text-right font-semibold">
                Action
              </th>
            </tr>
          </thead>

          <tbody>
            <AnimatePresence mode="wait" initial={false}>
              {paginatedAlerts.length === 0 ? (
                <motion.tr
                  key="empty-alerts"
                  initial={shouldReduceMotion ? false : { opacity: 0, y: 5 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: shouldReduceMotion ? 0 : 0.2 }}
                >
                  <td colSpan={5} className="px-4 py-14 text-center">
                    <div className="mx-auto flex max-w-xs flex-col items-center">
                      <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-slate-900 text-slate-500 ring-1 ring-inset ring-slate-800/70">
                        <ShieldAlert size={18} strokeWidth={1.5} />
                      </div>

                      <p className="text-sm font-medium text-slate-300">
                        No critical alerts
                      </p>

                      <p className="mt-1 text-xs text-slate-600">
                        High and critical severity events will appear here.
                      </p>
                    </div>
                  </td>
                </motion.tr>
              ) : (
                paginatedAlerts.map((log, index) => (
                  <motion.tr
                    key={
                      log?.metadata?.fingerprint ||
                      `${log?.event?.time || log?.time || "alert"}-${log?.event?.event_id ?? "unknown"}-${startIndex + index}`
                    }
                    variants={shouldReduceMotion ? undefined : rowVariants}
                    initial={shouldReduceMotion ? false : "hidden"}
                    animate="visible"
                    exit={shouldReduceMotion ? undefined : "exit"}
                    transition={{
                      duration: shouldReduceMotion ? 0 : 0.2,
                      delay: shouldReduceMotion
                        ? 0
                        : Math.min(index * 0.008, 0.16),
                    }}
                    whileHover={
                      shouldReduceMotion
                        ? undefined
                        : {
                            backgroundColor: "rgba(15, 23, 42, 0.5)",
                          }
                    }
                    className="group border-b border-slate-800/40 transition-colors duration-150 last:border-b-0"
                  >
                    {/* Timestamp */}
                    <td className="whitespace-nowrap px-4 py-3 font-mono text-[11px] tabular-nums text-slate-400">
                      {formatTimestamp(log)}
                    </td>

                    {/* Host */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <motion.span
                          aria-hidden="true"
                          className="h-1.5 w-1.5 shrink-0 rounded-full bg-slate-600"
                          whileHover={
                            shouldReduceMotion
                              ? undefined
                              : { backgroundColor: "#22d3ee", scale: 1.15 }
                          }
                        />

                        <span className="max-w-[220px] truncate text-xs font-medium text-slate-300 transition-colors duration-150 group-hover:text-white">
                          {log?.event?.host || "Unknown"}
                        </span>
                      </div>
                    </td>

                    {/* Event ID */}
                    <td className="px-4 py-3 text-center">
                      <span className="inline-flex rounded bg-slate-900/70 px-2 py-1 font-mono text-[11px] font-semibold tabular-nums text-cyan-400/90 ring-1 ring-inset ring-slate-800/70 transition-colors duration-150 group-hover:text-cyan-300">
                        {log?.event?.event_id ?? "—"}
                      </span>
                    </td>

                    {/* Severity */}
                    <td className="px-4 py-3 text-center">
                      <div className="inline-block scale-95">
                        <SeverityBadge
                          severity={log?.detection?.severity}
                        />
                      </div>
                    </td>

                    {/* Investigation Action */}
                    <td className="px-4 py-3 text-right">
                      <motion.button
                        type="button"
                        onClick={() => onInvestigate?.(log)}
                        whileHover={
                          shouldReduceMotion ? undefined : { scale: 1.035 }
                        }
                        whileTap={
                          shouldReduceMotion ? undefined : { scale: 0.97 }
                        }
                        transition={{ duration: 0.13 }}
                        className="inline-flex items-center gap-1.5 rounded-md bg-slate-900 px-3 py-1.5 text-xs font-semibold text-slate-400 ring-1 ring-inset ring-slate-800/80 transition-colors duration-150 hover:bg-cyan-500/10 hover:text-cyan-300 hover:ring-cyan-500/25 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500/50"
                      >
                        Open
                        <ChevronRight
                          size={12}
                          className="transition-transform duration-150 group-hover:translate-x-0.5"
                        />
                      </motion.button>
                    </td>
                  </motion.tr>
                ))
              )}
            </AnimatePresence>
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <AnimatePresence initial={false}>
        {totalPages > 1 && (
          <motion.div
            key="pagination"
            initial={shouldReduceMotion ? false : { opacity: 0, y: 5 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 4 }}
            transition={{ duration: shouldReduceMotion ? 0 : 0.2 }}
            className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-800/50 bg-slate-950/20 px-4 py-3"
          >
            <div className="font-mono text-[10px] font-medium text-slate-600">
              {ROWS_PER_PAGE} rows per page
            </div>

            <div className="flex items-center gap-1">
              {/* Previous */}
              <motion.button
                type="button"
                whileHover={shouldReduceMotion ? undefined : { scale: 1.05 }}
                whileTap={shouldReduceMotion ? undefined : { scale: 0.95 }}
                onClick={() => goToPage(currentPage - 1)}
                disabled={currentPage <= 1}
                className="flex h-7 w-7 items-center justify-center rounded-md text-slate-500 transition-colors hover:bg-slate-800/80 hover:text-slate-200 disabled:cursor-not-allowed disabled:opacity-25"
                title="Previous page"
                aria-label="Previous page"
              >
                <ChevronLeft size={15} />
              </motion.button>

              {/* Page Numbers */}
              {getPageNumbers().map((page, index) =>
                page === "..." ? (
                  <span
                    key={`ellipsis-${index}`}
                    className="px-1.5 text-[10px] text-slate-600"
                  >
                    ···
                  </span>
                ) : (
                  <motion.button
                    type="button"
                    key={`page-${page}`}
                    whileHover={
                      shouldReduceMotion ? undefined : { scale: 1.04 }
                    }
                    whileTap={
                      shouldReduceMotion ? undefined : { scale: 0.96 }
                    }
                    onClick={() => goToPage(page)}
                    aria-label={`Go to page ${page}`}
                    aria-current={
                      currentPage === page ? "page" : undefined
                    }
                    className={`relative flex h-7 min-w-[28px] items-center justify-center overflow-hidden rounded-md px-1.5 font-mono text-[11px] font-semibold tabular-nums transition-colors duration-150 ${
                      currentPage === page
                        ? "bg-cyan-500/10 text-cyan-300"
                        : "text-slate-500 hover:bg-slate-800/60 hover:text-slate-300"
                    }`}
                  >
                    {currentPage === page && (
                      <motion.span
                        layoutId="recent-alerts-active-page"
                        transition={{
                          type: "spring",
                          stiffness: 380,
                          damping: 30,
                        }}
                        className="absolute inset-0 rounded-md ring-1 ring-inset ring-cyan-500/30"
                      />
                    )}

                    <span className="relative z-10">{page}</span>
                  </motion.button>
                )
              )}

              {/* Next */}
              <motion.button
                type="button"
                whileHover={shouldReduceMotion ? undefined : { scale: 1.05 }}
                whileTap={shouldReduceMotion ? undefined : { scale: 0.95 }}
                onClick={() => goToPage(currentPage + 1)}
                disabled={currentPage >= totalPages}
                className="flex h-7 w-7 items-center justify-center rounded-md text-slate-500 transition-colors hover:bg-slate-800/80 hover:text-slate-200 disabled:cursor-not-allowed disabled:opacity-25"
                title="Next page"
                aria-label="Next page"
              >
                <ChevronRight size={15} />
              </motion.button>
            </div>

            <div className="font-mono text-[10px] font-medium tabular-nums text-slate-600">
              Page <span className="text-slate-400">{currentPage}</span> of{" "}
              {totalPages}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

export default RecentAlerts;