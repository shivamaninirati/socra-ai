import { useEffect, useState, useMemo, useRef, useCallback } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import {
  Search,
  Terminal,
  AlertTriangle,
  Monitor,
  User,
  Cpu,
  ArrowUpRight,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Loader2,
  X,
  SlidersHorizontal,
  Shield,
  Globe,
  FolderOpen,
  Target,
} from "lucide-react";
import api from "../services/api";
import SeverityBadge from "../components/SeverityBadge";
import SearchErrorBoundary from "../components/SearchErrorBoundary";

const PAGE_SIZE = 100;
const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"];

// Client-side token extraction (display only)
const parseQuery = (query) => {
  const tokens = {};
  const keywords = [];
  if (!query) return { tokens, keywords, raw: "" };

  const fieldRegex = /(\w+):(?:"([^"]*)"|\[([^\]]*)\]|(\S+))/g;
  let match;
  let cleaned = query;
  while ((match = fieldRegex.exec(query)) !== null) {
    const key = match[1].toLowerCase().trim();
    const value = (match[2] || match[3] || match[4] || "").trim();
    if (value) tokens[key] = value;
    cleaned = cleaned.replace(match[0], "");
  }

  const remaining = cleaned.trim();
  if (remaining) {
    remaining.split(/\s+/).forEach((word) => {
      const w = word.trim();
      if (w && !["AND", "OR", "NOT"].includes(w.toUpperCase())) {
        keywords.push(w);
      }
    });
  }

  return { tokens, keywords, raw: query };
};

const formatTime = (time) => {
  if (!time) return { clock: "-", date: "", full: "-" };
  try {
    const parsed = new Date(time);
    if (isNaN(parsed.getTime())) return { clock: time, date: "", full: time };
    const clock = parsed.toLocaleTimeString("en-GB", {
      hour12: false,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
    const date = parsed.toLocaleDateString("en-GB", {
      day: "2-digit",
      month: "short",
      year: "numeric",
    });
    const full = `${date} ${clock}`;
    return { clock, date, full };
  } catch {
    return { clock: time, date: "", full: time };
  }
};

const isUnmappedMitre = (id) =>
  !id || id === "-" || id === "N/A" || id === "Unknown" || id === "Unmapped";

// Tab definitions
const TABS = [
  { id: "events", label: "Events", icon: Terminal },
  { id: "alerts", label: "Alerts", icon: AlertTriangle },
  { id: "hosts", label: "Hosts", icon: Monitor },
  { id: "processes", label: "Processes", icon: Cpu },
  { id: "mitre", label: "MITRE", icon: Target },
  { id: "cases", label: "Cases", icon: FolderOpen },
];

function EnterpriseSearchResultsInner() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const query = searchParams.get("q") || "";

  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState("events");
  const [page, setPage] = useState(1);
  const fetchSeqRef = useRef(0);

  const parsed = useMemo(() => parseQuery(query), [query]);

  const fetchResults = useCallback(async () => {
        const seq = ++fetchSeqRef.current;

        if (!query.trim()) {
            setResults(null);
            return;
        }

        setLoading(true);
        setError("");

        try {
             const response = await api.get("/search", {
                 params: { q: query, page: page, page_size: PAGE_SIZE },
             });
  
             if (seq !== fetchSeqRef.current) return;

             if (response.data) {
                 setResults(response.data);
             } else {
                 setResults(null);
             }
         } catch (err) {
             if (seq === fetchSeqRef.current) {
                 const status = err?.response?.status;
                 if (status === 401) {
                     setError("Session expired. Please log in again.");
                 } else if (status === 422) {
                     setError("Invalid search query. Please check your syntax.");
                 } else if (status === 429) {
                     setError("Too many requests. Please wait a moment and try again.");
                 } else if (status >= 500) {
                     setError("Search service temporarily unavailable. Please try again.");
                 } else {
                     setError("Search could not be completed. Please try again.");
                 }
                 setResults(null);
             }
         } finally {
             if (seq === fetchSeqRef.current) setLoading(false);
         }
     }, [query, page]);

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchResults();
    }, 0);
    return () => clearTimeout(timer);
  }, [page, query, fetchResults]);

  // Reset page and tab when query changes
  useEffect(() => {
    setPage(1);
    setActiveTab("events");
  }, [query]);

  // Navigation helpers
  const openInvestigation = useCallback((log) => {
    sessionStorage.setItem("socra_investigation_log", JSON.stringify(log));
    navigate("/investigation", { state: { log } });
  }, [navigate]);

  const openInAlerts = useCallback(() => {
    navigate(`/alerts?search=${encodeURIComponent(query)}`);
  }, [navigate, query]);

  const hostToken = parsed.tokens.host || parsed.tokens.computer || "";
  const openInTimeline = useCallback(() => {
    if (hostToken) {
      navigate(`/timeline?host=${encodeURIComponent(hostToken)}`);
    } else {
      navigate("/timeline");
    }
  }, [navigate, hostToken]);

  const tokenEntries = Object.entries(parsed.tokens);

  // Get tab counts
  const tabCounts = useMemo(() => {
    if (!results) return {};
    return {
      events: results.events?.total || 0,
      alerts: results.alerts?.total || 0,
      hosts: results.hosts?.length || 0,
      processes: results.processes?.length || 0,
      mitre: results.mitre?.length || 0,
      cases: results.cases?.total || 0,
    };
  }, [results]);

  const totalResults = results?.total || 0;

  // ------------------------------------------------------------------
  // Empty state (no query)
  // ------------------------------------------------------------------
  if (!query.trim()) {
    return (
      <div className="w-full pb-8 select-none">
        <div className="flex flex-col items-center justify-center py-32">
          <div className="w-16 h-16 rounded-full bg-slate-800/50 border border-slate-700/50 flex items-center justify-center mb-5">
            <Search size={28} className="text-slate-500" />
          </div>
          <h1 className="text-lg font-bold text-slate-300 tracking-wide">Enterprise SIEM Search</h1>
          <p className="text-sm text-slate-500 mt-2 max-w-md text-center">
            Search across all security telemetry with structured queries. Use the search bar above
            to begin your investigation.
          </p>
          <div className="mt-8 flex flex-wrap gap-2 justify-center">
            {["host:MANI", "severity:critical", "eventid:4688", "process:powershell.exe", "mitre:T1059"].map((q) => (
              <span key={q} className="px-2.5 py-1 rounded-md bg-slate-800/60 border border-slate-700 text-[11px] text-slate-400 font-mono">
                {q}
              </span>
            ))}
          </div>
        </div>
      </div>
    );
  }

  // ------------------------------------------------------------------
  // Results state
  // ------------------------------------------------------------------
  return (
    <div className="w-full pb-8 space-y-4 select-none">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2.5">
            <Search size={17} className="text-cyan-400 shrink-0" />
            <h1 className="text-lg font-bold text-white tracking-tight">Search Results</h1>
            <span className={`inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border ${
              loading
                ? "border-cyan-500/30 bg-cyan-500/10 text-cyan-400"
                : error
                  ? "border-red-500/30 bg-red-500/10 text-red-400"
                  : "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
            }`}>
              {loading ? (
                <><Loader2 size={9} className="animate-spin" /> Searching</>
              ) : error ? (
                <><X size={9} /> Error</>
              ) : (
                <><span className="h-1.5 w-1.5 rounded-full bg-emerald-400" /> Complete</>
              )}
            </span>
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-2">
            <code className="text-cyan-400 font-mono bg-cyan-950/20 px-2 py-0.5 rounded border border-cyan-900/30 text-xs">
              {query}
            </code>
            {!loading && !error && (
              <span className="text-xs text-slate-400">
                <span className="font-mono text-white font-bold">{totalResults.toLocaleString()}</span> total matches
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={openInAlerts}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs font-semibold text-slate-300 transition hover:border-cyan-500/40 hover:text-white"
          >
            <AlertTriangle size={13} />
            Open in Alerts
            <ExternalLink size={11} />
          </button>
          <button
            onClick={openInTimeline}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs font-semibold text-slate-300 transition hover:border-cyan-500/40 hover:text-white"
          >
            <Terminal size={13} />
            Open in Timeline
            <ExternalLink size={11} />
          </button>
        </div>
      </div>

      {/* Parsed tokens */}
      {tokenEntries.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[9px] uppercase font-bold tracking-wider text-slate-500 mr-1">
            <SlidersHorizontal size={10} className="inline mr-1" />
            Filters
          </span>
          {tokenEntries.map(([key, value]) => (
            <span key={key} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md border border-cyan-500/20 bg-cyan-500/5 text-cyan-300 text-[10px] font-semibold">
              {key}:<span className="font-bold">{value}</span>
            </span>
          ))}
          {parsed.keywords.map((kw, i) => (
            <span key={`kw-${i}`} className="px-2 py-0.5 rounded-md border border-slate-700 bg-slate-800/60 text-slate-400 text-[10px] font-semibold">
              &ldquo;{kw}&rdquo;
            </span>
          ))}
        </div>
      )}

      {/* Category tabs */}
      {!loading && !error && results && (
        <div className="flex items-center gap-1 overflow-x-auto pb-1">
          {TABS.map((tab) => {
            const Icon = tab.icon;
            const count = tabCounts[tab.id] || 0;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-1.5 px-3 py-2 text-[11px] font-bold uppercase tracking-wider rounded-lg transition-all whitespace-nowrap ${
                  isActive
                    ? "bg-cyan-600/20 text-cyan-400 border border-cyan-500/30 shadow-sm"
                    : "text-slate-500 hover:text-slate-300 border border-transparent hover:bg-slate-800/40"
                }`}
              >
                <Icon size={13} />
                {tab.label}
                <span className={`text-[9px] font-mono ml-0.5 ${isActive ? "text-cyan-500" : "text-slate-600"}`}>
                  {count.toLocaleString()}
                </span>
              </button>
            );
          })}
        </div>
      )}

      {/* Error state */}
      {error && !loading && (
        <div className="flex flex-col items-center justify-center py-20">
          <div className="w-14 h-14 rounded-full bg-red-500/10 border border-red-500/30 flex items-center justify-center mb-4">
            <AlertTriangle size={24} className="text-red-400" />
          </div>
          <p className="text-sm font-bold text-red-400">Search Error</p>
          <p className="text-xs text-slate-500 mt-1.5 max-w-sm text-center">{error}</p>
          <button
            onClick={fetchResults}
            className="mt-4 inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs font-semibold text-slate-300 transition hover:border-cyan-500/40 hover:text-white"
          >
            <Loader2 size={12} /> Retry
          </button>
        </div>
      )}

      {/* Loading skeleton */}
      {loading && (
        <div className="space-y-3">
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="h-12 animate-pulse rounded-lg border border-slate-800/70 bg-slate-900/50" />
          ))}
        </div>
      )}

      {/* Results by tab */}
      {!loading && !error && results && (
        <>
          {/* Events tab */}
          {activeTab === "events" && (
            <EventsResults
              events={results.events?.results || []}
              total={results.events?.total || 0}
              page={page}
              setPage={setPage}
              openInvestigation={openInvestigation}
            />
          )}

          {/* Alerts tab */}
          {activeTab === "alerts" && (
            <AlertsResults
              alerts={results.alerts?.results || []}
              total={results.alerts?.total || 0}
              openInvestigation={openInvestigation}
            />
          )}

          {/* Hosts tab */}
          {activeTab === "hosts" && (
            <HostsResults
              hosts={results.hosts || []}
              navigate={navigate}
            />
          )}

          {/* Processes tab */}
          {activeTab === "processes" && (
            <ProcessesResults
              processes={results.processes || []}
              navigate={navigate}
            />
          )}

          {/* MITRE tab */}
          {activeTab === "mitre" && (
            <MitreResults
              techniques={results.mitre || []}
              navigate={navigate}
            />
          )}

          {/* Cases tab */}
          {activeTab === "cases" && (
            <CasesResults
              cases={results.cases?.results || []}
              total={results.cases?.total || 0}
              navigate={navigate}
            />
          )}
        </>
      )}

      {/* Empty result state */}
      {!loading && !error && results && totalResults === 0 && (
        <div className="flex flex-col items-center justify-center py-24">
          <div className="w-14 h-14 rounded-full bg-slate-800/50 border border-slate-700/50 flex items-center justify-center mb-4">
            <Search size={24} className="text-slate-500" />
          </div>
          <p className="text-sm font-bold text-slate-300">No matching security telemetry found.</p>
          <p className="text-xs text-slate-500 mt-1.5 max-w-sm text-center">
            Nothing matches <code className="text-cyan-400">{query}</code>. Try a different field,
            severity, or time range.
          </p>
          <button
            onClick={openInAlerts}
            className="mt-5 inline-flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs font-semibold text-slate-300 transition hover:border-cyan-500/40 hover:text-white"
          >
            Open in Alerts
            <ExternalLink size={11} />
          </button>
        </div>
      )}
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────
// Events Results
// ────────────────────────────────────────────────────────────────────
function EventsResults({ events, total, page, setPage, openInvestigation }) {
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const start = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1;
  const end = Math.min(page * PAGE_SIZE, total);

  if (events.length === 0) {
    return (
      <div className="text-center py-16 text-slate-500 text-sm">
        No events match this search.
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/30 shadow-sm overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[1080px] table-fixed border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-left text-[11px] font-bold uppercase tracking-wider text-slate-500">
              <th className="w-[130px] px-4 py-3">Time</th>
              <th className="w-[100px] px-4 py-3 text-center">Severity</th>
              <th className="w-[130px] px-4 py-3">Host</th>
              <th className="w-[110px] px-4 py-3">User</th>
              <th className="w-[80px] px-4 py-3 text-center">Event ID</th>
              <th className="px-4 py-3">Process</th>
              <th className="w-[100px] px-4 py-3 text-center">PID</th>
              <th className="w-[120px] px-4 py-3 text-center">MITRE</th>
              <th className="w-[90px] px-4 py-3 text-center">Status</th>
              <th className="w-[110px] px-4 py-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-900/80">
            {events.map((log, index) => {
              if (!log) return null;
              const event = log.event || {};
              const detection = log.detection || {};
              const mitre = detection.mitre || {};
              const mitreObj = typeof mitre === "object" ? mitre : { id: mitre };
              const time = formatTime(event.time);
              const processName = event.process_name || "Not available in event";
              const processId = event.process_id || "Not available";
              const host = event.host || event.computer || "-";
              const status = event.status || detection.status || "New";
              const key = log?.metadata?.fingerprint ||
                `${event.time || ""}-${event.event_id || ""}-${event.process_id || ""}-${event.record_number || index}`;

              return (
                <tr
                  key={key}
                  onClick={() => openInvestigation(log)}
                  className="cursor-pointer bg-slate-950/10 transition hover:bg-slate-900/50"
                >
                  <td className="px-4 py-2.5 align-middle">
                    <div className="font-mono text-xs font-semibold text-slate-200" title={time.full}>{time.clock}</div>
                    <div className="text-[10px] text-slate-500 font-mono">{time.date}</div>
                  </td>
                  <td className="px-4 py-2.5 text-center align-middle">
                    <div className="inline-flex scale-90">
                      <SeverityBadge severity={detection.severity} />
                    </div>
                  </td>
                  <td className="px-4 py-2.5 align-middle">
                    <div className="flex items-center gap-1.5 min-w-0">
                      <Monitor size={12} className="shrink-0 text-slate-600" />
                      <span title={host} className="truncate text-xs font-semibold text-slate-200">{host}</span>
                    </div>
                  </td>
                  <td className="px-4 py-2.5 align-middle">
                    <div className="flex items-center gap-1.5 min-w-0">
                      <User size={12} className="shrink-0 text-slate-600" />
                      <span className="truncate text-xs text-slate-300">{event.user || "-"}</span>
                    </div>
                  </td>
                  <td className="px-4 py-2.5 text-center align-middle font-mono text-xs font-bold text-cyan-400">
                    {event.event_id || "-"}
                  </td>
                  <td className="px-4 py-2.5 align-middle">
                    <div className="flex items-center gap-1.5 min-w-0">
                      <Cpu size={12} className="shrink-0 text-slate-600" />
                      <span title={processName} className={`truncate font-mono text-xs ${
                        processName === "Not available in event" ? "text-slate-600" : "text-slate-300"
                      }`}>
                        {processName}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-2.5 text-center align-middle">
                    <span className={`font-mono text-xs ${
                      processId === "Not available" ? "text-slate-600" : "text-slate-400"
                    }`}>
                      {processId}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-center align-middle">
                    {isUnmappedMitre(mitreObj.id) ? (
                      <span className="text-slate-600">Unmapped</span>
                    ) : (
                      <span className="truncate font-mono text-xs font-bold text-purple-400">{mitreObj.id}</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-center align-middle">
                    <span className="inline-flex rounded-md border border-cyan-500/20 bg-cyan-500/10 px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wide text-cyan-400">
                      {status}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-right align-middle">
                    <button
                      onClick={(e) => { e.stopPropagation(); openInvestigation(log); }}
                      className="inline-flex items-center gap-1 rounded-md border border-slate-800 bg-slate-900/70 px-2 py-1 text-[10px] font-bold text-slate-300 transition hover:border-cyan-500/40 hover:text-white"
                    >
                      Investigate
                      <ArrowUpRight size={11} />
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {total > PAGE_SIZE && (
        <div className="flex flex-col gap-3 border-t border-slate-800 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
          <p className="text-xs text-slate-500">
            Showing <span className="font-mono text-slate-300">{start}-{end.toLocaleString()}</span> of{" "}
            <span className="font-mono text-slate-300">{total.toLocaleString()}</span>
          </p>
          <div className="flex items-center gap-2">
            <button
              disabled={page <= 1}
              onClick={() => setPage((v) => Math.max(1, v - 1))}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-1.5 text-xs font-semibold text-slate-300 transition hover:border-slate-700 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
            >
              <ChevronLeft size={13} /> Previous
            </button>
            <span className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-1.5 text-xs font-semibold text-slate-400">
              Page {page} / {pages}
            </span>
            <button
              disabled={page >= pages}
              onClick={() => setPage((v) => Math.min(pages, v + 1))}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-1.5 text-xs font-semibold text-slate-300 transition hover:border-slate-700 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
            >
              Next <ChevronRight size={13} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────
// Alerts Results
// ────────────────────────────────────────────────────────────────────
function AlertsResults({ alerts, total, openInvestigation }) {
  if (alerts.length === 0) {
    return (
      <div className="text-center py-16 text-slate-500 text-sm">
        No alerts match this search.
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/30 shadow-sm overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
        <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">
          {total.toLocaleString()} alert{total !== 1 ? "s" : ""} found
        </span>
      </div>
      <div className="divide-y divide-slate-900/80">
        {alerts.slice(0, 50).map((log, index) => {
          if (!log) return null;
          const event = log.event || {};
          const detection = log.detection || {};
          const time = formatTime(event.time);
          const host = event.host || event.computer || "-";
          const key = log?.metadata?.fingerprint || `alert-${index}`;

          return (
            <div
              key={key}
              onClick={() => openInvestigation(log)}
              className="flex items-center gap-4 px-4 py-3 cursor-pointer hover:bg-slate-900/50 transition"
            >
              <div className="inline-flex scale-90">
                <SeverityBadge severity={detection.severity} />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-bold text-slate-200 truncate">
                  {detection.detection || "Security Event"}
                </p>
                <p className="text-[10px] text-slate-500 mt-0.5">
                  {time.clock} · {host} · EID {event.event_id || "-"}
                </p>
              </div>
              <button
                onClick={(e) => { e.stopPropagation(); openInvestigation(log); }}
                className="inline-flex items-center gap-1 rounded-md border border-slate-800 bg-slate-900/70 px-2 py-1 text-[10px] font-bold text-slate-300 transition hover:border-cyan-500/40 hover:text-white shrink-0"
              >
                Investigate <ArrowUpRight size={11} />
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────
// Hosts Results
// ────────────────────────────────────────────────────────────────────
function HostsResults({ hosts, navigate }) {
  if (hosts.length === 0) {
    return (
      <div className="text-center py-16 text-slate-500 text-sm">
        No hosts match this search.
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
      {hosts.map((host) => (
        <button
          key={host}
          onClick={() => navigate(`/alerts?search=host:${encodeURIComponent(host)}`)}
          className="flex items-center gap-3 p-4 rounded-xl border border-slate-800 bg-slate-900/30 hover:border-cyan-500/40 hover:bg-slate-900/50 transition text-left"
        >
          <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center shrink-0">
            <Monitor size={18} className="text-emerald-400" />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-bold text-slate-200 truncate">{host}</p>
            <p className="text-[10px] text-slate-500">View events for this host</p>
          </div>
          <ArrowUpRight size={14} className="text-slate-600 shrink-0 ml-auto" />
        </button>
      ))}
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────
// Processes Results
// ────────────────────────────────────────────────────────────────────
function ProcessesResults({ processes, navigate }) {
  if (processes.length === 0) {
    return (
      <div className="text-center py-16 text-slate-500 text-sm">
        No processes match this search.
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
      {processes.map((proc) => (
        <button
          key={proc}
          onClick={() => navigate(`/alerts?search=process:${encodeURIComponent(proc)}`)}
          className="flex items-center gap-3 p-4 rounded-xl border border-slate-800 bg-slate-900/30 hover:border-cyan-500/40 hover:bg-slate-900/50 transition text-left"
        >
          <div className="w-10 h-10 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center shrink-0">
            <Cpu size={18} className="text-amber-400" />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-mono font-bold text-slate-200 truncate">{proc}</p>
            <p className="text-[10px] text-slate-500">View events for this process</p>
          </div>
          <ArrowUpRight size={14} className="text-slate-600 shrink-0 ml-auto" />
        </button>
      ))}
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────
// MITRE Results
// ────────────────────────────────────────────────────────────────────
function MitreResults({ techniques, navigate }) {
  if (techniques.length === 0) {
    return (
      <div className="text-center py-16 text-slate-500 text-sm">
        No MITRE techniques match this search.
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
      {techniques.map((tech) => (
        <button
          key={tech.id || `mitre-${tech.name || Math.random()}`}
          onClick={() => navigate(`/alerts?search=mitre:${encodeURIComponent(tech.id)}`)}
          className="flex items-center gap-3 p-4 rounded-xl border border-slate-800 bg-slate-900/30 hover:border-cyan-500/40 hover:bg-slate-900/50 transition text-left"
        >
          <div className="w-10 h-10 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center shrink-0">
            <Target size={18} className="text-purple-400" />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-mono font-bold text-purple-400">{tech.id}</p>
            <p className="text-xs text-slate-300 truncate">{tech.name}</p>
            {tech.tactic && (
              <p className="text-[10px] text-slate-500">{tech.tactic}</p>
            )}
          </div>
          <ArrowUpRight size={14} className="text-slate-600 shrink-0 ml-auto" />
        </button>
      ))}
    </div>
  );
}

// ────────────────────────────────────────────────────────────────────
// Cases Results
// ────────────────────────────────────────────────────────────────────
function CasesResults({ cases, total, navigate }) {
  if (cases.length === 0) {
    return (
      <div className="text-center py-16 text-slate-500 text-sm">
        No cases match this search.
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/30 shadow-sm overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-800">
        <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">
          {total.toLocaleString()} case{total !== 1 ? "s" : ""} found
        </span>
      </div>
      <div className="divide-y divide-slate-900/80">
        {cases.map((c) => (
          <button
            key={c.case_id || c.id}
            onClick={() => navigate("/cases")}
            className="w-full flex items-center gap-4 px-4 py-3 hover:bg-slate-900/50 transition text-left"
          >
            <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center shrink-0">
              <FolderOpen size={18} className="text-cyan-400" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-bold text-slate-200 truncate">{c.case_id || c.id}</p>
              <p className="text-xs text-slate-400 truncate">{c.title || "No title"}</p>
            </div>
            <span className={`text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded border shrink-0 ${
              c.status === "Open" ? "text-cyan-400 border-cyan-500/30 bg-cyan-500/10" :
              c.status === "Investigating" ? "text-amber-400 border-amber-500/30 bg-amber-500/10" :
              c.status === "Resolved" ? "text-emerald-400 border-emerald-500/30 bg-emerald-500/10" :
              "text-slate-400 border-slate-600/30 bg-slate-600/10"
            }`}>
              {c.status || "Open"}
            </span>
            <ArrowUpRight size={14} className="text-slate-600 shrink-0" />
          </button>
        ))}
      </div>
    </div>
  );
}

function EnterpriseSearchResults() {
  return (
    <SearchErrorBoundary>
      <EnterpriseSearchResultsInner />
    </SearchErrorBoundary>
  );
}

export default EnterpriseSearchResults;