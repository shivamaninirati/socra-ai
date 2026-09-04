import { useEffect, useState, useMemo, useCallback } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { 
  AlertCircle, Terminal,
  Filter, Monitor, Clock3, Eye,
  ArrowUpRight, ListTree, Calendar, ChevronLeft, ChevronRight, ChevronDown
} from "lucide-react";
import liveSocket from "../services/liveSocket";
import api from "../services/api";
import Dropdown from "../components/ui/Dropdown";

const severityColor = (sev) => {
  switch ((sev || "").toLowerCase()) {
    case "critical": return { dot: "bg-red-500", text: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30", glow: "shadow-red-500/20" };
    case "high": return { dot: "bg-orange-500", text: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/30", glow: "shadow-orange-500/20" };
    case "medium": return { dot: "bg-yellow-500", text: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/30", glow: "shadow-yellow-500/20" };
    case "low": return { dot: "bg-green-500", text: "text-green-400", bg: "bg-green-500/10", border: "border-green-500/30", glow: "shadow-green-500/20" };
    default: return { dot: "bg-slate-500", text: "text-slate-400", bg: "bg-slate-500/10", border: "border-slate-500/30", glow: "shadow-slate-500/20" };
  }
};

const normalizeSeverity = (sev) => {
  const s = (sev || "").toLowerCase();
  if (["", "unknown", "none", "null", "info", "informational"].includes(s)) return "Informational";
  const cap = sev.charAt(0).toUpperCase() + sev.slice(1).toLowerCase();
  return ["Critical", "High", "Medium", "Low"].includes(cap) ? cap : "Informational";
};

const RANGE_OPTIONS = [
  { value: "today", label: "Today" },
  { value: "last_24h", label: "Last 24 Hours" },
  { value: "last_7d", label: "Last 7 Days" },
  { value: "last_30d", label: "Last 30 Days" },
  { value: "all", label: "All History" },
  { value: "custom", label: "Custom Range" },
];

const DEFAULT_FILTER_OPTIONS = {
  hosts: ["All"],
  users: ["All"],
  processes: ["All"],
  eventIds: ["All"],
  mitres: ["All"],
  severities: ["All", "Critical", "High", "Medium", "Low", "Informational"],
};



function Timeline() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [expandedEvent, setExpandedEvent] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);

  // Server-side time range + pagination
  const [range, setRange] = useState("all");
  const [customFrom, setCustomFrom] = useState("");
  const [customTo, setCustomTo] = useState("");
  const [appliedFrom, setAppliedFrom] = useState("");
  const [appliedTo, setAppliedTo] = useState("");
  const [page, setPage] = useState(1);
  const [limit] = useState(100);
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState(1);
  const [refreshKey, setRefreshKey] = useState(0);

  // Server-side filters. The host filter initializes from Enterprise Search
  // navigation (/timeline?host=X) so the requested host is applied immediately.
  const [filterSeverity, setFilterSeverity] = useState("All");
  const [filterHost, setFilterHost] = useState(() => searchParams.get("host") || "All");
  const [filterMitre, setFilterMitre] = useState("All");
  const [filterEventId, setFilterEventId] = useState("All");
  const [filterProcess, setFilterProcess] = useState("All");
  const [filterUser, setFilterUser] = useState("All");
  const [filterOptions, setFilterOptions] = useState(DEFAULT_FILTER_OPTIONS);

  const handleFilterChange = (setter) => (value) => { setter(value); setPage(1); };

  // Single server-side fetch path: time range, filters and pagination are all
  // sent to the backend and only the requested page is loaded into the browser.
  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        setError("");
        const params = { range, page, limit };
        if (range === "custom") {
          if (appliedFrom) params.from = new Date(appliedFrom).toISOString();
          if (appliedTo) params.to = new Date(appliedTo).toISOString();
        }
        if (filterHost !== "All") params.host = filterHost;
        if (filterUser !== "All") params.user = filterUser;
        if (filterProcess !== "All") params.process = filterProcess;
        if (filterEventId !== "All") params.event_id = filterEventId;
        if (filterSeverity !== "All") params.severity = filterSeverity;
        if (filterMitre !== "All") params.mitre = filterMitre;

        const response = await api.get("/timeline/events", { params });
        if (cancelled) return;
        setEvents(response.data.results || []);
        setTotal(response.data.total || 0);
        setPages(response.data.pages || 1);
        setLastUpdated(new Date());
      } catch (err) {
        console.error("Timeline fetch error:", err);
        if (!cancelled) setError("Could not load timeline data. Check the backend connection and try again.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [range, page, limit, appliedFrom, appliedTo, filterHost, filterUser, filterProcess, filterEventId, filterSeverity, filterMitre, refreshKey]);

  // Filter option values come from the backend (real telemetry), so the
  // dropdowns are complete regardless of which page is loaded.
  useEffect(() => {
    api.get("/timeline/filters")
      .then((res) => {
        const d = res.data || {};
        setFilterOptions({
          hosts: d.hosts?.length ? d.hosts : DEFAULT_FILTER_OPTIONS.hosts,
          users: d.users?.length ? d.users : DEFAULT_FILTER_OPTIONS.users,
          processes: d.processes?.length ? d.processes : DEFAULT_FILTER_OPTIONS.processes,
          eventIds: d.event_ids?.length ? d.event_ids : DEFAULT_FILTER_OPTIONS.eventIds,
          mitres: d.mitres?.length ? d.mitres : DEFAULT_FILTER_OPTIONS.mitres,
          severities: d.severities?.length ? d.severities : DEFAULT_FILTER_OPTIONS.severities,
        });
      })
      .catch((err) => console.error("Timeline filter options error:", err));
  }, []);

  const mapLiveEvent = useCallback((a) => ({
    timestamp: a.event?.time,
    event_id: String(a.event?.event_id || ""),
    user: a.event?.user || "SYSTEM",
    process: a.event?.process_name || "Not available in event",
    host: a.event?.host || a.event?.computer || "Unknown",
    action: a.detection?.detection || "Security Event",
    severity: normalizeSeverity(a.detection?.severity),
    mitre_id: (a.detection?.mitre && typeof a.detection.mitre === "object" ? a.detection.mitre.id : a.detection?.mitre) || "Unmapped",
    details: {
      command_line: a.event?.command_line || "",
      parent_process: a.event?.parent_process || a.event?.parent_image || "N/A",
      description: a.detection?.description || "",
    },
    fingerprint: a.metadata?.fingerprint,
  }), []);

  const inTimeRange = useCallback((ts) => {
    if (!ts) return true;
    const t = new Date(ts).getTime();
    if (Number.isNaN(t)) return true;
    const now = Date.now();
    if (range === "today") {
      const start = new Date(); start.setHours(0, 0, 0, 0);
      return t >= start.getTime();
    }
    if (range === "last_24h") return t >= now - 24 * 3600 * 1000;
    if (range === "last_7d") return t >= now - 7 * 24 * 3600 * 1000;
    if (range === "last_30d") return t >= now - 30 * 24 * 3600 * 1000;
    if (range === "custom") {
      if (appliedFrom && new Date(appliedFrom).getTime() > t) return false;
      if (appliedTo && new Date(appliedTo).getTime() < t) return false;
    }
    return true;
  }, [range, appliedFrom, appliedTo]);

  const matchesFilters = useCallback((e) => {
    if (filterSeverity !== "All" && (e.severity || "").toLowerCase() !== filterSeverity.toLowerCase()) return false;
    if (filterHost !== "All" && e.host !== filterHost) return false;
    if (filterMitre !== "All" && e.mitre_id !== filterMitre) return false;
    if (filterEventId !== "All" && String(e.event_id) !== filterEventId) return false;
    if (filterProcess !== "All") {
      const proc = (e.process || "").split("\\").pop();
      if (proc !== filterProcess) return false;
    }
    if (filterUser !== "All" && e.user !== filterUser) return false;
    return true;
  }, [filterSeverity, filterHost, filterMitre, filterEventId, filterProcess, filterUser]);

  // Live WebSocket events: prepend real events as they stream in, deduped
  // against persisted events by fingerprint, respecting the active filters.
  useEffect(() => {
    const handler = (msg) => {
      if (!msg || !msg.type || (msg.type !== "alert" && msg.type !== "incident")) return;
      const live = mapLiveEvent(msg);
      if (!inTimeRange(live.timestamp)) return;
      if (!matchesFilters(live)) return;
      setEvents((prev) => {
        const key = (e) => e.fingerprint || `${e.timestamp}-${e.event_id}`;
        const existing = new Set(prev.map(key));
        if (existing.has(key(live))) return prev;
        const merged = [live, ...prev];
        merged.sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0));
        return merged.slice(0, 2000);
      });
    };
    liveSocket.subscribe(handler);
    return () => liveSocket.unsubscribe(handler);
  }, [mapLiveEvent, inTimeRange, matchesFilters]);

  const openInvestigation = (event) => {
    navigate("/investigation", {
      state: {
        log: {
          event: {
            time: event.timestamp,
            host: event.host || "Unknown",
            event_id: event.event_id,
            process_name: event.process,
            user: event.user,
            command_line: event.details?.command_line,
            parent_process_name: event.details?.parent_process
          },
          detection: {
            severity: event.severity,
            detection: event.action,
            mitre: { id: event.mitre_id },
            description: event.details?.description || ""
          }
        }
      }
    });
  };

  const formatTime = (t) => {
    if (!t) return { time: "-", date: "" };
    try {
      const d = new Date(t);
      return {
        time: d.toLocaleTimeString("en-GB", { hour12: false }),
        date: d.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" })
      };
    } catch { return { time: t, date: "" }; }
  };

  const activeFilters = [filterSeverity, filterHost, filterMitre, filterEventId, filterProcess, filterUser]
    .filter(v => v !== "All").length;

  const clearFilters = () => {
    setFilterSeverity("All"); setFilterHost("All"); setFilterMitre("All");
    setFilterEventId("All"); setFilterProcess("All"); setFilterUser("All");
    setPage(1);
  };

  const applyCustomRange = () => {
    setAppliedFrom(customFrom);
    setAppliedTo(customTo);
    setPage(1);
  };

  const shownCount = useMemo(() => events.length, [events]);

  return (
    <div className="w-full pb-8 space-y-5 select-none">
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3 pt-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-extrabold tracking-tight text-white flex items-center gap-2">
              <Clock3 size={20} className="text-cyan-400" />
              <span>Forensic Timeline</span>
            </h1>
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-[9px] font-black tracking-widest uppercase">
              <span className="w-1 h-1 rounded-full bg-cyan-400 animate-pulse" />
              LIVE
            </span>
          </div>
          <p className="text-xs text-slate-500 font-medium mt-1.5">
            Chronological event sequence — {shownCount} of {total} matching events
            {lastUpdated ? ` · Last sync: ${lastUpdated.toLocaleTimeString("en-GB")}` : ""}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {activeFilters > 0 && (
            <button
              onClick={clearFilters}
              className="px-2.5 py-1.5 bg-red-500/10 text-red-400 border border-red-500/20 rounded-lg text-[10px] font-bold uppercase tracking-wider hover:bg-red-500/20 transition-all"
            >
              Clear Filters ({activeFilters})
            </button>
          )}
          <button
            onClick={() => setRefreshKey((k) => k + 1)}
            className="px-3 py-1.5 bg-slate-800/60 border border-slate-700/60 text-xs font-bold text-slate-300 rounded-lg hover:bg-slate-700/60 transition-all"
          >
            Refresh
          </button>
        </div>
      </div>

      <div className="flex items-center gap-2 flex-wrap p-3 bg-slate-900/30 border border-slate-800/60 rounded-xl">
        <Filter size={13} className="text-slate-500 shrink-0" />
        <div className="min-w-[140px]">
          <Dropdown
            value={range}
            onChange={(v) => { setRange(v); setPage(1); }}
            options={RANGE_OPTIONS.map((o) => ({ value: o.value, label: o.label }))}
            ariaLabel="Time range"
          />
        </div>
        <div className="w-px h-5 bg-slate-800/80 mx-1 shrink-0" />
        <div className="min-w-[140px]">
          <Dropdown value={filterSeverity} onChange={handleFilterChange(setFilterSeverity)}
            options={filterOptions.severities.map((s) => ({ value: s, label: s }))} ariaLabel="Severity" />
        </div>
        <div className="min-w-[140px]">
          <Dropdown value={filterHost} onChange={handleFilterChange(setFilterHost)}
            options={filterOptions.hosts.map((h) => ({ value: h, label: h }))} ariaLabel="Host" searchable clearable />
        </div>
        <div className="min-w-[140px]">
          <Dropdown value={filterMitre} onChange={handleFilterChange(setFilterMitre)}
            options={filterOptions.mitres.map((m) => ({ value: m, label: m }))} ariaLabel="MITRE" searchable clearable />
        </div>
        <div className="min-w-[140px]">
          <Dropdown value={filterEventId} onChange={handleFilterChange(setFilterEventId)}
            options={filterOptions.eventIds.map((e) => ({ value: e, label: e }))} ariaLabel="Event ID" searchable clearable />
        </div>
        <div className="min-w-[140px]">
          <Dropdown value={filterProcess} onChange={handleFilterChange(setFilterProcess)}
            options={filterOptions.processes.map((p) => ({ value: p, label: p }))} ariaLabel="Process" searchable clearable />
        </div>
        <div className="min-w-[140px]">
          <Dropdown value={filterUser} onChange={handleFilterChange(setFilterUser)}
            options={filterOptions.users.map((u) => ({ value: u, label: u }))} ariaLabel="User" searchable clearable />
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {range === "custom" && (
        <div className="flex items-center gap-3 flex-wrap p-3 bg-slate-900/30 border border-slate-800/60 rounded-xl">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
            <Calendar size={11} /> Custom Range
          </span>
          <label className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-wider text-slate-600">
            From
            <input
              type="datetime-local"
              value={customFrom}
              onChange={(e) => setCustomFrom(e.target.value)}
              className="bg-slate-900/60 border border-slate-700/60 rounded-lg px-2 py-1.5 text-xs text-slate-300 font-medium normal-case tracking-normal"
            />
          </label>
          <label className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-wider text-slate-600">
            To
            <input
              type="datetime-local"
              value={customTo}
              onChange={(e) => setCustomTo(e.target.value)}
              className="bg-slate-900/60 border border-slate-700/60 rounded-lg px-2 py-1.5 text-xs text-slate-300 font-medium normal-case tracking-normal"
            />
          </label>
          <button
            onClick={applyCustomRange}
            className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-[10px] font-bold rounded-lg transition-all"
          >
            Apply
          </button>
        </div>
      )}

      <div className="w-full bg-slate-900/20 border border-slate-800/80 rounded-xl min-h-[55vh]">
        {loading ? (
          <div className="flex flex-col items-center justify-center py-24">
            <div className="animate-spin rounded-full h-10 w-10 border-4 border-cyan-500 border-t-transparent mb-4"></div>
            <p className="text-slate-500 text-xs animate-pulse">Loading forensic timeline data...</p>
          </div>
        ) : events.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-24">
            <div className="p-3 bg-slate-950/40 border border-slate-800 rounded-xl mb-3 text-slate-600">
              <AlertCircle size={24} />
            </div>
            <h2 className="text-xs font-bold text-slate-400 tracking-wider uppercase">No Timeline Events</h2>
            <p className="text-[11px] text-slate-600 max-w-xs mt-1">
              {activeFilters > 0 || range !== "all" ? "No events match the current filter criteria." : "No forensic timeline events available."}
            </p>
          </div>
        ) : (
          <div className="relative pl-8 pr-4 py-6 space-y-0">
            <div className="absolute left-[27px] top-0 bottom-0 w-[2px] bg-slate-800/60" />
            
            {events.map((event, index) => {
              const colors = severityColor(event.severity);
              const ts = formatTime(event.timestamp);
              const isSelected = selectedEvent === event;
              const isExpanded = expandedEvent === index;

              return (
                <div key={`${event.timestamp}-${event.event_id}-${index}`} className="relative group">
                  <div className="absolute left-[-31px] top-5 z-10">
                    <div className={`w-4 h-4 rounded-full ${colors.bg} border-2 ${colors.border} flex items-center justify-center shadow-lg ${colors.glow}`}>
                      <div className={`w-1.5 h-1.5 rounded-full ${colors.dot}`} />
                    </div>
                  </div>

                  <div 
                    onClick={() => { setSelectedEvent(event); setExpandedEvent(isExpanded ? null : index); }}
                    className={`ml-4 mb-3 p-4 rounded-xl border transition-all duration-150 cursor-pointer ${
                      isSelected
                        ? "bg-slate-800/60 border-cyan-500/40 shadow-lg shadow-cyan-950/10"
                        : "bg-slate-900/30 border-slate-800/40 hover:border-slate-700/60 hover:bg-slate-800/30"
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-3 flex-1 min-w-0">
                        <div className={`w-1 h-8 rounded-full ${colors.dot} shrink-0`} />
                        
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            <h3 className={`text-sm font-bold ${colors.text} truncate`}>
                              {event.action || "Security Event"}
                            </h3>
                            {event.mitre_id && event.mitre_id !== "N/A" && event.mitre_id !== "Unknown" && event.mitre_id !== "Unmapped" && (
                              <span className="text-[9px] font-mono font-bold text-purple-400 bg-purple-500/10 border border-purple-500/20 px-1.5 py-0.5 rounded shrink-0">
                                {event.mitre_id}
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-2 mt-1">
                            <span className="text-[11px] font-mono text-slate-500">{ts.time}</span>
                            <span className="text-[10px] text-slate-700">•</span>
                            <span className="text-[11px] text-slate-400 truncate flex items-center gap-1">
                              <Monitor size={10} className="text-slate-600 shrink-0" />
                              {event.host || "Unknown"}
                            </span>
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        <span className="text-[10px] font-mono font-bold text-cyan-500/80 bg-cyan-500/10 border border-cyan-500/20 px-1.5 py-0.5 rounded">
                          EID: {event.event_id || "-"}
                        </span>
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${colors.bg} ${colors.text} ${colors.border} border`}>
                          {event.severity || "Info"}
                        </span>
                        <ChevronDown size={12} className={`text-slate-600 transition-transform duration-150 ${isExpanded ? "rotate-180" : ""}`} />
                      </div>
                    </div>

                    {isExpanded && (
                      <div className="mt-3 pt-3 border-t border-slate-800/60 space-y-3 animate-fadeIn">
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                          <div className="p-2 bg-slate-900/40 rounded-lg">
                            <p className="text-[9px] uppercase tracking-widest text-slate-600 font-bold">Process</p>
                            <p className="text-xs font-mono text-cyan-400 mt-0.5 truncate">{(event.process || "Not available in event").split("\\").pop()}</p>
                          </div>
                          <div className="p-2 bg-slate-900/40 rounded-lg">
                            <p className="text-[9px] uppercase tracking-widest text-slate-600 font-bold">User</p>
                            <p className="text-xs text-slate-300 mt-0.5 truncate">{event.user || "N/A"}</p>
                          </div>
                          <div className="p-2 bg-slate-900/40 rounded-lg">
                            <p className="text-[9px] uppercase tracking-widest text-slate-600 font-bold">Date</p>
                            <p className="text-xs text-slate-400 mt-0.5">{ts.date || "-"}</p>
                          </div>
                          <div className="p-2 bg-slate-900/40 rounded-lg">
                            <p className="text-[9px] uppercase tracking-widest text-slate-600 font-bold">MITRE</p>
                            <p className={"text-xs font-mono mt-0.5 " + (event.mitre_id && event.mitre_id !== "Unmapped" ? "text-purple-400" : "text-slate-600")}>
                              {event.mitre_id || "Unmapped"}
                            </p>
                          </div>
                        </div>

                        {event.details?.command_line && (
                          <div className="p-2.5 bg-slate-900/40 rounded-lg border border-slate-800/40">
                            <div className="flex items-center gap-1.5 mb-1">
                              <Terminal size={11} className="text-cyan-500" />
                              <span className="text-[9px] uppercase tracking-wider text-slate-600 font-bold">Command Line</span>
                            </div>
                            <pre className="text-[11px] text-emerald-400 font-mono whitespace-pre-wrap break-all">{event.details.command_line}</pre>
                          </div>
                        )}

                        {event.details?.description && (
                          <p className="text-xs text-slate-500 leading-6">{event.details.description}</p>
                        )}

                        {event.details?.parent_process && event.details.parent_process !== "N/A" && (
                          <div className="flex items-center gap-1.5 text-[10px] text-slate-500">
                            <ListTree size={11} className="text-slate-600" />
                            <span className="font-bold uppercase tracking-wider text-slate-600">Parent:</span>
                            <span className="font-mono text-slate-400">{event.details.parent_process}</span>
                          </div>
                        )}

                        <div className="flex justify-end">
                          <button
                            onClick={(e) => { e.stopPropagation(); openInvestigation(event); }}
                            className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-[10px] font-bold rounded-lg transition-all"
                          >
                            <Eye size={11} />
                            Open in Investigation
                            <ArrowUpRight size={10} />
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {total > 0 && (
        <div className="flex items-center justify-between px-3 py-2 bg-slate-900/30 border border-slate-800/60 rounded-xl">
          <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
            Page {page} of {pages} · {total} events
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs font-semibold text-slate-300 transition hover:border-slate-700 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
            >
              <ChevronLeft size={14} /> Previous
            </button>
            <span className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2 text-xs font-semibold text-slate-400">
              Page {page} / {pages}
            </span>
            <button
              onClick={() => setPage((p) => Math.min(pages, p + 1))}
              disabled={page >= pages}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs font-semibold text-slate-300 transition hover:border-slate-700 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
            >
              Next <ChevronRight size={14} />
            </button>
          </div>
        </div>
      )}

      <style dangerouslySetInnerHTML={{__html: `
        @keyframes fadeIn { from { opacity: 0; transform: translateY(-4px); } to { opacity: 1; transform: translateY(0); } }
        .animate-fadeIn { animation: fadeIn 0.15s ease-out forwards; }
      `}} />
    </div>
  );
}

export default Timeline;
