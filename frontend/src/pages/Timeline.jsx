import { useEffect, useState, useMemo, useCallback } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
  AlertCircle,
  Terminal,
  Filter,
  Monitor,
  Clock3,
  Eye,
  ArrowUpRight,
  ListTree,
  Calendar,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
} from "lucide-react";
import liveSocket from "../services/liveSocket";
import api from "../services/api";
import Dropdown from "../components/ui/Dropdown";

const severityColor = (severity) => {
  switch ((severity || "").toLowerCase()) {
    case "critical":
      return {
        dot: "bg-red-500",
        text: "text-red-400",
        bg: "bg-red-500/10",
        border: "border-red-500/25",
      };
    case "high":
      return {
        dot: "bg-orange-500",
        text: "text-orange-400",
        bg: "bg-orange-500/10",
        border: "border-orange-500/25",
      };
    case "medium":
      return {
        dot: "bg-amber-500",
        text: "text-amber-400",
        bg: "bg-amber-500/10",
        border: "border-amber-500/25",
      };
    case "low":
      return {
        dot: "bg-emerald-500",
        text: "text-emerald-400",
        bg: "bg-emerald-500/10",
        border: "border-emerald-500/25",
      };
    default:
      return {
        dot: "bg-slate-500",
        text: "text-slate-400",
        bg: "bg-slate-500/10",
        border: "border-slate-500/25",
      };
  }
};

const normalizeSeverity = (severity) => {
  const value = (severity || "").toLowerCase();

  if (
    ["", "unknown", "none", "null", "info", "informational"].includes(value)
  ) {
    return "Informational";
  }

  const capitalized = value.charAt(0).toUpperCase() + value.slice(1).toLowerCase();

  return ["Critical", "High", "Medium", "Low"].includes(capitalized)
    ? capitalized
    : "Informational";
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

  const [range, setRange] = useState("all");
  const [customFrom, setCustomFrom] = useState("");
  const [customTo, setCustomTo] = useState("");
  const [appliedFrom, setAppliedFrom] = useState("");
  const [appliedTo, setAppliedTo] = useState("");
  const [page, setPage] = useState(1);
  const limit = 100;
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState(1);
  const [refreshKey, setRefreshKey] = useState(0);

  const [filterSeverity, setFilterSeverity] = useState("All");
  const [filterHost, setFilterHost] = useState(
    () => searchParams.get("host") || "All"
  );
  const [filterMitre, setFilterMitre] = useState("All");
  const [filterEventId, setFilterEventId] = useState("All");
  const [filterProcess, setFilterProcess] = useState("All");
  const [filterUser, setFilterUser] = useState("All");
  const [filterOptions, setFilterOptions] = useState(DEFAULT_FILTER_OPTIONS);

  const handleFilterChange = (setter) => (value) => {
    setter(value);
    setPage(1);
  };

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

        if (!cancelled) {
          setError(
            "Could not load timeline data. Check the backend connection and try again."
          );
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();

    return () => {
      cancelled = true;
    };
  }, [
    range,
    page,
    limit,
    appliedFrom,
    appliedTo,
    filterHost,
    filterUser,
    filterProcess,
    filterEventId,
    filterSeverity,
    filterMitre,
    refreshKey,
  ]);

  useEffect(() => {
    api
      .get("/timeline/filters")
      .then((response) => {
        const data = response.data || {};

        setFilterOptions({
          hosts: data.hosts?.length
            ? data.hosts
            : DEFAULT_FILTER_OPTIONS.hosts,
          users: data.users?.length
            ? data.users
            : DEFAULT_FILTER_OPTIONS.users,
          processes: data.processes?.length
            ? data.processes
            : DEFAULT_FILTER_OPTIONS.processes,
          eventIds: data.event_ids?.length
            ? data.event_ids
            : DEFAULT_FILTER_OPTIONS.eventIds,
          mitres: data.mitres?.length
            ? data.mitres
            : DEFAULT_FILTER_OPTIONS.mitres,
          severities: data.severities?.length
            ? data.severities
            : DEFAULT_FILTER_OPTIONS.severities,
        });
      })
      .catch((err) => console.error("Timeline filter options error:", err));
  }, []);

  const mapLiveEvent = useCallback(
    (alert) => ({
      timestamp: alert.event?.time,
      event_id: String(alert.event?.event_id || ""),
      user: alert.event?.user || "SYSTEM",
      process: alert.event?.process_name || "Not available in event",
      host: alert.event?.host || alert.event?.computer || "Unknown",
      action: alert.detection?.detection || "Security Event",
      severity: normalizeSeverity(alert.detection?.severity),
      mitre_id:
        (alert.detection?.mitre &&
        typeof alert.detection.mitre === "object"
          ? alert.detection.mitre.id
          : alert.detection?.mitre) || "Unmapped",
      details: {
        command_line: alert.event?.command_line || "",
        parent_process:
          alert.event?.parent_process || alert.event?.parent_image || "N/A",
        description: alert.detection?.description || "",
      },
      fingerprint: alert.metadata?.fingerprint,
    }),
    []
  );

  const inTimeRange = useCallback(
    (timestamp) => {
      if (!timestamp) return true;

      const time = new Date(timestamp).getTime();
      if (Number.isNaN(time)) return true;

      const now = Date.now();

      if (range === "today") {
        const start = new Date();
        start.setHours(0, 0, 0, 0);
        return time >= start.getTime();
      }

      if (range === "last_24h") return time >= now - 24 * 3600 * 1000;
      if (range === "last_7d") return time >= now - 7 * 24 * 3600 * 1000;
      if (range === "last_30d") return time >= now - 30 * 24 * 3600 * 1000;

      if (range === "custom") {
        if (appliedFrom && new Date(appliedFrom).getTime() > time) return false;
        if (appliedTo && new Date(appliedTo).getTime() < time) return false;
      }

      return true;
    },
    [range, appliedFrom, appliedTo]
  );

  const matchesFilters = useCallback(
    (event) => {
      if (
        filterSeverity !== "All" &&
        (event.severity || "").toLowerCase() !== filterSeverity.toLowerCase()
      ) {
        return false;
      }

      if (filterHost !== "All" && event.host !== filterHost) return false;
      if (filterMitre !== "All" && event.mitre_id !== filterMitre) return false;
      if (
        filterEventId !== "All" &&
        String(event.event_id) !== filterEventId
      ) {
        return false;
      }

      if (filterProcess !== "All") {
        const process = (event.process || "").split("\\").pop();
        if (process !== filterProcess) return false;
      }

      if (filterUser !== "All" && event.user !== filterUser) return false;

      return true;
    },
    [
      filterSeverity,
      filterHost,
      filterMitre,
      filterEventId,
      filterProcess,
      filterUser,
    ]
  );

  useEffect(() => {
    const handler = (message) => {
      if (
        !message ||
        !message.type ||
        !["alert", "incident"].includes(message.type)
      ) {
        return;
      }

      const liveEvent = mapLiveEvent(message);

      if (!inTimeRange(liveEvent.timestamp)) return;
      if (!matchesFilters(liveEvent)) return;

      setEvents((previous) => {
        const key = (event) =>
          event.fingerprint || `${event.timestamp}-${event.event_id}`;

        const existing = new Set(previous.map(key));

        if (existing.has(key(liveEvent))) return previous;

        const merged = [liveEvent, ...previous];

        merged.sort(
          (a, b) =>
            new Date(b.timestamp || 0) - new Date(a.timestamp || 0)
        );

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
            parent_process_name: event.details?.parent_process,
          },
          detection: {
            severity: event.severity,
            detection: event.action,
            mitre: { id: event.mitre_id },
            description: event.details?.description || "",
          },
        },
      },
    });
  };

  const formatTime = (timestamp) => {
    if (!timestamp) return { time: "-", date: "" };

    try {
      const date = new Date(timestamp);

      return {
        time: date.toLocaleTimeString("en-GB", { hour12: false }),
        date: date.toLocaleDateString("en-GB", {
          day: "2-digit",
          month: "short",
          year: "numeric",
        }),
      };
    } catch {
      return { time: timestamp, date: "" };
    }
  };

  const activeFilters = [
    filterSeverity,
    filterHost,
    filterMitre,
    filterEventId,
    filterProcess,
    filterUser,
  ].filter((value) => value !== "All").length;

  const clearFilters = () => {
    setFilterSeverity("All");
    setFilterHost("All");
    setFilterMitre("All");
    setFilterEventId("All");
    setFilterProcess("All");
    setFilterUser("All");
    setPage(1);
  };

  const applyCustomRange = () => {
    setAppliedFrom(customFrom);
    setAppliedTo(customTo);
    setPage(1);
  };

  const shownCount = useMemo(() => events.length, [events]);

  return (
    <div className="w-full space-y-5 pb-8 select-none">
      {/* Header */}
      <div className="flex flex-col justify-between gap-3 pt-4 sm:flex-row sm:items-center">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="flex items-center gap-2 text-xl font-extrabold tracking-tight text-slate-100">
              <Clock3 size={20} className="text-slate-400" />
              <span>Forensic Timeline</span>
            </h1>

            <span className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/15 bg-emerald-500/5 px-2 py-0.5 text-[9px] font-bold uppercase tracking-widest text-emerald-400">
              <span className="h-1 w-1 animate-pulse rounded-full bg-emerald-400" />
              Live
            </span>
          </div>

          <p className="mt-1.5 text-xs font-medium text-slate-500">
            Chronological event sequence — {shownCount} of {total} matching
            events
            {lastUpdated
              ? ` · Last sync: ${lastUpdated.toLocaleTimeString("en-GB")}`
              : ""}
          </p>
        </div>

        <div className="flex items-center gap-2">
          {activeFilters > 0 && (
            <button
              onClick={clearFilters}
              className="rounded-lg border border-slate-700/70 bg-slate-900/70 px-2.5 py-1.5 text-[10px] font-bold uppercase tracking-wider text-slate-400 transition hover:border-slate-600 hover:text-slate-200"
            >
              Clear Filters ({activeFilters})
            </button>
          )}

          <button
            onClick={() => setRefreshKey((key) => key + 1)}
            className="rounded-lg border border-slate-700/70 bg-slate-900/70 px-3 py-1.5 text-xs font-semibold text-slate-300 transition hover:border-slate-600 hover:bg-slate-800 hover:text-white"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2 rounded-xl border border-slate-800/80 bg-slate-950/40 p-3">
        <Filter size={13} className="mr-1 shrink-0 text-slate-500" />

        <div className="min-w-[140px]">
          <Dropdown
            value={range}
            onChange={(value) => {
              setRange(value);
              setPage(1);
            }}
            options={RANGE_OPTIONS}
            ariaLabel="Time range"
          />
        </div>

        <div className="mx-1 h-5 w-px shrink-0 bg-slate-800" />

        <div className="min-w-[140px]">
          <Dropdown
            value={filterSeverity}
            onChange={handleFilterChange(setFilterSeverity)}
            options={filterOptions.severities.map((value) => ({
              value,
              label: value,
            }))}
            ariaLabel="Severity"
          />
        </div>

        <div className="min-w-[140px]">
          <Dropdown
            value={filterHost}
            onChange={handleFilterChange(setFilterHost)}
            options={filterOptions.hosts.map((value) => ({
              value,
              label: value,
            }))}
            ariaLabel="Host"
            searchable
            clearable
          />
        </div>

        <div className="min-w-[140px]">
          <Dropdown
            value={filterMitre}
            onChange={handleFilterChange(setFilterMitre)}
            options={filterOptions.mitres.map((value) => ({
              value,
              label: value,
            }))}
            ariaLabel="MITRE"
            searchable
            clearable
          />
        </div>

        <div className="min-w-[140px]">
          <Dropdown
            value={filterEventId}
            onChange={handleFilterChange(setFilterEventId)}
            options={filterOptions.eventIds.map((value) => ({
              value,
              label: value,
            }))}
            ariaLabel="Event ID"
            searchable
            clearable
          />
        </div>

        <div className="min-w-[140px]">
          <Dropdown
            value={filterProcess}
            onChange={handleFilterChange(setFilterProcess)}
            options={filterOptions.processes.map((value) => ({
              value,
              label: value,
            }))}
            ariaLabel="Process"
            searchable
            clearable
          />
        </div>

        <div className="min-w-[140px]">
          <Dropdown
            value={filterUser}
            onChange={handleFilterChange(setFilterUser)}
            options={filterOptions.users.map((value) => ({
              value,
              label: value,
            }))}
            ariaLabel="User"
            searchable
            clearable
          />
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/5 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* Custom date range */}
      {range === "custom" && (
        <div className="flex flex-wrap items-center gap-3 rounded-xl border border-slate-800/80 bg-slate-950/40 p-3">
          <span className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-widest text-slate-500">
            <Calendar size={12} />
            Custom Range
          </span>

          <label className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">
            From
            <input
              type="datetime-local"
              value={customFrom}
              onChange={(event) => setCustomFrom(event.target.value)}
              className="rounded-lg border border-slate-700/70 bg-slate-900 px-2 py-1.5 text-xs font-medium normal-case tracking-normal text-slate-300 outline-none transition focus:border-slate-600"
            />
          </label>

          <label className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">
            To
            <input
              type="datetime-local"
              value={customTo}
              onChange={(event) => setCustomTo(event.target.value)}
              className="rounded-lg border border-slate-700/70 bg-slate-900 px-2 py-1.5 text-xs font-medium normal-case tracking-normal text-slate-300 outline-none transition focus:border-slate-600"
            />
          </label>

          <button
            onClick={applyCustomRange}
            className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-[10px] font-bold text-slate-200 transition hover:bg-slate-700"
          >
            Apply
          </button>
        </div>
      )}

      {/* Timeline */}
      <div className="min-h-[55vh] w-full rounded-xl border border-slate-800/80 bg-slate-950/30">
        {loading ? (
          <div className="flex flex-col items-center justify-center py-24">
            <div className="mb-4 h-9 w-9 animate-spin rounded-full border-2 border-slate-700 border-t-slate-300" />
            <p className="animate-pulse text-xs text-slate-500">
              Loading forensic timeline data...
            </p>
          </div>
        ) : events.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-24">
            <div className="mb-3 rounded-xl border border-slate-800 bg-slate-900/60 p-3 text-slate-500">
              <AlertCircle size={24} />
            </div>

            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-300">
              No Timeline Events
            </h2>

            <p className="mt-1 max-w-xs text-center text-[11px] text-slate-500">
              {activeFilters > 0 || range !== "all"
                ? "No events match the current filter criteria."
                : "No forensic timeline events available."}
            </p>
          </div>
        ) : (
          <div className="relative space-y-0 py-6 pl-8 pr-4">
            <div className="absolute bottom-0 left-[27px] top-0 w-px bg-slate-800" />

            {events.map((event, index) => {
              const colors = severityColor(event.severity);
              const timestamp = formatTime(event.timestamp);
              const isSelected = selectedEvent === event;
              const isExpanded = expandedEvent === index;

              return (
                <div
                  key={`${event.timestamp}-${event.event_id}-${index}`}
                  className="group relative"
                >
                  <div className="absolute left-[-31px] top-5 z-10">
                    <div
                      className={`flex h-4 w-4 items-center justify-center rounded-full border-2 ${colors.bg} ${colors.border}`}
                    >
                      <div className={`h-1.5 w-1.5 rounded-full ${colors.dot}`} />
                    </div>
                  </div>

                  <div
                    onClick={() => {
                      setSelectedEvent(event);
                      setExpandedEvent(isExpanded ? null : index);
                    }}
                    className={`mb-3 ml-4 cursor-pointer rounded-xl border p-4 transition-colors duration-150 ${
                      isSelected
                        ? "border-slate-600 bg-slate-800/60"
                        : "border-slate-800/70 bg-slate-900/40 hover:border-slate-700 hover:bg-slate-900/80"
                    }`}
                  >
                    <div className="flex flex-col justify-between gap-2 sm:flex-row sm:items-center">
                      <div className="flex min-w-0 flex-1 items-center gap-3">
                        <div className={`h-8 w-1 shrink-0 rounded-full ${colors.dot}`} />

                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            <h3 className={`truncate text-sm font-bold ${colors.text}`}>
                              {event.action || "Security Event"}
                            </h3>

                            {event.mitre_id &&
                              !["N/A", "Unknown", "Unmapped"].includes(
                                event.mitre_id
                              ) && (
                                <span className="shrink-0 rounded border border-purple-500/20 bg-purple-500/5 px-1.5 py-0.5 font-mono text-[9px] font-bold text-purple-400">
                                  {event.mitre_id}
                                </span>
                              )}
                          </div>

                          <div className="mt-1 flex items-center gap-2">
                            <span className="font-mono text-[11px] text-slate-500">
                              {timestamp.time}
                            </span>

                            <span className="text-[10px] text-slate-700">•</span>

                            <span className="flex min-w-0 items-center gap-1 truncate text-[11px] text-slate-400">
                              <Monitor
                                size={10}
                                className="shrink-0 text-slate-500"
                              />
                              {event.host || "Unknown"}
                            </span>
                          </div>
                        </div>
                      </div>

                      <div className="flex shrink-0 items-center gap-2">
                        <span className="rounded border border-slate-700/70 bg-slate-950/60 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-slate-400">
                          EID: {event.event_id || "-"}
                        </span>

                        <span
                          className={`rounded border px-2 py-0.5 text-[10px] font-bold ${colors.bg} ${colors.text} ${colors.border}`}
                        >
                          {event.severity || "Info"}
                        </span>

                        <ChevronDown
                          size={13}
                          className={`text-slate-500 transition-transform duration-150 ${
                            isExpanded ? "rotate-180" : ""
                          }`}
                        />
                      </div>
                    </div>

                    {isExpanded && (
                      <div className="mt-4 space-y-3 border-t border-slate-800/80 pt-3">
                        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                          <div className="rounded-lg border border-slate-800/60 bg-slate-950/50 p-2">
                            <p className="text-[9px] font-bold uppercase tracking-widest text-slate-500">
                              Process
                            </p>
                            <p className="mt-1 truncate font-mono text-xs text-slate-300">
                              {(event.process || "Not available in event")
                                .split("\\")
                                .pop()}
                            </p>
                          </div>

                          <div className="rounded-lg border border-slate-800/60 bg-slate-950/50 p-2">
                            <p className="text-[9px] font-bold uppercase tracking-widest text-slate-500">
                              User
                            </p>
                            <p className="mt-1 truncate text-xs text-slate-300">
                              {event.user || "N/A"}
                            </p>
                          </div>

                          <div className="rounded-lg border border-slate-800/60 bg-slate-950/50 p-2">
                            <p className="text-[9px] font-bold uppercase tracking-widest text-slate-500">
                              Date
                            </p>
                            <p className="mt-1 text-xs text-slate-400">
                              {timestamp.date || "-"}
                            </p>
                          </div>

                          <div className="rounded-lg border border-slate-800/60 bg-slate-950/50 p-2">
                            <p className="text-[9px] font-bold uppercase tracking-widest text-slate-500">
                              MITRE
                            </p>
                            <p
                              className={`mt-1 font-mono text-xs ${
                                event.mitre_id && event.mitre_id !== "Unmapped"
                                  ? "text-purple-400"
                                  : "text-slate-500"
                              }`}
                            >
                              {event.mitre_id || "Unmapped"}
                            </p>
                          </div>
                        </div>

                        {event.details?.command_line && (
                          <div className="rounded-lg border border-slate-800/70 bg-slate-950/70 p-3">
                            <div className="mb-2 flex items-center gap-1.5">
                              <Terminal size={12} className="text-slate-400" />
                              <span className="text-[9px] font-bold uppercase tracking-widest text-slate-500">
                                Command Line
                              </span>
                            </div>

                            <pre className="whitespace-pre-wrap break-all font-mono text-[11px] text-emerald-400">
                              {event.details.command_line}
                            </pre>
                          </div>
                        )}

                        {event.details?.description && (
                          <p className="text-xs leading-6 text-slate-400">
                            {event.details.description}
                          </p>
                        )}

                        {event.details?.parent_process &&
                          event.details.parent_process !== "N/A" && (
                            <div className="flex items-center gap-1.5 text-[10px] text-slate-400">
                              <ListTree size={12} className="text-slate-500" />
                              <span className="font-bold uppercase tracking-wider text-slate-500">
                                Parent:
                              </span>
                              <span className="break-all font-mono">
                                {event.details.parent_process}
                              </span>
                            </div>
                          )}

                        <div className="flex justify-end">
                          <button
                            onClick={(clickEvent) => {
                              clickEvent.stopPropagation();
                              openInvestigation(event);
                            }}
                            className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-[10px] font-semibold text-slate-200 transition hover:border-slate-600 hover:bg-slate-700 hover:text-white"
                          >
                            <Eye size={12} />
                            Open in Investigation
                            <ArrowUpRight size={11} />
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

      {/* Pagination */}
      {total > 0 && (
        <div className="flex flex-col justify-between gap-3 rounded-xl border border-slate-800/80 bg-slate-950/40 px-3 py-3 sm:flex-row sm:items-center">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
            Page {page} of {pages} · {total} events
          </span>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((current) => Math.max(1, current - 1))}
              disabled={page <= 1}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2 text-xs font-semibold text-slate-300 transition hover:border-slate-700 hover:bg-slate-800 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
            >
              <ChevronLeft size={14} />
              Previous
            </button>

            <span className="rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs font-semibold text-slate-400">
              {page} / {pages}
            </span>

            <button
              onClick={() => setPage((current) => Math.min(pages, current + 1))}
              disabled={page >= pages}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2 text-xs font-semibold text-slate-300 transition hover:border-slate-700 hover:bg-slate-800 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
            >
              Next
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default Timeline;