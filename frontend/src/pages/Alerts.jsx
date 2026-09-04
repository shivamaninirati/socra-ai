import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { ChevronDown, ChevronLeft, ChevronRight, Search, SlidersHorizontal, X } from "lucide-react";

import api from "../services/api";
import { useLiveSOC } from "../context/LiveSOCContext";
import { useSettings } from "../context/SettingsContext";
import LiveStatusBadge from "../components/live/LiveStatusBadge";
import EventDetailsDrawer from "../components/Events/EventDetailsDrawer";
import AlertTable, { ROW_HEIGHT } from "../components/AlertTable";
import Dropdown from "../components/ui/Dropdown";

const PAGE_SIZE = 50;
const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"];

const normalizeSeverityName = (raw) => {
  const value = String(raw || "Informational").trim().toLowerCase();
  const map = {
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
    informational: "Informational",
  };
  return map[value] || "Informational";
};

const fingerprintOf = (log) =>
  log?.metadata?.fingerprint ||
  `${log?.event?.time}-${log?.event?.event_id}-${log?.event?.process_id}-${log?.event?.record_number || ""}`;

const processedAfter = (log, timestamp) => {
  const processedAt = log?.metadata?.processed_at
    ? new Date(log.metadata.processed_at).getTime()
    : Date.now();

  return Number.isNaN(processedAt) || processedAt > timestamp;
};

const eventSourceMatches = (eventSource, selectedSource) => {
  if (selectedSource === "all") return true;
  if (selectedSource === "live") return true;
  if (selectedSource === "history") return false;
  return String(eventSource || "").toLowerCase() === selectedSource.toLowerCase();
};

const matchesLiveFilters = (log, filters) => {
  // Keyword search is resolved server-side (live + history) by the search
  // engine, so the client-side live overlay must not merge extra rows.
  if (filters.search) return false;
  const event = log?.event || {};
  const detection = log?.detection || {};
  const mitre = detection?.mitre;
  const processName = String(event.process_name || "").split("\\").pop();

  if (filters.severity !== "All" && normalizeSeverityName(detection.severity) !== filters.severity) return false;
  if (filters.host !== "All" && (event.host || event.computer) !== filters.host) return false;
  if (filters.mitre !== "All" && mitre?.id !== filters.mitre) return false;
  if (filters.eventId !== "All" && String(event.event_id) !== filters.eventId) return false;
  if (filters.process !== "All" && processName !== filters.process) return false;
  if (filters.pid !== "All" && String(event.process_id || "") !== filters.pid) return false;
  if (filters.user !== "All" && String(event.user || "") !== filters.user) return false;
  if (filters.status !== "All" && (event.status || detection.status || "New") !== filters.status) return false;
  if (!eventSourceMatches(event.source, filters.source)) return false;

  return true;
};

const toOptionList = (items, valueKey = "value") =>
  items.map((item) => ({
    value: item[valueKey],
    label: item.label || String(item[valueKey]),
    count: item.count || 0,
  }));

function SelectFilter({ label, value, onChange, options, searchable = false, clearable = false, loading = false, emptyText }) {
  return (
    <label className="flex min-w-[140px] flex-1 flex-col gap-1 sm:max-w-[220px]">
      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
        {label}
      </span>
      <Dropdown
        value={value}
        onChange={onChange}
        options={options}
        ariaLabel={label}
        searchable={searchable}
        clearable={clearable}
        loading={loading}
        emptyText={emptyText}
      />
    </label>
  );
}

function Alerts() {
  const { analytics, alertStatusUpdates } = useLiveSOC();
  const { settings } = useSettings();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const [filters, setFilters] = useState({
    timeRange: "today",
    severity: "All",
    host: "All",
    mitre: "All",
    eventId: "All",
    process: "All",
    pid: "All",
    user: "All",
    status: "All",
    source: "all",
    sort: "newest",
    // Keyword filter applied from Enterprise Search (?search=...) navigation.
    search: searchParams.get("search") || "",
  });

  const [page, setPage] = useState(1);
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [severityCounts, setSeverityCounts] = useState(null);
  const [filterMeta, setFilterMeta] = useState({
    hosts: [],
    users: [],
    processes: [],
    eventIds: [],
    mitres: [],
    statuses: [],
    pids: [],
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);
  const [selectedLog, setSelectedLog] = useState(null);
  const [showMoreFilters, setShowMoreFilters] = useState(false);

  const fetchSeqRef = useRef(0);
  const filtersRef = useRef(filters);
  const lastFetchTimeRef = useRef(Date.now());
  const previousLiveInsertRef = useRef(0);
  const appliedStatusUpdatesRef = useRef(0);
  const tableScrollRef = useRef(null);

  filtersRef.current = filters;

  const liveEvents = analytics?.liveEvents || [];

  const updateFilter = useCallback((key, value) => {
    setFilters((prev) => ({ ...prev, [key]: value }));
  }, []);

  // Removing the search filter also drops ?search= from the URL so a page
  // refresh does not silently re-apply the query.
  const clearSearchFromUrl = useCallback(() => {
    if (!searchParams.get("search")) return;
    const next = new URLSearchParams(searchParams);
    next.delete("search");
    setSearchParams(next, { replace: true });
  }, [searchParams, setSearchParams]);

  // Match a row to a status update by the persisted row id (_id) or the
  // metadata fingerprint — the two identities the backend uses.
  const statusMatches = useCallback((item, target) => {
    if (target?.alert_id != null && item?._id === target.alert_id) return true;
    if (
      target?.fingerprint &&
      item?.metadata?.fingerprint &&
      item.metadata.fingerprint === target.fingerprint
    ) return true;
    return false;
  }, []);

  const patchLogsStatus = useCallback((items, target, status) => {
    const matched = items.some((item) => statusMatches(item, target));
    if (!matched) return items;
    return items.map((item) =>
      statusMatches(item, target)
        ? { ...item, event: { ...(item.event || {}), status } }
        : item
    );
  }, [statusMatches]);

  // Optimistically apply a status change made in the details drawer to the
  // table rows (the drawer itself owns the API call + persistence).
  const handleStatusChange = useCallback((log, status) => {
    const target = { alert_id: log?._id, fingerprint: log?.metadata?.fingerprint };
    setLogs((prev) => patchLogsStatus(prev, target, status));
    setSelectedLog((prev) => (prev ? patchLogsStatus([prev], target, status)[0] : prev));
  }, [patchLogsStatus]);

  // Open the Investigation workspace for a real alert. The payload is kept in
  // sessionStorage so a page refresh (which drops router state) still restores
  // the same alert.
  const openInvestigation = useCallback((log) => {
    sessionStorage.setItem("socra_investigation_log", JSON.stringify(log));
    navigate("/investigation", { state: { log } });
  }, [navigate]);

  const fetchPage = useCallback(async (pageNumber, options = {}) => {
    const seq = ++fetchSeqRef.current;
    if (!options.silent) setLoading(true);
    setError("");

    try {
      const current = filtersRef.current;
      const response = await api.get("/logs/windows", {
        params: {
          page: pageNumber,
          limit: PAGE_SIZE,
          source: current.source,
          time_range: current.timeRange,
          severity: current.severity !== "All" ? current.severity : undefined,
          host: current.host !== "All" ? current.host : undefined,
          mitre: current.mitre !== "All" ? current.mitre : undefined,
          event_id: current.eventId !== "All" ? current.eventId : undefined,
          process: current.process !== "All" ? current.process : undefined,
          process_id: current.pid !== "All" ? current.pid : undefined,
          user: current.user !== "All" ? current.user : undefined,
          status: current.status !== "All" ? current.status : undefined,
          search: current.search || undefined,
        },
      });

      if (seq !== fetchSeqRef.current) return;

      setLogs(response.data.results || []);
      setTotal(response.data.total || 0);
      setSeverityCounts(response.data.severity_counts || null);
      setLastUpdated(new Date());
      lastFetchTimeRef.current = Date.now();
    } catch {
      if (seq === fetchSeqRef.current) {
        setError("Telemetry data is temporarily unavailable.");
      }
    } finally {
      if (seq === fetchSeqRef.current) {
        setLoading(false);
      }
    }
  }, []);

  const loadFilterMeta = useCallback(async () => {
    try {
      const response = await api.get("/alerts/filters");
      const data = response.data || {};
      setFilterMeta({
        hosts: toOptionList(data.hosts || []),
        users: toOptionList(data.users || []),
        processes: toOptionList(data.processes || []),
        eventIds: toOptionList(data.event_ids || []),
        mitres: toOptionList(data.mitre_ids || []),
        statuses: toOptionList(data.statuses || []),
        pids: toOptionList(data.pids || []),
      });
    } catch {
      // Existing filters remain usable with the last loaded metadata.
    }
  }, []);

  useEffect(() => {
    fetchPage(1);
    loadFilterMeta();
  }, [fetchPage, loadFilterMeta]);

  // Live clients receive every persisted status change over the WebSocket.
  // Apply them to REST-served rows and refetch the page (a status filter can
  // change which rows belong on the page). Only NEW updates are processed.
  useEffect(() => {
    if (alertStatusUpdates.length <= appliedStatusUpdatesRef.current) return;
    const fresh = alertStatusUpdates.slice(appliedStatusUpdatesRef.current);
    appliedStatusUpdatesRef.current = alertStatusUpdates.length;

    setLogs((prev) =>
      fresh.reduce((items, update) =>
        patchLogsStatus(items, update, update.status), prev)
    );
    const timer = setTimeout(() => fetchPage(page, { silent: true }), 300);
    return () => clearTimeout(timer);
  }, [alertStatusUpdates, fetchPage, page, patchLogsStatus]);

  // Keep dropdown filter metadata in sync with live telemetry: the backend
  // filter cache is updated incrementally per event, so a light periodic
  // refresh (plus a debounced refresh right after new WebSocket events
  // arrive) surfaces new hosts/processes/PIDs/event IDs without rescanning
  // anything or recalculating on every dropdown open.
  useEffect(() => {
    const timer = setInterval(loadFilterMeta, 30000);
    return () => clearInterval(timer);
  }, [loadFilterMeta]);

  const liveEventCountRef = useRef(0);
  useEffect(() => {
    const liveCount = analytics?.liveEvents?.length || 0;
    if (liveCount <= liveEventCountRef.current) return;
    liveEventCountRef.current = liveCount;
    const timer = setTimeout(loadFilterMeta, 2000);
    return () => clearTimeout(timer);
  }, [analytics?.liveEvents?.length, loadFilterMeta]);

  useEffect(() => {
    setPage(1);
    const timer = setTimeout(() => fetchPage(1, { silent: true }), 300);
    return () => clearTimeout(timer);
  }, [filters, fetchPage]);

  useEffect(() => {
    fetchPage(page, { silent: true });
  }, [fetchPage, page]);

  // Real-time updates come from the WebSocket live overlay (new events are
  // merged into the table and severity counters immediately via
  // analytics.liveEvents) — the initial REST fetch plus filter/page changes
  // keep the paginated view synchronized, so no periodic REST poll is needed.

  // Settings → Auto Refresh Alerts: when OFF, new telemetry still arrives over
  // the WebSocket (and REST fetches below still work for manual refresh), but
  // the table does not live-insert new rows into the current view.
  const autoRefresh = settings.autoRefresh;

  const liveInsertCount = useMemo(() => {
    if (!autoRefresh || page !== 1 || liveEvents.length === 0) return 0;

    const seen = new Set(logs.map(fingerprintOf));
    let count = 0;

    for (const event of liveEvents) {
      if (count >= PAGE_SIZE) break;
      if (!matchesLiveFilters(event, filters)) continue;
      if (!processedAfter(event, lastFetchTimeRef.current)) continue;

      const key = fingerprintOf(event);
      if (seen.has(key)) continue;

      seen.add(key);
      count += 1;
    }

    return count;
  }, [autoRefresh, filters, liveEvents, logs, page]);

  const displayLogs = useMemo(() => {
    const merged = [...logs];

    if (autoRefresh && page === 1 && liveInsertCount > 0) {
      const seen = new Set(logs.map(fingerprintOf));
      let inserted = 0;

      for (const event of liveEvents) {
        if (inserted >= PAGE_SIZE) break;
        if (!matchesLiveFilters(event, filters)) continue;
        if (!processedAfter(event, lastFetchTimeRef.current)) continue;

        const key = fingerprintOf(event);
        if (seen.has(key)) continue;

        seen.add(key);
        merged.push(event);
        inserted += 1;
      }
    }

    merged.sort((a, b) => {
      if (filters.sort === "oldest") {
        return new Date(a?.event?.time || 0) - new Date(b?.event?.time || 0);
      }

      if (filters.sort === "severity") {
        return SEVERITY_ORDER.indexOf(normalizeSeverityName(a?.detection?.severity)) -
          SEVERITY_ORDER.indexOf(normalizeSeverityName(b?.detection?.severity));
      }

      return new Date(b?.event?.time || 0) - new Date(a?.event?.time || 0);
    });

    return merged.slice(0, PAGE_SIZE);
  }, [autoRefresh, filters, liveEvents, liveInsertCount, logs, page]);

  useEffect(() => {
    const element = tableScrollRef.current;
    const delta = liveInsertCount - previousLiveInsertRef.current;

    if (element && delta > 0 && element.scrollLeft > 0) {
      element.scrollLeft += delta * ROW_HEIGHT;
    }

    previousLiveInsertRef.current = liveInsertCount;
  }, [liveInsertCount]);

  const activeFilterCount = useMemo(() => {
    return ["severity", "host", "mitre", "eventId", "process", "pid", "user", "status"]
      .filter((key) => filters[key] !== "All").length +
      (filters.search ? 1 : 0) +
      (filters.timeRange !== "today" ? 1 : 0) +
      (filters.source !== "all" ? 1 : 0) +
      (filters.sort !== "newest" ? 1 : 0);
  }, [filters]);

  const liveOverlayCounts = useMemo(() => {
    if (!autoRefresh) return {};
    const counts = {};

    for (const event of liveEvents) {
      if (!matchesLiveFilters(event, filters)) continue;
      if (!processedAfter(event, lastFetchTimeRef.current)) continue;

      const severity = normalizeSeverityName(event?.detection?.severity);
      counts[severity] = (counts[severity] || 0) + 1;
    }

    return counts;
  }, [autoRefresh, filters, liveEvents]);

  const displayCounts = useMemo(() => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };

    if (severityCounts) {
      SEVERITY_ORDER.forEach((severity) => {
        counts[severity] = severityCounts[severity] || 0;
      });
    }

    Object.entries(liveOverlayCounts).forEach(([severity, count]) => {
      counts[severity] = (counts[severity] || 0) + count;
    });

    return counts;
  }, [liveOverlayCounts, severityCounts]);

  const liveOverlayTotal = useMemo(
    () => Object.values(liveOverlayCounts).reduce((sum, count) => sum + count, 0),
    [liveOverlayCounts]
  );

  const filteredTotal = total + liveOverlayTotal;
  const pages = Math.max(1, Math.ceil(filteredTotal / PAGE_SIZE));
  const pageStart = filteredTotal === 0 ? 0 : (page - 1) * PAGE_SIZE + 1;
  const pageEnd = Math.min(page * PAGE_SIZE, filteredTotal);

  const timeOptions = [
    { value: "today", label: "Today" },
    { value: "last_15m", label: "Last 15m" },
    { value: "last_3h", label: "Last 3h" },
    { value: "last_24h", label: "Last 24h" },
    { value: "last_7d", label: "Last 7d" },
    { value: "all", label: "All time" },
  ];

  const severityOptions = [
    { value: "All", label: "All severities" },
    ...SEVERITY_ORDER.map((severity) => ({
      value: severity,
      label: `${severity} (${(displayCounts[severity] || 0).toLocaleString()})`,
    })),
  ];

  const hostOptions = useMemo(() => [
    { value: "All", label: "All hosts" },
    ...filterMeta.hosts.map((item) => ({
      value: item.value,
      label: `${item.value} (${item.count.toLocaleString()})`,
    })),
  ], [filterMeta.hosts]);

  const mitreOptions = useMemo(() => [
    { value: "All", label: "All MITRE" },
    ...filterMeta.mitres.map((item) => ({
      value: item.value,
      label: `${item.label || item.value} (${item.count.toLocaleString()})`,
    })),
  ], [filterMeta.mitres]);

  const eventIdOptions = useMemo(() => [
    { value: "All", label: "All event IDs" },
    ...filterMeta.eventIds.map((item) => ({
      value: item.value,
      label: `${item.label || item.value} (${item.count.toLocaleString()})`,
    })),
  ], [filterMeta.eventIds]);

  const processOptions = useMemo(() => [
    { value: "All", label: "All processes" },
    ...filterMeta.processes.map((item) => ({
      value: item.value,
      label: `${item.value} (${item.count.toLocaleString()})`,
    })),
  ], [filterMeta.processes]);

  const pidOptions = useMemo(() => [
    { value: "All", label: "All process IDs" },
    ...filterMeta.pids.map((item) => ({
      value: item.value,
      label: `${item.value} (${item.count.toLocaleString()})`,
    })),
  ], [filterMeta.pids]);

  const userOptions = useMemo(() => [
    { value: "All", label: "All users" },
    ...filterMeta.users.map((item) => ({
      value: item.value,
      label: `${item.value} (${item.count.toLocaleString()})`,
    })),
  ], [filterMeta.users]);

  const statusOptions = useMemo(() => [
    { value: "All", label: "All statuses" },
    ...(filterMeta.statuses.length ? filterMeta.statuses : [{ value: "New", count: 0 }]).map((item) => ({
      value: item.value,
      label: `${item.value} (${item.count.toLocaleString()})`,
    })),
  ], [filterMeta.statuses]);

  const sourceOptions = [
    { value: "all", label: "All sources" },
    { value: "live", label: "Live memory" },
    { value: "history", label: "History" },
  ];

  const sortOptions = [
    { value: "newest", label: "Newest first" },
    { value: "oldest", label: "Oldest first" },
    { value: "severity", label: "Severity first" },
  ];

  const clearFilters = () => {
    setFilters({
      timeRange: "today",
      severity: "All",
      host: "All",
      mitre: "All",
      eventId: "All",
      process: "All",
      pid: "All",
      user: "All",
      status: "All",
      source: "all",
      sort: "newest",
      search: "",
    });
    clearSearchFromUrl();
    setShowMoreFilters(false);
  };

  return (
    <section className="space-y-5 pb-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-2xl font-bold text-white">Alerts</h1>
            <span className="inline-flex items-center gap-2 rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 text-xs font-bold uppercase tracking-wide text-emerald-400">
              <span className="h-2 w-2 rounded-full bg-emerald-400" />
              Live
            </span>
          </div>
          <p className="mt-1 text-sm text-slate-400">
            Browse live Windows security telemetry and open investigations from one focused queue.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <LiveStatusBadge />
          <div className="rounded-xl border border-slate-800 bg-slate-900/40 px-4 py-2">
            <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Matching Alerts</p>
            <p className="font-mono text-xl font-bold text-white">{filteredTotal.toLocaleString()}</p>
          </div>
          {activeFilterCount > 0 && (
            <button
              onClick={clearFilters}
              className="text-xs font-semibold text-slate-400 transition hover:text-cyan-400"
            >
              Clear filters
            </button>
          )}
        </div>
      </div>

      <div className="rounded-xl border border-slate-800 bg-slate-900/30 p-4 shadow-sm">
        <div className="flex flex-wrap items-end gap-3">
          <SelectFilter label="Time Range" value={filters.timeRange} onChange={(value) => updateFilter("timeRange", value)} options={timeOptions} />
          <SelectFilter label="Severity" value={filters.severity} onChange={(value) => updateFilter("severity", value)} options={severityOptions} />
          <SelectFilter label="Host" value={filters.host} onChange={(value) => updateFilter("host", value)} options={hostOptions} searchable clearable />
          <SelectFilter label="MITRE" value={filters.mitre} onChange={(value) => updateFilter("mitre", value)} options={mitreOptions} searchable clearable />
          <SelectFilter label="Event ID" value={filters.eventId} onChange={(value) => updateFilter("eventId", value)} options={eventIdOptions} searchable clearable />
          <SelectFilter label="Process" value={filters.process} onChange={(value) => updateFilter("process", value)} options={processOptions} searchable clearable />

          {filters.search && (
            <button
              onClick={() => { updateFilter("search", ""); clearSearchFromUrl(); }}
              title="Clear search filter"
              className="inline-flex h-10 items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 text-xs font-semibold text-cyan-400 transition hover:bg-cyan-500/20"
            >
              <Search size={13} />
              <span className="max-w-[200px] truncate">{filters.search}</span>
              <X size={13} />
            </button>
          )}

          <div className="relative ml-auto">
            <button
              onClick={() => setShowMoreFilters((value) => !value)}
              className="inline-flex h-10 items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-3 text-xs font-semibold text-slate-300 transition hover:border-slate-700 hover:text-white"
            >
              <SlidersHorizontal size={14} />
              More Filters
              <ChevronDown size={14} className={`transition ${showMoreFilters ? "rotate-180" : ""}`} />
            </button>

            {showMoreFilters && (
              <div className="absolute right-0 z-30 mt-2 w-[min(720px,calc(100vw-4rem))] rounded-xl border border-slate-600 bg-slate-700 p-4 shadow-2xl shadow-black/50">
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                  <SelectFilter label="User" value={filters.user} onChange={(value) => updateFilter("user", value)} options={userOptions} searchable clearable />
                  <SelectFilter label="Process ID" value={filters.pid} onChange={(value) => updateFilter("pid", value)} options={pidOptions} searchable clearable />
                  <SelectFilter label="Status" value={filters.status} onChange={(value) => updateFilter("status", value)} options={statusOptions} />
                  <SelectFilter label="Source" value={filters.source} onChange={(value) => updateFilter("source", value)} options={sourceOptions} />
                  <SelectFilter label="Sort" value={filters.sort} onChange={(value) => updateFilter("sort", value)} options={sortOptions} />
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-slate-500">
          <span>{activeFilterCount ? `${activeFilterCount} active filter${activeFilterCount === 1 ? "" : "s"}` : "No additional filters active"}</span>
          {lastUpdated && <span>Updated {lastUpdated.toLocaleTimeString("en-GB", { hour12: false })}</span>}
          {liveOverlayTotal > 0 && <span className="text-cyan-400">+{liveOverlayTotal} live match{liveOverlayTotal === 1 ? "" : "es"}</span>}
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="rounded-xl border border-slate-800 bg-slate-900/30 shadow-sm">
        <div ref={tableScrollRef} className="overflow-x-auto">
          {loading && logs.length === 0 ? (
            <div className="space-y-3 p-4">
              {Array.from({ length: 8 }).map((_, index) => (
                <div key={index} className="h-14 animate-pulse rounded-lg border border-slate-800/70 bg-slate-900/50" />
              ))}
            </div>
          ) : (
            <AlertTable
              logs={displayLogs}
              onSelect={setSelectedLog}
              onInvestigate={openInvestigation}
              totalCount={filteredTotal}
            />
          )}
        </div>
      </div>

      <div className="flex flex-col gap-3 rounded-xl border border-slate-800 bg-slate-900/30 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-xs text-slate-500">
          Showing <span className="font-mono text-slate-300">{pageStart.toLocaleString()}-{pageEnd.toLocaleString()}</span> of{" "}
          <span className="font-mono text-slate-300">{filteredTotal.toLocaleString()}</span>
        </p>
        <div className="flex items-center gap-2">
          <button
            disabled={page <= 1}
            onClick={() => setPage((value) => Math.max(1, value - 1))}
            className="inline-flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs font-semibold text-slate-300 transition hover:border-slate-700 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
          >
            <ChevronLeft size={14} />
            Previous
          </button>
          <span className="rounded-lg border border-slate-800 bg-slate-950/40 px-3 py-2 text-xs font-semibold text-slate-400">
            Page {page} / {pages}
          </span>
          <button
            disabled={page >= pages}
            onClick={() => setPage((value) => Math.min(pages, value + 1))}
            className="inline-flex items-center gap-1 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs font-semibold text-slate-300 transition hover:border-slate-700 hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
          >
            Next
            <ChevronRight size={14} />
          </button>
        </div>
      </div>

      <EventDetailsDrawer
        log={selectedLog}
        onClose={() => setSelectedLog(null)}
        onStatusChange={handleStatusChange}
      />
    </section>
  );
}

export default Alerts;