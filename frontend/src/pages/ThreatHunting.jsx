import { useEffect, useState, useMemo, useCallback } from "react";

import PageHeader from "../components/ui/PageHeader";
import HuntCard from "../components/HuntCard";
import HuntResultsTable from "../components/HuntResultsTable";
import Dropdown from "../components/ui/Dropdown";
import api from "../services/api";

function ThreatHunting() {
  const [hunts, setHunts] = useState({});
  const [results, setResults] = useState([]);
  const [total, setTotal] = useState(0);
  const [selectedHunt, setSelectedHunt] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Dynamic filter options from backend
  const [filterOptions, setFilterOptions] = useState({
    hosts: [],
    users: [],
    processes: [],
    eventIds: [],
    mitres: [],
    severities: [],
    pids: [],
  });
  const [filterLoading, setFilterLoading] = useState(true);

  // Custom hunt criteria (all optional, ANDed server-side).
  const [criteria, setCriteria] = useState({
    event_id: "",
    process: "",
    pid: "",
    host: "",
    user: "",
    mitre: "",
    severity: "",
    time_range: "last_7d",
    keyword: "",
  });

  // Load hunts list
  useEffect(() => {
    let cancelled = false;
    async function init() {
      try {
        const data = await api.get("/hunt/list");
        if (!cancelled) setHunts(data.data.hunts || {});
      } catch {
        // Non-critical — existing hunts remain visible.
      }
    }
    init();
    return () => { cancelled = true; };
  }, []);

  // Load dynamic filter options from backend
  useEffect(() => {
    let cancelled = false;
    async function loadFilters() {
      try {
        const res = await api.get("/hunt/filters");
        const d = res.data || {};
        if (cancelled) return;
        setFilterOptions({
          hosts: d.hosts || [],
          users: d.users || [],
          processes: d.processes || [],
          eventIds: d.event_ids || [],
          mitres: d.mitres || [],
          severities: d.severities || [],
          pids: d.pids || [],
        });
      } catch {
        // Fallback to empty — dropdowns will show "No options available"
      } finally {
        if (!cancelled) setFilterLoading(false);
      }
    }
    loadFilters();
    return () => { cancelled = true; };
  }, []);

  const executeHunt = async (huntKey) => {
    setLoading(true);
    setSelectedHunt(huntKey);
    setError("");
    try {
      const response = await api.post("/hunt/run", { hunt: huntKey });
      const data = response.data;
      if (data.success) {
        setResults(data.results || []);
        setTotal(data.total || data.count || 0);
      } else {
        setResults([]);
        setTotal(0);
        setError(data.error || "Hunt failed.");
      }
    } catch {
      setResults([]);
      setTotal(0);
      setError("Hunt backend is unavailable.");
    }
    setLoading(false);
  };

  const runCustomHunt = async () => {
    const payload = {};
    Object.entries(criteria).forEach(([key, value]) => {
      if (value && value !== "All" && value !== "") payload[key] = value;
    });
    if (Object.keys(payload).length === 0) {
      setError("Provide at least one hunt criterion.");
      return;
    }
    setLoading(true);
    setSelectedHunt("Custom Hunt");
    setError("");
    try {
      const response = await api.post("/hunt/search", payload);
      const data = response.data;
      if (data.success) {
        setResults(data.results || []);
        setTotal(data.total || data.count || 0);
      } else {
        setResults([]);
        setTotal(0);
        setError(data.error || "Hunt failed.");
      }
    } catch {
      setResults([]);
      setTotal(0);
      setError("Hunt backend is unavailable.");
    }
    setLoading(false);
  };

  const updateCriteria = useCallback((key, value) => {
    setCriteria((prev) => ({ ...prev, [key]: value }));
  }, []);

  // Build option lists with "Any" as first option
  const hostOptions = useMemo(() => [
    { value: "", label: "Any host" },
    ...filterOptions.hosts.map((item) => ({
      value: item.value,
      label: `${item.value} (${item.count.toLocaleString()})`,
    })),
  ], [filterOptions.hosts]);

  const userOptions = useMemo(() => [
    { value: "", label: "Any user" },
    ...filterOptions.users.map((item) => ({
      value: item.value,
      label: `${item.value} (${item.count.toLocaleString()})`,
    })),
  ], [filterOptions.users]);

  const processOptions = useMemo(() => [
    { value: "", label: "Any process" },
    ...filterOptions.processes.map((item) => ({
      value: item.value,
      label: `${item.value} (${item.count.toLocaleString()})`,
    })),
  ], [filterOptions.processes]);

  const eventIdOptions = useMemo(() => [
    { value: "", label: "Any event ID" },
    ...filterOptions.eventIds.map((item) => ({
      value: item.value,
      label: `${item.value} (${item.count.toLocaleString()})`,
    })),
  ], [filterOptions.eventIds]);

  const mitreOptions = useMemo(() => [
    { value: "", label: "Any MITRE technique" },
    ...filterOptions.mitres.map((item) => ({
      value: item.value,
      label: `${item.value} (${item.count.toLocaleString()})`,
    })),
  ], [filterOptions.mitres]);

  const severityOptions = useMemo(() => [
    { value: "", label: "Any severity" },
    ...filterOptions.severities.map((item) => ({
      value: item.value,
      label: `${item.value} (${item.count.toLocaleString()})`,
    })),
  ], [filterOptions.severities]);

  const pidOptions = useMemo(() => [
    { value: "", label: "Any PID" },
    ...filterOptions.pids.map((item) => ({
      value: item.value,
      label: `${item.value} (${item.count.toLocaleString()})`,
    })),
  ], [filterOptions.pids]);

  const timeOptions = [
    { value: "today", label: "Today" },
    { value: "last_24h", label: "Last 24 hours" },
    { value: "last_7d", label: "Last 7 days" },
    { value: "last_30d", label: "Last 30 days" },
    { value: "all", label: "All time" },
  ];

  const activeFilterCount = useMemo(() => {
    return ["event_id", "process", "pid", "host", "user", "mitre", "severity"]
      .filter((key) => criteria[key] !== "" && criteria[key] !== "All").length +
      (criteria.keyword ? 1 : 0) +
      (criteria.time_range !== "last_7d" ? 1 : 0);
  }, [criteria]);

  const clearFilters = useCallback(() => {
    setCriteria({
      event_id: "",
      process: "",
      pid: "",
      host: "",
      user: "",
      mitre: "",
      severity: "",
      time_range: "last_7d",
      keyword: "",
    });
  }, []);

  return (
    <div className="space-y-8">
      <PageHeader
        title="Threat Hunting"
        subtitle="Run enterprise hunting queries against local SOCRA AI telemetry."
      />

      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-3 text-xs text-red-300 flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError("")} className="text-red-400 hover:text-red-300 text-[10px] font-bold uppercase">Dismiss</button>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        {Object.entries(hunts).map(([key, hunt]) => (
          <HuntCard
            key={key}
            huntKey={key}
            hunt={hunt}
            onRun={executeHunt}
          />
        ))}
      </div>

      {/* Custom hunt over local telemetry */}
      <div className="bg-slate-800/40 rounded-xl p-5 border border-slate-700/60">
        <div className="flex items-center justify-between mb-1">
          <h2 className="text-xl font-semibold text-white">Custom Hunt</h2>
          {activeFilterCount > 0 && (
            <button
              onClick={clearFilters}
              className="text-xs font-semibold text-slate-400 transition hover:text-cyan-400"
            >
              Clear filters ({activeFilterCount})
            </button>
          )}
        </div>
        <p className="text-slate-500 text-sm mb-4">
          Query the local SQLite telemetry store by any combination of criteria.
        </p>

        <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-5 gap-3">
          <label className="flex flex-col gap-1">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Event ID</span>
            <Dropdown
              value={criteria.event_id}
              onChange={(val) => updateCriteria("event_id", val)}
              options={eventIdOptions}
              ariaLabel="Event ID"
              searchable
              clearable
              loading={filterLoading}
              emptyText="No event IDs available"
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Process</span>
            <Dropdown
              value={criteria.process}
              onChange={(val) => updateCriteria("process", val)}
              options={processOptions}
              ariaLabel="Process"
              searchable
              clearable
              loading={filterLoading}
              emptyText="No processes available"
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">PID</span>
            <Dropdown
              value={criteria.pid}
              onChange={(val) => updateCriteria("pid", val)}
              options={pidOptions}
              ariaLabel="Process ID"
              searchable
              clearable
              loading={filterLoading}
              emptyText="No PIDs available"
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Host</span>
            <Dropdown
              value={criteria.host}
              onChange={(val) => updateCriteria("host", val)}
              options={hostOptions}
              ariaLabel="Host"
              searchable
              clearable
              loading={filterLoading}
              emptyText="No hosts available"
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">User</span>
            <Dropdown
              value={criteria.user}
              onChange={(val) => updateCriteria("user", val)}
              options={userOptions}
              ariaLabel="User"
              searchable
              clearable
              loading={filterLoading}
              emptyText="No users available"
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">MITRE</span>
            <Dropdown
              value={criteria.mitre}
              onChange={(val) => updateCriteria("mitre", val)}
              options={mitreOptions}
              ariaLabel="MITRE technique"
              searchable
              clearable
              loading={filterLoading}
              emptyText="No MITRE techniques available"
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Severity</span>
            <Dropdown
              value={criteria.severity}
              onChange={(val) => updateCriteria("severity", val)}
              options={severityOptions}
              ariaLabel="Severity"
              clearable
              loading={filterLoading}
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Time Range</span>
            <Dropdown
              value={criteria.time_range}
              onChange={(val) => updateCriteria("time_range", val)}
              options={timeOptions}
              ariaLabel="Time range"
            />
          </label>

          <label className="flex flex-col gap-1 col-span-2 md:col-span-1">
            <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Keyword / IP / Hash</span>
            <input
              type="text"
              value={criteria.keyword}
              onChange={(e) => updateCriteria("keyword", e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && runCustomHunt()}
              placeholder="e.g. 198.51.100.7"
              className="h-10 bg-slate-900/50 border border-slate-800 rounded-lg px-3 text-xs font-semibold text-slate-200 placeholder:text-slate-600 outline-none focus:border-cyan-500/60"
            />
          </label>
        </div>

        <div className="flex items-center gap-3 mt-4">
          <button
            onClick={runCustomHunt}
            disabled={loading}
            className="px-5 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-white text-xs font-bold rounded-lg transition-all"
          >
            {loading ? "Running..." : "Run Custom Hunt"}
          </button>
          {selectedHunt && selectedHunt !== "Custom Hunt" && (
            <span className="text-xs text-slate-500">
              Last run: <span className="text-cyan-400 font-bold">{selectedHunt}</span>
            </span>
          )}
        </div>
      </div>

      <div className="bg-slate-800/40 rounded-xl p-5 border border-slate-700/60">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-xl font-semibold text-white">Hunt Results</h2>
          <div className="flex items-center gap-3">
            {total > 0 && (
              <span className="text-xs text-slate-500">
                <span className="font-mono font-bold text-cyan-400">{total.toLocaleString()}</span> matching
              </span>
            )}
            {selectedHunt && (
              <span className="text-cyan-400 text-xs font-bold uppercase tracking-wider">{selectedHunt}</span>
            )}
          </div>
        </div>

        {loading ? (
          <div className="text-center py-20">
            <div className="animate-spin rounded-full h-12 w-12 border-4 border-cyan-500 border-t-transparent mx-auto"></div>
            <p className="mt-6 text-slate-400">Querying local telemetry...</p>
          </div>
        ) : (
          <HuntResultsTable results={results} />
        )}
      </div>
    </div>
  );
}

export default ThreatHunting;
