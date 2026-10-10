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

  // Custom hunt criteria
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

  // Load available hunts
  useEffect(() => {
    let cancelled = false;

    async function init() {
      try {
        const response = await api.get("/hunt/list");

        if (!cancelled) {
          setHunts(response.data.hunts || {});
        }
      } catch {
        // Existing hunts remain visible if loading fails.
      }
    }

    init();

    return () => {
      cancelled = true;
    };
  }, []);

  // Load dynamic filter options
  useEffect(() => {
    let cancelled = false;

    async function loadFilters() {
      try {
        const response = await api.get("/hunt/filters");
        const data = response.data || {};

        if (cancelled) return;

        setFilterOptions({
          hosts: data.hosts || [],
          users: data.users || [],
          processes: data.processes || [],
          eventIds: data.event_ids || [],
          mitres: data.mitres || [],
          severities: data.severities || [],
          pids: data.pids || [],
        });
      } catch {
        // Dropdowns fall back to empty option lists.
      } finally {
        if (!cancelled) {
          setFilterLoading(false);
        }
      }
    }

    loadFilters();

    return () => {
      cancelled = true;
    };
  }, []);

  // Execute a predefined hunt
  const executeHunt = async (huntKey) => {
    setLoading(true);
    setSelectedHunt(huntKey);
    setError("");

    try {
      const response = await api.post("/hunt/run", {
        hunt: huntKey,
      });

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
    } finally {
      setLoading(false);
    }
  };

  // Execute a custom hunt
  const runCustomHunt = async () => {
    const payload = {};

    Object.entries(criteria).forEach(([key, value]) => {
      if (value && value !== "All" && value !== "") {
        payload[key] = value;
      }
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
    } finally {
      setLoading(false);
    }
  };

  const updateCriteria = useCallback((key, value) => {
    setCriteria((previous) => ({
      ...previous,
      [key]: value,
    }));
  }, []);

  // Build dropdown options
  const buildOptions = useCallback((items, label) => {
    return [
      { value: "", label },
      ...items.map((item) => ({
        value: item.value,
        label: `${item.value} (${(item.count || 0).toLocaleString()})`,
      })),
    ];
  }, []);

  const hostOptions = useMemo(
    () => buildOptions(filterOptions.hosts, "Any host"),
    [filterOptions.hosts, buildOptions]
  );

  const userOptions = useMemo(
    () => buildOptions(filterOptions.users, "Any user"),
    [filterOptions.users, buildOptions]
  );

  const processOptions = useMemo(
    () => buildOptions(filterOptions.processes, "Any process"),
    [filterOptions.processes, buildOptions]
  );

  const eventIdOptions = useMemo(
    () => buildOptions(filterOptions.eventIds, "Any event ID"),
    [filterOptions.eventIds, buildOptions]
  );

  const mitreOptions = useMemo(
    () => buildOptions(filterOptions.mitres, "Any MITRE technique"),
    [filterOptions.mitres, buildOptions]
  );

  const severityOptions = useMemo(
    () => buildOptions(filterOptions.severities, "Any severity"),
    [filterOptions.severities, buildOptions]
  );

  const pidOptions = useMemo(
    () => buildOptions(filterOptions.pids, "Any PID"),
    [filterOptions.pids, buildOptions]
  );

  const timeOptions = [
    { value: "today", label: "Today" },
    { value: "last_24h", label: "Last 24 hours" },
    { value: "last_7d", label: "Last 7 days" },
    { value: "last_30d", label: "Last 30 days" },
    { value: "all", label: "All time" },
  ];

  const activeFilterCount = useMemo(() => {
    const selectedFilters = [
      "event_id",
      "process",
      "pid",
      "host",
      "user",
      "mitre",
      "severity",
    ].filter((key) => criteria[key] !== "" && criteria[key] !== "All").length;

    return (
      selectedFilters +
      (criteria.keyword ? 1 : 0) +
      (criteria.time_range !== "last_7d" ? 1 : 0)
    );
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

  const labelClass =
    "text-[10px] font-bold uppercase tracking-wider text-slate-500";

  const fieldClass = "flex flex-col gap-1 min-w-0";

  const inputClass =
    "h-10 w-full rounded-lg border border-slate-800 bg-slate-950/70 px-3 text-xs font-medium text-slate-200 placeholder:text-slate-600 outline-none transition-colors focus:border-slate-600 focus:ring-1 focus:ring-slate-700/40";

  return (
    <div className="space-y-8">
      <PageHeader
        title="Threat Hunting"
        subtitle="Run enterprise hunting queries against local SOCRA AI telemetry."
      />

      {error && (
        <div className="flex items-center justify-between gap-4 rounded-xl border border-red-500/20 bg-red-500/[0.06] px-4 py-3">
          <div className="flex items-center gap-3">
            <span className="h-2 w-2 shrink-0 rounded-full bg-red-400" />
            <span className="text-xs text-red-300">{error}</span>
          </div>

          <button
            onClick={() => setError("")}
            className="shrink-0 text-[10px] font-bold uppercase tracking-wider text-red-400 transition hover:text-red-300"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Predefined threat hunts */}
      <section className="space-y-4">
        <div className="flex items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-200">
              Detection Hunts
            </h2>
            <p className="mt-1 text-xs text-slate-500">
              Run predefined queries against collected telemetry.
            </p>
          </div>

          <span className="rounded-md border border-slate-800 bg-slate-900/60 px-2.5 py-1 text-[10px] font-medium text-slate-500">
            {Object.keys(hunts).length} available
          </span>
        </div>

        {Object.keys(hunts).length > 0 ? (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
            {Object.entries(hunts).map(([key, hunt]) => (
              <HuntCard
                key={key}
                huntKey={key}
                hunt={hunt}
                onRun={executeHunt}
              />
            ))}
          </div>
        ) : (
          <div className="rounded-xl border border-slate-800/80 bg-slate-950/40 px-5 py-8 text-center">
            <p className="text-sm text-slate-400">
              No predefined hunts are available.
            </p>
            <p className="mt-1 text-xs text-slate-600">
              You can still create a custom hunt below.
            </p>
          </div>
        )}
      </section>

      {/* Custom hunt */}
      <section className="rounded-xl border border-slate-800/80 bg-slate-950/50 p-5 sm:p-6">
        <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-slate-700/70 bg-slate-900">
                <svg
                  width="16"
                  height="16"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.7"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  className="text-slate-400"
                >
                  <circle cx="11" cy="11" r="7" />
                  <path d="m20 20-4-4" />
                  <path d="M11 8v6M8 11h6" />
                </svg>
              </div>

              <h2 className="text-base font-semibold text-slate-100">
                Custom Hunt
              </h2>
            </div>

            <p className="mt-2 max-w-2xl text-xs leading-5 text-slate-500">
              Query the local SQLite telemetry store using one or more
              criteria. Selected criteria are combined server-side.
            </p>
          </div>

          {activeFilterCount > 0 && (
            <button
              onClick={clearFilters}
              className="rounded-lg border border-slate-800 px-3 py-2 text-xs font-medium text-slate-400 transition hover:border-slate-700 hover:bg-slate-900 hover:text-slate-200"
            >
              Clear filters
              <span className="ml-2 rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300">
                {activeFilterCount}
              </span>
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 gap-x-4 gap-y-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
          <label className={fieldClass}>
            <span className={labelClass}>Event ID</span>
            <Dropdown
              value={criteria.event_id}
              onChange={(value) => updateCriteria("event_id", value)}
              options={eventIdOptions}
              ariaLabel="Event ID"
              searchable
              clearable
              loading={filterLoading}
              emptyText="No event IDs available"
            />
          </label>

          <label className={fieldClass}>
            <span className={labelClass}>Process</span>
            <Dropdown
              value={criteria.process}
              onChange={(value) => updateCriteria("process", value)}
              options={processOptions}
              ariaLabel="Process"
              searchable
              clearable
              loading={filterLoading}
              emptyText="No processes available"
            />
          </label>

          <label className={fieldClass}>
            <span className={labelClass}>PID</span>
            <Dropdown
              value={criteria.pid}
              onChange={(value) => updateCriteria("pid", value)}
              options={pidOptions}
              ariaLabel="Process ID"
              searchable
              clearable
              loading={filterLoading}
              emptyText="No PIDs available"
            />
          </label>

          <label className={fieldClass}>
            <span className={labelClass}>Host</span>
            <Dropdown
              value={criteria.host}
              onChange={(value) => updateCriteria("host", value)}
              options={hostOptions}
              ariaLabel="Host"
              searchable
              clearable
              loading={filterLoading}
              emptyText="No hosts available"
            />
          </label>

          <label className={fieldClass}>
            <span className={labelClass}>User</span>
            <Dropdown
              value={criteria.user}
              onChange={(value) => updateCriteria("user", value)}
              options={userOptions}
              ariaLabel="User"
              searchable
              clearable
              loading={filterLoading}
              emptyText="No users available"
            />
          </label>

          <label className={fieldClass}>
            <span className={labelClass}>MITRE Technique</span>
            <Dropdown
              value={criteria.mitre}
              onChange={(value) => updateCriteria("mitre", value)}
              options={mitreOptions}
              ariaLabel="MITRE technique"
              searchable
              clearable
              loading={filterLoading}
              emptyText="No MITRE techniques available"
            />
          </label>

          <label className={fieldClass}>
            <span className={labelClass}>Severity</span>
            <Dropdown
              value={criteria.severity}
              onChange={(value) => updateCriteria("severity", value)}
              options={severityOptions}
              ariaLabel="Severity"
              clearable
              loading={filterLoading}
              emptyText="No severities available"
            />
          </label>

          <label className={fieldClass}>
            <span className={labelClass}>Time Range</span>
            <Dropdown
              value={criteria.time_range}
              onChange={(value) => updateCriteria("time_range", value)}
              options={timeOptions}
              ariaLabel="Time range"
            />
          </label>

          <label className={`${fieldClass} sm:col-span-2 lg:col-span-1`}>
            <span className={labelClass}>Keyword / IP / Hash</span>
            <input
              type="text"
              value={criteria.keyword}
              onChange={(event) =>
                updateCriteria("keyword", event.target.value)
              }
              onKeyDown={(event) => {
                if (event.key === "Enter" && !loading) {
                  runCustomHunt();
                }
              }}
              placeholder="e.g. 198.51.100.7"
              className={inputClass}
            />
          </label>
        </div>

        <div className="mt-6 flex flex-wrap items-center gap-3 border-t border-slate-800/70 pt-5">
          <button
            onClick={runCustomHunt}
            disabled={loading}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800 px-4 py-2.5 text-xs font-semibold text-slate-100 transition hover:border-slate-600 hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {loading && selectedHunt === "Custom Hunt" ? (
              <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-slate-400 border-t-transparent" />
            ) : (
              <svg
                width="14"
                height="14"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.8"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <circle cx="11" cy="11" r="7" />
                <path d="m20 20-4-4" />
              </svg>
            )}
            {loading && selectedHunt === "Custom Hunt"
              ? "Running hunt..."
              : "Run Custom Hunt"}
          </button>

          {selectedHunt && selectedHunt !== "Custom Hunt" && (
            <span className="text-xs text-slate-500">
              Last predefined hunt:{" "}
              <span className="font-medium text-slate-300">
                {selectedHunt}
              </span>
            </span>
          )}

          {activeFilterCount > 0 && (
            <span className="ml-auto text-[11px] text-slate-500">
              {activeFilterCount} active{" "}
              {activeFilterCount === 1 ? "filter" : "filters"}
            </span>
          )}
        </div>
      </section>

      {/* Hunt results */}
      <section className="overflow-hidden rounded-xl border border-slate-800/80 bg-slate-950/50">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 px-5 py-4 sm:px-6">
          <div>
            <h2 className="text-base font-semibold text-slate-100">
              Hunt Results
            </h2>
            <p className="mt-1 text-xs text-slate-500">
              Matching events from local telemetry.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            {selectedHunt && (
              <span className="rounded-md border border-slate-800 bg-slate-900/70 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                {selectedHunt}
              </span>
            )}

            {!loading && (
              <span className="text-xs text-slate-500">
                <span className="font-mono font-semibold tabular-nums text-slate-200">
                  {total.toLocaleString()}
                </span>{" "}
                matching
              </span>
            )}
          </div>
        </div>

        {loading ? (
          <div className="flex flex-col items-center justify-center py-20">
            <div className="relative flex h-10 w-10 items-center justify-center">
              <div className="absolute inset-0 animate-spin rounded-full border-2 border-slate-700 border-t-slate-300" />
              <div className="h-2 w-2 rounded-full bg-slate-300" />
            </div>

            <p className="mt-5 text-sm font-medium text-slate-300">
              Querying local telemetry...
            </p>
            <p className="mt-1 text-xs text-slate-600">
              This may take a moment.
            </p>
          </div>
        ) : (
          <HuntResultsTable results={results} />
        )}
      </section>
    </div>
  );
}

export default ThreatHunting;