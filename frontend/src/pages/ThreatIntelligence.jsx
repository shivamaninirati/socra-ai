import { useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
  Fingerprint,
  Globe,
  FileSearch,
  Database,
  ExternalLink,
  CircleAlert,
} from "lucide-react";

import PageHeader from "../components/ui/PageHeader";
import api from "../services/api";

const STATUS_LABEL = {
  ok: "Connected",
  error: "Lookup failed",
  not_configured: "Provider not configured",
  not_applicable: "Not applicable",
};

const TYPE_BADGE = {
  "IPv4 Address": "border-slate-700 bg-slate-800/70 text-slate-300",
  "IPv6 Address": "border-slate-700 bg-slate-800/70 text-slate-300",
  Domain: "border-purple-500/20 bg-purple-500/[0.07] text-purple-300",
  URL: "border-blue-500/20 bg-blue-500/[0.07] text-blue-300",
  MD5: "border-emerald-500/20 bg-emerald-500/[0.07] text-emerald-300",
  "SHA-1": "border-emerald-500/20 bg-emerald-500/[0.07] text-emerald-300",
  "SHA-256": "border-emerald-500/20 bg-emerald-500/[0.07] text-emerald-300",
  Unknown: "border-slate-700 bg-slate-800/60 text-slate-400",
};

const SEVERITY_COLOR = {
  Critical: "bg-red-400",
  High: "bg-orange-400",
  Medium: "bg-yellow-400",
  Low: "bg-emerald-400",
  Informational: "bg-slate-500",
};

const panelClass =
  "rounded-xl border border-slate-800/80 bg-slate-950/50";

const sectionTitleClass =
  "text-sm font-semibold tracking-wide text-slate-200";

function SectionHeading({ icon: Icon, title, detail }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3">
      <div className="flex items-center gap-2.5">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-slate-800 bg-slate-900/80">
          <Icon size={15} className="text-slate-400" />
        </div>
        <h3 className={sectionTitleClass}>{title}</h3>
      </div>

      {detail && (
        <span className="text-[10px] text-slate-500">{detail}</span>
      )}
    </div>
  );
}

function ProviderCard({ provider }) {
  const entry = provider.entry || {};
  const status = entry.status || "not_configured";
  const result = entry.result || {};

  const isError = status === "error";
  const isOk = status === "ok";

  const statusColor = isError
    ? "text-red-400"
    : isOk
      ? "text-emerald-400"
      : status === "not_applicable"
        ? "text-slate-400"
        : "text-slate-500";

  const detailLines = [];

  if (provider.key === "virustotal") {
    detailLines.push(
      { label: "Malicious", value: result.malicious },
      { label: "Suspicious", value: result.suspicious },
      { label: "Harmless", value: result.harmless },
      { label: "Undetected", value: result.undetected },
      { label: "Reputation", value: result.reputation }
    );
  }

  if (provider.key === "abuseipdb") {
    detailLines.push(
      { label: "Abuse Score", value: result.abuse_score },
      { label: "Reports", value: result.total_reports },
      { label: "Country", value: result.country },
      { label: "Usage Type", value: result.usage_type },
      { label: "Whitelisted", value: result.is_whitelisted }
    );
  }

  return (
    <div className={`${panelClass} p-5 transition-colors hover:border-slate-700`}>
      <div className="flex items-center justify-between gap-3">
        <div className="flex min-w-0 items-center gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-slate-800 bg-slate-900">
            <Globe size={16} className="text-slate-400" />
          </div>

          <div className="min-w-0">
            <p className="text-sm font-semibold text-slate-200">
              {provider.label}
            </p>
            <p className="mt-0.5 text-[10px] text-slate-500">
              External intelligence source
            </p>
          </div>
        </div>

        <span
          className={`shrink-0 text-right text-[10px] font-semibold uppercase tracking-wider ${statusColor}`}
        >
          {STATUS_LABEL[status] || status}
        </span>
      </div>

      {isOk && entry.confidence != null && (
        <div className="mt-4 flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-slate-800/70 pt-3 text-[11px] text-slate-500">
          <span>
            Confidence{" "}
            <span className="font-mono font-semibold text-slate-300">
              {entry.confidence}%
            </span>
          </span>

          {entry.lookup_time != null && (
            <span>
              Lookup time{" "}
              <span className="font-mono text-slate-400">
                {entry.lookup_time}s
              </span>
            </span>
          )}
        </div>
      )}

      {isOk &&
        entry.lookup_scope === "host_of_url" &&
        entry.lookup_target && (
          <p className="mt-3 break-all text-[10px] leading-5 text-slate-500">
            Enriched host:{" "}
            <span className="font-mono text-slate-300">
              {entry.lookup_target}
            </span>{" "}
            (URL host lookup)
          </p>
        )}

      {isError && (
        <div className="mt-4 rounded-lg border border-red-500/15 bg-red-500/[0.04] px-3 py-2.5">
          <p className="text-xs leading-5 text-red-300">
            {entry.error || "Provider lookup failed."}
          </p>
        </div>
      )}

      {status === "not_configured" && (
        <p className="mt-4 text-xs leading-5 text-slate-500">
          No API key is configured for this provider.
        </p>
      )}

      {status === "not_applicable" && (
        <p className="mt-4 text-xs leading-5 text-slate-500">
          {entry.message || "Provider does not support this indicator type."}
        </p>
      )}

      {isOk && detailLines.length > 0 && (
        <div className="mt-4 space-y-0 border-t border-slate-800/70 pt-2">
          {detailLines.map((line) => (
            <div
              key={line.label}
              className="flex items-center justify-between gap-3 border-b border-slate-800/40 py-2 last:border-b-0"
            >
              <span className="text-xs text-slate-500">{line.label}</span>
              <span className="break-all text-right font-mono text-xs font-medium text-slate-200">
                {String(line.value ?? "-")}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function InternalIntel({ internal }) {
  if (!internal || !internal.searched) {
    return (
      <div className={`${panelClass} flex flex-col items-center px-5 py-10 text-center`}>
        <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-xl border border-slate-800 bg-slate-900">
          <Database size={18} className="text-slate-500" />
        </div>
        <p className="text-sm font-medium text-slate-300">
          No local intelligence search
        </p>
        <p className="mt-1 max-w-md text-xs leading-5 text-slate-500">
          No local SOCRA intelligence search was performed for this indicator.
        </p>
      </div>
    );
  }

  const events = internal.events || [];
  const cases = internal.cases || [];
  const investigations = internal.investigations || [];

  const noMatches =
    internal.total_sightings === 0 &&
    cases.length === 0 &&
    investigations.length === 0;

  const stats = [
    {
      label: "Total Sightings",
      value: internal.total_sightings || 0,
    },
    {
      label: "Hosts",
      value: internal.hosts?.length || 0,
    },
    {
      label: "Cases",
      value: cases.length,
    },
    {
      label: "Investigations",
      value: investigations.length,
    },
  ];

  return (
    <div className={`${panelClass} overflow-hidden`}>
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 bg-slate-900/40 px-5 py-4">
        <div className="flex items-center gap-2.5">
          <Database size={15} className="text-slate-400" />
          <h3 className="text-sm font-semibold text-slate-200">
            SOCRA Internal Intelligence
          </h3>
        </div>

        <span className="rounded-md border border-slate-800 bg-slate-950/60 px-2.5 py-1 text-[10px] text-slate-500">
          Last {internal.window_days} days
        </span>
      </div>

      <div className="p-5">
        {noMatches ? (
          <div className="flex flex-col items-center py-8 text-center">
            <div className="mb-3 flex h-9 w-9 items-center justify-center rounded-lg border border-slate-800 bg-slate-900">
              <CircleAlert size={17} className="text-slate-500" />
            </div>
            <p className="text-sm text-slate-300">No local sightings found</p>
            <p className="mt-1 max-w-md text-xs leading-5 text-slate-500">
              No local sightings of this indicator were found in events, cases,
              or investigations.
            </p>
          </div>
        ) : (
          <div className="space-y-6">
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              {stats.map((stat) => (
                <div
                  key={stat.label}
                  className="rounded-lg border border-slate-800/80 bg-slate-900/40 p-4"
                >
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                    {stat.label}
                  </p>
                  <p className="mt-2 font-mono text-2xl font-semibold tabular-nums text-slate-100">
                    {stat.value.toLocaleString()}
                  </p>
                </div>
              ))}
            </div>

            {events.length > 0 && (
              <div>
                <div className="mb-3 flex items-center justify-between gap-3">
                  <h4 className="text-xs font-semibold text-slate-300">
                    Recent Sightings
                  </h4>
                  <span className="text-[10px] text-slate-500">
                    {events.length} displayed
                  </span>
                </div>

                <div className="space-y-2">
                  {events.map((event) => (
                    <div
                      key={event.id}
                      className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-lg border border-slate-800/70 bg-slate-900/30 px-3 py-3"
                    >
                      <span
                        className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                          SEVERITY_COLOR[event.severity] || "bg-slate-500"
                        }`}
                      />

                      <span className="w-36 shrink-0 truncate font-mono text-[10px] text-slate-500">
                        {event.time}
                      </span>

                      <span className="shrink-0 rounded border border-slate-700/70 bg-slate-800/60 px-2 py-1 font-mono text-[10px] text-slate-300">
                        EID {event.event_id || "-"}
                      </span>

                      <span className="min-w-0 flex-1 truncate font-mono text-xs text-slate-300">
                        {event.host || "-"}
                      </span>

                      <span className="hidden max-w-[200px] truncate text-[10px] text-slate-500 lg:inline">
                        {event.detection || ""}
                      </span>

                      <span className="shrink-0 text-[9px] font-semibold uppercase tracking-wider text-slate-500">
                        {event.status || "New"}
                      </span>
                    </div>
                  ))}

                  {internal.total_sightings > events.length && (
                    <p className="px-1 pt-1 text-[10px] text-slate-500">
                      +{(
                        internal.total_sightings - events.length
                      ).toLocaleString()}{" "}
                      more sightings
                    </p>
                  )}
                </div>
              </div>
            )}

            {(cases.length > 0 || investigations.length > 0) && (
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                {cases.length > 0 && (
                  <div className="rounded-lg border border-slate-800/80 bg-slate-900/30 p-4">
                    <div className="mb-3 flex items-center justify-between gap-2">
                      <h4 className="text-xs font-semibold text-slate-300">
                        Related Cases
                      </h4>
                      <span className="text-[10px] text-slate-500">
                        {cases.length}
                      </span>
                    </div>

                    <div className="space-y-2">
                      {cases.map((item) => (
                        <div
                          key={item.case_id}
                          className="flex items-center gap-3 border-b border-slate-800/50 pb-2 last:border-b-0 last:pb-0"
                        >
                          <span className="shrink-0 font-mono text-[10px] font-semibold text-slate-300">
                            {item.case_id}
                          </span>
                          <span className="min-w-0 flex-1 truncate text-[10px] text-slate-500">
                            {item.title || "-"}
                          </span>
                          <span className="shrink-0 text-[9px] font-semibold uppercase text-slate-400">
                            {item.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {investigations.length > 0 && (
                  <div className="rounded-lg border border-slate-800/80 bg-slate-900/30 p-4">
                    <div className="mb-3 flex items-center justify-between gap-2">
                      <h4 className="text-xs font-semibold text-slate-300">
                        Related Investigations
                      </h4>
                      <span className="text-[10px] text-slate-500">
                        {investigations.length}
                      </span>
                    </div>

                    <div className="space-y-2">
                      {investigations.map((item) => (
                        <div
                          key={item.id}
                          className="flex items-center gap-3 border-b border-slate-800/50 pb-2 last:border-b-0 last:pb-0"
                        >
                          <span className="min-w-0 flex-1 truncate font-mono text-[10px] text-slate-300">
                            {item.id}
                          </span>
                          <span className="max-w-[100px] truncate text-[10px] text-slate-500">
                            {item.host || "-"}
                          </span>
                          <span className="shrink-0 text-[9px] font-semibold uppercase text-slate-400">
                            {item.severity || ""}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {internal.note && (
              <p className="border-t border-slate-800/70 pt-4 text-[10px] leading-5 text-slate-500">
                {internal.note}
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function ThreatIntelligence() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const [indicator, setIndicator] = useState(
    searchParams.get("indicator") || ""
  );
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const lastAnalyzedRef = useRef("");
  const requestIdRef = useRef(0);

  const analyze = async (valueOverride) => {
    const value = (valueOverride ?? indicator).trim();

    if (!value || loading) return;

    const requestId = ++requestIdRef.current;

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await api.post("/threat/intelligence", {
        indicator: value,
      });

      if (requestId !== requestIdRef.current) return;

      if (response.data.success) {
        setResult(response.data.data);
        lastAnalyzedRef.current = value;
        setSearchParams({ indicator: value }, { replace: true });
      } else {
        setError(response.data.error || "Lookup failed.");
      }
    } catch {
      if (requestId === requestIdRef.current) {
        setError("Threat intelligence backend is unavailable.");
      }
    } finally {
      if (requestId === requestIdRef.current) {
        setLoading(false);
      }
    }
  };

  // Support direct links from investigation IOC lookups.
  useEffect(() => {
    const linkedIndicator = searchParams.get("indicator");

    if (
      linkedIndicator &&
      linkedIndicator !== lastAnalyzedRef.current
    ) {
      setIndicator(linkedIndicator);
      analyze(linkedIndicator);
    }

    // analyze is intentionally omitted: this effect reacts to URL changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  const valid = result?.valid !== false;

  const providers = [
    {
      key: "virustotal",
      label: "VirusTotal",
      entry: result?.providers?.virustotal,
    },
    {
      key: "abuseipdb",
      label: "AbuseIPDB",
      entry: result?.providers?.abuseipdb,
    },
  ];

  const allProvidersUnconfigured =
    result &&
    providers.every(
      (provider) =>
        !provider.entry || provider.entry.status === "not_configured"
    );

  return (
    <div className="space-y-8">
      <PageHeader
        title="Threat Intelligence"
        subtitle="Enrich IPs, domains, URLs and hashes with configured providers and local SOCRA sightings."
      />

      <section className={`${panelClass} p-5 sm:p-6`}>
        <div className="mb-5 flex items-start gap-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-slate-800 bg-slate-900">
            <Fingerprint size={17} className="text-slate-400" />
          </div>

          <div>
            <h2 className="text-sm font-semibold text-slate-200">
              Indicator Analysis
            </h2>
            <p className="mt-1 text-xs leading-5 text-slate-500">
              Investigate an IP address, domain, URL, or file hash using
              configured intelligence sources.
            </p>
          </div>
        </div>

        <form
          onSubmit={(event) => {
            event.preventDefault();
            analyze();
          }}
          className="flex flex-col gap-3 sm:flex-row"
        >
          <input
            value={indicator}
            onChange={(event) => setIndicator(event.target.value)}
            placeholder="Enter IP, domain, URL or hash"
            aria-label="Indicator to analyze"
            autoComplete="off"
            spellCheck={false}
            className="h-11 min-w-0 flex-1 rounded-lg border border-slate-800 bg-slate-900/70 px-4 text-sm text-slate-200 outline-none transition-colors placeholder:text-slate-600 focus:border-slate-600 focus:ring-1 focus:ring-slate-700/40"
          />

          <button
            type="submit"
            disabled={loading || !indicator.trim()}
            className="inline-flex h-11 shrink-0 items-center justify-center gap-2 rounded-lg border border-slate-700 bg-slate-800 px-6 text-xs font-semibold text-slate-100 transition-colors hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {loading ? (
              <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-slate-400 border-t-transparent" />
            ) : (
              <Globe size={14} />
            )}
            {loading ? "Analyzing..." : "Analyze Indicator"}
          </button>
        </form>

        {error && (
          <div
            role="alert"
            className="mt-4 flex items-start gap-2.5 rounded-lg border border-red-500/20 bg-red-500/[0.05] px-3.5 py-3"
          >
            <CircleAlert size={15} className="mt-0.5 shrink-0 text-red-400" />
            <p className="text-xs leading-5 text-red-300">{error}</p>
            <button
              onClick={() => setError("")}
              className="ml-auto shrink-0 text-[10px] font-semibold text-slate-500 transition hover:text-slate-300"
              type="button"
            >
              Dismiss
            </button>
          </div>
        )}
      </section>

      {loading && (
        <div className={`${panelClass} flex flex-col items-center px-5 py-14 text-center`}>
          <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-slate-800 bg-slate-900">
            <span className="h-5 w-5 animate-spin rounded-full border-2 border-slate-700 border-t-slate-300" />
          </div>
          <p className="mt-4 text-sm font-medium text-slate-300">
            Analyzing indicator
          </p>
          <p className="mt-1 text-xs text-slate-500">
            Checking available intelligence sources and local context...
          </p>
        </div>
      )}

      {result && !loading && (
        <div className="space-y-7">
          {/* Indicator overview */}
          <section className={`${panelClass} p-5 sm:p-6`}>
            <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
              <div className="min-w-0">
                <p className="mb-2 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">
                  Analyzed Indicator
                </p>
                <p className="break-all font-mono text-lg font-semibold text-slate-100 sm:text-xl">
                  {result.indicator}
                </p>
              </div>

              <div className="flex shrink-0 flex-wrap items-center gap-2 sm:flex-col sm:items-end">
                <span
                  className={`inline-flex items-center rounded-md border px-2.5 py-1.5 text-[10px] font-semibold uppercase tracking-wider ${
                    TYPE_BADGE[result.type] || TYPE_BADGE.Unknown
                  }`}
                >
                  {result.type || "Unknown"}
                </span>

                <span
                  className={`text-[10px] ${
                    result.valid
                      ? "text-emerald-400"
                      : "text-amber-400"
                  }`}
                >
                  {result.valid
                    ? "Validated indicator"
                    : "Not a recognized IOC"}
                </span>
              </div>
            </div>
          </section>

          {!valid && (
            <div className="rounded-xl border border-amber-500/20 bg-amber-500/[0.04] px-4 py-3.5">
              <div className="flex items-start gap-2.5">
                <CircleAlert
                  size={15}
                  className="mt-0.5 shrink-0 text-amber-400"
                />
                <p className="text-xs leading-5 text-amber-300">
                  {result.detail ||
                    "This value is not a valid IP address, domain, URL or hash."}
                </p>
              </div>
            </div>
          )}

          {/* External intelligence */}
          <section className="space-y-4">
            <SectionHeading
              icon={Globe}
              title="External Threat Intelligence"
              detail="Third-party provider enrichment"
            />

            {allProvidersUnconfigured && (
              <div className="rounded-xl border border-slate-800 bg-slate-900/40 px-4 py-4">
                <div className="flex items-start gap-3">
                  <CircleAlert
                    size={16}
                    className="mt-0.5 shrink-0 text-slate-400"
                  />
                  <div>
                    <p className="text-xs font-medium text-slate-300">
                      No external providers configured
                    </p>
                    <p className="mt-1 text-xs leading-5 text-slate-500">
                      Add{" "}
                      <code className="rounded bg-slate-800 px-1.5 py-0.5 text-slate-300">
                        VT_API_KEY
                      </code>{" "}
                      and/or{" "}
                      <code className="rounded bg-slate-800 px-1.5 py-0.5 text-slate-300">
                        ABUSEIPDB_API_KEY
                      </code>{" "}
                      to the backend environment to enable provider enrichment.
                      SOCRA does not fabricate missing results.
                    </p>
                  </div>
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
              {providers.map((provider) => (
                <ProviderCard key={provider.key} provider={provider} />
              ))}
            </div>
          </section>

          {/* Local intelligence */}
          <section className="space-y-4">
            <SectionHeading
              icon={Fingerprint}
              title="Local Context"
              detail="SOCRA telemetry, cases and investigations"
            />

            <InternalIntel internal={result.internal} />
          </section>

          {/* SOC workflow navigation */}
          <section className={`${panelClass} p-4`}>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-xs font-semibold text-slate-300">
                  Continue investigation
                </p>
                <p className="mt-1 text-[11px] text-slate-500">
                  Explore related security events and case records.
                </p>
              </div>

              <div className="flex flex-wrap gap-2">
                <button
                  onClick={() => navigate("/alerts")}
                  className="inline-flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs font-medium text-slate-300 transition hover:border-slate-700 hover:bg-slate-800"
                >
                  <FileSearch size={13} />
                  Browse Alerts
                </button>

                {result.internal?.cases?.length > 0 && (
                  <button
                    onClick={() => navigate("/cases")}
                    className="inline-flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs font-medium text-slate-300 transition hover:border-slate-700 hover:bg-slate-800"
                  >
                    <ExternalLink size={13} />
                    Case Management
                  </button>
                )}
              </div>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}

export default ThreatIntelligence;