import { useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Fingerprint, Globe, Link2, Hash, FileSearch, Database, ExternalLink, CircleAlert } from "lucide-react";
import PageHeader from "../components/ui/PageHeader";
import api from "../services/api";

const STATUS_LABEL = {
  ok: "Connected",
  error: "Lookup failed",
  not_configured: "Provider not configured",
  not_applicable: "Not applicable",
};

const TYPE_BADGE = {
  "IPv4 Address": "bg-cyan-500/15 border-cyan-500/25 text-cyan-300",
  "IPv6 Address": "bg-cyan-500/15 border-cyan-500/25 text-cyan-300",
  Domain: "bg-purple-500/15 border-purple-500/25 text-purple-300",
  URL: "bg-blue-500/15 border-blue-500/25 text-blue-300",
  MD5: "bg-green-500/15 border-green-500/25 text-green-300",
  "SHA-1": "bg-green-500/15 border-green-500/25 text-green-300",
  "SHA-256": "bg-green-500/15 border-green-500/25 text-green-300",
  Unknown: "bg-slate-500/15 border-slate-500/25 text-slate-300",
};

const SEVERITY_COLOR = {
  Critical: "text-red-400",
  High: "text-orange-400",
  Medium: "text-yellow-400",
  Low: "text-green-400",
  Informational: "text-slate-400",
};

function ProviderCard({ provider }) {
  const entry = provider.entry || {};
  const status = entry.status || "not_configured";
  const result = entry.result || {};
  const isError = status === "error";
  const isOk = status === "ok";
  const isApplicable = !["error", "not_applicable"].includes(status);
  const color = isError
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
      { label: "Reputation", value: result.reputation },
    );
  }
  if (provider.key === "abuseipdb") {
    detailLines.push(
      { label: "Abuse Score", value: result.abuse_score },
      { label: "Reports", value: result.total_reports },
      { label: "Country", value: result.country },
      { label: "Usage Type", value: result.usage_type },
      { label: "Whitelisted", value: result.is_whitelisted },
    );
  }

  return (
    <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl p-6">
      <div className="flex items-center justify-between">
        <p className="text-slate-400 text-sm">{provider.label}</p>
        <span className={`text-xs font-bold uppercase tracking-wider ${color}`}>
          {STATUS_LABEL[status] || status}
        </span>
      </div>

      {isOk && entry.confidence != null && (
        <p className="mt-3 text-xs text-slate-500">
          Confidence{" "}
          <span className="font-mono font-bold text-slate-300">{entry.confidence}%</span>
          {entry.lookup_time != null && (
            <span className="ml-2">· {entry.lookup_time}s</span>
          )}
        </p>
      )}

      {isOk && entry.lookup_scope === "host_of_url" && entry.lookup_target && (
        <p className="mt-2 text-[10px] text-slate-500">
          Enriched host: <span className="font-mono text-slate-300">{entry.lookup_target}</span>
          {" "}(URL host lookup)
        </p>
      )}

      {isError && (
        <p className="mt-3 text-xs text-red-400">{entry.error || "Provider lookup failed."}</p>
      )}

      {status === "not_configured" && (
        <p className="mt-3 text-xs text-slate-500">
          No API key configured for this provider.
        </p>
      )}

      {status === "not_applicable" && (
        <p className="mt-3 text-xs text-slate-500">
          {entry.message || "Provider does not support this indicator type."}
        </p>
      )}

      {isOk && isApplicable && detailLines.length > 0 && (
        <div className="mt-3 space-y-1.5">
          {detailLines.map((line) => (
            <div key={line.label} className="flex justify-between text-xs">
              <span className="text-slate-500">{line.label}</span>
              <span className="font-mono font-bold text-slate-200">{String(line.value ?? "-")}</span>
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
      <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl p-6 text-center">
        <Database size={22} className="text-slate-600 mx-auto mb-2" />
        <p className="text-xs text-slate-500">
          No local SOCRA intelligence search was performed for this indicator.
        </p>
      </div>
    );
  }

  const events = internal.events || [];
  const cases = internal.cases || [];
  const investigations = internal.investigations || [];
  const noMatches = internal.total_sightings === 0 && cases.length === 0 && investigations.length === 0;

  return (
    <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-700/40 bg-slate-800/60">
        <div className="flex items-center gap-2.5">
          <Database size={15} className="text-cyan-400" />
          <h3 className="text-sm font-bold text-slate-200">SOCRA Internal Intelligence</h3>
        </div>
        <span className="text-[10px] text-slate-500">window: last {internal.window_days} days</span>
      </div>

      <div className="p-5">
        {noMatches ? (
          <div className="text-center py-4">
            <CircleAlert size={20} className="text-slate-600 mx-auto mb-2" />
            <p className="text-xs text-slate-500">
              No local sightings of this indicator in events, cases or investigations.
            </p>
          </div>
        ) : (
          <div className="space-y-5">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                <p className="text-[10px] uppercase tracking-wider text-slate-500 font-bold">Total Sightings</p>
                <p className="text-xl font-black text-cyan-400 mt-1">{internal.total_sightings || 0}</p>
              </div>
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                <p className="text-[10px] uppercase tracking-wider text-slate-500 font-bold">Hosts</p>
                <p className="text-xl font-black text-cyan-400 mt-1">{internal.hosts?.length || 0}</p>
              </div>
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                <p className="text-[10px] uppercase tracking-wider text-slate-500 font-bold">Cases</p>
                <p className="text-xl font-black text-cyan-400 mt-1">{cases.length}</p>
              </div>
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                <p className="text-[10px] uppercase tracking-wider text-slate-500 font-bold">Investigations</p>
                <p className="text-xl font-black text-cyan-400 mt-1">{investigations.length}</p>
              </div>
            </div>

            {events.length > 0 && (
              <div>
                <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-2">Recent Sightings</p>
                <div className="space-y-1.5">
                  {events.map((e) => (
                    <div key={e.id} className="flex items-center gap-3 p-2 bg-slate-900/40 rounded-lg border border-slate-800/40">
                      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${SEVERITY_COLOR[e.severity] || "text-slate-400"}`} />
                      <span className="text-[10px] font-mono text-slate-500 shrink-0 w-36 truncate">{e.time}</span>
                      <span className="text-[10px] font-mono font-bold text-cyan-500/80 bg-cyan-500/10 border border-cyan-500/20 px-1.5 py-0.5 rounded shrink-0">EID {e.event_id || "-"}</span>
                      <span className="text-[10px] font-mono text-slate-300 truncate flex-1">{e.host || "-"}</span>
                      <span className="text-[9px] text-slate-500 truncate hidden md:inline max-w-[200px]">{e.detection || ""}</span>
                      <span className="text-[9px] font-bold uppercase tracking-wider text-slate-500 shrink-0">{e.status || "New"}</span>
                    </div>
                  ))}
                  {internal.total_sightings > events.length && (
                    <p className="text-[10px] text-slate-600">+{internal.total_sightings - events.length} more sightings</p>
                  )}
                </div>
              </div>
            )}

            {(cases.length > 0 || investigations.length > 0) && (
              <div className="grid md:grid-cols-2 gap-3">
                {cases.length > 0 && (
                  <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                    <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-2">Related Cases</p>
                    <div className="space-y-1.5">
                      {cases.map((c) => (
                        <div key={c.case_id} className="flex items-center justify-between gap-2">
                          <span className="text-[10px] font-mono font-bold text-cyan-400">{c.case_id}</span>
                          <span className="text-[9px] text-slate-500 truncate">{c.title || "-"}</span>
                          <span className="text-[9px] font-bold uppercase text-slate-400 shrink-0">{c.status}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {investigations.length > 0 && (
                  <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                    <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-2">Related Investigations</p>
                    <div className="space-y-1.5">
                      {investigations.map((inv) => (
                        <div key={inv.id} className="flex items-center justify-between gap-2">
                          <span className="text-[10px] font-mono text-cyan-400 truncate">{inv.id}</span>
                          <span className="text-[9px] text-slate-500">{inv.host || "-"}</span>
                          <span className="text-[9px] font-bold uppercase text-slate-400 shrink-0">{inv.severity || ""}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            <p className="text-[10px] text-slate-600 leading-4">{internal.note}</p>
          </div>
        )}
      </div>
    </div>
  );
}

function ThreatIntelligence() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [indicator, setIndicator] = useState(searchParams.get("indicator") || "");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const analyze = async (valueOverride) => {
    const value = (valueOverride ?? indicator).trim();
    if (!value) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const response = await api.post("/threat/intelligence", { indicator: value });
      if (response.data.success) {
        setResult(response.data.data);
        // Keep the URL shareable so deep links from investigations work.
        setSearchParams({ indicator: value }, { replace: true });
      } else {
        setError(response.data.error || "Lookup failed.");
      }
    } catch {
      setError("Threat intelligence backend is unavailable.");
    }
    setLoading(false);
  };

  // Deep-link support: /threat-intel?indicator=... (used by the Investigation
  // workspace IOC "Lookup" buttons) auto-fills and runs the analysis.
  // Keyed on searchParams (not just mount) so a deep link still triggers when
  // the user is ALREADY on this page - e.g. opening a second IOC link without
  // leaving the route. lastAnalyzedRef prevents re-running the same indicator.
  const lastAnalyzedRef = useRef("");
  useEffect(() => {
    const initial = searchParams.get("indicator");
    if (initial && initial !== lastAnalyzedRef.current) {
      lastAnalyzedRef.current = initial;
      setIndicator(initial);
      analyze(initial);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  const valid = result?.valid !== false;
  const providers = [
    { key: "virustotal", label: "VirusTotal", entry: result?.providers?.virustotal },
    { key: "abuseipdb", label: "AbuseIPDB", entry: result?.providers?.abuseipdb },
  ];
  const allProvidersUnconfigured =
    result && providers.every((p) => !p.entry || p.entry.status === "not_configured");

  return (
    <div className="space-y-8">
      <PageHeader
        title="Threat Intelligence"
        subtitle="Enrich IPs, domains, URLs and hashes with configured providers and local SOCRA sightings."
      />

      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-3 text-xs text-red-300">
          {error}
        </div>
      )}

      <div className="bg-slate-800/40 rounded-xl border border-slate-700/60 p-6">
        <div className="flex gap-4">
          <input
            value={indicator}
            onChange={(e) => setIndicator(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && analyze()}
            placeholder="Enter IP, Domain, URL or Hash"
            className="flex-1 bg-slate-900/50 border border-slate-800 rounded-lg px-4 py-3 text-sm text-slate-200 placeholder:text-slate-600 outline-none focus:border-cyan-500/60"
          />
          <button
            onClick={() => analyze()}
            className="bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold px-6 py-2.5 rounded-lg transition-all duration-150"
          >
            Analyze
          </button>
        </div>
      </div>

      {loading && (
        <div className="bg-slate-800/40 rounded-xl border border-slate-700/60 p-10 text-center text-slate-400">
          Analyzing...
        </div>
      )}

      {result && !loading && (
        <div className="space-y-6">
          <div className="flex items-center justify-between gap-3 bg-slate-800/40 border border-slate-700/60 rounded-xl px-5 py-4">
            <div className="min-w-0">
              <p className="text-slate-500 text-xs mb-1">Indicator</p>
              <p className="text-white text-lg font-semibold break-all">{result.indicator}</p>
            </div>
            <div className="flex flex-col items-end gap-2 shrink-0">
              <span className={`inline-flex items-center px-2.5 py-1 rounded border text-[10px] font-bold uppercase tracking-wider ${TYPE_BADGE[result.type] || TYPE_BADGE.Unknown}`}>
                {result.type}
              </span>
              <span className="text-[10px] text-slate-500">
                {result.valid ? "Validated indicator" : "Not a recognized IOC"}
              </span>
            </div>
          </div>

          {!valid && (
            <div className="rounded-xl border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-xs text-amber-300 leading-5">
              {result.detail || "This value is not a valid IP address, domain, URL or hash."}
            </div>
          )}

          {/* External Threat Intelligence */}
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <Globe size={15} className="text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-200 tracking-wide">External Threat Intelligence</h3>
            </div>
            {allProvidersUnconfigured && (
              <div className="rounded-xl border border-slate-700/50 bg-slate-900/30 px-4 py-3 text-xs text-slate-400 leading-5">
                No external intelligence provider is configured. Add{" "}
                <code className="text-cyan-400">VT_API_KEY</code> and/or{" "}
                <code className="text-cyan-400">ABUSEIPDB_API_KEY</code> to the backend
                environment to enable real provider enrichment. No results are fabricated.
              </div>
            )}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {providers.map((provider) => (
                <ProviderCard key={provider.key} provider={provider} />
              ))}
            </div>
          </div>

          {/* SOCRA Internal Intelligence */}
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <Fingerprint size={15} className="text-emerald-400" />
              <h3 className="text-sm font-bold text-slate-200 tracking-wide">Local Context</h3>
            </div>
            <InternalIntel internal={result.internal} />
          </div>

          {/* Supporting navigation for a real SOC workflow */}
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => navigate("/alerts")}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-800/60 border border-slate-700/60 text-xs font-bold text-slate-300 rounded-lg hover:bg-slate-700/60 transition-all"
            >
              <FileSearch size={12} /> Browse Alerts
            </button>
            {result?.internal?.cases?.length > 0 && (
              <button
                onClick={() => navigate("/cases")}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-800/60 border border-slate-700/60 text-xs font-bold text-slate-300 rounded-lg hover:bg-slate-700/60 transition-all"
              >
                <ExternalLink size={12} /> Open Case Management
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default ThreatIntelligence;
