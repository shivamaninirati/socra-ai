import { useState, useEffect, useMemo, useCallback } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { 
  Shield, ShieldAlert,
  Server, FileCode, Terminal, Clock, 
  Activity,
  ChevronDown,
  ChevronRight, ExternalLink, Fingerprint,
  Search, ListTree,
  ScanLine, CheckCircle2,
  Target, Hash, Link2,
  Bot, Globe, Key, List, NotebookPen, Plus, RefreshCw
} from "lucide-react";
import SeverityBadge from "../components/SeverityBadge";
import api from "../services/api";

const INVESTIGATION_STATUSES = ["New", "Investigating", "Contained", "Resolved", "Closed"];

const RELATED_WINDOWS = [
  { value: 15, label: "±15 min" },
  { value: 30, label: "±30 min" },
  { value: 60, label: "±1 hour" },
  { value: 360, label: "±6 hours" },
  { value: 1440, label: "±24 hours" },
];

const severityColor = (sev) => {
  switch ((sev || "").toLowerCase()) {
    case "critical": return "text-red-400";
    case "high": return "text-orange-400";
    case "medium": return "text-yellow-400";
    case "low": return "text-green-400";
    default: return "text-slate-400";
  }
};

function ProcessTreeNode({ node, depth = 0 }) {
  const [expanded, setExpanded] = useState(true);
  const hasChildren = node.children && node.children.length > 0;

  return (
    <div className="select-none">
      <div 
        className={`flex items-center gap-2 py-1.5 px-2 rounded-lg hover:bg-slate-800/40 transition-colors cursor-pointer group ${depth > 0 ? "ml-8" : ""}`}
        onClick={() => hasChildren && setExpanded(!expanded)}
      >
        {depth > 0 && (
          <div className="flex items-center">
            <div className="w-4 h-[1px] bg-slate-700/60" />
            <div className="w-[1px] h-4 bg-slate-700/40" />
          </div>
        )}
        {hasChildren ? (
          expanded ? <ChevronDown size={12} className="text-slate-500 shrink-0" /> : <ChevronRight size={12} className="text-slate-500 shrink-0" />
        ) : (
          <span className="w-2 h-2 rounded-full bg-slate-700 shrink-0 ml-1" />
        )}
        <Terminal size={13} className={`shrink-0 ${depth === 0 ? "text-cyan-400" : depth === 1 ? "text-amber-400" : depth === 2 ? "text-red-400" : "text-slate-400"}`} />
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className={`text-xs font-mono font-bold ${depth === 0 ? "text-cyan-300" : depth === 1 ? "text-amber-300" : depth === 2 ? "text-red-300" : "text-slate-300"}`}>
              {node.name}
            </span>
            {node.process_id && (
              <span className="text-[9px] font-mono text-slate-600">PID {node.process_id}</span>
            )}
          </div>
          {node.command_line && (
            <p className="text-[10px] font-mono text-emerald-400/80 truncate max-w-[520px]">{node.command_line}</p>
          )}
          {node.note && (
            <p className="text-[10px] text-slate-500 italic">{node.note}</p>
          )}
        </div>
      </div>
      {expanded && hasChildren && (
        <div className="border-l border-slate-800/60 ml-[18px] pl-2">
          {node.children.map((child, idx) => (
            <ProcessTreeNode key={idx} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

function IOCTypeBadge({ type }) {
  const colors = {
    IPv4: "bg-cyan-500/15 border-cyan-500/25 text-cyan-300",
    IPv6: "bg-cyan-500/15 border-cyan-500/25 text-cyan-300",
    Domain: "bg-purple-500/15 border-purple-500/25 text-purple-300",
    URL: "bg-blue-500/15 border-blue-500/25 text-blue-300",
    "SHA-256": "bg-green-500/15 border-green-500/25 text-green-300",
    "SHA-1": "bg-green-500/15 border-green-500/25 text-green-300",
    MD5: "bg-green-500/15 border-green-500/25 text-green-300",
  };
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider rounded border ${colors[type] || "bg-slate-500/15 border-slate-500/25 text-slate-300"}`}>
      {type}
    </span>
  );
}

function IPClassification({ classification }) {
  if (!classification || classification === "Unknown") return null;
  const colors = {
    "Public": "text-emerald-400",
    "Private / Local": "text-blue-400",
    "Loopback": "text-slate-400",
  };
  return (
    <span className={`text-[9px] font-bold uppercase ${colors[classification] || "text-slate-500"}`}>
      {classification}
    </span>
  );
}

function IOCItem({ item, onLookup }) {
  const value = typeof item === "string" ? item : item.value;
  const role = typeof item === "object" ? item.role : null;
  const field = typeof item === "object" ? item.field : null;
  const classification = typeof item === "object" ? item.classification : null;
  const type = typeof item === "object" ? item.type : null;
  const sourceEvent = typeof item === "object" ? item.source_event : null;

  return (
    <div className="group flex items-start gap-2 p-2 bg-slate-900/30 rounded-lg border border-slate-800/30 hover:border-slate-700/50 transition-all">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[11px] font-mono text-slate-200 break-all">{value}</span>
          {type && <IOCTypeBadge type={type} />}
          {classification && <IPClassification classification={classification} />}
        </div>
        <div className="flex items-center gap-2 mt-1 flex-wrap">
          {role && (
            <span className="text-[9px] font-bold text-cyan-400/80 uppercase">{role}</span>
          )}
          {field && (
            <span className="text-[9px] text-slate-600">← {field}</span>
          )}
          {sourceEvent && (
            <span className="text-[9px] text-slate-600">• {sourceEvent}</span>
          )}
        </div>
      </div>
      <div className="flex items-center gap-1 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
        <button
          onClick={() => onLookup(value)}
          className="px-2 py-1 bg-cyan-600/20 hover:bg-cyan-600/40 border border-cyan-500/30 rounded text-[9px] font-bold text-cyan-300 transition-all"
        >
          Lookup
        </button>
      </div>
    </div>
  );
}

function IOCCategory({ label, icon: Icon, color, bg, border, items, onLookup }) {
  if (!items || items.length === 0) return null;
  return (
    <div className={`${bg} ${border} border rounded-lg p-3`}>
      <div className="flex items-center gap-2 mb-2">
        <Icon size={13} className={color} />
        <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400">{label}</span>
        <span className={`text-[10px] font-mono font-bold ${color} ml-auto`}>{items.length}</span>
      </div>
      <div className="space-y-1.5">
        {items.slice(0, 10).map((item, idx) => (
          <IOCItem key={idx} item={item} onLookup={onLookup} />
        ))}
        {items.length > 10 && (
          <p className="text-[10px] text-slate-600">+{items.length - 10} more</p>
        )}
      </div>
    </div>
  );
}

function IOCSection({ ioc, investigationId, onLookup }) {
  const [deepIOCs, setDeepIOCs] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Fetch deep field-aware IOCs from backend on mount
  useEffect(() => {
    if (!investigationId) return;
    let cancelled = false;
    setLoading(true);
    api.get(`/investigations/${investigationId}/iocs`)
      .then((resp) => {
        if (!cancelled && resp.data?.success) {
          setDeepIOCs(resp.data.iocs);
        }
      })
      .catch((err) => {
        if (!cancelled) setError("Could not extract IOCs from event.");
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [investigationId]);

  // Use deep IOCs if available, fallback to event-level ioc
  const data = deepIOCs || ioc || {};
  const hasIOC = (data.ips?.length || 0) + (data.domains?.length || 0) +
    (data.urls?.length || 0) + (data.hashes?.length || 0) > 0;

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-8">
        <div className="animate-spin rounded-full h-8 w-8 border-2 border-green-500 border-t-transparent mb-3"></div>
        <p className="text-slate-500 text-xs">Extracting IOCs from event fields...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-4">
        <p className="text-xs text-amber-300">{error}</p>
      </div>
    );
  }

  if (!hasIOC) {
    const checked = data.checked_fields || ["IP addresses", "Domains", "URLs", "File hashes"];
    return (
      <div className="bg-slate-800/30 border border-slate-700/50 rounded-lg p-5">
        <div className="text-center py-4">
          <Fingerprint size={24} className="text-slate-600 mx-auto mb-2" />
          <p className="text-slate-400 text-xs mb-3">No network or file IOCs were observed in this event.</p>
          <div className="flex flex-wrap justify-center gap-1.5">
            {checked.map((field) => (
              <span key={field} className="text-[9px] px-2 py-0.5 bg-slate-800/60 border border-slate-700/40 rounded text-slate-500">✓ {field}</span>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* IP Addresses */}
      <IOCCategory
        label="IP Addresses"
        icon={Globe}
        color="text-cyan-400"
        bg="bg-cyan-500/10"
        border="border-cyan-500/20"
        items={data.ips}
        onLookup={onLookup}
      />

      {/* Domains */}
      <IOCCategory
        label="Domains"
        icon={Link2}
        color="text-purple-400"
        bg="bg-purple-500/10"
        border="border-purple-500/20"
        items={data.domains}
        onLookup={onLookup}
      />

      {/* URLs */}
      <IOCCategory
        label="URLs"
        icon={ExternalLink}
        color="text-blue-400"
        bg="bg-blue-500/10"
        border="border-blue-500/20"
        items={data.urls}
        onLookup={onLookup}
      />

      {/* File Hashes */}
      <IOCCategory
        label="File Hashes"
        icon={Hash}
        color="text-green-400"
        bg="bg-green-500/10"
        border="border-green-500/20"
        items={data.hashes}
        onLookup={onLookup}
      />
    </div>
  );
}

function EnterpriseCard({ title, icon: Icon, iconColor, children, className = "" }) {
  return (
    <div className={`bg-slate-800/40 border border-slate-700/60 rounded-xl overflow-hidden transition-all duration-200 hover:border-slate-600/60 ${className}`}>
      <div className="flex items-center gap-2.5 px-5 py-3.5 border-b border-slate-700/40 bg-slate-800/60">
        {Icon && <Icon size={16} className={`${iconColor || "text-cyan-400"} shrink-0`} />}
        <h3 className="text-sm font-bold text-slate-200 tracking-wide">{title}</h3>
      </div>
      <div className="p-5">
        {children}
      </div>
    </div>
  );
}

function Investigation() {
  const location = useLocation();
  const navigate = useNavigate();

  // Prefer the router state (set by Alerts / Enterprise Search / Timeline),
  // fall back to the persisted alert so a refresh or state drop never opens
  // an empty investigation.
  const log = useMemo(() => {
    if (location.state?.log) return location.state.log;
    try {
      const raw = sessionStorage.getItem("socra_investigation_log");
      if (raw) return JSON.parse(raw);
    } catch { /* ignore malformed payloads */ }
    return null;
  }, [location.state]);

  // Real persisted investigation record created/loaded from the backend.
  const [investigation, setInvestigation] = useState(null);
  const [invLoading, setInvLoading] = useState(false);
  const [invError, setInvError] = useState("");
  const [statusSaving, setStatusSaving] = useState(false);
  const [noteText, setNoteText] = useState("");
  const [noteSaving, setNoteSaving] = useState(false);
  const [relatedWindow, setRelatedWindow] = useState(60);
  const [relatedLoading, setRelatedLoading] = useState(false);
  const [relatedError, setRelatedError] = useState("");

  const [aiSummary, setAiSummary] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState("");
  const [activeSection, setActiveSection] = useState("overview");

  // Real case management (Task 20): escalate this alert to a persistent case.
  const [caseRecord, setCaseRecord] = useState(null);
  const [caseCreating, setCaseCreating] = useState(false);
  const [caseError, setCaseError] = useState("");

  const logKey = useMemo(() => log?.metadata?.fingerprint || `${log?.event?.time}-${log?.event?.event_id}`, [log]);

  // Create (or reuse) the persistent investigation for this alert.
  useEffect(() => {
    if (!log) return;
    let cancelled = false;
    async function load() {
      setInvLoading(true);
      setInvError("");
      try {
        const response = await api.post("/investigations", { event: log });
        if (cancelled) return;
        if (response.data?.success && response.data.investigation) {
          setInvestigation(response.data.investigation);
        } else {
          setInvError(response.data?.error || "Could not create investigation record.");
        }
      } catch {
        if (!cancelled) setInvError("Investigation backend is unavailable; showing event details only.");
      } finally {
        if (!cancelled) setInvLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [log, logKey]);

  const investigationId = investigation?.id || null;

  // Run a real AI investigation. The persisted investigation id is passed so
  // the model receives the real analyst notes / related events / process tree;
  // a backend "unavailable" response surfaces as a useful error, never as an
  // endless spinner or fake analysis.
  const runInvestigation = useCallback(async () => {
    if (!log) return;
    setAiLoading(true);
    setAiError("");
    setAiSummary(null);
    try {
      const response = await api.post("/ai/investigate", {
        event: log,
        investigation_id: investigationId || undefined,
      });
      const data = response.data || {};
      if (data.success === false) {
        setAiError(data.detail || data.error || "AI investigation is unavailable.");
      } else {
        setAiSummary(data.analysis || "No AI investigation was returned.");
      }
    } catch {
      setAiError("Unable to generate AI investigation.");
    } finally {
      setAiLoading(false);
    }
  }, [log, investigationId]);

  // AI summary — real analysis over the alert. Waits for the persisted
  // investigation record so the model gets real context (notes, related
  // events, process tree) instead of analyzing the alert in isolation.
  useEffect(() => {
    if (!log || invLoading) return;
    let cancelled = false;
    (async () => {
      setAiLoading(true);
      setAiError("");
      setAiSummary(null);
      try {
        const response = await api.post("/ai/investigate", {
          event: log,
          investigation_id: investigationId || undefined,
        });
        if (cancelled) return;
        const data = response.data || {};
        if (data.success === false) {
          setAiError(data.detail || data.error || "AI investigation is unavailable.");
        } else {
          setAiSummary(data.analysis || "No AI investigation was returned.");
        }
      } catch {
        if (!cancelled) setAiError("Unable to generate AI investigation.");
      } finally {
        if (!cancelled) setAiLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [log, logKey, invLoading, investigationId]);

  const updateStatus = useCallback(async (status) => {
    if (!investigation || statusSaving) return;
    setStatusSaving(true);
    try {
      const response = await api.put(`/investigations/${investigation.id}/status`, { status });
      if (response.data?.success && response.data.investigation) {
        setInvestigation(response.data.investigation);
      }
    } catch { /* keep current status */ }
    setStatusSaving(false);
  }, [investigation, statusSaving]);

  const addNote = useCallback(async () => {
    const text = noteText.trim();
    if (!investigation || !text || noteSaving) return;
    setNoteSaving(true);
    try {
      const response = await api.put(`/investigations/${investigation.id}/notes`, { note: text });
      if (response.data?.success && response.data.investigation) {
        setInvestigation(response.data.investigation);
        setNoteText("");
      }
    } catch { /* keep current notes */ }
    setNoteSaving(false);
  }, [investigation, noteText, noteSaving]);

  const createCase = useCallback(async () => {
    if (!log || caseCreating) return;
    setCaseCreating(true);
    setCaseError("");
    try {
      const response = await api.post("/cases/create", {
        event: log,
        investigation_id: investigationId || undefined,
      });
      if (response.data?.success && response.data.case) {
        setCaseRecord(response.data.case);
      } else {
        setCaseError(response.data?.error || "Could not create case.");
      }
    } catch {
      setCaseError("Unable to connect to SOCRA AI backend.");
    }
    setCaseCreating(false);
  }, [log, investigationId, caseCreating]);

  const loadRelatedEvents = useCallback(async (windowMinutes) => {
    if (!investigation) return;
    setRelatedLoading(true);
    setRelatedError("");
    try {
      const response = await api.get(`/investigations/${investigation.id}/related-events`, {
        params: { window: windowMinutes },
      });
      if (response.data?.success) {
        setInvestigation((prev) => prev ? {
          ...prev,
          related_events: response.data.related_events || [],
          process_tree: response.data.process_tree || [],
        } : prev);
      } else {
        setRelatedError(response.data?.error || "Could not load related events.");
      }
    } catch {
      setRelatedError("Could not load related events from telemetry.");
    }
    setRelatedLoading(false);
  }, [investigation]);

  if (!log) {
    return (
      <div className="w-full pb-8 flex flex-col items-center justify-center select-none min-h-[calc(100vh-10rem)]">
        <div className="max-w-lg text-center">
          <div className="w-20 h-20 mx-auto rounded-2xl bg-slate-800/60 border border-slate-700/60 flex items-center justify-center mb-6">
            <Search size={36} className="text-slate-600" />
          </div>
          <h2 className="text-2xl font-bold text-slate-300 mb-3">No Investigation Active</h2>
          <p className="text-slate-500 leading-relaxed mb-6">
            Select a security alert from the{" "}
            <span className="text-cyan-400 font-semibold cursor-pointer hover:underline" onClick={() => navigate("/alerts")}>Alerts</span>
            {" "}page to begin an enterprise investigation.
          </p>
          <button
            onClick={() => navigate("/alerts")}
            className="px-6 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-bold rounded-lg transition-all duration-150 shadow-lg shadow-cyan-950/30"
          >
            View Alerts
          </button>
        </div>
      </div>
    );
  }

  if (invLoading && !investigation) {
    return (
      <div className="w-full pb-8 flex flex-col items-center justify-center select-none min-h-[calc(100vh-10rem)]">
        <div className="animate-spin rounded-full h-10 w-10 border-4 border-cyan-500 border-t-transparent mb-4"></div>
        <p className="text-slate-400 text-xs font-semibold animate-pulse">Creating investigation record from telemetry...</p>
      </div>
    );
  }

  const ev = log.event || {};
  const det = log.detection || {};
  // Canonical detection.mitre is a list of blocks (single = one-element list);
  // legacy rows may carry a dict or string. Normalize to the first block for
  // the single-technique display.
  let mitreBlock = det.mitre;
  if (Array.isArray(mitreBlock)) {
    mitreBlock = mitreBlock.length > 0 ? mitreBlock[0] : null;
  }
  const mitre = mitreBlock && typeof mitreBlock === "object"
    ? mitreBlock
    : { id: investigation?.mitre || mitreBlock || "N/A", technique: "Unknown", tactic: "Unknown" };
  const ioc = investigation?.ioc || det.ioc || log.ioc || {};
  const riskScore = investigation?.risk_score ?? log.metadata?.risk_score ?? (
    det.severity === "Critical" ? 95 : det.severity === "High" ? 80 : det.severity === "Medium" ? 60 : det.severity === "Low" ? 30 : 10
  );
  const confidence = investigation?.confidence;
  const status = investigation?.status || "New";
  const relatedEvents = investigation?.related_events || [];
  const processTree = investigation?.process_tree || [];
  const notes = investigation?.notes || [];

  const formatTime = (t) => {
    if (!t) return "-";
    try { return new Date(t).toLocaleString("en-GB", { hour12: false }); }
    catch { return t; }
  };

  const sections = [
    { id: "overview", label: "Overview", icon: Activity },
    { id: "details", label: "Alert Details", icon: FileCode },
    { id: "related", label: "Related Events", icon: List },
    { id: "process", label: "Process Tree", icon: ListTree },
    { id: "ioc", label: "IOC Extraction", icon: Fingerprint },
    { id: "mitre", label: "MITRE Mapping", icon: Target },
    { id: "notes", label: "Analyst Notes", icon: NotebookPen },
    { id: "ai", label: "AI Summary", icon: Bot },
    { id: "response", label: "Response Actions", icon: Shield },
  ];

  return (
    <div className="w-full pb-8 space-y-5 select-none">
      <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-3 pt-4">
        <div>
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-xl font-extrabold tracking-tight text-white flex items-center gap-2">
              <Search size={20} className="text-cyan-400" />
              <span>Investigation Workspace</span>
            </h1>
            <SeverityBadge severity={investigation?.severity || det.severity} />
            {investigation?.id && (
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/25 text-cyan-400 text-[10px] font-mono font-bold tracking-wider">
                {investigation.id}
              </span>
            )}
          </div>
          <p className="text-xs text-slate-500 font-medium mt-1.5">
            {investigation?.alert_id ? (
              <>Alert <span className="font-mono text-slate-400">{investigation.alert_id.slice(0, 24)}{investigation.alert_id.length > 24 ? "…" : ""}</span> — </>
            ) : null}
            Enterprise incident investigation for {ev.host || "Unknown Host"} — Event ID {ev.event_id || "N/A"}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {caseRecord && (
            <button
              onClick={() => navigate("/cases")}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600/20 border border-cyan-500/40 text-xs font-bold text-cyan-400 rounded-lg hover:bg-cyan-600/30 transition-all"
            >
              Case {caseRecord.case_id} → View Cases
            </button>
          )}
          <button
            onClick={createCase}
            disabled={caseCreating || !!caseRecord}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600/20 border border-emerald-500/40 text-xs font-bold text-emerald-400 rounded-lg hover:bg-emerald-600/30 transition-all disabled:opacity-40"
          >
            <Plus size={12} />
            {caseRecord ? "Case Escalated" : caseCreating ? "Creating..." : "Create Case"}
          </button>
          <button
            onClick={() => navigate("/alerts")}
            className="px-3 py-1.5 bg-slate-800/60 border border-slate-700/60 text-xs font-bold text-slate-300 rounded-lg hover:bg-slate-700/60 transition-all"
          >
            ← Back to Alerts
          </button>
        </div>
      </div>

      {/* Investigation lifecycle status control */}
      <div className="flex items-center gap-2 flex-wrap p-3 bg-slate-900/30 border border-slate-800/60 rounded-xl">
        <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
          <Shield size={12} /> Investigation Status
        </span>
        {INVESTIGATION_STATUSES.map((s) => (
          <button
            key={s}
            disabled={statusSaving}
            onClick={() => updateStatus(s)}
            className={`px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider rounded-lg border transition-all duration-100 disabled:opacity-50 ${
              status === s
                ? "bg-cyan-600/20 border-cyan-500/40 text-cyan-400"
                : "bg-slate-900/60 border-slate-800/60 text-slate-500 hover:text-slate-300 hover:border-slate-700"
            }`}
          >
            {s}
          </button>
        ))}
      </div>

      <div className="flex gap-1.5 overflow-x-auto pb-1 scrollbar-none">
        {sections.map((sec) => {
          const Icon = sec.icon;
          const isActive = activeSection === sec.id;
          return (
            <button
              key={sec.id}
              onClick={() => setActiveSection(sec.id)}
              className={`flex items-center gap-1.5 px-3 py-2 text-[11px] font-bold uppercase tracking-wider rounded-lg transition-all duration-150 whitespace-nowrap ${
                isActive 
                  ? "bg-cyan-600/20 text-cyan-400 border border-cyan-500/30 shadow-sm" 
                  : "text-slate-500 hover:text-slate-300 border border-transparent hover:bg-slate-800/40"
              }`}
            >
              <Icon size={13} />
              {sec.label}
            </button>
          );
        })}
      </div>

      {invError && (
        <div className="rounded-xl border border-amber-500/20 bg-amber-500/10 px-4 py-2.5 text-xs text-amber-300">
          {invError}
        </div>
      )}

      {caseError && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-2.5 text-xs text-red-300">
          {caseError}
        </div>
      )}

      <div className="bg-slate-800/50 border border-slate-700/60 rounded-xl p-4">
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 xl:grid-cols-9 gap-3">
          <div className="p-2">
            <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-1">Severity</p>
            <SeverityBadge severity={investigation?.severity || det.severity} />
          </div>
          <div className="p-2">
            <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-1">Event ID</p>
            <p className="font-mono text-cyan-400 text-sm font-bold">{investigation?.event_id || ev.event_id || "-"}</p>
          </div>
          <div className="p-2">
            <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-1">Host</p>
            <p className="text-white text-sm font-bold truncate">{investigation?.host || ev.host || "-"}</p>
          </div>
          <div className="p-2">
            <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-1">User</p>
            <p className="text-slate-300 text-sm truncate">{investigation?.user || ev.user || "-"}</p>
          </div>
          <div className="p-2">
            <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-1">Process</p>
            <p className="text-cyan-400 text-sm font-mono truncate">{(investigation?.process || ev.process_name || "-").split("\\").pop()}</p>
          </div>
          <div className="p-2">
            <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-1">Parent Process</p>
            <p className="text-slate-300 text-sm font-mono truncate">{(investigation?.parent_process || ev.parent_process_name || "-").split("\\").pop()}</p>
          </div>
          <div className="p-2">
            <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-1">Timestamp</p>
            <p className="text-slate-300 text-xs font-mono">{formatTime(investigation?.timestamp || ev.time)}</p>
          </div>
          <div className="p-2">
            <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-1">MITRE</p>
            <p className="text-purple-400 text-xs font-mono font-bold">{mitre.id || "-"}</p>
          </div>
          <div className="p-2">
            <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-1">Risk Score</p>
            <div className="flex items-center gap-2">
              <span className={`text-lg font-black ${riskScore >= 80 ? "text-red-400" : riskScore >= 60 ? "text-orange-400" : riskScore >= 30 ? "text-yellow-400" : "text-green-400"}`}>
                {riskScore}
              </span>
              <span className="text-[10px] text-slate-600">/100</span>
            </div>
          </div>
        </div>
      </div>

      <div className="space-y-4">
        {activeSection === "overview" && (
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            <EnterpriseCard title="Executive Summary" icon={Activity} iconColor="text-cyan-400">
              <p className="text-slate-300 text-sm leading-7">
                This event was detected as{" "}
                <span className="text-cyan-400 font-semibold">{det.detection || "Unknown"}</span>
                {" "}on host <span className="text-white font-semibold">{investigation?.host || ev.host || "Unknown"}</span>
                {" "}by user <span className="text-white font-semibold">{investigation?.user || ev.user || "SYSTEM"}</span>.
                The activity has been classified as{" "}
                <span className={`font-semibold ${severityColor(investigation?.severity || det.severity)}`}>{investigation?.severity || det.severity}</span>
                {" "}severity and mapped to MITRE ATT&CK technique{" "}
                <span className="text-purple-400 font-semibold">{mitre.id || "Unknown"}</span>.
              </p>
              {det.description && (
                <p className="text-slate-400 text-sm mt-3 leading-7">{det.description}</p>
              )}
            </EnterpriseCard>
            <EnterpriseCard title="Detection Summary" icon={ShieldAlert} iconColor="text-red-400">
              <div className="space-y-3">
                <div className="flex justify-between items-center p-2.5 bg-slate-900/40 rounded-lg border border-slate-800/40">
                  <span className="text-xs text-slate-400">Detection Rule</span>
                  <span className="text-xs font-bold text-cyan-400">{det.detection || "-"}</span>
                </div>
                <div className="flex justify-between items-center p-2.5 bg-slate-900/40 rounded-lg border border-slate-800/40">
                  <span className="text-xs text-slate-400">Risk Score</span>
                  <span className={`text-lg font-black ${riskScore >= 80 ? "text-red-400" : riskScore >= 60 ? "text-orange-400" : riskScore >= 30 ? "text-yellow-400" : "text-green-400"}`}>{riskScore}/100</span>
                </div>
                <div className="flex justify-between items-center p-2.5 bg-slate-900/40 rounded-lg border border-slate-800/40">
                  <span className="text-xs text-slate-400">Confidence</span>
                  <span className="text-xs font-bold text-green-400">
                    {confidence != null ? `${confidence}% (derived from telemetry)` : "—"}
                  </span>
                </div>
                <div className="flex justify-between items-center p-2.5 bg-slate-900/40 rounded-lg border border-slate-800/40">
                  <span className="text-xs text-slate-400">Related Events</span>
                  <span className="text-xs font-bold text-cyan-400">{relatedEvents.length}</span>
                </div>
                <div className="flex justify-between items-center p-2.5 bg-slate-900/40 rounded-lg border border-slate-800/40">
                  <span className="text-xs text-slate-400">Investigation Status</span>
                  <span className="text-xs font-bold text-cyan-400">{status}</span>
                </div>
              </div>
            </EnterpriseCard>
          </div>
        )}

        {activeSection === "details" && (
          <EnterpriseCard title="Alert Details" icon={FileCode} iconColor="text-cyan-400">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-2">Investigation ID</p>
                <p className="font-mono text-cyan-400 text-sm font-bold">{investigation?.id || "-"}</p>
              </div>
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-2">Alert ID</p>
                <p className="text-slate-300 text-sm font-mono break-all">{investigation?.alert_id || log.metadata?.fingerprint || "-"}</p>
              </div>
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-2">Event ID</p>
                <p className="font-mono text-cyan-400 text-sm font-bold">{investigation?.event_id || ev.event_id || "-"}</p>
              </div>
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-2">Time (UTC)</p>
                <p className="text-slate-300 text-sm font-mono">{formatTime(investigation?.timestamp || ev.time)}</p>
              </div>
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-2">Host</p>
                <p className="text-white text-sm font-bold">{investigation?.host || ev.host || "-"}</p>
              </div>
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-2">User / Account</p>
                <p className="text-slate-300 text-sm">{investigation?.user || ev.user || "-"}</p>
              </div>
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-2">Process Name</p>
                <p className="text-cyan-400 text-sm font-mono truncate">{investigation?.process || ev.process_name || "-"}</p>
              </div>
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-2">Parent Process</p>
                <p className="text-slate-300 text-sm font-mono truncate">{investigation?.parent_process || ev.parent_process_name || "-"}</p>
              </div>
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-2">Risk Score</p>
                <p className="font-mono text-slate-300 text-sm font-bold">{riskScore}/100</p>
              </div>
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-2">Confidence</p>
                <p className="text-slate-300 text-sm">{confidence != null ? `${confidence}%` : "—"}</p>
              </div>
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-2">Process ID</p>
                <p className="font-mono text-slate-300 text-sm">{ev.process_id || "-"}</p>
              </div>
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-2">Source</p>
                <p className="text-slate-300 text-sm">{ev.source || "-"}</p>
              </div>
              <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-2">Provider</p>
                <p className="text-slate-300 text-sm">{ev.provider || "-"}</p>
              </div>
              {ev.command_line && (
                <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40 col-span-full">
                  <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-2">Command Line</p>
                  <pre className="text-xs text-emerald-400 font-mono whitespace-pre-wrap break-all bg-emerald-950/10 p-2 rounded border border-emerald-950/30">{ev.command_line}</pre>
                </div>
              )}
            </div>
          </EnterpriseCard>
        )}

        {activeSection === "related" && (
          <EnterpriseCard title="Related Events" icon={List} iconColor="text-cyan-400">
            <div className="flex items-center gap-2 flex-wrap mb-4">
              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Time Window</span>
              {RELATED_WINDOWS.map((w) => (
                <button
                  key={w.value}
                  onClick={() => { setRelatedWindow(w.value); loadRelatedEvents(w.value); }}
                  className={`px-2.5 py-1.5 text-[10px] font-bold uppercase tracking-wider rounded-lg border transition-all duration-100 ${
                    relatedWindow === w.value
                      ? "bg-cyan-500/10 border-cyan-500/30 text-cyan-400"
                      : "bg-slate-900/60 border-slate-800/60 text-slate-500 hover:text-slate-300 hover:border-slate-700"
                  }`}
                >
                  {w.label}
                </button>
              ))}
              <button
                onClick={() => loadRelatedEvents(relatedWindow)}
                disabled={relatedLoading}
                className="ml-auto flex items-center gap-1.5 px-2.5 py-1.5 text-[10px] font-bold uppercase tracking-wider rounded-lg border bg-slate-800/60 border-slate-700/60 text-slate-300 hover:bg-slate-700/60 transition-all disabled:opacity-50"
              >
                <RefreshCw size={11} className={relatedLoading ? "animate-spin" : ""} />
                Refresh
              </button>
            </div>
            {relatedError && (
              <p className="text-xs text-amber-300 mb-3">{relatedError}</p>
            )}
            {relatedLoading ? (
              <div className="flex flex-col items-center justify-center py-12">
                <div className="animate-spin rounded-full h-8 w-8 border-2 border-cyan-500 border-t-transparent mb-3"></div>
                <p className="text-slate-500 text-xs">Querying historical telemetry...</p>
              </div>
            ) : relatedEvents.length === 0 ? (
              <div className="bg-slate-900/40 border border-slate-800/40 rounded-lg p-6 text-center">
                <p className="text-xs text-slate-500">No related events found on this host within the selected time window.</p>
              </div>
            ) : (
              <div className="space-y-2">
                {relatedEvents.slice(0, 30).map((item, idx) => {
                  const ts = (() => {
                    try { return new Date(item.timestamp).toLocaleString("en-GB", { hour12: false }); }
                    catch { return item.timestamp; }
                  })();
                  return (
                    <div key={`${item.fingerprint || `${item.timestamp}-${item.event_id}`}-${idx}`} className="flex items-center gap-3 p-2.5 bg-slate-900/40 rounded-lg border border-slate-800/40 hover:border-slate-700/60 transition-all">
                      <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${severityColor(item.severity)}`} />
                      <span className="text-[10px] font-mono text-slate-500 shrink-0 w-36 truncate">{ts}</span>
                      <span className="text-[10px] font-mono font-bold text-cyan-500/80 bg-cyan-500/10 border border-cyan-500/20 px-1.5 py-0.5 rounded shrink-0">
                        EID: {item.event_id || "-"}
                      </span>
                      <span className="text-[11px] font-mono text-slate-300 truncate flex-1">{item.process || "-"}</span>
                      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 shrink-0">{item.severity}</span>
                    </div>
                  );
                })}
                {relatedEvents.length > 30 && (
                  <p className="text-[10px] text-slate-600">+{relatedEvents.length - 30} more</p>
                )}
              </div>
            )}
          </EnterpriseCard>
        )}

        {activeSection === "process" && (
          <EnterpriseCard title="Process Execution Tree" icon={ListTree} iconColor="text-amber-400">
            <div className="bg-slate-900/40 border border-slate-800/40 rounded-lg p-4">
              {processTree.length > 0 ? (
                processTree.map((node, idx) => (
                  <ProcessTreeNode key={idx} node={node} depth={0} />
                ))
              ) : (
                <div className="p-2">
                  <p className="text-xs text-slate-400 flex items-center gap-2">
                    <Terminal size={13} className="text-cyan-400" />
                    {(ev.parent_process_name || ev.parent_process ? ev.parent_process_name || ev.parent_process : ev.process_name || "Unknown process") + (ev.parent_process_name || ev.parent_process ? " → " + (ev.process_name || "Unknown process") : "")}
                  </p>
                  {(ev.parent_process_name || ev.parent_process) && (
                    <p className="text-[10px] text-slate-600 mt-1 italic">Parent event not observed in the related-event window.</p>
                  )}
                </div>
              )}
            </div>
            {ev.command_line && (
              <div className="mt-3 p-3 bg-slate-900/30 border border-slate-800/40 rounded-lg">
                <div className="flex items-center gap-2 mb-2">
                  <Terminal size={13} className="text-cyan-400" />
                  <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">Command Line Arguments</span>
                </div>
                <pre className="text-xs text-emerald-400 font-mono whitespace-pre-wrap break-all bg-emerald-950/10 p-2 rounded border border-emerald-950/30">{ev.command_line}</pre>
              </div>
            )}
          </EnterpriseCard>
        )}

        {activeSection === "ioc" && (
          <EnterpriseCard title="Indicators of Compromise" icon={Fingerprint} iconColor="text-green-400">
            <IOCSection
              ioc={ioc}
              investigationId={investigationId}
              onLookup={(value) => navigate(`/threat-intel?indicator=${encodeURIComponent(value)}`)}
            />
          </EnterpriseCard>
        )}

        {activeSection === "mitre" && (
          <EnterpriseCard title="MITRE ATT&CK Mapping" icon={Target} iconColor="text-purple-400">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-4 bg-purple-500/5 border border-purple-500/20 rounded-lg text-center">
                <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-2">Technique ID</p>
                <p className="text-2xl font-black text-purple-400 font-mono">{mitre.id || "N/A"}</p>
              </div>
              <div className="p-4 bg-purple-500/5 border border-purple-500/20 rounded-lg">
                <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-2">Technique</p>
                <p className="text-sm font-bold text-purple-300">{mitre.technique || "Unknown"}</p>
              </div>
              <div className="p-4 bg-purple-500/5 border border-purple-500/20 rounded-lg">
                <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold mb-2">Tactic</p>
                <p className="text-sm font-bold text-purple-300">{mitre.tactic || "Unknown"}</p>
              </div>
            </div>
            {mitre.id && mitre.id !== "N/A" && mitre.id !== "Unknown" && (
              <div className="mt-4 p-4 bg-slate-900/40 border border-slate-800/40 rounded-lg">
                <p className="text-xs text-slate-400 leading-7">
                  This event was mapped to MITRE ATT&CK technique{" "}
                  <span className="text-purple-400 font-bold">{mitre.id}</span>{" "}
                  ({mitre.technique}) under the{" "}
                  <span className="text-purple-400 font-bold">{mitre.tactic}</span>{" "}
                  tactic. This indicates the activity is associated with an adversary technique used for{" "}
                  <span className="text-slate-300">{mitre.tactic?.toLowerCase() || "unknown purposes"}</span>.
                </p>
              </div>
            )}
          </EnterpriseCard>
        )}

        {activeSection === "notes" && (
          <EnterpriseCard title="Analyst Notes" icon={NotebookPen} iconColor="text-cyan-400">
            <div className="flex items-start gap-2 mb-4">
              <textarea
                value={noteText}
                onChange={(e) => setNoteText(e.target.value)}
                rows={2}
                placeholder="Add an investigation note..."
                className="flex-1 bg-slate-900/40 border border-slate-800/40 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder:text-slate-600 outline-none focus:border-cyan-500/40 resize-none"
              />
              <button
                onClick={addNote}
                disabled={noteSaving || !noteText.trim()}
                className="flex items-center gap-1.5 px-3 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-white text-[10px] font-bold rounded-lg transition-all shrink-0"
              >
                <Plus size={12} /> Add Note
              </button>
            </div>
            {notes.length === 0 ? (
              <div className="bg-slate-900/40 border border-slate-800/40 rounded-lg p-6 text-center">
                <p className="text-xs text-slate-500">No analyst notes recorded yet for this investigation.</p>
              </div>
            ) : (
              <div className="space-y-2">
                {notes.map((n, idx) => (
                  <div key={idx} className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                    <div className="flex items-center gap-2 mb-1.5">
                      <span className="text-[10px] font-mono text-slate-500">{formatTime(n.time)}</span>
                      <span className="text-[10px] font-bold uppercase tracking-wider text-cyan-500">SOC Analyst</span>
                    </div>
                    <p className="text-xs text-slate-300 leading-6">{n.note}</p>
                  </div>
                ))}
              </div>
            )}
          </EnterpriseCard>
        )}

        {activeSection === "ai" && (
          <EnterpriseCard title="AI Investigation Summary" icon={Bot} iconColor="text-cyan-400">
            {aiLoading ? (
              <div className="flex flex-col items-center justify-center py-12">
                <div className="animate-spin rounded-full h-10 w-10 border-2 border-cyan-500 border-t-transparent mb-4"></div>
                <p className="text-cyan-400 text-sm font-semibold">SOCRA AI is analyzing this security event...</p>
                <p className="text-slate-500 text-xs mt-2">Generating enterprise investigation report</p>
              </div>
            ) : aiError ? (
              <div>
                <div className="rounded-xl border border-amber-500/20 bg-amber-500/10 px-4 py-3 text-xs text-amber-300 leading-6">
                  <span className="font-bold uppercase tracking-wider">AI investigation unavailable — </span>
                  {aiError}
                </div>
                <div className="flex items-center gap-3 mt-4">
                  <button
                    onClick={runInvestigation}
                    className="flex items-center gap-1.5 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold rounded-lg transition-all"
                  >
                    <RefreshCw size={12} /> Retry
                  </button>
                  <span className="text-[10px] text-slate-500">Ensure the Ollama service is running and the model is installed.</span>
                </div>
              </div>
            ) : aiSummary ? (
              <div>
                <div className="flex items-center gap-2 mb-4 p-3 bg-cyan-500/5 border border-cyan-500/20 rounded-lg">
                  <Bot size={16} className="text-cyan-400" />
                  <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider">SOCRA AI — Llama 3 Analysis</span>
                  <span className="ml-auto text-[10px] text-slate-500">Generated in real-time</span>
                </div>
                <div className="bg-slate-900/40 border border-slate-800/40 rounded-lg p-5">
                  <pre className="text-slate-300 text-sm leading-7 whitespace-pre-wrap font-sans">
                    {aiSummary}
                  </pre>
                </div>
                <button
                  onClick={runInvestigation}
                  className="mt-3 px-4 py-2 bg-slate-800/60 border border-slate-700/60 text-xs font-bold text-slate-300 rounded-lg hover:bg-slate-700/60 transition-all"
                >
                  Regenerate Analysis
                </button>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-12">
                <Bot size={40} className="text-slate-700 mb-3" />
                <p className="text-slate-500 text-sm">AI investigation not available</p>
                <button
                  onClick={runInvestigation}
                  className="mt-3 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold rounded-lg transition-all"
                >
                  Run AI Investigation
                </button>
              </div>
            )}
          </EnterpriseCard>
        )}

        {activeSection === "response" && (
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            <EnterpriseCard title="Immediate Containment Actions" icon={Shield} iconColor="text-red-400">
              <ul className="space-y-2">
                {[
                  { action: "Review affected endpoint", desc: "Isolate host if malicious activity confirmed", severity: "High" },
                  { action: "Validate user activity", desc: "Check user account for anomalous behavior", severity: "High" },
                  { action: "Investigate parent process", desc: "Trace parent process lineage for compromise", severity: "Medium" },
                  { action: "Verify indicators of compromise", desc: "Cross-reference IOCs with threat intelligence", severity: "Medium" },
                  { action: "Escalate if malicious", desc: "Escalate to Tier-2/Tier-3 SOC analyst", severity: "High" },
                ].map((item, idx) => (
                  <li key={idx} className="flex items-start gap-3 p-2.5 bg-slate-900/40 rounded-lg border border-slate-800/40 hover:border-slate-700/60 transition-all">
                    <span className={`w-5 h-5 rounded-full flex items-center justify-center shrink-0 mt-0.5 ${
                      item.severity === "High" ? "bg-red-500/20 text-red-400" : "bg-yellow-500/20 text-yellow-400"
                    }`}>
                      <span className="text-[10px] font-black">{idx + 1}</span>
                    </span>
                    <div>
                      <p className="text-xs font-bold text-slate-200">{item.action}</p>
                      <p className="text-[11px] text-slate-500 mt-0.5">{item.desc}</p>
                    </div>
                  </li>
                ))}
              </ul>
            </EnterpriseCard>
            <EnterpriseCard title="Recommended Remediation Steps" icon={CheckCircle2} iconColor="text-green-400">
              <ul className="space-y-2">
                {[
                  { action: "Terminate malicious processes", desc: "Kill identified malicious process trees" },
                  { action: "Remove persistence mechanisms", desc: "Delete scheduled tasks, services, registry run keys" },
                  { action: "Reset compromised credentials", desc: "Force password reset for affected accounts" },
                  { action: "Run full EDR/AV scan", desc: "Perform deep scan on all affected endpoints" },
                  { action: "Monitor for recurrence", desc: "Enhanced monitoring for 48 hours post-remediation" },
                  { action: "Update detection rules", desc: "Tune SIEM rules based on investigation findings" },
                ].map((item, idx) => (
                  <li key={idx} className="flex items-start gap-3 p-2.5 bg-slate-900/40 rounded-lg border border-slate-800/40 hover:border-slate-700/60 transition-all">
                    <CheckCircle2 size={14} className="text-green-400 shrink-0 mt-0.5" />
                    <div>
                      <p className="text-xs font-bold text-slate-200">{item.action}</p>
                      <p className="text-[11px] text-slate-500 mt-0.5">{item.desc}</p>
                    </div>
                  </li>
                ))}
              </ul>
            </EnterpriseCard>
          </div>
        )}
      </div>
    </div>
  );
}

export default Investigation;
