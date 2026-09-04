import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  FolderOpen,
  User,
  Clock,
  Shield,
  ChevronDown,
  ChevronUp,
  Plus,
  ExternalLink,
  NotebookPen,
  ListChecks,
} from "lucide-react";

import api from "../services/api";
import PageHeader from "../components/ui/PageHeader";

// Real case lifecycle (Task 20).
const CASE_STATUSES = ["Open", "Investigating", "Contained", "Resolved", "Closed"];

// Priority levels match the platform severity vocabulary.
const CASE_PRIORITIES = ["Critical", "High", "Medium", "Low", "Informational"];

const STATUS_STYLE = {
  Open: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
  Investigating: "bg-amber-500/10 text-amber-400 border-amber-500/30",
  Contained: "bg-violet-500/10 text-violet-400 border-violet-500/30",
  Resolved: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
  Closed: "bg-slate-600/10 text-slate-400 border-slate-600/30",
};

function Cases() {
  const navigate = useNavigate();

  const [cases, setCases] = useState([]);
  const [stats, setStats] = useState({
    total: 0,
    open: 0,
    investigating: 0,
    contained: 0,
    resolved: 0,
    closed: 0,
    in_progress: 0,
  });
  const [expandedId, setExpandedId] = useState(null);
  const [error, setError] = useState("");
  const [statusSavingId, setStatusSavingId] = useState(null);
  const [prioritySavingId, setPrioritySavingId] = useState(null);
  const [assignText, setAssignText] = useState("");
  const [assignSavingId, setAssignSavingId] = useState(null);
  const [noteText, setNoteText] = useState("");
  const [noteSavingId, setNoteSavingId] = useState(null);

  const loadCases = useCallback(async () => {
    try {
      const [caseResponse, statsResponse] = await Promise.all([
        api.get("/cases"),
        api.get("/cases/statistics/summary"),
      ]);
      setCases(caseResponse.data.cases || []);
      setStats(statsResponse.data || {});
      setError("");
    } catch {
      setError("Case management backend is unavailable.");
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    async function init() {
      try {
        const [caseResponse, statsResponse] = await Promise.all([
          api.get("/cases"),
          api.get("/cases/statistics/summary"),
        ]);
        if (!cancelled) {
          setCases(caseResponse.data.cases || []);
          setStats(statsResponse.data || {});
          setError("");
        }
      } catch {
        if (!cancelled) setError("Case management backend is unavailable.");
      }
    }
    init();
    return () => { cancelled = true; };
  }, []);

  const updateStatus = useCallback(async (item, status) => {
    setStatusSavingId(item.case_id);
    try {
      const response = await api.put(`/cases/${item.case_id}/status`, { status });
      if (response.data?.success) {
        setCases((prev) => prev.map((c) => (c.case_id === item.case_id ? response.data.case : c)));
        await loadCases();
      }
    } catch {
      setError("Could not update case status.");
    }
    setStatusSavingId(null);
  }, [loadCases]);

  const updatePriority = useCallback(async (item, priority) => {
    setPrioritySavingId(item.case_id);
    try {
      const response = await api.put(`/cases/${item.case_id}`, { priority });
      if (response.data?.success) {
        setCases((prev) => prev.map((c) => (c.case_id === item.case_id ? response.data.case : c)));
        await loadCases();
      } else {
        setError(response.data?.error || "Could not update case priority.");
      }
    } catch {
      setError("Could not update case priority.");
    }
    setPrioritySavingId(null);
  }, [loadCases]);

  const assignAnalyst = useCallback(async (item) => {
    const analyst = assignText.trim();
    if (!analyst) return;
    setAssignSavingId(item.case_id);
    try {
      const response = await api.put(`/cases/${item.case_id}/assign`, { analyst });
      if (response.data?.success) {
        setCases((prev) => prev.map((c) => (c.case_id === item.case_id ? response.data.case : c)));
        setAssignText("");
        await loadCases();
      }
    } catch {
      setError("Could not assign analyst.");
    }
    setAssignSavingId(null);
  }, [assignText, loadCases]);

  const addNote = useCallback(async (item) => {
    const note = noteText.trim();
    if (!note) return;
    setNoteSavingId(item.case_id);
    try {
      const response = await api.put(`/cases/${item.case_id}/note`, { note });
      if (response.data?.success) {
        setCases((prev) => prev.map((c) => (c.case_id === item.case_id ? response.data.case : c)));
        setNoteText("");
        await loadCases();
      }
    } catch {
      setError("Could not add case note.");
    }
    setNoteSavingId(null);
  }, [noteText, loadCases]);

  const statCards = [
    { label: "Total Cases", value: stats.total, color: "text-cyan-400" },
    { label: "Open", value: stats.open, color: "text-red-400" },
    { label: "Investigating", value: stats.investigating, color: "text-amber-400" },
    { label: "Contained", value: stats.contained, color: "text-violet-400" },
    { label: "Resolved", value: stats.resolved, color: "text-emerald-400" },
    { label: "Closed", value: stats.closed, color: "text-slate-400" },
  ];

  const formatTime = (t) => {
    if (!t) return "-";
    try {
      return new Date(t).toLocaleString("en-GB", { hour12: false });
    } catch {
      return t;
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Case Management"
        subtitle="Track investigations and analyst workflow."
      />

      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-3 text-xs text-red-300">
          {error}
        </div>
      )}

      {/* Statistics */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
        {statCards.map((card) => (
          <div key={card.label} className="bg-slate-800/40 rounded-xl p-5 border border-slate-700/60">
            <p className="text-slate-400 text-sm">{card.label}</p>
            <h2 className={`text-3xl font-bold mt-2 ${card.color}`}>{card.value}</h2>
          </div>
        ))}
      </div>

      {/* Case List */}
      <div className="space-y-4">
        {cases.length === 0 && (
          <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl p-10 text-center">
            <FolderOpen className="mx-auto text-slate-500 mb-4" size={50} />
            <h2 className="text-xl font-semibold">No Cases Found</h2>
            <p className="text-slate-500 mt-2">
              Escalate a real alert to a case from the Investigation workspace.
            </p>
            <button
              onClick={() => navigate("/alerts")}
              className="mt-4 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold rounded-lg transition-all"
            >
              View Alerts
            </button>
          </div>
        )}

        {cases.map((item) => {
          const expanded = expandedId === item.case_id;
          const timeline = item.timeline || [];
          const notes = item.notes || [];
          return (
            <div
              key={item.case_id}
              className="bg-slate-800/40 border border-slate-700/60 rounded-xl overflow-hidden hover:border-slate-600/60 transition-all duration-200"
            >
              <div
                className="p-6 cursor-pointer select-none"
                onClick={() => setExpandedId(expanded ? null : item.case_id)}
              >
                <div className="flex justify-between items-start">
                  <div className="flex items-center gap-3">
                    {expanded ? (
                      <ChevronUp size={18} className="text-slate-500" />
                    ) : (
                      <ChevronDown size={18} className="text-slate-500" />
                    )}
                    <div>
                      <h2 className="text-xl font-semibold text-cyan-400">{item.case_id}</h2>
                      <p className="text-slate-400 mt-1">{item.title}</p>
                    </div>
                  </div>
                  <span className={`px-4 py-2 rounded-lg border text-xs font-bold ${STATUS_STYLE[item.status] || STATUS_STYLE.Open}`}>
                    {item.status}
                  </span>
                </div>
                <div className="grid md:grid-cols-4 gap-5 mt-6">
                  <div>
                    <div className="flex items-center gap-2 text-slate-400">
                      <Shield size={16} /> Priority
                    </div>
                    <p className="mt-2">{item.priority}</p>
                  </div>
                  <div>
                    <div className="flex items-center gap-2 text-slate-400">
                      <User size={16} /> Analyst
                    </div>
                    <p className="mt-2">{item.assigned_to || "Unassigned"}</p>
                  </div>
                  <div>
                    <div className="flex items-center gap-2 text-slate-400">
                      <Clock size={16} /> Host
                    </div>
                    <p className="mt-2">{item.host || "-"}</p>
                  </div>
                  <div>
                    <div className="flex items-center gap-2 text-slate-400">
                      <Plus size={16} /> Event ID
                    </div>
                    <p className="mt-2">{item.event_id || "-"}</p>
                  </div>
                </div>
                <p className="mt-4 text-[11px] text-slate-500">
                  Created {formatTime(item.created_at)} · Updated {formatTime(item.updated_at)}
                  {item.investigation_id ? ` · Investigation ${item.investigation_id}` : ""}
                </p>
              </div>

              {expanded && (
                <div className="border-t border-slate-700/70 p-6 space-y-6">
                  {/* Status lifecycle */}
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
                      <Shield size={12} /> Case Status
                    </span>
                    {CASE_STATUSES.map((s) => (
                      <button
                        key={s}
                        disabled={statusSavingId === item.case_id}
                        onClick={() => updateStatus(item, s)}
                        className={`px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider rounded-lg border transition-all duration-100 disabled:opacity-50 ${
                          item.status === s
                            ? "bg-cyan-600/20 border-cyan-500/40 text-cyan-400"
                            : "bg-slate-900/60 border-slate-800/60 text-slate-500 hover:text-slate-300 hover:border-slate-700"
                        }`}
                      >
                        {s}
                      </button>
                    ))}
                  </div>

                  {/* Case priority */}
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
                      <Shield size={12} /> Case Priority
                    </span>
                    {CASE_PRIORITIES.map((p) => (
                      <button
                        key={p}
                        disabled={prioritySavingId === item.case_id}
                        onClick={() => updatePriority(item, p)}
                        className={`px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider rounded-lg border transition-all duration-100 disabled:opacity-50 ${
                          item.priority === p
                            ? p === "Critical" || p === "High"
                              ? "bg-red-600/20 border-red-500/40 text-red-400"
                              : p === "Medium"
                                ? "bg-amber-600/20 border-amber-500/40 text-amber-400"
                                : "bg-emerald-600/20 border-emerald-500/40 text-emerald-400"
                            : "bg-slate-900/60 border-slate-800/60 text-slate-500 hover:text-slate-300 hover:border-slate-700"
                        }`}
                      >
                        {p}
                      </button>
                    ))}
                  </div>

                  {/* Assign analyst */}
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
                      <User size={12} /> Assign
                    </span>
                    <input
                      value={assignText}
                      onChange={(e) => setAssignText(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && assignAnalyst(item)}
                      placeholder="Analyst username"
                      className="w-48 bg-slate-900/40 border border-slate-800/60 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-600 outline-none focus:border-cyan-500/40"
                    />
                    <button
                      onClick={() => assignAnalyst(item)}
                      disabled={assignSavingId === item.case_id || !assignText.trim()}
                      className="px-3 py-1.5 bg-slate-700/60 hover:bg-slate-600/60 text-white text-[10px] font-bold rounded-lg transition-all disabled:opacity-40"
                    >
                      Assign
                    </button>
                  </div>

                  {/* Timeline */}
                  <div>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-1.5">
                      <ListChecks size={13} className="text-cyan-400" /> Case Timeline
                    </h3>
                    {timeline.length === 0 ? (
                      <p className="text-xs text-slate-500">No timeline events recorded.</p>
                    ) : (
                      <div className="space-y-2">
                        {timeline.map((entry, idx) => (
                          <div key={idx} className="flex items-start gap-3 p-2.5 bg-slate-900/40 rounded-lg border border-slate-800/40">
                            <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 shrink-0 mt-1.5" />
                            <div className="min-w-0">
                              <p className="text-xs text-slate-300">{entry.action}</p>
                              <p className="text-[10px] text-slate-500">
                                {formatTime(entry.time)}{entry.by ? ` · ${entry.by}` : ""}
                              </p>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Notes */}
                  <div>
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-1.5">
                      <NotebookPen size={13} className="text-cyan-400" /> Analyst Notes
                    </h3>
                    <div className="flex items-start gap-2 mb-3">
                      <textarea
                        value={noteText}
                        onChange={(e) => setNoteText(e.target.value)}
                        rows={2}
                        placeholder="Add a case note..."
                        className="flex-1 bg-slate-900/40 border border-slate-800/40 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder:text-slate-600 outline-none focus:border-cyan-500/40 resize-none"
                      />
                      <button
                        onClick={() => addNote(item)}
                        disabled={noteSavingId === item.case_id || !noteText.trim()}
                        className="flex items-center gap-1.5 px-3 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-white text-[10px] font-bold rounded-lg transition-all shrink-0"
                      >
                        <Plus size={12} /> Add Note
                      </button>
                    </div>
                    {notes.length === 0 ? (
                      <p className="text-xs text-slate-500">No notes recorded for this case.</p>
                    ) : (
                      <div className="space-y-2">
                        {notes.map((n, idx) => (
                          <div key={idx} className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/40">
                            <p className="text-[10px] font-mono text-slate-500 mb-1">{formatTime(n.time)}</p>
                            <p className="text-xs text-slate-300 leading-6">{n.note}</p>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {item.investigation_id && (
                    <button
                      onClick={() => navigate("/investigation")}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-slate-800/60 border border-slate-700/60 text-xs font-bold text-slate-300 rounded-lg hover:bg-slate-700/60 transition-all"
                    >
                      <ExternalLink size={12} /> Open Linked Investigation
                    </button>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default Cases;
