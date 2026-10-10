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

const CASE_STATUSES = [
  "Open",
  "Investigating",
  "Contained",
  "Resolved",
  "Closed",
];

const CASE_PRIORITIES = [
  "Critical",
  "High",
  "Medium",
  "Low",
  "Informational",
];

const STATUS_STYLE = {
  Open: "bg-slate-700/40 text-slate-300 border-slate-700/70",
  Investigating: "bg-amber-500/10 text-amber-400 border-amber-500/20",
  Contained: "bg-violet-500/10 text-violet-400 border-violet-500/20",
  Resolved: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
  Closed: "bg-slate-800/60 text-slate-500 border-slate-700/60",
};

const PRIORITY_STYLE = {
  Critical: "bg-red-500/10 text-red-400 border-red-500/20",
  High: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  Medium: "bg-amber-500/10 text-amber-400 border-amber-500/20",
  Low: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
  Informational: "bg-slate-800/60 text-slate-400 border-slate-700/60",
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
        if (!cancelled) {
          setError("Case management backend is unavailable.");
        }
      }
    }

    init();

    return () => {
      cancelled = true;
    };
  }, []);

  const updateStatus = useCallback(
    async (item, status) => {
      setStatusSavingId(item.case_id);

      try {
        const response = await api.put(
          `/cases/${item.case_id}/status`,
          { status }
        );

        if (response.data?.success) {
          setCases((prev) =>
            prev.map((c) =>
              c.case_id === item.case_id ? response.data.case : c
            )
          );

          await loadCases();
        } else {
          setError(response.data?.error || "Could not update case status.");
        }
      } catch {
        setError("Could not update case status.");
      } finally {
        setStatusSavingId(null);
      }
    },
    [loadCases]
  );

  const updatePriority = useCallback(
    async (item, priority) => {
      setPrioritySavingId(item.case_id);

      try {
        const response = await api.put(`/cases/${item.case_id}`, {
          priority,
        });

        if (response.data?.success) {
          setCases((prev) =>
            prev.map((c) =>
              c.case_id === item.case_id ? response.data.case : c
            )
          );

          await loadCases();
        } else {
          setError(response.data?.error || "Could not update case priority.");
        }
      } catch {
        setError("Could not update case priority.");
      } finally {
        setPrioritySavingId(null);
      }
    },
    [loadCases]
  );

  const assignAnalyst = useCallback(
    async (item) => {
      const analyst = assignText.trim();
      if (!analyst) return;

      setAssignSavingId(item.case_id);

      try {
        const response = await api.put(
          `/cases/${item.case_id}/assign`,
          { analyst }
        );

        if (response.data?.success) {
          setCases((prev) =>
            prev.map((c) =>
              c.case_id === item.case_id ? response.data.case : c
            )
          );

          setAssignText("");
          await loadCases();
        } else {
          setError(response.data?.error || "Could not assign analyst.");
        }
      } catch {
        setError("Could not assign analyst.");
      } finally {
        setAssignSavingId(null);
      }
    },
    [assignText, loadCases]
  );

  const addNote = useCallback(
    async (item) => {
      const note = noteText.trim();
      if (!note) return;

      setNoteSavingId(item.case_id);

      try {
        const response = await api.put(`/cases/${item.case_id}/note`, {
          note,
        });

        if (response.data?.success) {
          setCases((prev) =>
            prev.map((c) =>
              c.case_id === item.case_id ? response.data.case : c
            )
          );

          setNoteText("");
          await loadCases();
        } else {
          setError(response.data?.error || "Could not add case note.");
        }
      } catch {
        setError("Could not add case note.");
      } finally {
        setNoteSavingId(null);
      }
    },
    [noteText, loadCases]
  );

  const statCards = [
    {
      label: "Total Cases",
      value: stats.total ?? 0,
      color: "text-slate-100",
      icon: <FolderOpen size={16} />,
    },
    {
      label: "Open",
      value: stats.open ?? 0,
      color: "text-red-400",
      icon: <Shield size={16} />,
    },
    {
      label: "Investigating",
      value: stats.investigating ?? 0,
      color: "text-amber-400",
      icon: <ActivityIcon />,
    },
    {
      label: "Contained",
      value: stats.contained ?? 0,
      color: "text-violet-400",
      icon: <Shield size={16} />,
    },
    {
      label: "Resolved",
      value: stats.resolved ?? 0,
      color: "text-emerald-400",
      icon: <ListChecks size={16} />,
    },
    {
      label: "Closed",
      value: stats.closed ?? 0,
      color: "text-slate-400",
      icon: <FolderOpen size={16} />,
    },
  ];

  const formatTime = (t) => {
    if (!t) return "-";

    try {
      return new Date(t).toLocaleString("en-GB", {
        hour12: false,
      });
    } catch {
      return t;
    }
  };

  return (
    <div className="space-y-6 text-slate-200">
      <PageHeader
        title="Case Management"
        subtitle="Track investigations and analyst workflow."
      />

      {error && (
        <div className="flex items-start justify-between gap-3 rounded-xl border border-red-500/15 bg-red-500/[0.04] px-4 py-3 text-xs text-red-300">
          <span>{error}</span>
          <button
            type="button"
            onClick={() => setError("")}
            className="shrink-0 text-red-400/70 transition-colors hover:text-red-300"
            aria-label="Dismiss error"
          >
            ×
          </button>
        </div>
      )}

      {/* Statistics */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        {statCards.map((card) => (
          <div
            key={card.label}
            className="rounded-xl border border-slate-800/80 bg-slate-950/60 p-4 transition-colors duration-200 hover:border-slate-700/80"
          >
            <div className="flex items-center justify-between gap-2">
              <p className="text-[11px] font-medium text-slate-500">
                {card.label}
              </p>
              <span className="text-slate-600">{card.icon}</span>
            </div>

            <h2
              className={`mt-3 font-mono text-2xl font-semibold tabular-nums ${card.color}`}
            >
              {card.value}
            </h2>
          </div>
        ))}
      </div>

      {/* Case list */}
      <div className="space-y-3">
        {cases.length === 0 && (
          <div className="rounded-xl border border-slate-800/80 bg-slate-950/60 px-5 py-12 text-center">
            <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl border border-slate-800 bg-slate-900/80">
              <FolderOpen className="text-slate-500" size={25} />
            </div>

            <h2 className="text-sm font-semibold text-slate-200">
              No Cases Found
            </h2>

            <p className="mx-auto mt-2 max-w-sm text-xs leading-5 text-slate-500">
              Escalate a real alert to a case from the Investigation workspace.
            </p>

            <button
              type="button"
              onClick={() => navigate("/alerts")}
              className="mt-5 inline-flex items-center gap-2 rounded-lg border border-slate-700/80 bg-slate-800/70 px-4 py-2 text-xs font-semibold text-slate-200 transition-colors hover:bg-slate-700/70"
            >
              View Alerts
              <ExternalLink size={12} />
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
              className="overflow-hidden rounded-xl border border-slate-800/80 bg-slate-950/60 transition-colors duration-200 hover:border-slate-700/80"
            >
              {/* Case summary */}
              <button
                type="button"
                onClick={() =>
                  setExpandedId(expanded ? null : item.case_id)
                }
                aria-expanded={expanded}
                className="block w-full cursor-pointer px-4 py-5 text-left transition-colors hover:bg-slate-900/30 sm:px-5"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex min-w-0 items-start gap-3">
                    <span className="mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-slate-800 bg-slate-900/80 text-slate-500">
                      {expanded ? (
                        <ChevronUp size={15} />
                      ) : (
                        <ChevronDown size={15} />
                      )}
                    </span>

                    <div className="min-w-0">
                      <h2 className="break-words font-mono text-sm font-semibold text-slate-100">
                        {item.case_id}
                      </h2>

                      <p className="mt-1 break-words text-xs leading-5 text-slate-400">
                        {item.title}
                      </p>
                    </div>
                  </div>

                  <span
                    className={`shrink-0 rounded-md border px-2.5 py-1 text-[9px] font-bold uppercase tracking-wider ${
                      STATUS_STYLE[item.status] || STATUS_STYLE.Open
                    }`}
                  >
                    {item.status}
                  </span>
                </div>

                <div className="mt-5 grid grid-cols-2 gap-x-4 gap-y-4 md:grid-cols-4">
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5 text-[10px] font-medium text-slate-500">
                      <Shield size={13} />
                      Priority
                    </div>
                    <p
                      className={`mt-2 inline-flex max-w-full rounded-md border px-2 py-1 text-[10px] font-semibold ${
                        PRIORITY_STYLE[item.priority] ||
                        PRIORITY_STYLE.Informational
                      }`}
                    >
                      {item.priority || "Informational"}
                    </p>
                  </div>

                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5 text-[10px] font-medium text-slate-500">
                      <User size={13} />
                      Analyst
                    </div>
                    <p className="mt-2 truncate text-xs text-slate-300">
                      {item.assigned_to || "Unassigned"}
                    </p>
                  </div>

                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5 text-[10px] font-medium text-slate-500">
                      <Clock size={13} />
                      Host
                    </div>
                    <p className="mt-2 truncate font-mono text-xs text-slate-300">
                      {item.host || "-"}
                    </p>
                  </div>

                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5 text-[10px] font-medium text-slate-500">
                      <Plus size={13} />
                      Event ID
                    </div>
                    <p className="mt-2 truncate font-mono text-xs text-slate-300">
                      {item.event_id || "-"}
                    </p>
                  </div>
                </div>

                <p className="mt-5 border-t border-slate-800/60 pt-3 text-[10px] leading-5 text-slate-500">
                  Created {formatTime(item.created_at)} · Updated{" "}
                  {formatTime(item.updated_at)}
                  {item.investigation_id
                    ? ` · Investigation ${item.investigation_id}`
                    : ""}
                </p>
              </button>

              {/* Expanded case details */}
              {expanded && (
                <div className="space-y-6 border-t border-slate-800/80 bg-slate-900/20 p-4 sm:p-5">
                  {/* Status lifecycle */}
                  <section>
                    <SectionHeading icon={<Shield size={13} />}>
                      Case Status
                    </SectionHeading>

                    <div className="flex flex-wrap gap-2">
                      {CASE_STATUSES.map((status) => {
                        const selected = item.status === status;

                        return (
                          <button
                            key={status}
                            type="button"
                            disabled={statusSavingId === item.case_id}
                            onClick={() => updateStatus(item, status)}
                            className={`rounded-md border px-3 py-2 text-[10px] font-semibold uppercase tracking-wider transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${
                              selected
                                ? STATUS_STYLE[status]
                                : "border-slate-800 bg-slate-950/70 text-slate-500 hover:border-slate-700 hover:text-slate-300"
                            }`}
                          >
                            {statusSavingId === item.case_id && selected
                              ? "Saving..."
                              : status}
                          </button>
                        );
                      })}
                    </div>
                  </section>

                  {/* Case priority */}
                  <section>
                    <SectionHeading icon={<Shield size={13} />}>
                      Case Priority
                    </SectionHeading>

                    <div className="flex flex-wrap gap-2">
                      {CASE_PRIORITIES.map((priority) => {
                        const selected = item.priority === priority;

                        return (
                          <button
                            key={priority}
                            type="button"
                            disabled={prioritySavingId === item.case_id}
                            onClick={() => updatePriority(item, priority)}
                            className={`rounded-md border px-3 py-2 text-[10px] font-semibold uppercase tracking-wider transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${
                              selected
                                ? PRIORITY_STYLE[priority]
                                : "border-slate-800 bg-slate-950/70 text-slate-500 hover:border-slate-700 hover:text-slate-300"
                            }`}
                          >
                            {prioritySavingId === item.case_id && selected
                              ? "Saving..."
                              : priority}
                          </button>
                        );
                      })}
                    </div>
                  </section>

                  {/* Assign analyst */}
                  <section>
                    <SectionHeading icon={<User size={13} />}>
                      Assign Analyst
                    </SectionHeading>

                    <div className="flex flex-col gap-2 sm:flex-row">
                      <input
                        value={assignText}
                        onChange={(e) => setAssignText(e.target.value)}
                        onKeyDown={(e) =>
                          e.key === "Enter" && assignAnalyst(item)
                        }
                        placeholder="Analyst username"
                        aria-label="Analyst username"
                        className="min-w-0 flex-1 rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-2.5 text-xs text-slate-200 outline-none transition-colors placeholder:text-slate-600 focus:border-slate-600"
                      />

                      <button
                        type="button"
                        onClick={() => assignAnalyst(item)}
                        disabled={
                          assignSavingId === item.case_id ||
                          !assignText.trim()
                        }
                        className="inline-flex items-center justify-center gap-2 rounded-lg border border-slate-700/80 bg-slate-800/80 px-4 py-2.5 text-xs font-semibold text-slate-200 transition-colors hover:bg-slate-700/80 disabled:cursor-not-allowed disabled:opacity-40"
                      >
                        <User size={13} />
                        {assignSavingId === item.case_id
                          ? "Assigning..."
                          : "Assign"}
                      </button>
                    </div>
                  </section>

                  {/* Timeline */}
                  <section>
                    <SectionHeading icon={<ListChecks size={13} />}>
                      Case Timeline
                    </SectionHeading>

                    {timeline.length === 0 ? (
                      <EmptyMessage>
                        No timeline events recorded.
                      </EmptyMessage>
                    ) : (
                      <div className="space-y-2">
                        {timeline.map((entry, idx) => (
                          <div
                            key={entry.id ?? idx}
                            className="flex items-start gap-3 rounded-lg border border-slate-800/60 bg-slate-950/50 p-3"
                          >
                            <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-slate-500" />

                            <div className="min-w-0 flex-1">
                              <p className="break-words text-xs leading-5 text-slate-300">
                                {entry.action}
                              </p>

                              <p className="mt-1 text-[10px] text-slate-500">
                                {formatTime(entry.time)}
                                {entry.by ? ` · ${entry.by}` : ""}
                              </p>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </section>

                  {/* Analyst notes */}
                  <section>
                    <SectionHeading icon={<NotebookPen size={13} />}>
                      Analyst Notes
                    </SectionHeading>

                    <div className="mb-3 flex flex-col items-stretch gap-2 sm:flex-row sm:items-start">
                      <textarea
                        value={noteText}
                        onChange={(e) => setNoteText(e.target.value)}
                        rows={3}
                        placeholder="Document findings, evidence, or investigation updates..."
                        aria-label="New case note"
                        className="min-w-0 flex-1 resize-y rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-2.5 text-xs leading-5 text-slate-200 outline-none transition-colors placeholder:text-slate-600 focus:border-slate-600"
                      />

                      <button
                        type="button"
                        onClick={() => addNote(item)}
                        disabled={
                          noteSavingId === item.case_id || !noteText.trim()
                        }
                        className="inline-flex shrink-0 items-center justify-center gap-1.5 rounded-lg border border-slate-700/80 bg-slate-800/80 px-3 py-2.5 text-xs font-semibold text-slate-200 transition-colors hover:bg-slate-700/80 disabled:cursor-not-allowed disabled:opacity-40"
                      >
                        <Plus size={13} />
                        {noteSavingId === item.case_id
                          ? "Adding..."
                          : "Add Note"}
                      </button>
                    </div>

                    {notes.length === 0 ? (
                      <EmptyMessage>
                        No notes recorded for this case.
                      </EmptyMessage>
                    ) : (
                      <div className="space-y-2">
                        {notes.map((note, idx) => (
                          <div
                            key={note.id ?? idx}
                            className="rounded-lg border border-slate-800/60 bg-slate-950/50 p-3"
                          >
                            <p className="mb-2 font-mono text-[10px] text-slate-500">
                              {formatTime(note.time)}
                            </p>

                            <p className="whitespace-pre-wrap break-words text-xs leading-5 text-slate-300">
                              {note.note}
                            </p>
                          </div>
                        ))}
                      </div>
                    )}
                  </section>

                  {/* Linked investigation */}
                  {item.investigation_id && (
                    <div className="border-t border-slate-800/70 pt-4">
                      <button
                        type="button"
                        onClick={() => navigate("/investigation")}
                        className="inline-flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/70 px-3 py-2 text-xs font-semibold text-slate-300 transition-colors hover:border-slate-700 hover:bg-slate-800/80 hover:text-slate-100"
                      >
                        <ExternalLink size={13} />
                        Open Linked Investigation
                      </button>
                    </div>
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

function SectionHeading({ icon, children }) {
  return (
    <h3 className="mb-3 flex items-center gap-2 text-[10px] font-bold uppercase tracking-wider text-slate-400">
      <span className="text-slate-500">{icon}</span>
      {children}
    </h3>
  );
}

function EmptyMessage({ children }) {
  return <p className="text-xs leading-5 text-slate-500">{children}</p>;
}

function ActivityIcon() {
  return <Clock size={16} />;
}

export default Cases;