import { useEffect, useState } from "react";
import SeverityBadge from "../SeverityBadge";
import Dropdown from "../ui/Dropdown";
import api from "../../services/api";
import { investigateEvent } from "../../services/investigation";

// The real alert triage lifecycle (Task 17) — distinct from investigation
// status (a separate workspace concept). Changing it here persists to SQLite
// and is broadcast to every live client.
const ALERT_STATUSES = ["New", "Investigating", "Contained", "Resolved", "Closed"];

function EventDetailsDrawer({ log, onClose, onStatusChange }) {

    const [activeTab, setActiveTab] = useState("summary");

    const [loadingAI, setLoadingAI] = useState(false);

    const [aiReport, setAIReport] = useState(null);

    const [aiError, setAIError] = useState("");

    // Alert triage status — local state so the drawer stays responsive while
    // the parent table syncs via the live broadcast.
    const [status, setStatus] = useState(() => log?.event?.status || "New");

    const [statusMeta, setStatusMeta] = useState(() =>
        log?._status_changed_by ? {
            changed_by: log._status_changed_by,
            changed_at: log._status_changed_at,
        } : null
    );

    const [statusError, setStatusError] = useState("");

    useEffect(() => {
        const timer = setTimeout(() => {
            setStatus(log?.event?.status || "New");
            setStatusMeta(log?._status_changed_by ? {
                changed_by: log._status_changed_by,
                changed_at: log._status_changed_at,
            } : null);
            setStatusError("");
        }, 0);
        return () => clearTimeout(timer);
    }, [log]);

    const changeStatus = async (newStatus) => {
        if (!log || newStatus === status) return;
        const previous = status;
        setStatus(newStatus);
        setStatusError("");
        try {
            const response = await api.post("/alerts/status", {
                alert_id: log._id ?? null,
                fingerprint: log?.metadata?.fingerprint ?? null,
                status: newStatus,
            });
            if (response.data?.success) {
                const alert = response.data.alert || {};
                if (alert.changed_by) {
                    setStatusMeta({ changed_by: alert.changed_by, changed_at: alert.changed_at });
                }
                onStatusChange?.(log, newStatus);
            } else {
                setStatus(previous);
                setStatusError(response.data?.error || "Could not update alert status.");
            }
        } catch {
            setStatus(previous);
            setStatusError("Unable to connect to SOCRA AI backend.");
        }
    };

    const runAIInvestigation = async () => {

        if (!log) return;

        if (aiReport) return;

        setLoadingAI(true);

        setAIError("");

        try {

            const response = await investigateEvent(log);

            if (response.success) {

                setAIReport(response.analysis);

            } else {

                setAIError(response.error || "AI investigation failed.");

            }

        } catch {

            setAIError("Unable to connect to SOCRA AI backend.");

        }

        setLoadingAI(false);

    };

    useEffect(() => {

        const timer = setTimeout(() => {

            setAIReport(null);

            setAIError("");

            setLoadingAI(false);

            setActiveTab("summary");

        }, 0);

        return () => clearTimeout(timer);

    }, [log]);

    if (!log) return null;

    // Canonical detection.mitre is a list of blocks; legacy rows may carry a
    // plain dict or string. Normalize to a single block for display (first
    // technique when multiple are mapped).
    let mitreRaw = log.detection?.mitre;
    if (Array.isArray(mitreRaw)) {
        mitreRaw = mitreRaw.length > 0 ? mitreRaw[0] : null;
    }
    const mitre = mitreRaw && typeof mitreRaw === "object"
        ? mitreRaw
        : { id: mitreRaw || "-" };

    const isUnmapped = !mitre.id || mitre.id === "-" || mitre.id === "N/A" || mitre.id === "Unknown";

    const ioc = log.detection?.ioc || log.ioc || {};

    return (

        <div
            className="
                fixed
                top-0
                right-0
                h-screen
                w-[560px]
                bg-slate-900
                border-l
                border-slate-700
                shadow-2xl
                z-50
                overflow-y-auto
            "
        >

            {/* Header */}

            <div className="sticky top-0 bg-slate-900 border-b border-slate-700 p-6 z-10">

                <div className="flex justify-between items-start">

                    <div>

                        <h2 className="text-2xl font-bold text-white">

                            Event Details

                        </h2>

                        <p className="text-slate-400 text-sm mt-1">

                            Windows Security Investigation

                        </p>

                    </div>

                    <button
                        onClick={onClose}
                        className="text-2xl text-slate-400 hover:text-white transition"
                    >
                        ✕
                    </button>

                </div>

                {/* Tabs */}

                <div className="flex gap-2 mt-6 overflow-x-auto">

                    <button
                        onClick={() => setActiveTab("summary")}
                        className={`px-4 py-2 rounded-lg transition ${
                            activeTab === "summary"
                                ? "bg-cyan-600 text-white"
                                : "bg-slate-800 hover:bg-slate-700"
                        }`}
                    >
                        Summary
                    </button>

                    <button
                        onClick={() => setActiveTab("ai")}
                        className={`px-4 py-2 rounded-lg transition ${
                            activeTab === "ai"
                                ? "bg-cyan-600 text-white"
                                : "bg-slate-800 hover:bg-slate-700"
                        }`}
                    >
                        AI Analysis
                    </button>

                    <button
                        onClick={() => setActiveTab("mitre")}
                        className={`px-4 py-2 rounded-lg transition ${
                            activeTab === "mitre"
                                ? "bg-cyan-600 text-white"
                                : "bg-slate-800 hover:bg-slate-700"
                        }`}
                    >
                        MITRE
                    </button>

                    <button
                        onClick={() => setActiveTab("ioc")}
                        className={`px-4 py-2 rounded-lg transition ${
                            activeTab === "ioc"
                                ? "bg-cyan-600 text-white"
                                : "bg-slate-800 hover:bg-slate-700"
                        }`}
                    >
                        IOCs
                    </button>

                    <button
                        onClick={() => setActiveTab("json")}
                        className={`px-4 py-2 rounded-lg transition ${
                            activeTab === "json"
                                ? "bg-cyan-600 text-white"
                                : "bg-slate-800 hover:bg-slate-700"
                        }`}
                    >
                        Raw JSON
                    </button>

                </div>

            </div>

            {/* Body */}

            <div className="p-6">

                {/* SUMMARY */}

                {activeTab === "summary" && (

                    <div className="space-y-6">

                        <div>

                            <p className="text-slate-500 text-sm">
                                Time
                            </p>

                            <p className="text-white">
                                {new Date(log.event.time).toLocaleString()}
                            </p>

                        </div>

                        <div>

                            <p className="text-slate-500 text-sm">
                                Host
                            </p>

                            <p className="text-white">
                                {log.event.host}
                            </p>

                        </div>

                        <div>

                            <p className="text-slate-500 text-sm">
                                Event ID
                            </p>

                            <p className="font-mono text-cyan-400">
                                {log.event.event_id}
                            </p>

                        </div>

                        <div>
                            <p className="text-slate-500 text-sm">
                                Process
                            </p>
                            <p className="text-cyan-400 break-all">
                                {log.event.process_name || "Not available in event"}
                            </p>
                        </div>

                        {/* Real PID from telemetry — a separate field from the
                            process name (never combined, never synthesized). */}
                        <div>
                            <p className="text-slate-500 text-sm">
                                PID
                            </p>
                            <p className="font-mono text-cyan-400">
                                {log.event.process_id || "Not available"}
                            </p>
                        </div>

                        {/* Parent process and parent PID stay separate fields,
                            preserved only when the event actually reports them. */}
                        <div>
                            <p className="text-slate-500 text-sm">
                                Parent Process
                            </p>
                            <p className="text-cyan-400 break-all">
                                {log.event.parent_process_name || log.event.parent_process || "Not available"}
                            </p>
                        </div>

                        <div>
                            <p className="text-slate-500 text-sm">
                                Parent PID
                            </p>
                            <p className="font-mono text-cyan-400">
                                {log.event.parent_process_id || "Not available"}
                            </p>
                        </div>

                        {/* PHASE10: Add Command Line field */}
                        <div>
                            <p className="text-slate-500 text-sm">
                                Command Line
                            </p>
                            <p className="text-cyan-400 break-all whitespace-pre-wrap">
                                {log.event.command_line || "-"}
                            </p>
                        </div>

                        <div>
                            <p className="text-slate-500 text-sm">
                                Username
                            </p>
                            <p className="text-white">
                                {log.event.user || "-"}
                            </p>
                        </div>

                        {/* REAL ALERT TRIAGE STATUS (Task 17) — persisted per
                            alert, changed by an authenticated analyst. This is
                            alert status, not investigation status. */}
                        <div>

                            <p className="text-slate-500 text-sm">
                                Alert Status
                            </p>

                            <div className="mt-2 max-w-[220px]">

                                <Dropdown
                                    value={status}
                                    onChange={changeStatus}
                                    options={ALERT_STATUSES.map((value) => ({
                                        value,
                                        label: value,
                                    }))}
                                    ariaLabel="Alert status"
                                />

                            </div>

                            {statusMeta && (
                                <p className="mt-2 text-xs text-slate-500">
                                    Changed by <span className="font-semibold text-slate-300">{statusMeta.changed_by}</span>
                                    {statusMeta.changed_at && (
                                        <> on {new Date(statusMeta.changed_at).toLocaleString()}</>
                                    )}
                                </p>
                            )}

                            {statusError && (
                                <p className="mt-2 text-xs text-red-400">
                                    {statusError}
                                </p>
                            )}

                        </div>

                        <div>

                            <p className="text-slate-500 text-sm">
                                Severity
                            </p>
                            <SeverityBadge
                                severity={log.detection.severity}
                            />
                        </div>

                        <div>

                            <p className="text-slate-500 text-sm">
                                MITRE Technique
                            </p>

                            <div className="space-y-2">

                                <p className="font-mono text-purple-400">

                                    {isUnmapped ? "Unmapped" : mitre.id}

                                </p>

                                {!isUnmapped && mitre.name && (
                                    <p className="text-cyan-400 font-semibold">

                                        {mitre.name}

                                    </p>
                                )}

                                <p className="text-slate-300">

                                    {isUnmapped ? "No applicable MITRE ATT&CK technique" : (mitre.technique || "-")}

                                </p>

                                <p className="text-slate-500 text-sm">

                                    {isUnmapped ? "Unknown" : (mitre.tactic || "-")}

                                </p>

                                {!isUnmapped && mitre.confidence != null && (
                                    <p className="text-slate-500 text-sm">
                                        Confidence: <span className="text-slate-300">{(mitre.confidence * 100).toFixed(0)}%</span>
                                    </p>
                                )}

                                {!isUnmapped && mitre.reason && (
                                    <p className="text-slate-500 text-sm">
                                        Reason: <span className="text-slate-300">{mitre.reason}</span>
                                    </p>
                                )}

                            </div>

                        </div>

                        <div>

                            <p className="text-slate-500 text-sm">
                                Detection Rule
                            </p>

                            <p className="text-white">
                                {log.detection.detection}
                            </p>

                        </div>

                        <div>

                            <p className="text-slate-500 text-sm">
                                Description
                            </p>

                            <p className="text-slate-300">
                                {log.detection.description}
                            </p>

                        </div>

                    </div>

                )}

                {/* AI */}

                {activeTab === "ai" && (

                    <div className="space-y-5">

                        {!aiReport && !loadingAI && (

                            <div className="bg-slate-800 rounded-xl p-6">

                                <h3 className="text-cyan-400 font-semibold text-lg mb-3">

                                    🛡 SOCRA AI Investigation

                                </h3>

                                <p className="text-slate-400 leading-7">

                                    Run an AI-powered investigation for this security event.
                                    SOCRA AI will analyze the event using Llama 3 and generate
                                    an executive investigation report with MITRE explanation,
                                    threat assessment, IOC analysis and recommended response.

                                </p>

                                <button

                                    onClick={runAIInvestigation}

                                    className="
                                        mt-6
                                        w-full
                                        bg-cyan-600
                                        hover:bg-cyan-500
                                        py-3
                                        rounded-lg
                                        font-semibold
                                        transition
                                    "

                                >

                                    Start AI Investigation

                                </button>

                            </div>

                        )}

                        {loadingAI && (

                            <div className="bg-slate-800 rounded-xl p-6 text-center">

                                <div className="animate-spin rounded-full h-12 w-12 border-4 border-cyan-500 border-t-transparent mx-auto mb-5"></div>

                                <p className="text-cyan-400 text-lg font-semibold">

                                    SOCRA AI is investigating...

                                </p>

                                <p className="text-slate-500 mt-2">

                                    Llama 3 is analyzing this security event.

                                </p>

                            </div>

                        )}

                        {aiError && (

                            <div className="bg-red-500/10 border border-red-500 rounded-xl p-5">

                                <h3 className="text-red-400 font-semibold mb-2">

                                    AI Investigation Failed

                                </h3>

                                <p className="text-red-300">

                                    {aiError}

                                </p>

                            </div>

                        )}

                        {aiReport && (

                            <div className="space-y-5">

                                <div className="bg-slate-800 rounded-xl p-5">

                                    <div className="flex justify-between items-center">

                                        <h3 className="text-cyan-400 font-semibold">

                                            🧠 AI Investigation Report

                                        </h3>

                                        <span className="text-green-400 text-sm">

                                            Llama 3

                                        </span>

                                    </div>

                                </div>

                                <div className="bg-slate-800 rounded-xl p-6">

                                    <pre className="whitespace-pre-wrap text-slate-300 leading-7">

                                        {typeof aiReport === "string"

                                            ? aiReport

                                            : aiReport.analysis}

                                    </pre>

                                </div>

                                <button

                                    onClick={() => {

                                        setAIReport(null);

                                        runAIInvestigation();

                                    }}

                                    className="
                                        w-full
                                        bg-slate-700
                                        hover:bg-slate-600
                                        py-3
                                        rounded-lg
                                        transition
                                    "

                                >

                                    Regenerate Investigation

                                </button>

                            </div>

                        )}

                    </div>

                )}

                {/* MITRE */}

                {activeTab === "mitre" && (

                    <div className="space-y-5">

                        <div className="bg-slate-800 rounded-xl p-5">

                            <h3 className="text-purple-400 font-semibold mb-3">

                                MITRE ATT&CK

                            </h3>

                            <p>

                                Technique

                            </p>

                            <div className="mt-4 space-y-3">

                                <div>

                                    <p className="text-slate-500 text-sm">

                                        Technique ID

                                    </p>

                                    <p className="font-mono text-cyan-400">

                                        {isUnmapped ? "Unmapped" : mitre.id}

                                    </p>

                                </div>

                                {!isUnmapped && mitre.name && (
                                    <div>

                                        <p className="text-slate-500 text-sm">

                                            Name

                                        </p>

                                        <p className="text-cyan-400">

                                            {mitre.name}

                                        </p>

                                    </div>
                                )}

                                <div>

                                    <p className="text-slate-500 text-sm">

                                        Technique

                                    </p>

                                    <p className="text-white">

                                        {isUnmapped ? "No applicable MITRE ATT&CK technique" : (mitre.technique || "-")}

                                    </p>

                                </div>

                                <div>

                                    <p className="text-slate-500 text-sm">

                                        Tactic

                                    </p>

                                    <p className="text-purple-400">

                                        {mitre.tactic || "-"}

                                    </p>

                                </div>

                            </div>

                            <p className="text-slate-400 mt-4">

                                Detailed ATT&CK mapping will be displayed here.

                            </p>

                        </div>

                    </div>

                )}

                {/* IOC */}

                    {activeTab === "ioc" && (

                    <div className="space-y-6">

                        {/* IP Addresses */}

                        <div className="bg-slate-800 rounded-xl p-5">

                            <h3 className="text-lg font-semibold text-white mb-4">

                                🌐 IP Addresses

                            </h3>

                            {ioc.ips?.length ? (

                                ioc.ips.map((ip, index) => (

                                    <div
                                        key={index}
                                        className="font-mono text-cyan-400 py-2"
                                    >
                                        {ip}
                                    </div>

                                ))

                            ) : (

                                <p className="text-slate-500">

                                    No IP addresses found.

                                </p>

                            )}

                        </div>

                        {/* File Hashes */}

                        <div className="bg-slate-800 rounded-xl p-5">

                            <h3 className="text-lg font-semibold text-white mb-4">

                                🔑 File Hashes

                            </h3>

                            {ioc.hashes?.length ? (

                                ioc.hashes.map((hash, index) => (

                                    <div
                                        key={index}
                                        className="font-mono break-all text-green-400 py-2"
                                    >
                                        {hash}
                                    </div>

                                ))

                            ) : (

                                <p className="text-slate-500">

                                    No file hashes found.

                                </p>

                            )}

                        </div>

                    </div>

                    )}

                {/* RAW JSON */}

                {activeTab === "json" && (

                    <div className="bg-slate-800 rounded-xl p-5">

                        <pre className="text-sm text-slate-300 whitespace-pre-wrap">

                            {JSON.stringify(log, null, 2)}

                        </pre>

                    </div>

                )}

            </div>

        </div>

    );

}

export default EventDetailsDrawer;