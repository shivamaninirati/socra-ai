import { useCallback, useEffect, useState } from "react";
import {
  Sliders,
  Cpu,
  CheckCircle,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Server,
  Activity,
  Wifi,
  Bot,
  Database,
  Loader2,
} from "lucide-react";
import PageHeader from "../components/ui/PageHeader";
import api from "../services/api";
import { useSettings } from "../context/SettingsContext";

const okTone = {
  icon: <CheckCircle size={12} className="text-green-500 shrink-0" />,
  text: "text-green-400",
};
const warnTone = {
  icon: <AlertTriangle size={12} className="text-amber-500 shrink-0" />,
  text: "text-amber-400",
};
const errTone = {
  icon: <XCircle size={12} className="text-red-500 shrink-0" />,
  text: "text-red-400",
};

function ToggleSwitch({ checked, onChange, label }) {
  return (
    <label className="relative inline-flex items-center cursor-pointer" aria-label={label}>
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="sr-only peer"
      />
      <div className="w-10 h-5 bg-slate-950/80 border border-slate-800 rounded-full peer peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[4px] after:left-[4px] after:bg-cyan-500 after:rounded-full after:h-3 after:w-4 after:transition-all peer-checked:border-cyan-500/30"></div>
    </label>
  );
}

function StatusCard({ icon: Icon, label, value, detail, tone }) {
  return (
    <div className="bg-slate-950/30 border border-slate-800/60 rounded-xl p-4 flex flex-col justify-between">
      <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
        <Icon size={11} className="text-cyan-400/80" />
        {label}
      </span>
      <span className={`text-sm font-extrabold font-mono mt-2 flex items-center gap-1.5 ${tone.text}`}>
        {tone.icon}
        {value}
      </span>
      {detail && (
        <span className="text-[10px] text-slate-500 font-medium mt-1.5 leading-4">
          {detail}
        </span>
      )}
    </div>
  );
}

function Settings() {
  const { settings, updateSetting, saveError, clearSaveError } = useSettings();
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadStatus = useCallback(async () => {
    try {
      const response = await api.get("/settings/status");
      setStatus(response.data || {});
      setError("");
    } catch (err) {
      console.error("Settings status error:", err);
      setError(
        "Could not reach the backend. Check that the SOCRA AI API is running."
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const timer = setTimeout(loadStatus, 0);
    return () => clearTimeout(timer);
  }, [loadStatus]);

  const apiTone = status?.api?.status === "ok" ? okTone : errTone;
  const collectorTone = status?.collector?.running ? okTone : warnTone;
  const wsTone = status?.websocket?.status === "Live" ? okTone : warnTone;
  const aiTone = status?.ai?.available ? okTone : errTone;
  const dbTone = status?.database?.status === "ok" ? okTone : errTone;

  const collectorDetail =
    status?.collector?.message ||
    (status?.collector?.running
      ? "Collector is actively ingesting telemetry."
      : "No collector is reporting events right now.");

  const dbDetail = status?.database
    ? `${(status.database.events ?? 0).toLocaleString()} events · ${
        status.database.size_bytes
          ? (status.database.size_bytes / (1024 * 1024)).toFixed(1) + " MB"
          : "size unknown"
      }`
    : "";

  const aiDetail = status?.ai?.available
    ? `Ollama reachable${status.ai.host ? ` · ${status.ai.host}` : ""}${
        status.ai.latency_ms != null ? ` · ${status.ai.latency_ms}ms` : ""
      }`
    : status?.ai?.detail || "Ollama is not reachable.";

  const modelDetail = status?.ai?.available
    ? status.ai.model_installed
      ? "Model installed and ready."
      : `Model "${status.ai.model}" is not installed. Run: ollama pull ${status.ai.model}`
    : "No model available while Ollama is unreachable.";

  return (
    <div className="w-full pb-8 space-y-6 select-none">
      {/* 1. HIGH-DENSITY PAGE HEADER */}
      <div className="flex justify-between items-center border-none m-0 pt-6">
        <PageHeader
          title="Settings"
          subtitle="Configure SOCRA AI preferences and application settings."
        />
        <button
          onClick={() => { setLoading(true); loadStatus(); }}
          className="inline-flex items-center gap-2 rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs font-semibold text-slate-300 transition hover:border-slate-700 hover:text-white"
        >
          <RefreshCw size={13} className={loading ? "animate-spin" : ""} />
          Refresh Status
        </button>
      </div>

      {/* 2. MAIN CONFIGURATION OVERLAY CANVAS */}
      <div className="w-full bg-slate-900/20 border border-slate-800/80 rounded-xl p-6 shadow-sm backdrop-blur-sm mt-6 space-y-8">

        {/* --- GENERAL SETTINGS SECTION --- */}
        <div>
          <div className="flex items-center gap-2 mb-5 border-b border-slate-900/50 pb-2">
            <Sliders size={16} className="text-cyan-400" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-white">
              General Preferences
            </h2>
          </div>

          {saveError && (
            <div className="flex items-center justify-between rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-2.5 mb-4">
              <p className="text-sm text-red-300">{saveError}</p>
              <button
                onClick={clearSaveError}
                className="text-xs font-bold text-red-300 hover:text-white transition"
              >
                Dismiss
              </button>
            </div>
          )}

          <div className="space-y-4">
            {/* Setting Row: Dark Theme */}
            <div className="flex items-center justify-between py-2">
              <div>
                <p className="text-sm font-bold text-slate-200">Dark UI Theme Canvas</p>
                <p className="text-xs text-slate-500 font-medium mt-0.5">
                  SOCRA AI runs on a low-opacity dark palette by default. Switch OFF for a light theme.
                </p>
              </div>
              <ToggleSwitch
                label="Dark UI Theme Canvas"
                checked={settings.darkTheme}
                onChange={(value) => updateSetting("darkTheme", value)}
              />
            </div>

            <div className="border-t border-slate-900/30"></div>

            {/* Setting Row: Notifications */}
            <div className="flex items-center justify-between py-2">
              <div>
                <p className="text-sm font-bold text-slate-200">Real-time System Notifications</p>
                <p className="text-xs text-slate-500 font-medium mt-0.5">
                  Receive system level alerts instantly when new anomalies break threshold.
                </p>
              </div>
              <ToggleSwitch
                label="Real-time System Notifications"
                checked={settings.notifications}
                onChange={(value) => updateSetting("notifications", value)}
              />
            </div>

            <div className="border-t border-slate-900/30"></div>

            {/* Setting Row: Auto Refresh */}
            <div className="flex items-center justify-between py-2">
              <div>
                <p className="text-sm font-bold text-slate-200">Auto Refresh Alerts</p>
                <p className="text-xs text-slate-500 font-medium mt-0.5">
                  Automatically receive new telemetry on the Alerts page over the WebSocket.
                </p>
              </div>
              <ToggleSwitch
                label="Auto Refresh Alerts"
                checked={settings.autoRefresh}
                onChange={(value) => updateSetting("autoRefresh", value)}
              />
            </div>
          </div>
        </div>

        {/* --- SYSTEM STATUS SECTION (REAL BACKEND STATE) --- */}
        <div>
          <div className="flex items-center gap-2 mb-5 border-b border-slate-900/50 pb-2">
            <Cpu size={16} className="text-cyan-400" />
            <h2 className="text-xs font-bold uppercase tracking-wider text-white">
              System Status
            </h2>
          </div>

          {error && (
            <div className="rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-300 mb-4">
              {error}
            </div>
          )}

          {loading && !status ? (
            <div className="flex items-center justify-center py-16">
              <div className="flex flex-col items-center gap-3">
                <Loader2 size={28} className="text-cyan-400 animate-spin" />
                <p className="text-xs text-slate-500">Loading backend status...</p>
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <StatusCard
                icon={Server}
                label="API Service"
                value={status?.api?.status === "ok" ? "Operational" : "Unavailable"}
                detail={status?.api?.detail || "API is not responding."}
                tone={apiTone}
              />
              <StatusCard
                icon={Activity}
                label="Telemetry Collector"
                value={status?.collector?.running ? "Running" : "Not running"}
                detail={collectorDetail}
                tone={collectorTone}
              />
              <StatusCard
                icon={Wifi}
                label="Live WebSocket"
                value={`${status?.websocket?.status || "Unknown"} · ${status?.websocket?.connected_clients ?? 0} client${(status?.websocket?.connected_clients ?? 0) === 1 ? "" : "s"}`}
                detail={status?.websocket?.detail || "No live connection information."}
                tone={wsTone}
              />
              <StatusCard
                icon={Bot}
                label="AI Engine (Ollama)"
                value={status?.ai?.available ? "Available" : "Unavailable"}
                detail={aiDetail}
                tone={aiTone}
              />
              <StatusCard
                icon={Cpu}
                label="Available AI Model"
                value={status?.ai?.model || "None"}
                detail={modelDetail}
                tone={status?.ai?.available ? okTone : errTone}
              />
              <StatusCard
                icon={Database}
                label="Database (SQLite)"
                value={status?.database?.status === "ok" ? "Operational" : "Error"}
                detail={dbDetail}
                tone={dbTone}
              />
            </div>
          )}

          {!loading && status && (
            <p className="text-[10px] uppercase tracking-wider text-slate-600 font-bold mt-4">
              SOCRA AI v{status.version || "0.1.0"} · Status reflects live backend state
            </p>
          )}
        </div>

      </div>
    </div>
  );
}

export default Settings;
