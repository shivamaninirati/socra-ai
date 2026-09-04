import { useEffect, useState, useCallback } from "react";
import { ShieldAlert, X } from "lucide-react";
import { useLiveSOC } from "../../context/LiveSOCContext";

const MAX_VISIBLE_TOASTS = 3;
const TOAST_DURATION_MS = 6000;
const STACK_WINDOW_MS = 1500;

function LiveAlertToast() {
  const { latestEvent } = useLiveSOC();

  // Toast stack: each entry is { event, id, timestamp }
  const [toasts, setToasts] = useState([]);
  const pendingCountRef = { current: 0 };

  // Process incoming alert events into compact toasts
  useEffect(() => {
    if (!latestEvent) return;

    const severity = (latestEvent.detection?.severity || "").toLowerCase();
    if (severity !== "high" && severity !== "critical") return;

    const toastId = Date.now() + Math.random();
    const newEntry = { event: latestEvent, id: toastId, timestamp: Date.now() };

    setToasts((prev) => {
      // Group rapid alerts: if the last toast is within STACK_WINDOW_MS,
      // increment a pending counter instead of spawning a new toast.
      const updated = [...prev];
      if (
        updated.length > 0 &&
        Date.now() - updated[updated.length - 1].timestamp < STACK_WINDOW_MS
      ) {
        // Increment the pending count on the last toast
        const last = { ...updated[updated.length - 1] };
        last.pendingCount = (last.pendingCount || 0) + 1;
        updated[updated.length - 1] = last;
        return updated.slice(-MAX_VISIBLE_TOASTS);
      }
      updated.push(newEntry);
      return updated.slice(-MAX_VISIBLE_TOASTS);
    });

    // Auto-dismiss after TOAST_DURATION_MS
    const timer = setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== toastId));
    }, TOAST_DURATION_MS);

    return () => clearTimeout(timer);
  }, [latestEvent]);

  const dismissToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-6 right-6 z-[9999] flex flex-col-reverse gap-2 max-w-[340px]">
      {toasts.map((toast) => (
        <CompactToast
          key={toast.id}
          event={toast.event}
          pendingCount={toast.pendingCount || 0}
          onDismiss={() => dismissToast(toast.id)}
        />
      ))}
    </div>
  );
}

function CompactToast({ event, pendingCount, onDismiss }) {
  const host = event?.event?.host || event?.event?.computer || "Unknown";
  const process = event?.event?.process_name || "";
  const severity = event?.detection?.severity || "Unknown";
  const eventId = event?.event?.event_id || "";
  const mitre = event?.detection?.mitre;
  const mitreLabel =
    typeof mitre === "object"
      ? mitre?.id || mitre?.technique || ""
      : mitre || "";
  const time = event?.event?.time
    ? new Date(event.event.time).toLocaleTimeString("en-GB", {
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      })
    : "";

  const severityLower = severity.toLowerCase();
  const severityColor =
    severityLower === "critical"
      ? "text-red-400"
      : severityLower === "high"
      ? "text-orange-400"
      : "text-yellow-400";

  const sevDot =
    severityLower === "critical"
      ? "bg-red-500"
      : severityLower === "high"
      ? "bg-orange-500"
      : "bg-yellow-500";

  return (
    <div className="w-[320px] rounded-lg border border-slate-700 bg-slate-900 shadow-2xl overflow-hidden animate-in slide-in-from-right">
      {/* Header bar */}
      <div className="flex items-center justify-between px-3 py-1.5 bg-red-500/10 border-b border-red-500/20">
        <div className="flex items-center gap-1.5">
          <div className={"w-1.5 h-1.5 rounded-full " + sevDot} />
          <ShieldAlert size={13} className="text-red-400" />
          <span className="text-[11px] font-bold text-red-400 uppercase tracking-wide">
            {pendingCount > 0
              ? `${pendingCount + 1} new alerts`
              : "New Security Alert"}
          </span>
        </div>
        <button onClick={onDismiss} className="p-0.5 text-slate-400 hover:text-white">
          <X size={13} />
        </button>
      </div>

      {/* Content */}
      <div className="px-3 py-2 space-y-1">
        <p className="text-xs text-white font-medium truncate">
          {host}
          {process ? (
            <span className="text-slate-400"> · {process}</span>
          ) : null}
        </p>
        <div className="flex items-center gap-2 text-[10px] text-slate-400">
          <span className={severityColor + " font-semibold"}>{severity}</span>
          {eventId && (
            <>
              <span className="text-slate-600">·</span>
              <span>EID {eventId}</span>
            </>
          )}
          {mitreLabel && (
            <>
              <span className="text-slate-600">·</span>
              <span className="text-purple-400">{mitreLabel}</span>
            </>
          )}
          {time && (
            <>
              <span className="text-slate-600">·</span>
              <span>{time}</span>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default LiveAlertToast;
