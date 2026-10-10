import { Wifi, WifiOff, RefreshCw, Loader } from "lucide-react";
import { useLiveSOC } from "../../context/LiveSOCContext";

function LiveStatusBadge() {
  const { connectionState } = useLiveSOC();

  const config = (() => {
    switch (connectionState) {
      case "connected":
        return {
          icon: <Wifi size={14} />,
          label: "Live Connected",
          classes:
            "border-emerald-900/60 bg-emerald-950/30 text-emerald-400",
          dot: "bg-emerald-400",
        };

      case "connecting":
        return {
          icon: <Loader size={14} className="animate-spin" />,
          label: "Connecting...",
          classes: "border-slate-700 bg-slate-900/70 text-slate-300",
          dot: "bg-slate-400",
        };

      case "reconnecting":
        return {
          icon: <RefreshCw size={14} className="animate-spin" />,
          label: "Reconnecting...",
          classes:
            "border-amber-900/50 bg-amber-950/20 text-amber-400",
          dot: "bg-amber-400",
        };

      case "disconnected":
      default:
        return {
          icon: <WifiOff size={14} />,
          label: "Offline",
          classes: "border-red-900/50 bg-red-950/20 text-red-400",
          dot: "bg-red-400",
        };
    }
  })();

  return (
    <div
      role="status"
      aria-live="polite"
      aria-label={`Connection status: ${config.label}`}
      className={`inline-flex items-center gap-2 rounded-lg border px-3 py-2 transition-colors duration-200 ${config.classes}`}
    >
      <span className="flex shrink-0 items-center justify-center">
        {config.icon}
      </span>

      <span className="whitespace-nowrap text-xs font-semibold uppercase tracking-wider">
        {config.label}
      </span>

      <span className="relative ml-0.5 flex h-2 w-2 shrink-0">
        {connectionState === "connected" && (
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400/30" />
        )}

        <span
          className={`relative inline-flex h-2 w-2 rounded-full ${config.dot}`}
        />
      </span>
    </div>
  );
}

export default LiveStatusBadge;