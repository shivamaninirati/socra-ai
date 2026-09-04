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
                    classes: "bg-green-500/10 border-green-500/20 text-green-400"
                };
            case "connecting":
                return {
                    icon: <Loader size={14} className="animate-spin" />,
                    label: "Connecting...",
                    classes: "bg-blue-500/10 border-blue-500/20 text-blue-400"
                };
            case "reconnecting":
                return {
                    icon: <RefreshCw size={14} className="animate-spin" />,
                    label: "Reconnecting...",
                    classes: "bg-yellow-500/10 border-yellow-500/20 text-yellow-400"
                };
            case "disconnected":
            default:
                return {
                    icon: <WifiOff size={14} />,
                    label: "Offline",
                    classes: "bg-red-500/10 border-red-500/20 text-red-400"
                };
        }
    })();

    return (
        <div
            className={`
                flex items-center gap-2
                px-3 py-2 rounded-lg
                border
                ${config.classes}
            `}
        >
            {config.icon}
            <span className="text-xs font-bold uppercase tracking-wider">
                {config.label}
            </span>
        </div>
    );
}

export default LiveStatusBadge;