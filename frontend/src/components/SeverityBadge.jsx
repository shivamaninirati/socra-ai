import {
    AlertTriangle,
    ShieldAlert,
    ShieldCheck,
    Info,
} from "lucide-react";

function SeverityBadge({ severity = "Unknown" }) {

    let config = {
        bg: "bg-slate-500/15",
        border: "border-slate-500/30",
        text: "text-slate-300",
        icon: <Info size={14} />,
        label: "Unknown",
    };

    switch (severity) {

        case "Critical":
            config = {
                bg: "bg-red-500/15",
                border: "border-red-500/30",
                text: "text-red-400",
                icon: <ShieldAlert size={14} />,
                label: "Critical",
            };
            break;

        case "High":
            config = {
                bg: "bg-orange-500/15",
                border: "border-orange-500/30",
                text: "text-orange-400",
                icon: <AlertTriangle size={14} />,
                label: "High",
            };
            break;

        case "Medium":
            config = {
                bg: "bg-yellow-500/15",
                border: "border-yellow-500/30",
                text: "text-yellow-400",
                icon: <AlertTriangle size={14} />,
                label: "Medium",
            };
            break;

        case "Low":
            config = {
                bg: "bg-green-500/15",
                border: "border-green-500/30",
                text: "text-green-400",
                icon: <ShieldCheck size={14} />,
                label: "Low",
            };
            break;

        case "Informational":
            config = {
                bg: "bg-cyan-500/15",
                border: "border-cyan-500/30",
                text: "text-cyan-400",
                icon: <Info size={14} />,
                label: "Info",
            };
            break;

        default:
            break;
    }

    return (

        <span
            className={`
                inline-flex
                items-center
                gap-2
                px-3
                py-1.5
                rounded-full
                border
                text-xs
                font-semibold
                whitespace-nowrap
                ${config.bg}
                ${config.border}
                ${config.text}
            `}
        >

            {config.icon}

            {config.label}

        </span>

    );

}

export default SeverityBadge;