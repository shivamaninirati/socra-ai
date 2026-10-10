import { useState, useRef, useEffect } from "react";
import { Clock, Calendar } from "lucide-react";

const TIME_PRESETS = [
  { label: "Last 15 minutes", value: "last_15m" },
  { label: "Last 30 minutes", value: "last_30m" },
  { label: "Last 1 hour", value: "last_1h" },
  { label: "Last 4 hours", value: "last_4h" },
  { label: "Last 12 hours", value: "last_12h" },
  { label: "Last 24 hours", value: "last_24h" },
  { label: "Last 7 days", value: "last_7d" },
  { label: "Last 30 days", value: "last_30d" },
  { label: "Custom range", value: "custom" },
];

function TimeRangePicker({ value, onChange }) {
  const [open, setOpen] = useState(false);
  const [customFrom, setCustomFrom] = useState("");
  const [customTo, setCustomTo] = useState("");
  const ref = useRef(null);

  const preset = TIME_PRESETS.find((p) => p.value === value);

  const handleSelect = (presetValue) => {
    if (presetValue === "custom") {
      setOpen(true);
    } else {
      onChange(presetValue);
      setOpen(false);
    }
  };

  const handleCustomApply = () => {
    if (customFrom && customTo) {
      onChange({ from: customFrom, to: customTo });
      setOpen(false);
    }
  };

  useEffect(() => {
    if (!open) return;
    const handler = (e) => {
      if (ref.current && !ref.current.contains(e.target)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 px-3 h-9 rounded-lg border border-slate-700/80 bg-slate-800/60 text-xs font-semibold text-slate-300 hover:border-slate-600 hover:bg-slate-800/80 transition-all focus:outline-none focus:ring-2 focus:ring-cyan-500/30"
      >
        <Clock size={13} className="text-cyan-400" />
        <span className="truncate max-w-[140px]">{preset?.label || "Time Range"}</span>
        <ChevronDown size={14} className={`text-slate-500 transition-transform ${open ? "rotate-180" : ""}`} />
      </button>

      {open && (
        <div className="absolute left-0 top-full mt-1.5 w-56 rounded-lg border border-slate-700 bg-slate-800 shadow-2xl shadow-black/50 overflow-hidden z-50">
          <div className="px-3 py-1.5 border-b border-slate-700 text-[10px] uppercase tracking-widest text-slate-500">
            Time Range
          </div>
          <div className="py-1 max-h-64 overflow-y-auto">
            {TIME_PRESETS.map((p) => (
              <button
                key={p.value}
                type="button"
                onClick={() => handleSelect(p.value)}
                className={`w-full px-3 py-2 text-left text-xs font-medium transition-colors ${
                  value === p.value
                    ? "bg-cyan-500/10 text-cyan-400"
                    : "text-slate-300 hover:bg-slate-700/60"
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>

          {value === "custom" && (
            <div className="px-3 py-3 border-t border-slate-700 space-y-2">
              <div className="flex items-center gap-2">
                <input
                  type="datetime-local"
                  value={customFrom}
                  onChange={(e) => setCustomFrom(e.target.value)}
                  className="flex-1 bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs text-slate-200 outline-none focus:border-cyan-500/60"
                  placeholder="From"
                />
                <span className="text-slate-500 text-xs">to</span>
                <input
                  type="datetime-local"
                  value={customTo}
                  onChange={(e) => setCustomTo(e.target.value)}
                  className="flex-1 bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs text-slate-200 outline-none focus:border-cyan-500/60"
                  placeholder="To"
                />
              </div>
              <button
                type="button"
                onClick={handleCustomApply}
                disabled={!customFrom || !customTo}
                className="w-full py-1.5 rounded-md bg-cyan-600 hover:bg-cyan-500 disabled:bg-cyan-600/50 text-white text-xs font-bold transition"
              >
                Apply Custom Range
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default TimeRangePicker;
