function HuntCard({ huntKey, hunt, onRun }) {
    const mitreLabel =
        typeof hunt.mitre === "object"
            ? hunt.mitre?.id || hunt.mitre?.technique || "-"
            : hunt.mitre || "-";

    return (
        <div className="rounded-xl border border-slate-800/80 bg-slate-950/60 p-6 transition-all duration-200 hover:border-slate-700 hover:bg-slate-900/80">
            <h2 className="text-xl font-semibold text-slate-100">
                {hunt.name}
            </h2>

            <div className="mt-4 space-y-3">
                <p className="text-sm text-slate-400">
                    <span className="font-semibold text-slate-300">
                        MITRE:
                    </span>{" "}
                    {mitreLabel}
                </p>

                <p className="text-sm text-slate-400">
                    <span className="font-semibold text-orange-400">
                        Severity:
                    </span>{" "}
                    {hunt.severity}
                </p>
            </div>

            <button
                type="button"
                onClick={() => onRun(huntKey)}
                className="mt-6 w-full rounded-lg border border-slate-700/80 bg-slate-800/80 py-3 text-xs font-bold text-slate-100 transition-all duration-200 hover:border-slate-600 hover:bg-slate-700 focus:outline-none focus:ring-2 focus:ring-slate-500/40"
            >
                Run Hunt
            </button>
        </div>
    );
}

export default HuntCard;