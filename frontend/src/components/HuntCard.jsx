function HuntCard({ huntKey, hunt, onRun }) {

    const mitreLabel = typeof hunt.mitre === "object"
        ? hunt.mitre?.id || hunt.mitre?.technique || "-"
        : hunt.mitre || "-";

    return (

        <div className="bg-slate-800/40 border border-slate-700/60 rounded-xl p-6 hover:border-cyan-500/40 transition-all duration-200">

            <h2 className="text-xl font-semibold text-white">

                {hunt.name}

            </h2>

            <div className="mt-4 space-y-2">

                <p className="text-slate-400">

                    <span className="font-semibold text-cyan-400">

                        MITRE:

                    </span>

                    {" "}

                    {mitreLabel}

                </p>

                <p className="text-slate-400">

                    <span className="font-semibold text-orange-400">

                        Severity:

                    </span>

                    {" "}

                    {hunt.severity}

                </p>

            </div>

            <button

                onClick={() => onRun(huntKey)}

                className="
                    mt-6
                    w-full
                    bg-cyan-600
                    hover:bg-cyan-500
                    text-white
                    text-xs
                    font-bold
                    rounded-lg
                    py-3
                    transition-all
                    duration-150
                "

            >

                Run Hunt

            </button>

        </div>

    );

}

export default HuntCard;
