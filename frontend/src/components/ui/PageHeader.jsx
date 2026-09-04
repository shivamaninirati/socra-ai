import { Activity } from "lucide-react";

function PageHeader({

    title,

    subtitle,

    actions

}) {

    return (

        <div className="mb-2">

            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">

                {/* Left */}

                <div>

                    <div className="flex items-center gap-3">

                        <h1 className="text-3xl font-bold tracking-tight text-white">

                            {title}

                        </h1>

                        <div className="flex items-center gap-1 px-2 py-1 rounded-md bg-emerald-500/10 border border-emerald-500/20">

                            <Activity
                                size={12}
                                className="text-emerald-400 animate-pulse"
                            />

                            <span className="text-[11px] font-semibold text-emerald-400">

                                LIVE

                            </span>

                        </div>

                    </div>

                    {

                        subtitle && (

                            <p className="text-sm text-slate-400 mt-2 max-w-3xl">

                                {subtitle}

                            </p>

                        )

                    }

                </div>

                {/* Right */}

                {

                    actions && (

                        <div className="flex flex-wrap items-center gap-3">

                            {actions}

                        </div>

                    )

                }

            </div>

            

        </div>

    );

}

export default PageHeader;