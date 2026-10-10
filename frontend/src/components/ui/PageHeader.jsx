import { Activity } from "lucide-react";

function PageHeader({ title, subtitle, actions }) {
  return (
    <div className="mb-2">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        {/* Left */}
        <div>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-3xl font-bold tracking-tight text-slate-100">
              {title}
            </h1>

            <div className="flex items-center gap-1.5 rounded-md border border-emerald-500/15 bg-emerald-500/[0.06] px-2 py-1">
              <Activity
                size={12}
                className="animate-pulse text-emerald-400"
              />

              <span className="text-[11px] font-semibold tracking-wide text-emerald-400">
                LIVE
              </span>
            </div>
          </div>

          {subtitle && (
            <p className="mt-2 max-w-3xl text-sm leading-relaxed text-slate-400">
              {subtitle}
            </p>
          )}
        </div>

        {/* Right */}
        {actions && (
          <div className="flex flex-wrap items-center gap-3">
            {actions}
          </div>
        )}
      </div>
    </div>
  );
}

export default PageHeader;