function DashboardSkeleton() {
  return (
    <div className="space-y-6 p-6 animate-pulse">
      {/* Header skeleton */}
      <div className="flex justify-between items-start">
        <div>
          <div className="h-8 w-64 bg-slate-800/50 rounded-lg"></div>
          <div className="h-4 w-96 bg-slate-800/30 rounded mt-3"></div>
        </div>
        <div className="h-10 w-40 bg-slate-800/50 rounded-lg"></div>
      </div>

      {/* Stat cards skeleton */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {[1, 2, 3, 4].map((i) => (
          <div
            key={i}
            className="h-32 rounded-xl bg-slate-800/30 border border-slate-800/50"
          />
        ))}
      </div>

      {/* Charts skeleton */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="xl:col-span-2 h-80 rounded-xl bg-slate-800/30 border border-slate-800/50"></div>
        <div className="h-80 rounded-xl bg-slate-800/30 border border-slate-800/50"></div>
      </div>

      {/* Bottom section skeleton */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="h-64 rounded-xl bg-slate-800/30 border border-slate-800/50"></div>
        <div className="h-64 rounded-xl bg-slate-800/30 border border-slate-800/50"></div>
      </div>
    </div>
  );
}

export default DashboardSkeleton;
