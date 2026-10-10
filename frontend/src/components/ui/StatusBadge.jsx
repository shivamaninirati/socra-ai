function StatusBadge({ color = "cyan", text, className = "" }) {
  const colors = {
    green: "bg-emerald-500/10 text-emerald-400 border border-emerald-500/15",
    red: "bg-red-500/10 text-red-400 border border-red-500/15",
    orange: "bg-orange-500/10 text-orange-400 border border-orange-500/15",
    yellow: "bg-amber-500/10 text-amber-400 border border-amber-500/15",
    blue: "bg-blue-500/10 text-blue-400 border border-blue-500/15",
    purple: "bg-purple-500/10 text-purple-400 border border-purple-500/15",
    cyan: "bg-slate-500/10 text-slate-300 border border-slate-700/70",
    gray: "bg-slate-800/60 text-slate-400 border border-slate-700/60",
  };

  return (
    <span
      className={`
        inline-flex
        items-center
        gap-1.5
        px-2.5
        py-1
        rounded-md
        text-[10px]
        font-semibold
        uppercase
        tracking-wider
        whitespace-nowrap
        transition-colors
        duration-150
        ${colors[color] || colors.cyan}
        ${className}
      `}
    >
      {text}
    </span>
  );
}

export default StatusBadge;