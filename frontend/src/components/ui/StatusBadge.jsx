function StatusBadge({ color = "cyan", text }) {

  const colors = {
    green: "bg-green-500/10 text-green-400",
    red: "bg-red-500/10 text-red-400",
    orange: "bg-orange-500/10 text-orange-400",
    yellow: "bg-yellow-500/10 text-yellow-400",
    blue: "bg-blue-500/10 text-blue-400",
    purple: "bg-purple-500/10 text-purple-400",
    cyan: "bg-cyan-500/10 text-cyan-400",
    gray: "bg-slate-700 text-slate-300",
  };

  return (
    <span
      className={`
        inline-flex
        items-center
        px-3
        py-1
        rounded-full
        text-xs
        font-semibold
        ${colors[color]}
      `}
    >
      {text}
    </span>
  );
}

export default StatusBadge;