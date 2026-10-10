function Card({
  title,
  children,
  className = "",
  noPadding = false,
}) {
  return (
    <div
      className={`
        rounded-xl
        border border-slate-800/80
        bg-slate-950/60
        p-6
        transition-all duration-200 ease-out
        hover:border-slate-700/80
        hover:bg-slate-950/80
        ${className}
      `}
    >
      {title && (
        <h2 className="mb-4 flex items-center gap-2 text-lg font-semibold text-slate-100">
          {title}
        </h2>
      )}

      <div className={noPadding ? "" : "space-y-4"}>
        {children}
      </div>
    </div>
  );
}

export default Card;