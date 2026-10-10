function Button({
  children,
  onClick,
  color = "cyan",
  disabled = false,
  className = "",
  loading = false,
  type = "button",
}) {
  const colors = {
    cyan: "bg-cyan-600 hover:bg-cyan-500 active:bg-cyan-700",
    green: "bg-green-600 hover:bg-green-500 active:bg-green-700",
    red: "bg-red-600 hover:bg-red-500 active:bg-red-700",
    orange: "bg-orange-600 hover:bg-orange-500 active:bg-orange-700",
    slate: "bg-slate-700 hover:bg-slate-600 active:bg-slate-800",
  };

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled || loading}
      className={`
        inline-flex items-center justify-center
        rounded-lg
        px-5 py-3
        text-sm font-medium
        transition-all duration-200 ease-in-out
        focus:outline-none
        focus:ring-2
        focus:ring-slate-500/30
        focus:ring-offset-2
        focus:ring-offset-slate-950
        disabled:cursor-not-allowed
        disabled:opacity-50
        disabled:hover:scale-100
        hover:shadow-lg
        hover:shadow-black/20
        active:scale-[0.98]
        ${colors[color] || colors.cyan}
        ${className}
      `}
    >
      {loading ? (
        <span className="flex items-center justify-center gap-2">
          <svg
            className="h-4 w-4 animate-spin"
            viewBox="0 0 24 24"
            fill="none"
            aria-hidden="true"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            />
          </svg>
          Processing...
        </span>
      ) : (
        children
      )}
    </button>
  );
}

export default Button;