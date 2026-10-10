import { ShieldAlert, Inbox } from "lucide-react";

function EmptyState({
  title = "No data",
  description = "Nothing to display yet.",
  icon = Inbox,
  action = null,
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-4 text-center">
      <div className="w-16 h-16 rounded-full bg-slate-800/50 border border-slate-700/50 flex items-center justify-center mb-4">
        <icon size={28} className="text-slate-500" />
      </div>
      <h3 className="text-sm font-semibold text-slate-300 mb-1">{title}</h3>
      <p className="text-xs text-slate-500 max-w-xs leading-relaxed">{description}</p>
      {action && (
        <div className="mt-4">
          {action}
        </div>
      )}
    </div>
  );
}

export default EmptyState;
