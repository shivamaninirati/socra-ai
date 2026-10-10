import { useState, useEffect, useCallback } from "react";
import { Save, Trash2, Star, Clock } from "lucide-react";
import api from "../services/api";

function SavedSearches({ onSelect, onDelete }) {
  const [searches, setSearches] = useState([]);
  const [showAll, setShowAll] = useState(false);

  const loadSearches = useCallback(async () => {
    try {
      const res = await api.get("/search/saved");
      setSearches(res.data?.searches || []);
    } catch {
      setSearches([]);
    }
  }, []);

  useEffect(() => { loadSearches(); }, [loadSearches]);

  const handleSave = async (query, name) => {
    try {
      await api.post("/search/saved", { query, name });
      loadSearches();
    } catch {
      // non-critical
    }
  };

  const handleDelete = async (id) => {
    try {
      await api.delete(`/search/saved/${id}`);
      loadSearches();
      onDelete?.(id);
    } catch {
      // non-critical
    }
  };

  const displaySearches = showAll ? searches : searches.slice(0, 3);

  if (searches.length === 0) return null;

  return (
    <div className="border-t border-slate-800">
      <div className="px-3.5 py-1.5 flex items-center justify-between text-[9px] uppercase tracking-widest text-slate-500 bg-slate-900/60">
        <span>Saved Searches</span>
        <button
          type="button"
          onClick={() => setShowAll(!showAll)}
          className="text-cyan-400 hover:text-cyan-300 transition"
        >
          {showAll ? "Show less" : `View all (${searches.length})`}
        </button>
      </div>
      <div className="py-1">
        {displaySearches.map((s) => (
          <button
            key={s.id}
            type="button"
            onMouseDown={() => onSelect?.(s.query, s.name)}
            className="w-full px-3.5 py-2 text-left text-xs transition-all flex items-center gap-2.5 text-slate-300 hover:bg-slate-800/60 border-l-2 border-transparent hover:border-cyan-500"
          >
            <Star size={12} className="shrink-0 text-amber-400" />
            <span className="flex-1 min-w-0 font-semibold truncate">{s.name}</span>
            <span className="text-[10px] text-slate-500 truncate hidden sm:block">
              {s.query}
            </span>
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); handleDelete(s.id); }}
              className="shrink-0 text-slate-600 hover:text-red-400 transition p-0.5"
            >
              <Trash2 size={10} />
            </button>
          </button>
        ))}
      </div>
    </div>
  );
}

export default SavedSearches;
