import { useState, useEffect, useMemo, useRef, useCallback } from "react";
import {
  Search,
  Terminal,
  X,
  Clock3,
  History,
  Sparkles,
  Monitor,
  User,
  Cpu,
  Shield,
  Globe,
  Loader2,
  HelpCircle,
} from "lucide-react";
import api from "../services/api";
import { isCleanSuggestion } from "./SearchSuggestionGuard";

// ===================================================================
// ENTERPRISE SEARCH QUERY PARSER (client-side token coloring/display)
// ===================================================================
const parseEnterpriseQuery = (input) => {
  const tokens = {};
  const keywords = [];
  const textChunks = [];

  if (!input || typeof input !== "string") {
    return { tokens, keywords, textChunks, raw: "", hasBoolean: false };
  }

  const fieldRegex = /(\w+):(?:"([^"]*)"|\[([^\]]*)\]|(\S+))/g;
  let match;
  let cleaned = input;

  const severityMap = {
    critical: "Critical", high: "High", medium: "Medium",
    low: "Low", informational: "Informational", info: "Informational",
  };

  while ((match = fieldRegex.exec(input)) !== null) {
    const key = match[1].toLowerCase().trim();
    const value = (match[2] || match[3] || match[4] || "").trim();
    if (value) {
      tokens[key] = key === "severity" ? (severityMap[value.toLowerCase()] || value) : value;
    }
    cleaned = cleaned.replace(match[0], "");
  }

  const eqRegex = /(\w+)=(?:"([^"]*)"|\[([^\]]*)\]|(\S+))/g;
  while ((match = eqRegex.exec(input)) !== null) {
    const key = match[1].toLowerCase().trim();
    const value = (match[2] || match[3] || match[4] || "").trim();
    if (value && !tokens[key]) {
      tokens[key] = key === "severity" ? (severityMap[value.toLowerCase()] || value) : value;
    }
    cleaned = cleaned.replace(match[0], "");
  }

  const timeKeywords = ["today", "yesterday", "last1h", "last4h", "last6h", "last12h", "last24h", "last7d", "last30d"];
  const remaining = cleaned.trim();
  if (remaining) {
    remaining.split(/\s+/).forEach((word) => {
      const w = word.trim();
      if (!w) return;
      if (timeKeywords.includes(w.toLowerCase())) return;
      if (["AND", "OR", "NOT"].includes(w.toUpperCase())) {
        textChunks.push({ type: "operator", value: w.toUpperCase() });
        return;
      }
      if (w.startsWith('"') && w.endsWith('"')) {
        keywords.push(w.slice(1, -1));
        textChunks.push({ type: "quoted", value: w.slice(1, -1) });
      } else {
        keywords.push(w);
        textChunks.push({ type: "keyword", value: w });
      }
    });
  }

  const hasBoolean = /(^|\s+)(AND|OR|NOT)(\s+|$)/i.test(input);

  return { tokens, keywords, textChunks, raw: input, hasBoolean };
};

// ===================================================================
// SUGGESTIONS DATA
// ===================================================================
const FIELD_SUGGESTIONS = [
  { value: "host:", label: "host", description: "Filter by hostname" },
  { value: "severity:", label: "severity", description: "Filter by severity level" },
  { value: "eventid:", label: "eventid", description: "Filter by Windows Event ID" },
  { value: "process:", label: "process", description: "Filter by process name" },
  { value: "pid:", label: "pid", description: "Filter by process ID" },
  { value: "user:", label: "user", description: "Filter by username" },
  { value: "mitre:", label: "mitre", description: "Filter by MITRE ATT&CK ID" },
  { value: "ioc:", label: "ioc", description: "Search for Indicator of Compromise" },
  { value: "status:", label: "status", description: "Filter by alert status" },
];

const TIME_KEYWORDS = ["today", "last1h", "last24h", "last7d", "last30d"];

// Syntax help examples
const SYNTAX_EXAMPLES = [
  { label: "Free text", example: "powershell" },
  { label: "Event ID", example: "eventid=4688" },
  { label: "Host", example: "host=MANI" },
  { label: "Process", example: "process=powershell.exe" },
  { label: "Severity", example: "severity=High" },
  { label: "MITRE", example: "mitre=T1059.001" },
  { label: "Combined", example: "host=MANI AND eventid=4688" },
  { label: "IOC", example: "192.168.1.50" },
  { label: "Time range", example: "host=MANI last24h" },
];

// ===================================================================
// ENTERPRISE SEARCH BAR COMPONENT
// ===================================================================
function EnterpriseSearchBar({
  value = "",
  onChange,
  onSearchSubmit,
  totalResults = null,
}) {
  const [queryStr, setQueryStr] = useState(value);
  const [isFocused, setIsFocused] = useState(false);
  const [selectedSuggestion, setSelectedSuggestion] = useState(0);
  const [activeField, setActiveField] = useState(null);
  const [searching, setSearching] = useState(false);
  const [liveSuggestions, setLiveSuggestions] = useState(null);
  const [suggestionsLoading, setSuggestionsLoading] = useState(false);
  const [showHelp, setShowHelp] = useState(false);
  const [serverHistory, setServerHistory] = useState([]);

  const inputRef = useRef(null);
  const containerRef = useRef(null);
  const suggestionsFetchRef = useRef(null);
  const helpRef = useRef(null);

  // Sync external value
  useEffect(() => {
    const timer = setTimeout(() => {
      if (value !== undefined && value !== queryStr) {
        setQueryStr(value);
      }
    }, 0);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);

  // Parse query on change + detect active field
  useEffect(() => {
    const timer = setTimeout(() => {
      if (queryStr.endsWith(":") || queryStr.endsWith("=")) {
        const lastColon = queryStr.slice(0, -1).lastIndexOf(":");
        const lastEq = queryStr.slice(0, -1).lastIndexOf("=");
        const splitIdx = Math.max(lastColon, lastEq);
        if (splitIdx >= 0) {
          const field = queryStr.slice(Math.max(queryStr.lastIndexOf(" ", splitIdx - 1) + 1, 0), splitIdx).trim();
          setActiveField(field.toLowerCase());
        } else {
          setActiveField(null);
        }
      } else {
        setActiveField(null);
      }
    }, 0);
    return () => clearTimeout(timer);
  }, [queryStr]);

  // Load server-side search history on mount
  useEffect(() => {
    let cancelled = false;
    async function loadHistory() {
      try {
        const res = await api.get("/search/history");
        if (!cancelled && res.data?.history) {
          setServerHistory(res.data.history.map((h) => h.query));
        }
      } catch {
        // Fall back to empty — history is non-critical
      }
    }
    loadHistory();
    return () => { cancelled = true; };
  }, []);

  // Also refresh history when a search is executed (triggered by queryStr changes after search)
  const refreshHistory = useCallback(async () => {
    try {
      const res = await api.get("/search/history");
      if (res.data?.history) {
        setServerHistory(res.data.history.map((h) => h.query));
      }
    } catch {
      // non-critical
    }
  }, []);

  // Use only server-side history (no localStorage fallback)
  const history = serverHistory;

  // ===========================================================
  // LIVE SUGGESTIONS: fetched from the backend (debounced)
  // ===========================================================
  useEffect(() => {
    if (suggestionsFetchRef.current) {
      clearTimeout(suggestionsFetchRef.current);
    }

    if (!queryStr.trim()) {
      suggestionsFetchRef.current = setTimeout(() => setLiveSuggestions(null), 0);
      return () => {
        if (suggestionsFetchRef.current) clearTimeout(suggestionsFetchRef.current);
      };
    }

    suggestionsFetchRef.current = setTimeout(async () => {
      setSuggestionsLoading(true);
      try {
        const lastWord = queryStr.split(/\s+/).pop() || "";
        const res = await api.get("/search/suggestions", {
          params: { q: lastWord.toLowerCase() },
        });
        setLiveSuggestions(res.data || {});
      } catch {
        setLiveSuggestions(null);
      } finally {
        setSuggestionsLoading(false);
      }
    }, 250);

    return () => {
      if (suggestionsFetchRef.current) clearTimeout(suggestionsFetchRef.current);
    };
  }, [queryStr]);

  // ===========================================================
  // Suggestions: field syntax + live backend values + history
  // ===========================================================
  const suggestions = useMemo(() => {
    if (!queryStr.trim()) {
      // Show field syntax suggestions when input is empty (no empty "Recent Searches")
      return { type: "syntax", items: FIELD_SUGGESTIONS.slice(0, 6) };
    }

    const lastWord = queryStr.split(/\s+/).pop() || "";
    const trimmed = lastWord.toLowerCase();

    if (activeField) {
      let fieldKey = activeField;
      if (fieldKey === "eventid") fieldKey = "event_ids";
      if (fieldKey === "mitre") fieldKey = "mitre_ids";
      if (fieldKey === "host") fieldKey = "hosts";
      if (fieldKey === "user") fieldKey = "users";
      if (fieldKey === "process") fieldKey = "processes";
      if (fieldKey === "pid") fieldKey = "pids";
      if (fieldKey === "ioc") fieldKey = "ips";
      if (fieldKey === "severity") fieldKey = "severities";
      if (fieldKey === "status") fieldKey = "statuses";

      if (liveSuggestions && liveSuggestions[fieldKey]) {
        const values = liveSuggestions[fieldKey].filter((v) =>
          isCleanSuggestion(v) && v.toLowerCase().startsWith(trimmed)
        );
        if (values.length > 0) {
          return {
            type: "values",
            items: values.map((v) => ({ value: `${activeField}:${v}`, label: v })),
          };
        }
      }
    }

    const fieldItems = FIELD_SUGGESTIONS.filter(
      (f) => f.value.toLowerCase().includes(trimmed) || f.label.toLowerCase().includes(trimmed)
    );
    const timeItems = TIME_KEYWORDS.filter((t) => t.includes(trimmed))
      .map((t) => ({ value: t, label: t, description: "Time range shortcut" }));
    const historyItems = history
      .filter((h) => h.toLowerCase().includes(trimmed))
      .slice(0, 5)
      .map((h) => ({ value: h, label: h, description: "Recent search" }));

    const liveItems = [];
    if (liveSuggestions) {
      const liveCategories = {
        hosts: { icon: "host", label: "Host" },
        users: { icon: "user", label: "User" },
        processes: { icon: "process", label: "Process" },
        event_ids: { icon: "eventid", label: "Event" },
        mitre_ids: { icon: "mitre", label: "MITRE" },
        ips: { icon: "ioc", label: "IP" },
      };
      Object.entries(liveCategories).forEach(([key, cfg]) => {
        const items = liveSuggestions[key];
        if (items && items.length > 0) {
          items.forEach((item) => {
            if (isCleanSuggestion(item)) {
              liveItems.push({
                value: item,
                label: item,
                description: cfg.label,
                _type: "live",
                _icon: cfg.icon,
              });
            }
          });
        }
      });
    }

    const all = [
      ...fieldItems.map((f) => ({ ...f, _type: "field" })),
      ...timeItems.map((t) => ({ ...t, _type: "time" })),
      ...liveItems.slice(0, 10),
      ...historyItems.map((h) => ({ ...h, _type: "history" })),
    ];

    return { type: "mixed", items: all.slice(0, 12) };
  }, [queryStr, activeField, history, liveSuggestions]);

  // Execute search
  const executeSearch = useCallback(async (overrideQuery) => {
    const q = overrideQuery || queryStr;
    const parsed = parseEnterpriseQuery(q);

    setSearching(true);
    setTimeout(() => setSearching(false), 600);

    if (onSearchSubmit) {
      onSearchSubmit({
        raw: q,
        tokens: parsed.tokens,
        keywords: parsed.keywords,
        hasBoolean: parsed.hasBoolean,
      });
    }

    // Save to server-side history (non-blocking, after search is triggered)
    api.post("/search/history", { query: q })
      .then(() => refreshHistory())
      .catch(() => {
        try {
          let items = JSON.parse(localStorage.getItem("socra-search-history") || "[]");
          items = [q, ...items.filter((x) => x !== q)].slice(0, 20);
          localStorage.setItem("socra-search-history", JSON.stringify(items));
        } catch {
          // ignore
        }
      });
  }, [queryStr, onSearchSubmit, refreshHistory]);

  const updateQuery = useCallback((text) => {
    setQueryStr(text);
    if (onChange) onChange(text);
  }, [onChange]);

  const clearSearch = useCallback(() => {
    updateQuery("");
    if (inputRef.current) inputRef.current.focus();
  }, [updateQuery]);

  const handleKeyDown = useCallback((e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "k") {
      e.preventDefault();
      if (inputRef.current) inputRef.current.focus();
      return;
    }

    switch (e.key) {
      case "Enter":
        e.preventDefault();
        if (suggestions && suggestions.items && suggestions.items.length > 0 && selectedSuggestion >= 0) {
          const item = suggestions.items[selectedSuggestion];
          if (item) {
            updateQuery(item.value);
            setSelectedSuggestion(0);
            // If it's a history item or live data value, execute search immediately
            if (item._type === "history" || item._type === "live") {
              setTimeout(() => executeSearch(item.value), 0);
            }
            return;
          }
        }
        executeSearch();
        break;
      case "Escape":
        if (queryStr) {
          clearSearch();
        } else {
          setIsFocused(false);
          setShowHelp(false);
          if (inputRef.current) inputRef.current.blur();
        }
        break;
      case "ArrowDown":
        e.preventDefault();
        if (suggestions && suggestions.items) {
          setSelectedSuggestion((prev) => Math.min(prev + 1, suggestions.items.length - 1));
        }
        break;
      case "ArrowUp":
        e.preventDefault();
        setSelectedSuggestion((prev) => Math.max(prev - 1, 0));
        break;
      case "Tab":
        e.preventDefault();
        if (suggestions && suggestions.items && suggestions.items.length > 0) {
          const idx = Math.max(0, selectedSuggestion);
          const item = suggestions.items[idx];
          if (item) {
            updateQuery(item.value);
            setSelectedSuggestion(0);
          }
        }
        break;
      default:
        break;
    }
  }, [queryStr, suggestions, selectedSuggestion, executeSearch, updateQuery, clearSearch]);

  // Global Ctrl+K handler
  useEffect(() => {
    const handler = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "k") {
        e.preventDefault();
        if (inputRef.current) inputRef.current.focus();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  // Click outside closes dropdowns
  useEffect(() => {
    const handler = (e) => {
      if (containerRef.current && !containerRef.current.contains(e.target)) {
        setIsFocused(false);
        setShowHelp(false);
      }
      if (helpRef.current && !helpRef.current.contains(e.target)) {
        setShowHelp(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const renderSuggestionItem = (item, index) => {
    const isSelected = selectedSuggestion === index;
    let icon = null;
    let typeLabel = "";

    if (item._type === "field") {
      icon = <Terminal size={12} className="text-cyan-400 shrink-0" />;
      typeLabel = "FIELD";
    } else if (item._type === "time") {
      icon = <Clock3 size={12} className="text-amber-400 shrink-0" />;
      typeLabel = "TIME";
    } else if (item._type === "live") {
      const catIcons = {
        host: <Monitor size={12} className="text-emerald-400 shrink-0" />,
        user: <User size={12} className="text-blue-400 shrink-0" />,
        process: <Cpu size={12} className="text-amber-400 shrink-0" />,
        eventid: <Terminal size={12} className="text-cyan-400 shrink-0" />,
        mitre: <Shield size={12} className="text-violet-400 shrink-0" />,
        ioc: <Globe size={12} className="text-rose-400 shrink-0" />,
      };
      icon = catIcons[item._icon] || <Sparkles size={12} className="text-slate-400 shrink-0" />;
      typeLabel = item.description || "DATA";
    } else if (item._type === "history") {
      icon = <History size={12} className="text-slate-400 shrink-0" />;
      typeLabel = "HISTORY";
    }

    // History items execute search immediately on click
    const isHistoryItem = item._type === "history";

    return (
      <button
        key={item.value + item.label}
        type="button"
        onMouseDown={() => {
          updateQuery(item.value);
          setSelectedSuggestion(0);
          if (isHistoryItem) {
            // Execute search immediately with the exact query value
            setTimeout(() => executeSearch(item.value), 0);
          }
        }}
        className={"w-full px-3.5 py-2 text-left text-xs transition-all flex items-center gap-2.5 " +
          (isSelected
            ? "bg-cyan-600/20 text-cyan-300 border-l-2 border-cyan-500"
            : "text-slate-300 hover:bg-slate-800/60 border-l-2 border-transparent")}
      >
        {icon && <span className="shrink-0">{icon}</span>}
        <span className="flex-1 min-w-0 font-semibold truncate">{item.label}</span>
        {item.description && item._type !== "live" && (
          <span className="text-[10px] text-slate-500 truncate hidden sm:block">{item.description}</span>
        )}
        {typeLabel && (
          <span className={"text-[9px] font-bold uppercase tracking-wider shrink-0 " +
            (isSelected ? "text-cyan-500" : "text-slate-600")}>{typeLabel}</span>
        )}
      </button>
    );
  };

  const showDropdown = isFocused && suggestions && suggestions.items && suggestions.items.length > 0;

  return (
    <form onSubmit={(e) => { e.preventDefault(); executeSearch(); }} ref={containerRef} className="w-full font-mono relative z-50">
      {/* PRIMARY SEARCH FIELD */}
      <div
        className={"w-full flex items-center gap-2 h-10 rounded-lg border px-3 transition-all duration-150 " +
          (isFocused
            ? "border-cyan-500/70 bg-slate-900 shadow-[0_0_0_3px_rgba(6,182,212,.12)]"
            : "border-slate-700/70 bg-slate-900/70 hover:border-slate-600")}
      >
        {searching || suggestionsLoading ? (
          <Loader2 size={15} className="text-cyan-400 animate-spin shrink-0" />
        ) : (
          <Search size={15} className={isFocused ? "text-cyan-400 shrink-0" : "text-slate-500 shrink-0"} />
        )}

        <input
          ref={inputRef}
          value={queryStr}
          onChange={(e) => updateQuery(e.target.value)}
          onFocus={() => { setIsFocused(true); setSelectedSuggestion(0); }}
          onKeyDown={handleKeyDown}
          placeholder="Search telemetry — host:MANI severity:critical eventid:4688"
          className="flex-1 min-w-0 bg-transparent outline-none text-slate-100 placeholder:text-slate-600 text-sm tracking-wide"
        />

        {totalResults !== null && (
          <span className="text-[10px] font-bold text-slate-500 tabular-nums shrink-0">
            {totalResults.toLocaleString()}
          </span>
        )}

        {queryStr && (
          <button
            onClick={clearSearch}
            title="Clear search (Esc)"
            className="text-slate-500 hover:text-white transition shrink-0"
          >
            <X size={14} />
          </button>
        )}

        {/* Syntax help button */}
        <div className="relative" ref={helpRef}>
          <button
            onClick={() => setShowHelp(!showHelp)}
            title="Search syntax help"
            className="text-slate-600 hover:text-cyan-400 transition shrink-0 p-0.5"
          >
            <HelpCircle size={14} />
          </button>
          {showHelp && (
            <div className="absolute right-0 top-8 z-[999] w-72 rounded-lg border border-slate-700/80 bg-slate-900/98 backdrop-blur-2xl shadow-2xl shadow-black/50 overflow-hidden">
              <div className="px-3 py-2 border-b border-slate-800 bg-slate-900/60">
                <p className="text-[10px] uppercase tracking-widest text-slate-500 font-bold">Search Syntax</p>
              </div>
              <div className="p-3 space-y-1.5">
                {SYNTAX_EXAMPLES.map((ex) => (
                  <div key={ex.example} className="flex items-center justify-between gap-3">
                    <span className="text-[10px] text-slate-500 font-semibold">{ex.label}</span>
                    <button
                      onMouseDown={(e) => {
                        e.preventDefault();
                        updateQuery(ex.example);
                        setShowHelp(false);
                        inputRef.current?.focus();
                      }}
                      className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 bg-slate-800/60 px-2 py-0.5 rounded border border-slate-700/40 transition"
                    >
                      {ex.example}
                    </button>
                  </div>
                ))}
              </div>
              <div className="px-3 py-1.5 border-t border-slate-800 bg-slate-900/60 text-[9px] text-slate-600">
                Supports AND, OR, NOT operators and quoted values
              </div>
            </div>
          )}
        </div>

        <button
          type="submit"
          disabled={searching}
          className="flex items-center gap-1.5 px-3 h-7 rounded-md bg-cyan-600 hover:bg-cyan-500 disabled:bg-cyan-600/50 transition-all text-xs font-bold text-white shrink-0"
        >
          {searching ? <Loader2 size={12} className="animate-spin" /> : <Search size={12} />}
          Search
        </button>
      </div>

      {/* SUGGESTIONS / HISTORY DROPDOWN */}
      {showDropdown && (
        <div className="absolute top-11 left-0 right-0 rounded-lg border border-slate-700/80 bg-slate-900/98 backdrop-blur-2xl shadow-2xl shadow-black/50 overflow-hidden z-[999]">
          <div className="px-3.5 py-1.5 border-b border-slate-800 text-[9px] uppercase tracking-widest text-slate-500 flex items-center gap-2 bg-slate-900/60">
            {suggestions.type === "history" ? (
              <><History size={10} /> Recent Searches</>
            ) : suggestions.type === "syntax" ? (
              <><Terminal size={10} /> Query Fields</>
            ) : suggestions.type === "values" ? (
              <><Sparkles size={10} /> Suggested Values</>
            ) : (
              <><Sparkles size={10} /> Suggestions</>
            )}
            {suggestionsLoading && <Loader2 size={9} className="animate-spin text-cyan-400 ml-auto" />}
          </div>

          <div className="max-h-64 overflow-y-auto">
            {suggestions.items.map((item, index) => renderSuggestionItem(item, index))}
          </div>

          <div className="px-3.5 py-1 border-t border-slate-800 flex items-center justify-between text-[9px] uppercase tracking-wider text-slate-600 bg-slate-900/60">
            <span>↑↓ Navigate · ↵ Select · Tab Complete</span>
            <div className="flex items-center gap-3">
              {suggestions.type === "history" && history.length > 0 && (
                <button
                  onClick={async () => {
                    try {
                      await api.delete("/search/history");
                      setServerHistory([]);
                      setIsFocused(false);
                    } catch { /* non-critical */ }
                  }}
                  className="text-red-400 hover:text-red-300 transition"
                >
                  Clear history
                </button>
              )}
              {suggestions.type === "syntax" && (
                <span>Type field:value syntax or free text</span>
              )}
              <span>{suggestions.items.length} results</span>
            </div>
          </div>
        </div>
      )}
    </form>
  );
}

export default EnterpriseSearchBar;
