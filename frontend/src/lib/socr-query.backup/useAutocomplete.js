import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import {
  ArrowUp,
  ArrowDown,
  Enter,
  Tab,
  Search,
  X,
  Clock,
  Sparkles,
  FileJson,
} from "lucide-react";
import {
  getAutocompleteSuggestions,
  suggestFields,
  suggestValues,
  SOCRA_FIELDS,
} from "../lib/socr-query";

const DEBOUNCE_MS = 120;
const MAX_SUGGESTIONS = 8;

/* ────────────────────────────────────────────
   Custom hook: useAutocomplete
   Handles debounced suggestion fetching,
   keyboard navigation, and selection.
   ──────────────────────────────────────────── */
export function useAutocomplete(query, onSelect) {
  const [suggestions, setSuggestions] = useState([]);
  const [activeIndex, setActiveIndex] = useState(-1);
  const [loading, setLoading] = useState(false);
  const timerRef = useRef(null);

  const updateSuggestions = useCallback(
    (text, cursorPos) => {
      if (!text.trim()) {
        setSuggestions([]);
        setActiveIndex(-1);
        return;
      }

      setLoading(true);
      try {
        const result = getAutocompleteSuggestions(text, cursorPos ?? text.length);
        const items = (result.items || []).slice(0, MAX_SUGGESTIONS);
        setSuggestions(items);
        setActiveIndex(items.length > 0 ? 0 : -1);
      } catch {
        setSuggestions([]);
        setActiveIndex(-1);
      } finally {
        setLoading(false);
      }
    },
    []
  );

  const debouncedUpdate = useCallback(
    (text, cursorPos) => {
      if (timerRef.current) clearTimeout(timerRef.current);
      timerRef.current = setTimeout(() => {
        updateSuggestions(text, cursorPos);
      }, DEBOUNCE_MS);
    },
    [updateSuggestions]
  );

  const clearSuggestions = useCallback(() => {
    setSuggestions([]);
    setActiveIndex(-1);
    if (timerRef.current) clearTimeout(timerRef.current);
  }, []);

  const selectSuggestion = useCallback(
    (item) => {
      if (!item) return;
      onSelect?.(item.value);
      clearSuggestions();
    },
    [onSelect, clearSuggestions]
  );

  const handleKeyDown = useCallback(
    (e, currentQuery) => {
      if (suggestions.length === 0) return false;

      switch (e.key) {
        case "ArrowDown":
          e.preventDefault();
          setActiveIndex((prev) =>
            Math.min(prev + 1, suggestions.length - 1)
          );
          return true;

        case "ArrowUp":
          e.preventDefault();
          setActiveIndex((prev) => Math.max(prev - 1, 0));
          return true;

        case "Enter":
          e.preventDefault();
          if (activeIndex >= 0 && suggestions[activeIndex]) {
            selectSuggestion(suggestions[activeIndex]);
            return true;
          }
          return false;

        case "Tab":
          if (activeIndex >= 0 && suggestions[activeIndex]) {
            e.preventDefault();
            selectSuggestion(suggestions[activeIndex]);
            return true;
          }
          return false;

        case "Escape":
          clearSuggestions();
          return true;

        default:
          return false;
      }
    },
    [suggestions, activeIndex, selectSuggestion, clearSuggestions]
  );

  return {
    suggestions,
    activeIndex,
    loading,
    setActiveIndex,
    handleKeyDown,
    debouncedUpdate,
    clearSuggestions,
    selectSuggestion,
  };
}
