import {
  useState,
  useEffect,
  useRef,
  useCallback,
  useMemo,
} from "react";

import {
  Search,
  X,
  Clock,
  Sparkles,
  ChevronDown,
  Loader2,
  HelpCircle,
  AlertTriangle,
  CheckCircle,
  History,
  FileJson,
  ArrowUpRight,
  Zap,
} from "lucide-react";

import api from "../services/api";
import { isCleanSuggestion } from "./SearchSuggestionGuard";

import {
  parseQuery,
  validateQuery,
  queryToBackend,
  SOCRA_FIELDS,
} from "../lib/socra-query";

/* ============================================================
   FIELD SUGGESTIONS
   ============================================================ */

const FIELD_SUGGESTIONS = Object.entries(SOCRA_FIELDS).map(
  ([key, def]) => ({
    value: `${key}:`,
    label: key,
    description: def?.description || "",
    type: def?.type || "field",
    category: def?.category || "general",
    examples: def?.examples || [],
    _type: "field",
  })
);

const TIME_KEYWORDS = [
  "today",
  "yesterday",
  "last1h",
  "last4h",
  "last6h",
  "last12h",
  "last24h",
  "last7d",
  "last30d",
];

const SYNTAX_EXAMPLES = [
  {
    label: "Free text",
    example: "powershell",
  },
  {
    label: "Event ID",
    example: "event_id:4688",
  },
  {
    label: "Host",
    example: "host:WORKSTATION01",
  },
  {
    label: "Process",
    example: "process:powershell.exe",
  },
  {
    label: "Severity",
    example: "severity:critical",
  },
  {
    label: "MITRE",
    example: "mitre:T1059.001",
  },
  {
    label: "Combined",
    example: "host:WORKSTATION01 AND event_id:4688",
  },
  {
    label: "IOC",
    example: "source_ip:192.168.1.50",
  },
  {
    label: "Time range",
    example: "host:WORKSTATION01 last24h",
  },
];

/* ============================================================
   HELPERS
   ============================================================ */

/**
 * Get the token currently under the cursor.
 *
 * Example:
 *
 * "host:PC01 event_id:4624"
 *                    ^
 *
 * returns the second token.
 */
function getActiveToken(text, cursorPosition) {
  const cursor = Number.isInteger(cursorPosition)
    ? cursorPosition
    : text.length;

  const before = text.slice(0, cursor);

  const start = before.lastIndexOf(" ") + 1;

  let end = text.indexOf(" ", cursor);

  if (end === -1) {
    end = text.length;
  }

  return {
    text: text.slice(start, end),
    start,
    end,
  };
}

/**
 * Determine whether the cursor is currently inside a field:value
 * expression.
 *
 * Examples:
 *
 * event_id:
 * event_id:46
 * username:adm
 */
function getQueryContext(text, cursorPosition) {
  const token = getActiveToken(text, cursorPosition);

  const tokenText = token.text;

  const colonIndex = tokenText.indexOf(":");

  if (colonIndex === -1) {
    return {
      type: "field",
      field: null,
      token,
      valueStart: token.start,
    };
  }

  const field = tokenText
    .slice(0, colonIndex)
    .trim()
    .toLowerCase();

  const value = tokenText.slice(colonIndex + 1);

  return {
    type: "value",
    field,
    value,
    token,
    fieldStart: token.start,
    colonIndex: token.start + colonIndex,
    valueStart: token.start + colonIndex + 1,
  };
}

/**
 * Insert a field suggestion.
 *
 * IMPORTANT:
 * This function always produces:
 *
 * field:
 *
 * never:
 *
 * field::
 */
function insertFieldSuggestion(text, cursorPosition, fieldName) {
  const context = getQueryContext(text, cursorPosition);

  const field = String(fieldName || "")
    .replace(/:$/, "")
    .trim();

  if (!field) {
    return {
      text,
      cursor: cursorPosition,
    };
  }

  const token = context.token;

  const before = text.slice(0, token.start);
  const after = text.slice(token.end);

  const newText = `${before}${field}:${after}`;

  const newCursor = before.length + field.length + 1;

  return {
    text: newText,
    cursor: newCursor,
  };
}

/**
 * Insert a value suggestion.
 *
 * Example:
 *
 * host:PC
 *
 * selecting SERVER01 gives:
 *
 * host:SERVER01
 *
 * It only replaces the value portion.
 */
function insertValueSuggestion(
  text,
  cursorPosition,
  value,
  fieldOverride = null
) {
  const context = getQueryContext(text, cursorPosition);

  const rawValue = String(value ?? "")
    .trim()
    .replace(/^:/, "");

  if (!rawValue) {
    return {
      text,
      cursor: cursorPosition,
    };
  }

  let field = fieldOverride || context.field;

  if (!field) {
    return {
      text,
      cursor: cursorPosition,
    };
  }

  field = String(field)
    .replace(/:$/, "")
    .trim();

  const token = context.token;

  let start;
  let end;

  if (context.type === "value") {
    start = context.valueStart;
    end = token.end;
  } else {
    start = token.start;
    end = token.end;
  }

  const before = text.slice(0, start);
  const after = text.slice(end);

  /*
   * If the user already has:
   *
   * username:
   *
   * start points AFTER the colon.
   *
   * Therefore we insert ONLY the value.
   *
   * This is the key fix for username::value.
   */
  let newText;

  if (context.type === "value") {
    newText = `${before}${rawValue}${after}`;
  } else {
    newText = `${before}${field}:${rawValue}${after}`;
  }

  const newCursor = before.length + rawValue.length;

  return {
    text: newText,
    cursor: newCursor,
  };
}

/**
 * Apply a suggestion to the query.
 *
 * ALL suggestion paths should use this function.
 */
function applySuggestionToQuery(
  text,
  cursorPosition,
  item
) {
  if (!item) {
    return {
      text,
      cursor: cursorPosition,
    };
  }

  const context = getQueryContext(text, cursorPosition);

  /*
   * FIELD suggestion
   */
  if (
    item._type === "field" ||
    item.type === "field"
  ) {
    return insertFieldSuggestion(
      text,
      cursorPosition,
      item.label || item.value
    );
  }

  /*
   * TIME suggestion
   */
  if (item._type === "time") {
    const token = context.token;

    const before = text.slice(0, token.start);
    const after = text.slice(token.end);

    const value = String(item.value || item.label);

    return {
      text: `${before}${value}${after}`,
      cursor: before.length + value.length,
    };
  }

  /*
   * VALUE / LIVE / AUTOCOMPLETE suggestion
   */
  const rawValue =
    item.rawValue ??
    item.value ??
    item.label ??
    "";

  return insertValueSuggestion(
    text,
    cursorPosition,
    rawValue,
    item.field || context.field
  );
}

/* ============================================================
   COMPONENT
   ============================================================ */

function EnterpriseSearchBar({
  value = "",
  onChange,
  onSearchSubmit,
  totalResults = null,
}) {
  const [queryStr, setQueryStr] = useState(value);

  const [isFocused, setIsFocused] = useState(false);

  const [selectedSuggestion, setSelectedSuggestion] =
    useState(0);

  const [activeField, setActiveField] = useState(null);

  const [searching, setSearching] = useState(false);

  const [liveSuggestions, setLiveSuggestions] =
    useState(null);

  const [suggestionsLoading, setSuggestionsLoading] =
    useState(false);

  const [showHelp, setShowHelp] = useState(false);

  const [serverHistory, setServerHistory] = useState([]);

  const [validationErrors, setValidationErrors] =
    useState([]);

  const [showPreview, setShowPreview] =
    useState(false);

  const inputRef = useRef(null);

  const containerRef = useRef(null);

  const suggestionsFetchRef = useRef(null);

  const helpRef = useRef(null);

  /* ==========================================================
     SYNC EXTERNAL VALUE
     ========================================================== */

  useEffect(() => {
    if (value !== undefined && value !== queryStr) {
      setQueryStr(value);
    }
  }, [value]);

  /* ==========================================================
     QUERY UPDATE
     ========================================================== */

  const updateQuery = useCallback(
    (text, cursorPosition = null) => {
      setQueryStr(text);

      onChange?.(text);

      requestAnimationFrame(() => {
        if (!inputRef.current) return;

        inputRef.current.focus();

        const position =
          cursorPosition === null
            ? text.length
            : cursorPosition;

        try {
          inputRef.current.setSelectionRange(
            position,
            position
          );
        } catch {
          // Ignore selection errors.
        }
      });
    },
    [onChange]
  );

  /* ==========================================================
     ACTIVE FIELD DETECTION
     ========================================================== */

  const detectActiveField = useCallback(() => {
    const input = inputRef.current;

    const cursorPosition =
      input?.selectionStart ?? queryStr.length;

    const context = getQueryContext(
      queryStr,
      cursorPosition
    );

    if (context.type === "value" && context.field) {
      setActiveField(context.field);
    } else {
      setActiveField(null);
    }

    return context;
  }, [queryStr]);

  useEffect(() => {
    detectActiveField();
  }, [queryStr, detectActiveField]);

  /* ==========================================================
     VALIDATION
     ========================================================== */

  useEffect(() => {
    if (!queryStr.trim()) {
      setValidationErrors([]);
      return;
    }

    try {
      const parsed = parseQuery(queryStr);

      const validation = validateQuery(parsed);

      setValidationErrors(
        validation?.errors || []
      );
    } catch (error) {
      console.error(
        "[SOCRA] Query validation error:",
        error
      );

      setValidationErrors([]);
    }
  }, [queryStr]);

  /* ==========================================================
     HISTORY
     ========================================================== */

  const refreshHistory = useCallback(async () => {
    try {
      const res = await api.get("/search/history");

      if (res.data?.history) {
        setServerHistory(
          res.data.history
            .map((item) => item.query)
            .filter(Boolean)
        );
      }
    } catch {
      // Search history is non-critical.
    }
  }, []);

  useEffect(() => {
    let cancelled = false;

    async function loadHistory() {
      try {
        const res = await api.get("/search/history");

        if (
          !cancelled &&
          Array.isArray(res.data?.history)
        ) {
          setServerHistory(
            res.data.history
              .map((item) => item.query)
              .filter(Boolean)
          );
        }
      } catch {
        // Ignore history errors.
      }
    }

    loadHistory();

    return () => {
      cancelled = true;
    };
  }, []);

  /* ==========================================================
     CLEAR SEARCH
     ========================================================== */

  const clearSearch = useCallback(() => {
    updateQuery("", 0);

    setValidationErrors([]);
    setLiveSuggestions(null);
    setActiveField(null);

    requestAnimationFrame(() => {
      inputRef.current?.focus();
    });
  }, [updateQuery]);

  /* ==========================================================
     BACKEND LIVE SUGGESTIONS
     ========================================================== */

  useEffect(() => {
    if (suggestionsFetchRef.current) {
      clearTimeout(suggestionsFetchRef.current);
    }

    if (!queryStr.trim()) {
      setLiveSuggestions(null);
      setSuggestionsLoading(false);
      return;
    }

    suggestionsFetchRef.current = setTimeout(
      async () => {
        setSuggestionsLoading(true);

        try {
          const input = inputRef.current;

          const cursorPosition =
            input?.selectionStart ?? queryStr.length;

          const context = getQueryContext(
            queryStr,
            cursorPosition
          );

          /*
           * Only ask backend for value suggestions when
           * we actually have a field.
           */
          if (
            context.type !== "value" ||
            !context.field
          ) {
            setLiveSuggestions(null);
            setSuggestionsLoading(false);
            return;
          }

          const valuePrefix =
            context.value || "";

          const res = await api.get(
            "/search/suggestions",
            {
              params: {
                q: valuePrefix.toLowerCase(),
              },
            }
          );

          if (res.data) {
            setLiveSuggestions(res.data);
          } else {
            setLiveSuggestions(null);
          }
        } catch (error) {
          console.warn(
            "[SOCRA] Suggestions request failed:",
            error
          );

          setLiveSuggestions(null);
        } finally {
          setSuggestionsLoading(false);
        }
      },
      250
    );

    return () => {
      if (suggestionsFetchRef.current) {
        clearTimeout(suggestionsFetchRef.current);
      }
    };
  }, [queryStr]);

  /* ==========================================================
     BUILD SUGGESTIONS
     ========================================================== */

  const suggestions = useMemo(() => {
    const input = inputRef.current;

    const cursorPosition =
      input?.selectionStart ?? queryStr.length;

    const context = getQueryContext(
      queryStr,
      cursorPosition
    );

    const items = [];

    /* --------------------------------------------------------
       FIELD SUGGESTIONS
       -------------------------------------------------------- */

    if (
      context.type === "field" &&
      context.token.text
    ) {
      const prefix =
        context.token.text.toLowerCase();

      FIELD_SUGGESTIONS.forEach((item) => {
        if (
          item.label
            .toLowerCase()
            .startsWith(prefix)
        ) {
          items.push(item);
        }
      });
    }

    /*
     * Empty query → show fields.
     */
    if (
      context.type === "field" &&
      !context.token.text
    ) {
      items.push(...FIELD_SUGGESTIONS);
    }

    /* --------------------------------------------------------
       VALUE SUGGESTIONS
       -------------------------------------------------------- */

    if (
      context.type === "value" &&
      context.field
    ) {
      const prefix =
        context.value?.toLowerCase() || "";

      /*
       * Backend response can have several categories.
       */
      if (liveSuggestions) {
        const categories = [
          "values",
          "usernames",
          "users",
          "event_ids",
          "ips",
          "hosts",
          "processes",
          "process_names",
          "statuses",
        ];

        for (const category of categories) {
          const values =
            liveSuggestions?.[category];

          if (!Array.isArray(values)) {
            continue;
          }

          for (const value of values) {
            if (value === null || value === undefined) {
              continue;
            }

            const stringValue = String(value);

            if (
              prefix &&
              !stringValue
                .toLowerCase()
                .includes(prefix)
            ) {
              continue;
            }

            if (!isCleanSuggestion(stringValue)) {
              continue;
            }

            items.push({
              value: stringValue,
              rawValue: stringValue,
              label: stringValue,
              field: context.field,
              description:
                `${context.field} value`,
              _type: "live",
            });
          }
        }
      }

      /*
       * Also show useful static values.
       */
      if (
        context.field === "event_id" ||
        context.field === "eventid"
      ) {
        const eventIds = [
          "4624",
          "4625",
          "4634",
          "4647",
          "4648",
          "4672",
          "4720",
          "4722",
        ];

        for (const id of eventIds) {
          if (
            !prefix ||
            id.includes(prefix)
          ) {
            items.push({
              value: id,
              rawValue: id,
              label: id,
              field: context.field,
              description:
                "Windows Event ID",
              _type: "live",
            });
          }
        }
      }
    }

    /* --------------------------------------------------------
       TIME SUGGESTIONS
       -------------------------------------------------------- */

    if (
      context.type === "field" &&
      !context.token.text
    ) {
      for (const keyword of TIME_KEYWORDS) {
        items.push({
          value: keyword,
          label: keyword,
          description: "Time filter",
          _type: "time",
        });
      }
    }

    /* --------------------------------------------------------
       HISTORY
       -------------------------------------------------------- */

    if (
      context.type === "field" &&
      !context.token.text &&
      serverHistory.length
    ) {
      serverHistory.slice(0, 5).forEach((historyItem) => {
        items.push({
          value: historyItem,
          label: historyItem,
          description: "Previous search",
          _type: "history",
        });
      });
    }

    /*
     * Remove duplicates.
     */
    const seen = new Set();

    const uniqueItems = items.filter((item) => {
      const key = `${item._type}:${item.value}`;

      if (seen.has(key)) {
        return false;
      }

      seen.add(key);
      return true;
    });

    return {
      type: "mixed",
      items: uniqueItems.slice(0, 12),
    };
  }, [
    queryStr,
    activeField,
    liveSuggestions,
    serverHistory,
  ]);

  /* ==========================================================
     SELECT SUGGESTION
     ========================================================== */

  const selectSuggestion = useCallback(
    (item) => {
      if (!item) return;

      const input = inputRef.current;

      const cursorPosition =
        input?.selectionStart ?? queryStr.length;

      const result = applySuggestionToQuery(
        queryStr,
        cursorPosition,
        item
      );

      /*
       * IMPORTANT:
       *
       * Never do:
       *
       * setQueryStr(item.value)
       *
       * That was the reason selecting 4624 could replace
       * "event_id:4" with only "4624".
       */
      updateQuery(
        result.text,
        result.cursor
      );

      setSelectedSuggestion(0);

      /*
       * History selection should execute the query.
       */
      if (item._type === "history") {
        setTimeout(() => {
          executeSearch(result.text);
        }, 0);
      }
    },
    [queryStr, updateQuery]
  );

  /* ==========================================================
     SEARCH
     ========================================================== */

  const executeSearch = useCallback(
    async (overrideQuery = null) => {
      const q =
        overrideQuery !== null
          ? overrideQuery
          : queryStr;

      if (!q.trim()) {
        return;
      }

      try {
        const parsed = parseQuery(q);

        const validation =
          validateQuery(parsed);

        if (!validation.valid) {
          setValidationErrors(
            validation.errors || []
          );
          return;
        }

        setValidationErrors([]);
        setSearching(true);

        const backendQuery =
          queryToBackend(q);

        onSearchSubmit?.({
          raw: q,

          tokens:
            parsed.tokens || {},

          keywords:
            parsed.keywords || [],

          hasBoolean:
            parsed.hasBoolean || false,

          filters:
            backendQuery.filters,

          formatted_query:
            backendQuery.formatted_query,
        });

        /*
         * Save search history.
         */
        try {
          await api.post(
            "/search/history",
            {
              query: q,
            }
          );

          await refreshHistory();
        } catch {
          /*
           * Local fallback.
           */
          try {
            let items = JSON.parse(
              localStorage.getItem(
                "socra-search-history"
              ) || "[]"
            );

            items = [
              q,
              ...items.filter(
                (item) => item !== q
              ),
            ].slice(0, 20);

            localStorage.setItem(
              "socra-search-history",
              JSON.stringify(items)
            );
          } catch {
            // Ignore local storage errors.
          }
        }

        setTimeout(() => {
          setSearching(false);
        }, 500);
      } catch (error) {
        console.error(
          "[SOCRA] Search execution error:",
          error
        );

        setSearching(false);
      }
    },
    [
      queryStr,
      onSearchSubmit,
      refreshHistory,
    ]
  );

  /* ==========================================================
     KEYBOARD HANDLING
     ========================================================== */

  const handleKeyDown = useCallback(
    (e) => {
      if (
        (e.ctrlKey || e.metaKey) &&
        e.key.toLowerCase() === "k"
      ) {
        e.preventDefault();

        inputRef.current?.focus();

        return;
      }

      const hasSuggestions =
        isFocused &&
        suggestions?.items?.length > 0;

      if (hasSuggestions) {
        if (e.key === "ArrowDown") {
          e.preventDefault();

          setSelectedSuggestion(
            (current) =>
              (current + 1) %
              suggestions.items.length
          );

          return;
        }

        if (e.key === "ArrowUp") {
          e.preventDefault();

          setSelectedSuggestion(
            (current) =>
              current <= 0
                ? suggestions.items.length - 1
                : current - 1
          );

          return;
        }

        if (
          e.key === "Enter" ||
          e.key === "Tab"
        ) {
          e.preventDefault();

          const item =
            suggestions.items[
              selectedSuggestion
            ];

          if (item) {
            selectSuggestion(item);
          }

          return;
        }
      }

      if (e.key === "Enter") {
        e.preventDefault();

        executeSearch();

        return;
      }

      if (e.key === "Escape") {
        e.preventDefault();

        if (queryStr) {
          clearSearch();
        } else {
          setIsFocused(false);
          setShowHelp(false);
          inputRef.current?.blur();
        }

        return;
      }
    },
    [
      isFocused,
      suggestions,
      selectedSuggestion,
      selectSuggestion,
      executeSearch,
      queryStr,
      clearSearch,
    ]
  );

  /* ==========================================================
     GLOBAL CTRL+K
     ========================================================== */

  useEffect(() => {
    const handler = (e) => {
      if (
        (e.ctrlKey || e.metaKey) &&
        e.key.toLowerCase() === "k"
      ) {
        e.preventDefault();

        inputRef.current?.focus();
      }
    };

    window.addEventListener(
      "keydown",
      handler
    );

    return () => {
      window.removeEventListener(
        "keydown",
        handler
      );
    };
  }, []);

  /* ==========================================================
     CLICK OUTSIDE
     ========================================================== */

  useEffect(() => {
    const handler = (e) => {
      if (
        containerRef.current &&
        !containerRef.current.contains(
          e.target
        )
      ) {
        setIsFocused(false);
        setShowHelp(false);
      }
    };

    document.addEventListener(
      "mousedown",
      handler
    );

    return () => {
      document.removeEventListener(
        "mousedown",
        handler
      );
    };
  }, []);

  /* ==========================================================
     INPUT CHANGE
     ========================================================== */

  const handleInputChange = useCallback(
    (e) => {
      const text = e.target.value;

      const cursor =
        e.target.selectionStart ?? text.length;

      setQueryStr(text);

      onChange?.(text);

      const context = getQueryContext(
        text,
        cursor
      );

      if (
        context.type === "value" &&
        context.field
      ) {
        setActiveField(
          context.field
        );
      } else {
        setActiveField(null);
      }

      setSelectedSuggestion(0);
    },
    [onChange]
  );

  /* ==========================================================
     INPUT CLICK / CURSOR
     ========================================================== */

  const handleCursorChange = useCallback(() => {
    detectActiveField();

    setSelectedSuggestion(0);
  }, [detectActiveField]);

  /* ==========================================================
     PREVIEW
     ========================================================== */

  const parsedQuery = useMemo(() => {
    try {
      return parseQuery(queryStr);
    } catch {
      return null;
    }
  }, [queryStr]);

  const previewFilters = useMemo(() => {
    if (!queryStr.trim()) {
      return [];
    }

    const tokens = {};

    /*
     * Simple UI preview parser.
     */
    const fieldRegex =
      /(\w+):(?:"([^"]*)"|\[([^\]]*)\]|(\S+))/g;

    let match;

    while (
      (match =
        fieldRegex.exec(queryStr)) !== null
    ) {
      tokens[
        match[1].toLowerCase()
      ] =
        match[2] ??
        match[3] ??
        match[4];
    }

    return Object.entries(tokens).map(
      ([field, filterValue]) => ({
        field,
        value: filterValue,
      })
    );
  }, [queryStr]);

  /* ==========================================================
     DROPDOWN VISIBILITY
     ========================================================== */

  const showDropdown =
    isFocused &&
    suggestions?.items?.length > 0;

  /* ==========================================================
     RENDER
     ========================================================== */

  return (
    <form
      ref={containerRef}
      onSubmit={(e) => {
        e.preventDefault();
        executeSearch();
      }}
      className="relative w-full"
    >
      {/* ======================================================
          SEARCH INPUT
          ====================================================== */}

      <div
        className={[
          "relative flex items-center",
          "w-full",
          "rounded-xl",
          "border",
          "transition-all",
          "duration-200",
          "focus-within:ring-2",
          "focus-within:ring-cyan-400",
          "focus-within:ring-offset-2",
          "focus-within:ring-offset-slate-950",

          isFocused
            ? "border-cyan-500/60 bg-slate-900 shadow-lg shadow-cyan-500/5"
            : "border-slate-700 bg-slate-950/80",

          validationErrors.length > 0
            ? "border-red-500/60 focus-within:ring-red-400"
            : "",
        ].join(" ")}
      >
        {/* SEARCH ICON */}

        <div className="pl-3.5 pr-2 text-slate-500">
          {searching ? (
            <Loader2
              size={17}
              className="animate-spin text-cyan-400"
            />
          ) : (
            <Search size={17} />
          )}
        </div>

        {/* INPUT */}

        <input
          ref={inputRef}
          type="text"
          value={queryStr}
          onChange={handleInputChange}
          onKeyDown={handleKeyDown}
          onFocus={() => {
            setIsFocused(true);
            detectActiveField();
          }}
          onClick={handleCursorChange}
          onKeyUp={handleCursorChange}
          onSelect={handleCursorChange}
          placeholder="Search events...  e.g. event_id:4624"
          aria-label="Search security events and logs. Use query syntax like event_id:4624 or host:WORKSTATION01"
          autoComplete="off"
          spellCheck="false"
          className={[
            "flex-1",
            "min-w-0",
            "bg-transparent",
            "outline-none",
            "border-none",
            "text-sm",
            "text-slate-200",
            "placeholder:text-slate-600",
            "py-3",
            "focus:ring-0", // Prevent double ring, container already has focus styling
          ].join(" ")}
        />

        {/* ACTIVE FIELD INDICATOR */}

        {activeField && (
          <div className="hidden sm:flex items-center mr-2">
            <span className="px-2 py-1 rounded-md bg-cyan-500/10 border border-cyan-500/20 text-[10px] font-semibold uppercase tracking-wider text-cyan-400">
              {activeField}
            </span>
          </div>
        )}

        {/* CLEAR */}

        {queryStr && (
          <button
            type="button"
            onMouseDown={(e) => {
              e.preventDefault();
              clearSearch();
            }}
            aria-label="Clear search query"
            className="p-2 text-slate-500 hover:text-slate-200 transition-colors focus:ring-2 focus:ring-cyan-400 focus:outline-none rounded-lg"
          >
            <X size={16} aria-hidden="true" />
          </button>
        )}

        {/* HELP */}

        <button
          type="button"
          onMouseDown={(e) => {
            e.preventDefault();

            setShowHelp((current) => !current);
            setIsFocused(true);
          }}
          aria-label="Show search syntax help"
          className={[
            "p-2 mr-1",
            "transition-colors",
            "focus:ring-2 focus:ring-cyan-400 focus:outline-none rounded-lg",
            showHelp
              ? "text-cyan-400"
              : "text-slate-600 hover:text-slate-300",
          ].join(" ")}
        >
          <HelpCircle size={16} aria-hidden="true" />
        </button>

        {/* SEARCH BUTTON */}

        <button
          type="submit"
          disabled={searching}
          aria-label="Submit search query"
          className={[
            "mr-1.5",
            "px-3",
            "py-1.5",
            "rounded-lg",
            "text-xs",
            "font-semibold",
            "transition-all",
            "focus:ring-2 focus:ring-cyan-400 focus:outline-none",
            searching
              ? "bg-slate-800 text-slate-500"
              : "bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20",
          ].join(" ")}
        >
          Search
        </button>
      </div>

      {/* ======================================================
          VALIDATION
          ====================================================== */}

      {validationErrors.length > 0 && (
        <div className="mt-2 rounded-lg border border-red-500/20 bg-red-500/5 px-3 py-2">
          <div className="flex items-start gap-2">
            <AlertTriangle
              size={14}
              className="mt-0.5 shrink-0 text-red-400"
            />

            <div className="space-y-1">
              {validationErrors
                .slice(0, 3)
                .map((error, index) => (
                  <div
                    key={index}
                    className="text-xs text-red-300"
                  >
                    {typeof error === "string"
                      ? error
                      : error?.message ||
                        "Invalid query"}
                  </div>
                ))}
            </div>
          </div>
        </div>
      )}

      {/* ======================================================
          SUGGESTIONS
          ====================================================== */}

      {showDropdown && (
        <div className="absolute z-50 left-0 right-0 mt-2 overflow-hidden rounded-xl border border-slate-700 bg-slate-950 shadow-2xl shadow-black/40">
          {/* HEADER */}

          <div className="flex items-center justify-between px-3.5 py-2 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Sparkles
                size={13}
                className="text-cyan-400"
              />

              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
                Suggestions
              </span>
            </div>

            {suggestionsLoading && (
              <Loader2
                size={13}
                className="animate-spin text-cyan-400"
              />
            )}
          </div>

          {/* ITEMS */}

          <div className="max-h-80 overflow-y-auto py-1">
            {suggestions.items.map(
              (item, index) => {
                const isSelected =
                  index ===
                  selectedSuggestion;

                let icon = null;

                let typeLabel = "SUGGEST";

                if (
                  item._type === "field"
                ) {
                  icon = (
                    <FileJson
                      size={13}
                      className="text-cyan-400"
                    />
                  );

                  typeLabel = "FIELD";
                } else if (
                  item._type === "time"
                ) {
                  icon = (
                    <Clock
                      size={13}
                      className="text-amber-400"
                    />
                  );

                  typeLabel = "TIME";
                } else if (
                  item._type === "history"
                ) {
                  icon = (
                    <History
                      size={13}
                      className="text-slate-400"
                    />
                  );

                  typeLabel = "HISTORY";
                } else if (
                  item._type === "live"
                ) {
                  icon = (
                    <Zap
                      size={13}
                      className="text-cyan-400"
                    />
                  );

                  typeLabel = "VALUE";
                }

                return (
                  <button
                    key={`${item._type}-${item.value}-${index}`}
                    type="button"
                    onMouseDown={(e) => {
                      /*
                       * Prevent input blur before selection.
                       *
                       * This is important.
                       */
                      e.preventDefault();

                      selectSuggestion(item);
                    }}
                    aria-label={`Select ${item.label} suggestion${item.description ? ` - ${item.description}` : ''}`}
                    className={[
                      "w-full",
                      "px-3.5",
                      "py-2",
                      "text-left",
                      "text-xs",
                      "transition-all",
                      "flex",
                      "items-center",
                      "gap-2.5",
                      "border-l-2",
                      "focus:ring-2",
                      "focus:ring-cyan-400",
                      "focus:outline-none",
                      isSelected
                        ? "bg-cyan-600/15 text-cyan-300 border-cyan-500"
                        : "text-slate-300 hover:bg-slate-800/60 border-transparent",
                    ].join(" ")}
                  >
                    {icon && (
                      <span className="shrink-0">
                        {icon}
                      </span>
                    )}

                    <span className="flex-1 min-w-0 font-medium truncate">
                      {item.label}
                    </span>

                    {item.description && (
                      <span className="hidden sm:block max-w-[180px] truncate text-[10px] text-slate-600">
                        {item.description}
                      </span>
                    )}

                    <span
                      className={[
                        "text-[9px]",
                        "font-bold",
                        "uppercase",
                        "tracking-wider",
                        "shrink-0",

                        isSelected
                          ? "text-cyan-500"
                          : "text-slate-600",
                      ].join(" ")}
                    >
                      {typeLabel}
                    </span>
                  </button>
                );
              }
            )}
          </div>

          {/* KEYBOARD HINT */}

          <div className="flex items-center justify-between border-t border-slate-800 px-3.5 py-2">
            <div className="flex items-center gap-3 text-[9px] text-slate-600">
              <span>↑↓ Navigate</span>
              <span>Enter Select</span>
              <span>Esc Close</span>
            </div>

            {activeField && (
              <span className="text-[9px] text-cyan-500">
                {activeField}: values
              </span>
            )}
          </div>
        </div>
      )}

      {/* ======================================================
          HELP PANEL
          ====================================================== */}

      {showHelp && (
        <div
          ref={helpRef}
          className="absolute z-40 left-0 right-0 mt-2 rounded-xl border border-slate-700 bg-slate-950 shadow-2xl shadow-black/40 overflow-hidden"
        >
          <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <HelpCircle
                size={15}
                className="text-cyan-400"
              />

              <span className="text-xs font-semibold text-slate-200">
                SOCRA Search Syntax
              </span>
            </div>

            <button
              type="button"
              onMouseDown={(e) => {
                e.preventDefault();
                setShowHelp(false);
              }}
              aria-label="Close search syntax help"
              className="p-1 text-slate-600 hover:text-slate-300 transition-colors focus:ring-2 focus:ring-cyan-400 focus:outline-none rounded-lg"
            >
              <X size={14} aria-hidden="true" />
            </button>
          </div>

          <div className="grid gap-2 p-3 sm:grid-cols-2 lg:grid-cols-3">
            {SYNTAX_EXAMPLES.map(
              (example) => (
                <button
                  key={example.label}
                  type="button"
                  aria-label={`Insert ${example.label} example: ${example.example}`}
                  onMouseDown={(e) => {
                    e.preventDefault();

                    updateQuery(
                      example.example,
                      example.example.length
                    );

                    setShowHelp(false);
                  }}
                  className="rounded-lg border border-slate-800 bg-slate-900/50 px-3 py-2 text-left hover:border-cyan-500/30 hover:bg-slate-900 focus:ring-2 focus:ring-cyan-400 focus:outline-none transition-all"
                >
                  <div className="text-[10px] font-semibold text-slate-500">
                    {example.label}
                  </div>

                  <div className="mt-1 font-mono text-[11px] text-cyan-300">
                    {example.example}
                  </div>
                </button>
              )
            )}
          </div>
        </div>
      )}

      {/* ======================================================
          SEARCH STATUS
          ====================================================== */}

      {(totalResults !== null ||
        previewFilters.length > 0) && (
        <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            {totalResults !== null && (
              <span className="text-[10px] text-slate-500">
                {totalResults.toLocaleString()} results
              </span>
            )}

            {queryStr && validationErrors.length === 0 && (
              <span className="flex items-center gap-1 text-[10px] text-emerald-500">
                <CheckCircle size={11} />
                Valid query
              </span>
            )}
          </div>

          {previewFilters.length > 0 && (
            <button
              type="button"
              onClick={() =>
                setShowPreview(
                  (current) => !current
                )
              }
              className="flex items-center gap-1 text-[10px] text-slate-500 hover:text-cyan-400"
            >
              <ArrowUpRight size={11} />

              Preview

              <ChevronDown
                size={11}
                className={
                  showPreview
                    ? "rotate-180"
                    : ""
                }
              />
            </button>
          )}
        </div>
      )}

      {/* ======================================================
          PREVIEW
          ====================================================== */}

      {showPreview &&
        previewFilters.length > 0 && (
          <div className="mt-2 rounded-lg border border-slate-800 bg-slate-950/70 p-3">
            <div className="mb-2 flex items-center gap-2">
              <FileJson
                size={13}
                className="text-cyan-400"
              />

              <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">
                Parsed Filters
              </span>
            </div>

            <div className="flex flex-wrap gap-2">
              {previewFilters.map(
                (filter) => (
                  <div
                    key={`${filter.field}-${filter.value}`}
                    className="rounded-md border border-slate-800 bg-slate-900 px-2 py-1"
                  >
                    <span className="text-[10px] font-semibold text-cyan-400">
                      {filter.field}
                    </span>

                    <span className="mx-1 text-slate-700">
                      :
                    </span>

                    <span className="font-mono text-[10px] text-slate-300">
                      {filter.value}
                    </span>
                  </div>
                )
              )}
            </div>
          </div>
        )}
    </form>
  );
}

export default EnterpriseSearchBar;