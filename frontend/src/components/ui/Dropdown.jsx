import { useEffect, useRef, useState, useMemo } from "react";
import { Check, ChevronDown, Search, X, Loader2 } from "lucide-react";

/**
 * Reusable dark-theme dropdown for the SOCRA AI interface.
 *
 * Replaces browser-native <select> with one consistent enterprise look:
 * dark navy panel, white text, cyan hover / selected states, subtle dark-blue
 * border, shadow, and scrollable long lists — with full keyboard +
 * screen-reader support.
 *
 * Props:
 *   value        – current value (must match an option's `value`)
 *   onChange     – (value) => void
 *   options      – [{ value, label }]
 *   placeholder  – text shown when `value` is not in `options`
 *   ariaLabel    – accessible name for the trigger
 *   className    – extra classes for the positioning wrapper
 *   menuClassName – extra classes for the popover panel
 *   searchable   – enable type-to-filter (default false)
 *   clearable    – show clear button to reset to first option (default false)
 *   loading      – show loading spinner in menu (default false)
 *   emptyText    – text to show when options are empty (default "No options available")
 *   disabled     – disable the dropdown (default false)
 */
function Dropdown({
  value,
  onChange,
  options,
  placeholder = "Select\u2026",
  ariaLabel = "",
  className = "",
  menuClassName = "",
  searchable = false,
  clearable = false,
  loading = false,
  emptyText = "No options available",
  disabled = false,
}) {
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(-1);
  const [searchQuery, setSearchQuery] = useState("");

  const rootRef = useRef(null);
  const triggerRef = useRef(null);
  const menuRef = useRef(null);
  const searchInputRef = useRef(null);

  const selectedIndex = options.findIndex((option) => option.value === value);
  const selected = selectedIndex >= 0 ? options[selectedIndex] : null;
  const idBase = String(ariaLabel || "dropdown").replace(/[^a-zA-Z0-9_-]/g, "-");

  // Filter options based on search query
  const filteredOptions = useMemo(() => {
    if (!searchable || !searchQuery.trim()) return options;
    const q = searchQuery.toLowerCase();
    return options.filter(
      (option) =>
        option.label.toLowerCase().includes(q) ||
        String(option.value).toLowerCase().includes(q)
    );
  }, [options, searchQuery, searchable]);

  // Close when clicking/tapping outside the dropdown OR another dropdown opens.
  useEffect(() => {
    if (!open) return;
    const handlePointerDown = (event) => {
      if (rootRef.current && !rootRef.current.contains(event.target)) {
        setOpen(false);
      }
    };
    const handleDropdownOpen = () => {
      setOpen(false);
    };
    document.addEventListener("mousedown", handlePointerDown);
    document.addEventListener("dropdown:open", handleDropdownOpen);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
      document.removeEventListener("dropdown:open", handleDropdownOpen);
    };
  }, [open]);

  // Reset search when closing
  useEffect(() => {
    if (!open) setSearchQuery("");
  }, [open]);

  // Focus search input when opened with searchable
  useEffect(() => {
    if (open && searchable && searchInputRef.current) {
      searchInputRef.current.focus();
    }
  }, [open, searchable]);

  const openMenu = () => {
    if (disabled || loading) return;
    document.dispatchEvent(new Event("dropdown:open"));
    setActiveIndex(selectedIndex >= 0 ? selectedIndex : 0);
    setOpen(true);
  };

  // Keep the highlighted option visible while navigating a long list.
  useEffect(() => {
    if (!open || activeIndex < 0 || !menuRef.current) return;
    const item = menuRef.current.querySelector(`[data-index="${activeIndex}"]`);
    if (item) item.scrollIntoView({ block: "nearest" });
  }, [open, activeIndex]);

  const closeMenu = (refocus = false) => {
    setOpen(false);
    if (refocus) triggerRef.current?.focus();
  };

  const toggleMenu = () => {
    if (open) closeMenu();
    else openMenu();
  };

  const selectOption = (index) => {
    const option = filteredOptions[index];
    if (!option) return;
    onChange(option.value);
    closeMenu(true);
  };

  const clearValue = (e) => {
    e.stopPropagation();
    if (options.length > 0) {
      onChange(options[0].value);
    }
  };

  const handleTriggerKeyDown = (event) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      if (!open) openMenu();
      else setActiveIndex((index) => Math.min(filteredOptions.length - 1, index + 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      if (!open) {
        openMenu();
        setActiveIndex(filteredOptions.length - 1);
      } else {
        setActiveIndex((index) => Math.max(0, index - 1));
      }
    } else if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      if (open) {
        if (activeIndex >= 0) selectOption(activeIndex);
      } else {
        openMenu();
      }
    } else if (event.key === "Escape") {
      closeMenu();
    } else if (event.key === "Backspace" && searchable && !open) {
      openMenu();
    }
  };

  const handleMenuKeyDown = (event) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActiveIndex((index) => Math.min(filteredOptions.length - 1, index + 1));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActiveIndex((index) => Math.max(0, index - 1));
    } else if (event.key === "Home") {
      event.preventDefault();
      setActiveIndex(0);
    } else if (event.key === "End") {
      event.preventDefault();
      setActiveIndex(filteredOptions.length - 1);
    } else if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      if (activeIndex >= 0) selectOption(activeIndex);
    } else if (event.key === "Escape") {
      event.preventDefault();
      closeMenu(true);
    } else if (event.key === "Tab") {
      closeMenu();
    }
  };

  const handleSearchKeyDown = (event) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setActiveIndex((index) => Math.min(filteredOptions.length - 1, index + 1));
      if (menuRef.current) {
        const item = menuRef.current.querySelector('[data-index="0"]');
        if (item) item.scrollIntoView({ block: "nearest" });
      }
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setActiveIndex((index) => Math.max(0, index - 1));
    } else if (event.key === "Enter") {
      event.preventDefault();
      if (activeIndex >= 0) selectOption(activeIndex);
    } else if (event.key === "Escape") {
      event.preventDefault();
      closeMenu(true);
    }
  };

  // Keep activeIndex in sync with filtered options
  useEffect(() => {
    if (activeIndex >= filteredOptions.length) {
      setActiveIndex(Math.max(0, filteredOptions.length - 1));
    }
  }, [filteredOptions.length, activeIndex]);

  const showClear = clearable && selected && options.length > 0;

  return (
    <div ref={rootRef} className={`relative w-full ${className}`}>
      <button
        ref={triggerRef}
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={ariaLabel}
        disabled={disabled}
        onClick={toggleMenu}
        onKeyDown={handleTriggerKeyDown}
        className={`inline-flex h-10 w-full items-center justify-between gap-2 rounded-lg border px-3 text-xs font-semibold outline-none transition ${
          disabled
            ? "border-slate-700/50 bg-slate-800/30 text-slate-600 cursor-not-allowed"
            : "border-slate-700/80 bg-slate-800/60 text-slate-200 hover:border-slate-600 hover:bg-slate-800/80 focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/30"
        }`}
      >
        <span className="truncate">{selected ? selected.label : placeholder}</span>
        <div className="flex items-center gap-1 shrink-0">
          {loading && <Loader2 size={12} className="animate-spin text-slate-500" />}
          {showClear && (
            // Rendered as a span (not a nested <button>) because this sits
            // INSIDE the trigger <button> - nested interactive <button>
            // elements are invalid HTML and trigger React DOM warnings.
            <span
              role="button"
              tabIndex={-1}
              onClick={clearValue}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  e.stopPropagation();
                  clearValue(e);
                }
              }}
              className="p-0.5 rounded hover:bg-slate-700/60 text-slate-500 hover:text-slate-300 transition cursor-pointer"
              aria-label="Clear selection"
            >
              <X size={12} />
            </span>
          )}
          <ChevronDown
            size={14}
            className={`text-slate-500 transition-transform ${open ? "rotate-180" : ""}`}
          />
        </div>
      </button>

      {open && (
        <div
          className={`absolute left-0 right-0 z-50 mt-1.5 rounded-lg border border-slate-600 bg-slate-800 shadow-2xl shadow-black/50 ${menuClassName}`}
        >
          {searchable && (
            <div className="px-2 pt-2 pb-1">
              <div className="flex items-center gap-2 rounded-md border border-slate-700/60 bg-slate-900/60 px-2 py-1.5">
                <Search size={12} className="shrink-0 text-slate-500" />
                <input
                  ref={searchInputRef}
                  type="text"
                  value={searchQuery}
                  onChange={(e) => {
                    setSearchQuery(e.target.value);
                    setActiveIndex(0);
                  }}
                  onKeyDown={handleSearchKeyDown}
                  placeholder="Type to filter..."
                  className="w-full bg-transparent text-xs text-slate-200 placeholder:text-slate-600 outline-none"
                />
                {searchQuery && (
                  <button
                    type="button"
                    onClick={() => {
                      setSearchQuery("");
                      setActiveIndex(0);
                      searchInputRef.current?.focus();
                    }}
                    className="shrink-0 text-slate-500 hover:text-slate-300"
                  >
                    <X size={10} />
                  </button>
                )}
              </div>
            </div>
          )}

          {loading ? (
            <div className="flex items-center justify-center gap-2 py-4 text-xs text-slate-500">
              <Loader2 size={14} className="animate-spin" />
              Loading...
            </div>
          ) : filteredOptions.length === 0 ? (
            <div className="py-4 text-center text-xs text-slate-500">{emptyText}</div>
          ) : (
            <ul
              ref={menuRef}
              role="listbox"
              tabIndex={-1}
              aria-activedescendant={activeIndex >= 0 ? `${idBase}-option-${activeIndex}` : undefined}
              onKeyDown={handleMenuKeyDown}
              className="max-h-[300px] overflow-y-auto py-1"
              style={{ scrollbarWidth: "none", msOverflowStyle: "none" }}
            >
              {filteredOptions.map((option, index) => {
                const isActive = index === activeIndex;
                const isSelected = option.value === value;
                return (
                  <li
                    key={option.value}
                    id={`${idBase}-option-${index}`}
                    role="option"
                    aria-selected={isSelected}
                    data-index={index}
                    onMouseEnter={() => setActiveIndex(index)}
                    onClick={() => selectOption(index)}
                    className={`flex cursor-pointer items-center justify-between gap-2 px-3 py-2 text-xs font-semibold transition-colors ${
                      isActive
                        ? "bg-slate-700 text-cyan-400"
                        : isSelected
                          ? "bg-cyan-500/10 text-cyan-400"
                          : "text-slate-300 hover:bg-slate-700/80 hover:text-slate-100"
                    }`}
                  >
                    <span className="truncate">{option.label}</span>
                    {isSelected && <Check size={12} className="shrink-0 text-cyan-400" />}
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

export default Dropdown;
