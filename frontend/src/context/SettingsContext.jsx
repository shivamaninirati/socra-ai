import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

// =========================================================================
// Application settings store (frontend-local preferences only — never
// credentials). Persisted to localStorage so the three preference toggles
// (dark theme, notifications, auto-refresh) survive page refresh, route
// changes and frontend restarts.
//
// These settings control presentation/behavior ONLY. They never touch the
// telemetry pipeline (collector → parser → processor → detection → database
// → WebSocket), which keeps running regardless of any UI preference.
// =========================================================================

const SETTINGS_STORAGE_KEY = "socra-settings";

const DEFAULT_SETTINGS = {
  // Dark UI Theme Canvas — ON (default) keeps the SOCRA AI dark palette.
  darkTheme: true,
  // Real-time System Notifications — ON (default) shows bell/toast alerts.
  notifications: true,
  // Auto Refresh Alerts — ON (default) live-inserts new telemetry into the
  // Alerts table via the WebSocket stream.
  autoRefresh: true,
};

const loadSettings = () => {
  try {
    const stored = JSON.parse(localStorage.getItem(SETTINGS_STORAGE_KEY) || "null");
    return { ...DEFAULT_SETTINGS, ...(stored && typeof stored === "object" ? stored : {}) };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
};

const persistSettings = (settings) => {
  localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(settings));
};

const SettingsContext = createContext(null);

export function SettingsProvider({ children }) {
  // Lazy init: read once from localStorage AND apply the theme class before
  // first paint so there is no dark-to-light flash on refresh.
  const [settings, setSettings] = useState(() => {
    const initial = loadSettings();
    document.documentElement.classList.toggle("light", initial.darkTheme === false);
    return initial;
  });

  const [saveError, setSaveError] = useState("");

  // Keep the theme class in sync whenever the preference changes.
  useEffect(() => {
    document.documentElement.classList.toggle("light", settings.darkTheme === false);
  }, [settings.darkTheme]);

  // Optimistic update: apply immediately; if persistence fails, revert the
  // switch and surface a friendly error so the UI never lies about state.
  const updateSetting = useCallback((key, value) => {
    if (!(key in DEFAULT_SETTINGS)) return false;

    let persisted = false;
    setSettings((prev) => {
      const next = { ...prev, [key]: value };
      try {
        persistSettings(next);
        persisted = true;
      } catch {
        // Persistence failed — revert to the previous value.
        setSaveError("Unable to save setting.");
        return prev;
      }
      setSaveError("");
      return next;
    });
    return persisted;
  }, []);

  const clearSaveError = useCallback(() => setSaveError(""), []);

  const value = useMemo(() => ({
    settings,
    updateSetting,
    saveError,
    clearSaveError,
  }), [settings, updateSetting, saveError, clearSaveError]);

  return (
    <SettingsContext.Provider value={value}>
      {children}
    </SettingsContext.Provider>
  );
}

export function useSettings() {
  const context = useContext(SettingsContext);
  if (!context) {
    throw new Error("useSettings must be used inside a SettingsProvider.");
  }
  return context;
}
