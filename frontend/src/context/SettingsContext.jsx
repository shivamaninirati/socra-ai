import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

const SETTINGS_STORAGE_KEY = "socra-settings";

const DEFAULT_SETTINGS = {
  darkTheme: true,
  notifications: true,
  autoRefresh: true,
};

const loadSettings = () => {
  try {
    const stored = JSON.parse(
      localStorage.getItem(SETTINGS_STORAGE_KEY) || "null"
    );

    if (!stored || typeof stored !== "object" || Array.isArray(stored)) {
      return { ...DEFAULT_SETTINGS };
    }

    return {
      darkTheme:
        typeof stored.darkTheme === "boolean"
          ? stored.darkTheme
          : DEFAULT_SETTINGS.darkTheme,
      notifications:
        typeof stored.notifications === "boolean"
          ? stored.notifications
          : DEFAULT_SETTINGS.notifications,
      autoRefresh:
        typeof stored.autoRefresh === "boolean"
          ? stored.autoRefresh
          : DEFAULT_SETTINGS.autoRefresh,
    };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
};

const persistSettings = (settings) => {
  localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(settings));
};

const applyTheme = (darkTheme) => {
  const root = document.documentElement;

  // Keep both selectors synchronized for compatibility with existing CSS.
  root.classList.toggle("dark", darkTheme);
  root.classList.toggle("light", !darkTheme);

  // Supports stylesheets using data-theme="dark" or data-theme="light".
  root.dataset.theme = darkTheme ? "dark" : "light";
};

const SettingsContext = createContext(null);

export function SettingsProvider({ children }) {
  const [settings, setSettings] = useState(() => {
    const initial = loadSettings();

    // Apply the saved theme before the first React render.
    if (typeof document !== "undefined") {
      applyTheme(initial.darkTheme);
    }

    return initial;
  });

  const [saveError, setSaveError] = useState("");

  // Synchronize the active theme across the application.
  useEffect(() => {
    applyTheme(settings.darkTheme);
  }, [settings.darkTheme]);

  // Persist and update a supported preference.
  const updateSetting = useCallback((key, value) => {
    if (
      !Object.prototype.hasOwnProperty.call(DEFAULT_SETTINGS, key) ||
      typeof value !== "boolean"
    ) {
      return false;
    }

    try {
      const current = loadSettings();
      const next = {
        ...current,
        [key]: value,
      };

      persistSettings(next);

      setSettings(next);
      setSaveError("");

      return true;
    } catch {
      setSaveError("Unable to save setting. Please try again.");
      return false;
    }
  }, []);

  const clearSaveError = useCallback(() => {
    setSaveError("");
  }, []);

  const value = useMemo(
    () => ({
      settings,
      updateSetting,
      saveError,
      clearSaveError,
    }),
    [settings, updateSetting, saveError, clearSaveError]
  );

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

export default SettingsContext;