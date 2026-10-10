// Shared enterprise security color definitions
export const SEVERITY_COLORS = {
  Critical: "#ef4444",      // Vibrant Red
  High: "#f97316",          // Orange Alert
  Medium: "#eab308",        // Tactical Yellow
  Low: "#22c55e",           // Success Green
  Informational: "#3b82f6", // Infrastructure Blue
};

// Strict layout priority sequencing
export const PREFERRED_ORDER = ["Critical", "High", "Medium", "Low", "Informational"];

// Recharts Legend re-sorts its entries with its default itemSorter ('value'),
// which alphabetizes them (CRITICAL, HIGH, INFORMATIONAL, LOW, MEDIUM).
// This rank restores the SOC severity order: Critical -> High -> Medium -> Low -> Informational.
export const severityRank = (label) => {
  const idx = PREFERRED_ORDER.findIndex((name) => name.toUpperCase() === String(label ?? "").toUpperCase());
  return idx === -1 ? PREFERRED_ORDER.length : idx;
};

// Stable module-level Recharts Legend `itemSorter` (function identity stays
// constant across renders so the Legend settings effect does not re-run).
export const severityLegendSorter = (entry) => severityRank(entry?.value);