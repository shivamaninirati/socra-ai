/**
 * Frontend safety guard for autocomplete suggestion values.
 * Rejects raw XML, payloads, and overly long strings.
 */

const MAX_SUGGESTION_LENGTH = 150;

export function isCleanSuggestion(value) {
  if (!value || typeof value !== "string") return false;
  if (value.length > MAX_SUGGESTION_LENGTH) return false;
  if (value.includes("<") || value.includes(">")) return false;
  if (value.includes("\n") || value.includes("\r")) return false;
  return true;
}

/**
 * Filter a list of suggestion values, keeping only clean ones.
 */
export function filterCleanSuggestions(values) {
  if (!Array.isArray(values)) return [];
  return values.filter(isCleanSuggestion);
}
