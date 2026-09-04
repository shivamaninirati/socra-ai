/**
 * SOCRA AI Enterprise Taxonomy & Theme Specification
 * Cohesive color registry matching standard SIEM platform models (Splunk/Wazuh)
 */

export const SEVERITY_MAP = {
  critical: {
    label: "Critical",
    hex: "#ef4444", // Red 500
    bg: "bg-red-500/10",
    border: "border-red-500/20",
    text: "text-red-400",
    dot: "bg-red-500"
  },
  high: {
    label: "High",
    hex: "#f97316", // Orange 500
    bg: "bg-orange-500/10",
    border: "border-orange-500/20",
    text: "text-orange-400",
    dot: "bg-orange-500"
  },
  medium: {
    label: "Medium",
    hex: "#eab308", // Yellow 500
    bg: "bg-yellow-500/10",
    border: "border-yellow-500/20",
    text: "text-yellow-400",
    dot: "bg-yellow-500"
  },
  low: {
    label: "Low",
    hex: "#22c55e", // Green 500
    bg: "bg-green-500/10",
    border: "border-green-500/20",
    text: "text-green-400",
    dot: "bg-green-500"
  },
  informational: {
    label: "Informational",
    hex: "#3b82f6", // Blue 500
    bg: "bg-blue-500/10",
    border: "border-blue-500/20",
    text: "text-blue-400",
    dot: "bg-blue-500"
  }
};

export const normalizeSeverity = (rawSev) => {
  const clean = String(rawSev || "").trim().toLowerCase();
  if (clean === "crit") return "critical";
  if (clean === "info") return "informational";
  return SEVERITY_MAP[clean] ? clean : "informational";
};