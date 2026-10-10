// Run this in your browser's devtools console to debug the login loop
console.log("=== AUTH DEBUG TOOL ===");

// Check if token exists in localStorage
const token = localStorage.getItem("token");
console.log("Token exists:", !!token);
if (token) {
  try {
    const parts = token.split(".");
    console.log("Token parts:", parts.length);
    if (parts.length === 3) {
      const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/").padEnd(parts[1].length + (4 - parts[1].length % 4) % 4, "=")));
      console.log("Payload:", payload);
      console.log("Expiration (UTC):", new Date(payload.exp * 1000).toISOString());
      console.log("Current time (UTC):", new Date().toISOString());
      console.log("Token valid for (seconds):", payload.exp - Math.floor(Date.now() / 1000));
    }
  } catch (e) {
    console.error("Token decode error:", e);
  }
}

// List all localStorage items
console.log("All localStorage items:", Object.keys(localStorage));