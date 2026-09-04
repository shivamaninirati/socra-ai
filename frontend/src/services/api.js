import axios from "axios";

// Environment-driven API base URL (VITE_API_URL) with a local-development
// default. Production hosts are configured at build time via the environment,
// never by editing source code.
const API_BASE_URL = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

const api = axios.create({
    baseURL: API_BASE_URL,
});

// Attach the JWT to every API request automatically. We also record *which*
// token was attached on the request config so the 401 handler can tell a
// genuine session expiry apart from stale responses sent by requests that
// fired before login (or with an older, already-replaced token).
api.interceptors.request.use((config) => {
    const token = localStorage.getItem("token");
    if (token) {
        config.headers = config.headers || {};
        config.headers.Authorization = `Bearer ${token}`;
        config._authToken = token;
    }
    return config;
});

// On a GENUINE 401 (the request carried the exact token that is still stored —
// i.e. the server just rejected the current session) clear it and return to
// login. Everything else is deliberately ignored:
//   - Requests fired while logged out (e.g. background analytics) may come back
//     401 long after the user has signed in — they must not wipe the new token.
//   - A 401 for an old token must not kill a newer session created after it
//     was sent.
//   - Network errors / timeouts (no response at all) never log the user out.
// The login request itself is exempt so bad credentials still show the inline
// error on the Login page.
api.interceptors.response.use(
    (response) => response,
    (error) => {
        const status = error?.response?.status;
        const url = error?.config?.url || "";
        const requestToken = error?.config?._authToken;
        const currentToken = localStorage.getItem("token");

        if (
            status === 401 &&
            url !== "/login" &&
            requestToken &&
            requestToken === currentToken
        ) {
            console.log("[LOGOUT_TRIGGERED] 401 on", url, "— token rejected by server, clearing session");
            localStorage.removeItem("token");
            if (window.location.pathname !== "/login") {
                window.location.href = "/login";
            }
        }
        return Promise.reject(error);
    }
);

export default api;