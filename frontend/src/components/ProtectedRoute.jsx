import { Navigate } from "react-router-dom";
import { useState, useEffect } from "react";

function ProtectedRoute({ children }) {
    const [isAuthenticated, setIsAuthenticated] = useState(null); // null = loading

    useEffect(() => {
        console.log("[AUTH_INITIALIZATION] ProtectedRoute auth check starting");

        const token = localStorage.getItem("token");

        if (!token) {
            console.log("[AUTH_INITIALIZATION] No token — user must log in");
            setIsAuthenticated(false);
            return;
        }

        // Basic JWT expiration check (decode payload without verification)
        try {
            const base64Url = token.split(".")[1];
            const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
            const paddedBase64 = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, "=");
            const payload = JSON.parse(atob(paddedBase64));

            // Add 5-minute buffer for clock drift between client/server
            const nowSec = Math.floor(Date.now() / 1000);
            if (payload.exp && (payload.exp + 300) < nowSec) {
                console.log("[AUTH_INITIALIZATION] Token expired — clearing and requiring re-login");
                localStorage.removeItem("token");
                setIsAuthenticated(false);
                return;
            }

            console.log("[AUTH_INITIALIZATION] Token valid — user authenticated");
            setIsAuthenticated(true);
        } catch (e) {
            console.error("[AUTH_INITIALIZATION] JWT decode error:", e.message);
            const tokenParts = token.split(".");
            if (tokenParts.length !== 3) {
                console.log("[AUTH_INITIALIZATION] Invalid token format — clearing");
                localStorage.removeItem("token");
                setIsAuthenticated(false);
                return;
            }
            // Token format looks correct, trust the backend to validate on API calls
            console.log("[AUTH_INITIALIZATION] Token format valid — trusting backend validation");
            setIsAuthenticated(true);
        }
    }, []); // Run only once on mount

    // Still checking — show loading. This state prevents redirect loops because
    // no Navigate or redirect is rendered while null.
    if (isAuthenticated === null) {
        return (
            <div className="flex items-center justify-center h-screen bg-slate-950">
                <div className="text-slate-400">Loading...</div>
            </div>
        );
    }

    // Not authenticated — redirect to login
    if (!isAuthenticated) {
        return <Navigate to="/login" replace />;
    }

    // Authenticated — render protected content
    return children;
}

export default ProtectedRoute;
