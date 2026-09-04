import { lazy, Suspense, useState, useEffect, useCallback } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";

import MainLayout from "./layouts/MainLayout";
import ProtectedRoute from "./components/ProtectedRoute";
import Loading from "./components/ui/Loading";
import api from "./services/api";

// Auth pages (loaded eagerly for fast initial render)
import Login from "./pages/Login";
import Register from "./pages/Register";
import VerifyEmail from "./pages/VerifyEmail";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";

// Route-level code splitting (Task 29): each major page is loaded on demand,
// so the initial bundle stays small. All chunks share one consistent loading
// state via the Suspense fallback below.
const Dashboard = lazy(() => import("./pages/Dashboard"));
const Alerts = lazy(() => import("./pages/Alerts"));
const EnterpriseSearchResults = lazy(() => import("./pages/EnterpriseSearchResults"));
const Cases = lazy(() => import("./pages/Cases"));
const Investigation = lazy(() => import("./pages/Investigation"));
const Timeline = lazy(() => import("./pages/Timeline"));
const Reports = lazy(() => import("./pages/Reports"));
const AIChat = lazy(() => import("./pages/AIChat"));
const Settings = lazy(() => import("./pages/Settings"));
const ThreatHunting = lazy(() => import("./pages/ThreatHunting"));
const ThreatIntelligence = lazy(() => import("./pages/ThreatIntelligence"));

/**
 * Tiny sentinel that fires onMounted once after Suspense resolves.
 * Placed inside the Suspense boundary to detect when lazy chunks finish.
 */
function SuspenseSentinel({ onResolved }) {
  useEffect(() => {
    onResolved?.();
  }, [onResolved]);
  return null;
}

/**
 * Gate component that shows the premium SOCRA AI loading screen during
 * initial app startup, then reveals the children with a smooth fade.
 *
 * Initialization checks:
 *  1. Verify the stored JWT is still valid (GET /health)
 *  2. Wait for React Suspense chunks to resolve (the lazy children)
 *
 * The loading screen only appears on genuine cold-start. Page refreshes,
 * navigation within the app, and login→dashboard transitions are NOT
 * gated — only the very first mount after a fresh load.
 */
function InitGate({ children }) {
  const [ready, setReady] = useState(false);
  const [showLoading, setShowLoading] = useState(true);
  const [childrenReady, setChildrenReady] = useState(false);

  // Phase 1: verify backend connectivity + auth
  useEffect(() => {
    const verify = async () => {
      try {
        const token = localStorage.getItem("token");
        if (!token) {
          setReady(true);
          return;
        }
        await api.get("/health");
        setReady(true);
      } catch {
        // Backend unreachable or token invalid — still show the screen
        // then let ProtectedRoute handle the redirect to /login
        setReady(true);
      }
    };
    verify();
  }, []);

  // Phase 2: once ready AND children (lazy chunks) are loaded, fade out
  useEffect(() => {
    if (ready && childrenReady) {
      // Small delay so the SYSTEM READY text is visible
      const t = setTimeout(() => setShowLoading(false), 1400);
      return () => clearTimeout(t);
    }
  }, [ready, childrenReady]);

  const handleLoadingComplete = useCallback(() => {
    setShowLoading(false);
  }, []);

  const handleChildrenResolved = useCallback(() => {
    setChildrenReady(true);
  }, []);

  return (
    <>
      {showLoading && (
        <Loading ready={ready} onComplete={handleLoadingComplete} />
      )}
      <div
        style={{
          opacity: showLoading ? 0 : 1,
          transition: "opacity 0.5s ease-out",
          pointerEvents: showLoading ? "none" : "auto",
        }}
      >
        <Suspense
          fallback={
            <div className="flex items-center justify-center h-screen bg-slate-950">
              <div className="animate-spin w-6 h-6 border-2 border-cyan-400 border-t-transparent rounded-full" />
            </div>
          }
        >
          <SuspenseSentinel onResolved={handleChildrenResolved} />
          {children}
        </Suspense>
      </div>
    </>
  );
}

function App() {

    return (

        <BrowserRouter>

            <InitGate>

                <Routes>

                    {/* Auth routes (public) */}
                    <Route path="/login" element={<Login />} />
                    <Route path="/register" element={<Register />} />
                    <Route path="/verify-email" element={<VerifyEmail />} />
                    <Route path="/forgot-password" element={<ForgotPassword />} />
                    <Route path="/reset-password" element={<ResetPassword />} />

                    {/* Protected routes */}
                    <Route
                        path="/"
                        element={
                            <ProtectedRoute>
                                <MainLayout />
                            </ProtectedRoute>
                        }
                    >

                        <Route
                            index
                            element={<Dashboard />}
                        />

                        <Route
                            path="search"
                            element={<EnterpriseSearchResults />}
                        />

                        <Route
                            path="alerts"
                            element={<Alerts />}
                        />

                        <Route
                            path="investigation"
                            element={<Investigation />}
                        />

                        <Route
                            path="cases"
                            element={<Cases />}
                        />

                        <Route
                            path="timeline"
                            element={<Timeline />}
                        />

                        <Route
                            path="reports"
                            element={<Reports />}
                        />

                        <Route
                            path="chat"
                            element={<AIChat />}
                        />

                        <Route
                            path="threat-hunting"
                            element={<ThreatHunting />}
                        />

                        <Route
                            path="threat-intel"
                            element={<ThreatIntelligence />}
                        />

                        <Route
                            path="settings"
                            element={<Settings />}
                        />

                    </Route>

                </Routes>

            </InitGate>

        </BrowserRouter>

    );

}

export default App;
