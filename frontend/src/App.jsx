import { lazy, Suspense, useState, useEffect, useCallback } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";

import MainLayout from "./layouts/MainLayout";
import ProtectedRoute from "./components/ProtectedRoute";
import Loading from "./components/ui/Loading";
import api from "./services/api";

// Auth pages
import Login from "./pages/Login";
import Register from "./pages/Register";
import VerifyEmail from "./pages/VerifyEmail";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";

// Lazy-loaded application pages
const Dashboard = lazy(() => import("./pages/Dashboard"));
const Alerts = lazy(() => import("./pages/Alerts"));
const EnterpriseSearchResults = lazy(
  () => import("./pages/EnterpriseSearchResults")
);
const Cases = lazy(() => import("./pages/Cases"));
const Investigation = lazy(() => import("./pages/Investigation"));
const Timeline = lazy(() => import("./pages/Timeline"));
const Reports = lazy(() => import("./pages/Reports"));
const AIChat = lazy(() => import("./pages/AIChat"));
const Settings = lazy(() => import("./pages/Settings"));
const ThreatHunting = lazy(() => import("./pages/ThreatHunting"));
const ThreatIntelligence = lazy(
  () => import("./pages/ThreatIntelligence")
);

/**
 * Detects when the lazy-loaded route tree has rendered.
 */
function SuspenseSentinel({ onResolved }) {
  useEffect(() => {
    onResolved?.();
  }, [onResolved]);

  return null;
}

/**
 * Premium SOCRA AI startup screen.
 * The initial loading screen appears on a cold app start.
 */
function InitGate({ children }) {
  const [ready, setReady] = useState(false);
  const [showLoading, setShowLoading] = useState(true);
  const [childrenReady, setChildrenReady] = useState(false);

  // Check backend connectivity during startup.
  useEffect(() => {
    let active = true;

    const verify = async () => {
      try {
        const token = localStorage.getItem("token");

        if (token) {
          await api.get("/health");
        }
      } catch {
        // ProtectedRoute remains responsible for authentication.
      } finally {
        if (active) {
          setReady(true);
        }
      }
    };

    verify();

    return () => {
      active = false;
    };
  }, []);

  // Reveal the app after initialization and initial route loading.
  useEffect(() => {
    if (!ready || !childrenReady) return;

    const timer = setTimeout(() => {
      setShowLoading(false);
    }, 1400);

    return () => clearTimeout(timer);
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
        <Loading
          ready={ready}
          onComplete={handleLoadingComplete}
        />
      )}

      <div
        className="min-h-screen bg-slate-950 text-slate-200"
        style={{
          opacity: showLoading ? 0 : 1,
          transition: "opacity 0.5s ease-out",
          pointerEvents: showLoading ? "none" : "auto",
        }}
      >
        <Suspense
          fallback={
            <div className="flex min-h-screen items-center justify-center bg-slate-950">
              <div className="h-7 w-7 animate-spin rounded-full border-2 border-slate-600 border-t-slate-200" />
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
          {/* Public authentication routes */}
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/verify-email" element={<VerifyEmail />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<ResetPassword />} />

          {/* Protected application routes */}
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <MainLayout />
              </ProtectedRoute>
            }
          >
            <Route index element={<Dashboard />} />
            <Route path="search" element={<EnterpriseSearchResults />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="investigation" element={<Investigation />} />
            <Route path="cases" element={<Cases />} />
            <Route path="timeline" element={<Timeline />} />
            <Route path="reports" element={<Reports />} />
            <Route path="chat" element={<AIChat />} />
            <Route path="threat-hunting" element={<ThreatHunting />} />
            <Route path="threat-intel" element={<ThreatIntelligence />} />
            <Route path="settings" element={<Settings />} />
          </Route>
        </Routes>
      </InitGate>
    </BrowserRouter>
  );
}

export default App;