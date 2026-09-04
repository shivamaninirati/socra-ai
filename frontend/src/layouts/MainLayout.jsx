import { useState } from "react";
import { Outlet } from "react-router-dom";

import Sidebar from "../components/Sidebar";
import Navbar from "../components/Navbar";
import LiveAlertToast from "../components/live/LiveAlertToast";

// The live SOC pipeline (WebSocket + analytics REST snapshot) is mounted here —
// inside the authenticated layout — so it only runs with a valid JWT. Mounting
// it at the app root previously fired unauthenticated requests from /login and
// their 401 responses cleared freshly-issued tokens (auto-logout bug).
import { LiveSOCProvider } from "../context/LiveSOCContext";

function MainLayout() {
  // =====================================================
  // Global Enterprise Search State
  // =====================================================

  const [globalSearchQuery, setGlobalSearchQuery] = useState({
    raw: "",
    tokens: {},
    keywords: [],
  });  return (

    <LiveSOCProvider>

    <div className="flex h-screen w-screen bg-slate-950 text-slate-100 overflow-hidden font-sans antialiased">
      {/* Sidebar */}
      <aside className="w-60 flex-none h-full border-r border-slate-800 bg-slate-900/40 overflow-y-auto">
        <Sidebar />
      </aside>

      {/* Main Content */}
      <div className="flex flex-col flex-1 min-w-0 h-full overflow-hidden">
        {/* Enterprise Navbar */}
        <Navbar
          globalSearchQuery={globalSearchQuery}
          setGlobalSearchQuery={setGlobalSearchQuery}
        />

        {/* Routed Pages */}
        <main className="flex-1 overflow-y-auto p-6 bg-slate-950 text-slate-200">
          <Outlet
            context={{
              globalSearchQuery,
              setGlobalSearchQuery,
            }}
          />
        </main>
      </div>

      {/* Live Alert Toast */}
      <LiveAlertToast />
    </div>

    </LiveSOCProvider>
  );
}

export default MainLayout;