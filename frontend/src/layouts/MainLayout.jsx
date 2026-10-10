
import { useState } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { AnimatePresence, motion } from "motion/react";

import Sidebar from "../components/Sidebar";
import Navbar from "../components/Navbar";
import LiveAlertToast from "../components/live/LiveAlertToast";
import { LiveSOCProvider } from "../context/LiveSOCContext";

function MainLayout() {
  const location = useLocation();

  const [globalSearchQuery, setGlobalSearchQuery] = useState({
    raw: "",
    tokens: {},
    keywords: [],
  });

  return (
    <LiveSOCProvider>
      <div className="flex h-dvh w-full min-w-0 overflow-hidden bg-slate-950 font-sans text-slate-100 antialiased">
        <aside className="h-full w-60 flex-none overflow-y-auto border-r border-slate-800 bg-slate-900/40">
          <Sidebar />
        </aside>

        <div className="flex h-full min-w-0 flex-1 flex-col overflow-hidden">
          <Navbar
            globalSearchQuery={globalSearchQuery}
            setGlobalSearchQuery={setGlobalSearchQuery}
          />

          <main className="min-h-0 min-w-0 flex-1 overflow-x-hidden overflow-y-auto bg-slate-950 p-4 text-slate-200 sm:p-6">
            <AnimatePresence mode="wait" initial={false}>
              <motion.div
                key={location.pathname}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -4 }}
                transition={{ duration: 0.18, ease: "easeOut" }}
                className="min-w-0"
              >
                <Outlet
                  context={{
                    globalSearchQuery,
                    setGlobalSearchQuery,
                  }}
                />
              </motion.div>
            </AnimatePresence>
          </main>
        </div>

        <LiveAlertToast />
      </div>
    </LiveSOCProvider>
  );
}

export default MainLayout;
