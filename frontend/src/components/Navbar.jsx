import { useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { User, LogOut, Search } from "lucide-react";
import { useNavigate } from "react-router-dom";

import NotificationBell from "./live/NotificationBell";
import EnterpriseSearchBar from "./EnterpriseSearchBar";

function Navbar({ globalSearchQuery, setGlobalSearchQuery }) {
  const navigate = useNavigate();
  const shouldReduceMotion = useReducedMotion();
  const [profileHovered, setProfileHovered] = useState(false);
  const [logoutHovered, setLogoutHovered] = useState(false);

  const logout = () => {
    localStorage.removeItem("token");
    navigate("/login");
  };

  const handleSearchSubmit = (query) => {
    if (!query?.raw?.trim()) return;

    setGlobalSearchQuery({
      raw: query.raw,
      tokens: query.tokens || {},
      keywords: query.keywords || [],
    });

    navigate(`/search?q=${encodeURIComponent(query.raw)}`);
  };

  const fadeIn = {
    hidden: {
      opacity: 0,
      y: shouldReduceMotion ? 0 : -12,
    },
    visible: {
      opacity: 1,
      y: 0,
      transition: {
        duration: shouldReduceMotion ? 0 : 0.45,
        ease: [0.22, 1, 0.36, 1],
      },
    },
  };

  const itemEntrance = (delay = 0) => ({
    hidden: {
      opacity: 0,
      y: shouldReduceMotion ? 0 : -8,
      scale: shouldReduceMotion ? 1 : 0.98,
    },
    visible: {
      opacity: 1,
      y: 0,
      scale: 1,
      transition: {
        duration: shouldReduceMotion ? 0 : 0.4,
        delay: shouldReduceMotion ? 0 : delay,
        ease: [0.22, 1, 0.36, 1],
      },
    },
  });

  return (
    <motion.header
      variants={fadeIn}
      initial="hidden"
      animate="visible"
      className="relative z-40 flex h-20 shrink-0 items-center justify-between overflow-visible border-b border-slate-800/60 bg-slate-950/80 px-6 backdrop-blur-xl"
    >
      {/* Subtle cinematic background lighting */}
      <div
        className="pointer-events-none absolute inset-0 overflow-hidden"
        aria-hidden="true"
      >
        <motion.div
          initial={{ opacity: 0, x: -30 }}
          animate={{
            opacity: [0.04, 0.09, 0.04],
            x: shouldReduceMotion ? 0 : [-30, 15, -30],
          }}
          transition={{
            duration: shouldReduceMotion ? 0 : 12,
            repeat: shouldReduceMotion ? 0 : Infinity,
            ease: "easeInOut",
          }}
          className="absolute -left-16 -top-20 h-40 w-72 rounded-full bg-cyan-500/20 blur-3xl"
        />

        <div className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-cyan-500/20 to-transparent" />
      </div>

      {/* Global Enterprise Search */}
      <motion.div
        variants={itemEntrance(0.08)}
        className="relative z-10 flex min-w-0 flex-1 items-center"
      >
        <div className="w-full">
          <EnterpriseSearchBar
            value={globalSearchQuery?.raw || ""}
            onChange={(val) => {
              setGlobalSearchQuery({
                raw: val,
                tokens: {},
                keywords: val ? [val] : [],
              });
            }}
            onSearchSubmit={handleSearchSubmit}
          />
        </div>
      </motion.div>

      {/* Right-side operator actions */}
      <motion.div
        initial="hidden"
        animate="visible"
        className="relative z-10 ml-5 flex shrink-0 items-center gap-3"
      >
        {/* Notifications */}
        <motion.div
          variants={itemEntrance(0.16)}
          whileHover={shouldReduceMotion ? undefined : { y: -2 }}
          whileTap={shouldReduceMotion ? undefined : { scale: 0.96 }}
          transition={{ type: "spring", stiffness: 400, damping: 25 }}
          className="relative"
        >
          <NotificationBell />
        </motion.div>

        {/* Operator profile */}
        <motion.div
          variants={itemEntrance(0.23)}
          onHoverStart={() => setProfileHovered(true)}
          onHoverEnd={() => setProfileHovered(false)}
          animate={{
            borderColor: profileHovered ? "rgba(34,211,238,0.35)" : "rgba(51,65,85,0.8)",
            backgroundColor: profileHovered ? "rgba(15,35,49,0.8)" : "rgba(15,23,42,0.4)",
          }}
          transition={{ duration: shouldReduceMotion ? 0 : 0.2 }}
          className="flex h-[44px] items-center gap-2 rounded-lg border px-3 shadow-sm"
          aria-label="Current user: MANI"
        >
          <motion.div
            animate={{
              scale: profileHovered && !shouldReduceMotion ? 1.12 : 1,
              rotate: profileHovered && !shouldReduceMotion ? -6 : 0,
            }}
            transition={{ type: "spring", stiffness: 350, damping: 18 }}
          >
            <User
              size={16}
              className="text-cyan-400"
              aria-hidden="true"
            />
          </motion.div>

          <span className="text-sm font-semibold tracking-wide text-white">
            MANI
          </span>

          <motion.span
            animate={{
              opacity: profileHovered ? 1 : 0.7,
              scale: profileHovered && !shouldReduceMotion ? 1.15 : 1,
            }}
            transition={{ duration: 0.2 }}
            className="ml-1 h-1.5 w-1.5 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.65)]"
            aria-label="Operator status indicator"
          />
        </motion.div>

        {/* Logout action */}
        <motion.button
          variants={itemEntrance(0.3)}
          type="button"
          onClick={logout}
          onHoverStart={() => setLogoutHovered(true)}
          onHoverEnd={() => setLogoutHovered(false)}
          whileHover={shouldReduceMotion ? undefined : { y: -2, scale: 1.02 }}
          whileTap={shouldReduceMotion ? undefined : { scale: 0.96 }}
          transition={{ type: "spring", stiffness: 400, damping: 22 }}
          aria-label="Logout from account"
          className="group relative flex h-[44px] items-center gap-2 overflow-hidden rounded-lg border border-red-500/20 bg-red-600 px-4 text-sm font-semibold text-white shadow-md shadow-red-950/20 transition-colors duration-200 hover:border-red-400/40 hover:bg-red-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400"
        >
          {/* Animated hover sheen */}
          <AnimatePresence>
            {logoutHovered && !shouldReduceMotion && (
              <motion.span
                key="logout-sheen"
                initial={{ x: "-120%", opacity: 0 }}
                animate={{ x: "180%", opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.55, ease: "easeInOut" }}
                className="pointer-events-none absolute inset-y-0 w-1/3 skew-x-[-20deg] bg-gradient-to-r from-transparent via-white/15 to-transparent"
                aria-hidden="true"
              />
            )}
          </AnimatePresence>

          <motion.span
            animate={{
              x: logoutHovered && !shouldReduceMotion ? 2 : 0,
            }}
            transition={{ type: "spring", stiffness: 400, damping: 20 }}
            className="relative z-10"
          >
            <LogOut size={15} aria-hidden="true" />
          </motion.span>

          <span className="relative z-10">Logout</span>
        </motion.button>
      </motion.div>
    </motion.header>
  );
}

export default Navbar;