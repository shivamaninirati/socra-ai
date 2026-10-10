import {
  LayoutDashboard,
  Bell,
  Clock3,
  FileText,
  Bot,
  Settings,
  Search,
  FolderOpen,
  Crosshair,
  ShieldCheck,
} from "lucide-react";

import { NavLink } from "react-router-dom";
import {
  motion,
  AnimatePresence,
  useReducedMotion,
} from "motion/react";
import { useState } from "react";
import logo from "../assets/socra-logo.png";

const sidebarVariants = {
  hidden: {
    opacity: 0,
    x: -12,
  },
  visible: {
    opacity: 1,
    x: 0,
    transition: {
      duration: 0.55,
      ease: [0.22, 1, 0.36, 1],
      staggerChildren: 0.055,
      delayChildren: 0.08,
    },
  },
};

const itemVariants = {
  hidden: {
    opacity: 0,
    x: -10,
    filter: "blur(3px)",
  },
  visible: {
    opacity: 1,
    x: 0,
    filter: "blur(0px)",
    transition: {
      duration: 0.35,
      ease: [0.22, 1, 0.36, 1],
    },
  },
};

const menu = [
  {
    name: "Dashboard",
    path: "/",
    icon: LayoutDashboard,
  },
  {
    name: "Alerts",
    path: "/alerts",
    icon: Bell,
  },
  {
    name: "Investigation",
    path: "/investigation",
    icon: Search,
  },
  {
    name: "Cases",
    path: "/cases",
    icon: FolderOpen,
  },
  {
    name: "Timeline",
    path: "/timeline",
    icon: Clock3,
  },
  {
    name: "Threat Hunting",
    path: "/threat-hunting",
    icon: Crosshair,
  },
  {
    name: "Threat Intelligence",
    path: "/threat-intel",
    icon: ShieldCheck,
  },
  {
    name: "Reports",
    path: "/reports",
    icon: FileText,
  },
  {
    name: "AI Assistant",
    path: "/chat",
    icon: Bot,
  },
  {
    name: "Settings",
    path: "/settings",
    icon: Settings,
  },
];

function Sidebar() {
  const shouldReduceMotion = useReducedMotion();
  const [logoHovered, setLogoHovered] = useState(false);

  return (
    <motion.div
      variants={sidebarVariants}
      initial="hidden"
      animate="visible"
      className="relative flex h-full flex-col select-none overflow-hidden p-4 text-slate-200"
    >
      {/* Cinematic ambient background */}
      <div
        className="pointer-events-none absolute inset-0 overflow-hidden"
        aria-hidden="true"
      >
        <motion.div
          animate={
            shouldReduceMotion
              ? { opacity: 0.04 }
              : {
                  opacity: [0.025, 0.07, 0.025],
                  y: [0, 25, 0],
                  x: [0, 8, 0],
                }
          }
          transition={{
            duration: 12,
            repeat: shouldReduceMotion ? 0 : Infinity,
            ease: "easeInOut",
          }}
          className="absolute -left-20 top-12 h-64 w-48 rounded-full bg-cyan-500/20 blur-3xl"
        />

        <div className="absolute bottom-0 right-0 h-48 w-32 rounded-full bg-blue-500/[0.04] blur-3xl" />
      </div>

      {/* Brand */}
      <motion.div
        variants={itemVariants}
        className="relative z-10 mb-4 flex shrink-0 items-center gap-4 px-2 py-2"
      >
        <motion.div
          onHoverStart={() => setLogoHovered(true)}
          onHoverEnd={() => setLogoHovered(false)}
          whileHover={
            shouldReduceMotion
              ? undefined
              : {
                  scale: 1.06,
                  rotate: -2,
                }
          }
          whileTap={shouldReduceMotion ? undefined : { scale: 0.96 }}
          transition={{
            type: "spring",
            stiffness: 280,
            damping: 18,
          }}
          className="relative flex h-12 w-12 shrink-0 items-center justify-center"
        >
          <AnimatePresence>
            {logoHovered && !shouldReduceMotion && (
              <motion.div
                key="logo-glow"
                initial={{ opacity: 0, scale: 0.7 }}
                animate={{ opacity: 0.65, scale: 1.3 }}
                exit={{ opacity: 0, scale: 0.8 }}
                transition={{ duration: 0.25 }}
                className="absolute inset-0 rounded-full bg-cyan-400/20 blur-xl"
              />
            )}
          </AnimatePresence>

          <motion.img
            src={logo}
            alt="SOCRA AI"
            className="relative z-10 h-12 w-12 object-contain"
            animate={
              shouldReduceMotion
                ? { opacity: 1 }
                : { opacity: [0.96, 1, 0.96] }
            }
            transition={{
              duration: 4,
              repeat: shouldReduceMotion ? 0 : Infinity,
              ease: "easeInOut",
            }}
          />
        </motion.div>

        <div className="-ml-3 flex min-w-0 flex-col justify-center">
          <motion.h1
            initial={{ opacity: 0, letterSpacing: "0.05em" }}
            animate={{ opacity: 1, letterSpacing: "0.12em" }}
            transition={{ duration: 0.6, delay: 0.15 }}
            className="text-xl font-bold leading-none text-white"
          >
            SOCRA AI
          </motion.h1>

          <p className="mt-1.5 max-w-[150px] break-words text-[10px] font-medium leading-normal text-slate-400">
            Security Investigation
            <br />
            Platform
          </p>
        </div>
      </motion.div>

      {/* Animated separator */}
      <motion.div
        variants={itemVariants}
        className="relative mx-2 mb-5 h-px shrink-0 overflow-hidden bg-slate-800"
      >
        <motion.div
          initial={{ x: "-100%" }}
          animate={{ x: "100%" }}
          transition={{
            duration: shouldReduceMotion ? 0 : 2,
            delay: 0.4,
            ease: "easeInOut",
          }}
          className="absolute inset-y-0 w-1/2 bg-gradient-to-r from-transparent via-cyan-400/70 to-transparent"
        />
      </motion.div>

      {/* Section heading */}
      <motion.div
        variants={itemVariants}
        className="relative z-10 mb-3 flex shrink-0 items-center justify-between px-3"
      >
        <p className="text-xs font-bold uppercase tracking-[0.2em] text-slate-400">
          Main Menu
        </p>

        <motion.span
          initial={{ opacity: 0, scale: 0.7 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.45, duration: 0.3 }}
          className="h-1.5 w-1.5 rounded-full bg-cyan-400/70"
        />
      </motion.div>

      {/* Navigation */}
      <nav
        aria-label="Main navigation"
        className="relative z-10 flex-1 space-y-1 overflow-y-auto px-1 pb-2"
      >
        {menu.map((item, index) => {
          const Icon = item.icon;

          return (
            <motion.div
              key={item.name}
              variants={itemVariants}
              whileHover={
                shouldReduceMotion
                  ? undefined
                  : { x: 3 }
              }
              whileTap={
                shouldReduceMotion
                  ? undefined
                  : { scale: 0.985 }
              }
              transition={{
                type: "spring",
                stiffness: 380,
                damping: 25,
              }}
            >
              <NavLink
                to={item.path}
                end={item.path === "/"}
                aria-label={`Navigate to ${item.name} page`}
                className={({ isActive }) =>
                  [
                    "group relative flex items-center gap-3 rounded-lg",
                    "border px-3 py-3 text-sm font-medium",
                    "transition-colors duration-200",
                    "focus:outline-none focus-visible:ring-1",
                    "focus-visible:ring-cyan-500/50",
                    isActive
                      ? "border-slate-800 bg-slate-900/80 text-cyan-400"
                      : "border-transparent text-slate-400 hover:bg-slate-900/50 hover:text-slate-100",
                  ].join(" ")
                }
              >
                {({ isActive }) => (
                  <>
                    {/* Animated active background */}
                    {isActive && (
                      <motion.span
                        layoutId="sidebar-active-background"
                        transition={{
                          type: "spring",
                          stiffness: 340,
                          damping: 30,
                        }}
                        className="absolute inset-0 rounded-lg bg-gradient-to-r from-cyan-500/[0.07] via-cyan-500/[0.025] to-transparent"
                        aria-hidden="true"
                      />
                    )}

                    {/* Sliding active indicator */}
                    {isActive && (
                      <motion.span
                        layoutId="sidebar-active-indicator"
                        initial={false}
                        transition={{
                          type: "spring",
                          stiffness: 420,
                          damping: 32,
                        }}
                        className="absolute bottom-2.5 left-0 top-2.5 w-[3px] rounded-r-md bg-cyan-400 shadow-[0_0_10px_rgba(34,211,238,0.45)]"
                        aria-hidden="true"
                      />
                    )}

                    {/* Navigation icon */}
                    <motion.span
                      className="relative z-10 flex shrink-0 items-center justify-center"
                      animate={{
                        color: isActive ? "#22d3ee" : "#64748b",
                      }}
                      whileHover={
                        shouldReduceMotion
                          ? undefined
                          : {
                              y: -1.5,
                              scale: 1.1,
                              rotate: -3,
                            }
                      }
                      transition={{
                        type: "spring",
                        stiffness: 360,
                        damping: 18,
                      }}
                    >
                      <Icon
                        size={16}
                        strokeWidth={isActive ? 2.2 : 1.8}
                        className={
                          isActive
                            ? "text-cyan-400"
                            : "text-slate-500 group-hover:text-slate-300"
                        }
                        aria-hidden="true"
                      />
                    </motion.span>

                    {/* Navigation label */}
                    <span className="relative z-10 truncate tracking-wide">
                      {item.name}
                    </span>

                    {/* Active status marker */}
                    <AnimatePresence>
                      {isActive && (
                        <motion.span
                          key="active-dot"
                          initial={{
                            opacity: 0,
                            scale: 0,
                          }}
                          animate={{
                            opacity: 1,
                            scale: 1,
                          }}
                          exit={{
                            opacity: 0,
                            scale: 0,
                          }}
                          transition={{
                            type: "spring",
                            stiffness: 400,
                            damping: 20,
                          }}
                          className="relative z-10 ml-auto h-1.5 w-1.5 shrink-0 rounded-full bg-cyan-400 shadow-[0_0_7px_rgba(34,211,238,0.5)]"
                          aria-hidden="true"
                        />
                      )}
                    </AnimatePresence>
                  </>
                )}
              </NavLink>
            </motion.div>
          );
        })}
      </nav>

      {/* Console status */}
      <motion.div
        variants={itemVariants}
        className="relative z-10 mt-auto shrink-0 border-t border-slate-900 px-1 pt-3"
      >
        <motion.div
          whileHover={
            shouldReduceMotion
              ? undefined
              : { backgroundColor: "rgba(15,23,42,0.65)" }
          }
          transition={{ duration: 0.2 }}
          className="relative flex items-center gap-2 overflow-hidden rounded-md border border-slate-900 bg-slate-900/30 px-2.5 py-2"
        >
          <motion.span
            animate={
              shouldReduceMotion
                ? { opacity: 1 }
                : {
                    opacity: [1, 0.45, 1],
                    scale: [1, 0.85, 1],
                  }
            }
            transition={{
              duration: 2,
              repeat: shouldReduceMotion ? 0 : Infinity,
              ease: "easeInOut",
            }}
            className="h-1.5 w-1.5 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.6)]"
          />

          <span className="text-[9px] font-bold uppercase tracking-wider text-slate-400">
            Console Live
          </span>

          <span className="ml-auto text-[8px] font-medium tracking-wider text-emerald-500/80">
            ACTIVE
          </span>
        </motion.div>
      </motion.div>
    </motion.div>
  );
}

export default Sidebar;