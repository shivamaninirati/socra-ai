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
import logo from "../assets/socra-logo.png";

function Sidebar() {
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

  return (
    <div className="h-full flex flex-col text-slate-200 p-4 select-none">
      
      {/* Premium Standalone Brand Area */}
      <div className="flex items-center gap-4 px-2 py-2 mb-4 shrink-0">
        {/* Logo - Maximized standalone scaling with zero bounding shape boxes */}
        <img
          src={logo}
          alt="SOCRA AI"
          className="w-17 h-17 object-contain shrink-5"
        />
        
        {/* Brand Text Content */}
        <div className="flex flex-col min-w-0 justify-center -ml-3">
          <h1 className="text-xl font-bold tracking-wider text-white leading-none">
            SOCRA AI
          </h1>
          <p className="text-[10px] text-slate-400 font-medium leading-normal mt-1.5 break-words max-w-[150px]">
            Security Investigation
            <br />
            Platform
          </p>
        </div>
      </div>

      {/* Technical Separation Rule */}
      <div className="h-[1px] bg-slate-800 mx-2 mb-5 shrink-0"></div>

      {/* Categorization Accent Label */}
      <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-slate-500 px-3 mb-3 shrink-0">
        Main Menu
      </p>

      {/* Navigation Options Interactive Matrix */}
      <nav className="space-y-1 flex-1 px-1 overflow-y-auto">
        {menu.map((item) => {
          const Icon = item.icon;

          return (
            <NavLink
              key={item.name}
              to={item.path}
              end={item.path === "/"}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 ease-in-out group relative ${
                  isActive
                    ? "bg-slate-900 border border-slate-800 text-cyan-400 shadow-sm"
                    : "text-slate-400 border border-transparent hover:bg-slate-900/40 hover:text-slate-100"
                }`
              }
            >
              {({ isActive }) => (
                <>
                  {/* Left Active Indicator Ribbon */}
                  {isActive && (
                    <span className="absolute left-0 top-1/4 bottom-1/4 w-[3px] rounded-r-md bg-cyan-400" />
                  )}

                  <Icon
                    size={16}
                    className={`shrink-0 transition-colors duration-150 ${
                      isActive ? "text-cyan-400" : "text-slate-500 group-hover:text-slate-300"
                    }`}
                  />
                  <span className="truncate tracking-wide">{item.name}</span>
                </>
              )}
            </NavLink>
          );
        })}
      </nav>

      {/* Technical Infrastructure Connected Console Tag */}
      <div className="pt-3 border-t border-slate-900 mt-auto shrink-0 px-1">
        <div className="flex items-center gap-2 px-2.5 py-2 rounded-md bg-slate-900/30 border border-slate-900">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse shadow-sm shadow-emerald-400" />
          <span className="text-[9px] text-slate-400 font-bold tracking-wider uppercase">
            Console Live
          </span>
        </div>
      </div>

    </div>
  );
}

export default Sidebar;