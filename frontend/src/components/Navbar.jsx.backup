import {
  User,
  LogOut,
} from "lucide-react";

import NotificationBell from "./live/NotificationBell";
import EnterpriseSearchBar from "./EnterpriseSearchBar";
import { useNavigate } from "react-router-dom";

function Navbar({ globalSearchQuery, setGlobalSearchQuery }) {
  const navigate = useNavigate();

  const logout = () => {
    localStorage.removeItem("token");
    navigate("/login");
  };

  const handleSearchSubmit = (query) => {
    if (!query?.raw?.trim()) return;
    
    // Update global search state
    setGlobalSearchQuery({
      raw: query.raw,
      tokens: query.tokens || {},
      keywords: query.keywords || [],
    });
    
    // Navigate to Enterprise Search Results page
    navigate(`/search?q=${encodeURIComponent(query.raw)}`);
  };

  return (
    <header className="h-20 bg-transparent border-b border-slate-800/60 px-6 flex items-center justify-between shrink-0 select-none z-40">
      
      {/* Left Section: Enterprise Global Search Bar */}
      <div className="flex items-center w-[58%] min-w-[400px]">
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
      </div>

      {/* Right Section: Core Action Center */}
      <div className="flex items-center gap-3">
        
        {/* Real-time Notifications Portal */}
        <div className="transform scale-100">
          <NotificationBell />
        </div>

        {/* Unified Operator Profile Tag */}
        <div className="flex items-center gap-2 px-3 py-2 h-[44px] rounded-lg bg-slate-900/40 border border-slate-700 shadow-sm">
          <User size={16} className="text-cyan-400" />
          <span className="text-sm text-white font-semibold tracking-wide">
            MANI
          </span>
        </div>

        {/* Premium Session Logout Action Trigger */}
        <button
          onClick={logout}
          className="flex items-center gap-2 px-4 py-2 h-[44px] rounded-lg bg-red-600 hover:bg-red-500 transition-all duration-150 text-sm font-semibold text-white shadow-md shadow-red-950/20 group"
        >
          <LogOut size={15} className="transition-transform duration-150 group-hover:translate-x-0.5" />
          <span>Logout</span>
        </button>

      </div>
    </header>
  );
}

export default Navbar;