import { Bell, CheckCheck, X, AlertTriangle, Shield, Clock, Hash, Target, ChevronDown, AlertCircle, Loader2, ExternalLink, CheckCircle2 } from "lucide-react";
import { useEffect, useState, useCallback, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useLiveSOC } from "../../context/LiveSOCContext";
import api from "../../services/api";

const PAGE_SIZE = 20;

function NotificationBell() {
  const { latestEvent, notificationUpdateTick } = useLiveSOC();
  const navigate = useNavigate();

  const [open, setOpen] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [summary, setSummary] = useState({ critical: 0, high: 0, system: 0, total_attention: 0 });
  const [totalToday, setTotalToday] = useState(0);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState(null);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(false);
  const [actionLoading, setActionLoading] = useState(null);
  const panelRef = useRef(null);

  // ----------------------------------------------------------------
  // Fetch notification summary (severity counts) from backend
  // ----------------------------------------------------------------
  const fetchSummary = useCallback(async () => {
    try {
      const res = await api.get("/notifications/summary");
      setSummary(res.data || { critical: 0, high: 0, system: 0, total_attention: 0 });
    } catch (err) {
      // Fallback to legacy unread-count
      try {
        const res = await api.get("/notifications/unread-count");
        const count = typeof res.data.count === "number" ? res.data.count : 0;
        setSummary({ critical: 0, high: 0, system: 0, total_attention: count });
      } catch { /* ignore */ }
    }
  }, []);

  // ----------------------------------------------------------------
  // Fetch notifications from the events table (derived, Critical/High only)
  // ----------------------------------------------------------------
  const fetchNotifications = useCallback(async (pageNum = 1, append = false) => {
    try {
      if (append) {
        setLoadingMore(true);
      } else {
        setLoading(true);
        setError(null);
      }

      const res = await api.get("/notifications/today", {
        params: { page: pageNum, page_size: PAGE_SIZE },
      });

      const data = res.data;
      const items = data.items || [];

      if (append) {
        setNotifications((prev) => [...prev, ...items]);
      } else {
        setNotifications(items);
      }

      setTotalToday(data.total || 0);
      setHasMore(data.has_more || false);
      setPage(data.page || pageNum);
      setError(null);
    } catch (err) {
      console.error("[NotificationBell] Failed to fetch:", err);
      if (!append) {
        setError("Unable to load notifications.");
        setNotifications([]);
      }
    } finally {
      setLoading(false);
      setLoadingMore(false);
    }
  }, []);

  const loadMore = useCallback(() => {
    if (!loadingMore && hasMore) fetchNotifications(page + 1, true);
  }, [fetchNotifications, page, hasMore, loadingMore]);

  // ----------------------------------------------------------------
  // Initial fetch + reactive updates
  // ----------------------------------------------------------------
  useEffect(() => { fetchSummary(); }, [fetchSummary]);

  useEffect(() => {
    if (open) { setPage(1); fetchNotifications(1, false); }
  }, [open, fetchNotifications]);

  useEffect(() => {
    if (latestEvent || notificationUpdateTick > 0) {
      fetchSummary();
      if (open) fetchNotifications(1, false);
    }
  }, [latestEvent, notificationUpdateTick, open, fetchSummary, fetchNotifications]);

  // ----------------------------------------------------------------
  // Close on outside click
  // ----------------------------------------------------------------
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (panelRef.current && !panelRef.current.contains(e.target)) setOpen(false);
    };
    if (open) document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [open]);

  // ----------------------------------------------------------------
  // Actions: Mark as Read, Mark All Read, Investigate
  // ----------------------------------------------------------------
  const handleMarkRead = useCallback(async (alertId, e) => {
    if (e) e.stopPropagation();
    setActionLoading(alertId);
    try {
      await api.patch("/notifications/mark-read", { notification_id: alertId });
      setNotifications((prev) => prev.map((n) =>
        n.alert_id === alertId ? { ...n, read: true } : n
      ));
      await fetchSummary();
    } catch (err) {
      console.error("[NotificationBell] Failed to mark as read:", err);
    } finally {
      setActionLoading(null);
    }
  }, [fetchSummary]);

  const handleMarkAllRead = useCallback(async () => {
    if (loading) return;
    setLoading(true);
    try {
      await api.patch("/notifications/mark-all-read");
      // Mark all visible notifications as read in local state
      setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
      // Re-fetch summary from backend (authoritative)
      await fetchSummary();
    } catch (err) {
      console.error("[NotificationBell] Failed to mark all as read:", err);
      // On error, re-fetch to get correct state
      fetchSummary();
    } finally {
      setLoading(false);
    }
  }, [fetchSummary, loading]);

  const handleInvestigate = useCallback((notification, e) => {
    if (e) e.stopPropagation();
    setOpen(false);
    navigate("/alerts", { state: { highlightAlertId: notification.alert_id } });
  }, [navigate]);

  const handleNotificationClick = useCallback((notification) => {
    setOpen(false);
    navigate("/alerts", { state: { highlightAlertId: notification.alert_id } });
  }, [navigate]);

  // ----------------------------------------------------------------
  // Helpers
  // ----------------------------------------------------------------
  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case "critical": return "text-red-400 bg-red-500/20 border-red-500/30";
      case "high": return "text-orange-400 bg-orange-500/20 border-orange-500/30";
      default: return "text-slate-400 bg-slate-500/20 border-slate-500/30";
    }
  };

  const getSeverityDot = (severity) => {
    switch (severity?.toLowerCase()) {
      case "critical": return "bg-red-500";
      case "high": return "bg-orange-500";
      default: return "bg-slate-500";
    }
  };

  const getRelativeTime = (timestamp) => {
    if (!timestamp) return "";
    const diffMs = Date.now() - new Date(timestamp).getTime();
    const diffMin = Math.floor(diffMs / 60000);
    const diffHr = Math.floor(diffMin / 60);
    if (diffMin < 1) return "Just now";
    if (diffMin < 60) return diffMin + "m ago";
    if (diffHr < 24) return diffHr + "h ago";
    return "Yesterday";
  };

  const badgeCount = summary.total_attention;

  // ================================================================
  // Render
  // ================================================================
  return (
    <div className="relative" ref={panelRef}>
      {/* Bell button with badge */}
      <button
        onClick={() => setOpen(!open)}
        className="relative w-[44px] h-[44px] flex items-center justify-center rounded-lg bg-slate-900/40 border border-slate-700 hover:bg-slate-800/60 transition-all duration-150"
      >
        <Bell size={20} className="text-cyan-400" />
        {badgeCount > 0 && (
          <span className="absolute -top-1 -right-1 min-w-[20px] h-5 px-1 rounded-full bg-red-500 text-white text-[10px] font-bold flex items-center justify-center shadow-lg shadow-red-500/30">
            {badgeCount > 99 ? "99+" : badgeCount}
          </span>
        )}
      </button>

      {/* Notification panel */}
      {open && (
        <div className="absolute right-0 mt-3 w-[480px] rounded-xl border border-slate-700/80 bg-slate-900 shadow-2xl shadow-black/50 overflow-hidden z-50">
          {/* Header with severity summary + Mark all read */}
          <div className="p-4 border-b border-slate-700/60 bg-slate-800/50">
            <div className="flex items-center justify-between mb-2">
              <h3 className="font-semibold text-white text-sm">Notifications</h3>
              <div className="flex items-center gap-2">
                {badgeCount > 0 && (
                  <button
                    onClick={handleMarkAllRead}
                    disabled={loading}
                    className={`flex items-center gap-1 text-[11px] transition-colors ${
                      loading ? "text-slate-500 cursor-not-allowed" : "text-cyan-400 hover:text-cyan-300"
                    }`}
                  >
                    <CheckCheck size={13} className={loading ? "animate-pulse" : ""} />
                    {loading ? "Marking..." : "Mark all read"}
                  </button>
                )}
                <button
                  onClick={() => setOpen(false)}
                  className="p-1 text-slate-400 hover:text-white rounded transition-colors"
                >
                  <X size={16} />
                </button>
              </div>
            </div>

            {/* Severity summary bar */}
            <div className="flex items-center gap-3 text-[11px]">
              {summary.critical > 0 && (
                <span className="flex items-center gap-1 text-red-400 font-semibold">
                  <span className="w-2 h-2 rounded-full bg-red-500" />
                  {summary.critical} Critical
                </span>
              )}
              {summary.high > 0 && (
                <span className="flex items-center gap-1 text-orange-400 font-semibold">
                  <span className="w-2 h-2 rounded-full bg-orange-500" />
                  {summary.high} High
                </span>
              )}
              {summary.system > 0 && (
                <span className="flex items-center gap-1 text-slate-400">
                  <span className="w-2 h-2 rounded-full bg-slate-500" />
                  {summary.system} System
                </span>
              )}
              {badgeCount === 0 && (
                <span className="text-green-400 font-medium">All clear</span>
              )}
              {totalToday > 0 && (
                <span className="text-slate-500 ml-auto">{totalToday} alerts today</span>
              )}
            </div>
          </div>

          {/* Content */}
          <div className="max-h-[520px] overflow-y-auto custom-scrollbar">
            {loading && notifications.length === 0 ? (
              <div className="p-10 text-center">
                <Loader2 size={28} className="mx-auto text-cyan-400 animate-spin" />
                <p className="mt-3 text-slate-400 text-sm">Loading...</p>
              </div>
            ) : error ? (
              <div className="p-8 text-center">
                <AlertCircle size={28} className="mx-auto text-red-400" />
                <p className="mt-3 text-red-400 text-sm">{error}</p>
                <button
                  onClick={() => fetchNotifications(1, false)}
                  className="mt-3 text-xs text-cyan-400 hover:text-cyan-300"
                >Try again</button>
              </div>
            ) : notifications.length === 0 && !loading ? (
              <div className="p-10 text-center">
                <Shield size={32} className="mx-auto text-slate-600" />
                <p className="mt-3 text-slate-400 text-sm">No security attention items</p>
                <p className="mt-1 text-slate-500 text-[11px]">
                  SOCRA AI will bring important threats to your attention
                </p>
              </div>
            ) : (
              <>
                {notifications.map((n) => (
                  <div
                    key={n.id}
                    onClick={() => handleNotificationClick(n)}
                    className={`p-3.5 border-b border-slate-700/30 hover:bg-slate-800/60 transition-all duration-100 cursor-pointer group ${
                      !n.read ? "bg-slate-800/30" : ""
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      <div className={`w-2.5 h-2.5 rounded-full mt-1.5 flex-shrink-0 ${getSeverityDot(n.severity)}`} />

                      <div className="flex-1 min-w-0">
                        {/* Severity badge + unread dot */}
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wide ${getSeverityColor(n.severity)}`}>
                            {n.severity}
                          </span>
                          {!n.read && (
                            <span className="w-2 h-2 bg-cyan-400 rounded-full shadow-sm shadow-cyan-400/50" />
                          )}
                        </div>

                        {/* Title */}
                        <p className="text-[13px] text-white font-medium truncate group-hover:text-cyan-100 transition-colors">
                          {n.title}
                        </p>

                        {/* Details */}
                        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 mt-1.5 text-[11px] text-slate-400">
                          {n.host && (
                            <span className="flex items-center gap-1">
                              <AlertTriangle size={10} className="text-slate-500" />
                              {n.host}
                            </span>
                          )}
                          {n.process_name && (
                            <span className="text-slate-300 font-mono text-[10px]">{n.process_name}</span>
                          )}
                          {n.process_id && (
                            <span className="text-slate-500 font-mono text-[10px]">PID: {n.process_id}</span>
                          )}
                          {n.mitre && (
                            <span className="flex items-center gap-1 text-purple-400">
                              <Target size={10} />{n.mitre}
                            </span>
                          )}
                          {n.event_id && (
                            <span className="flex items-center gap-1">
                              <Hash size={10} className="text-slate-500" />{n.event_id}
                            </span>
                          )}
                        </div>

                        {/* Timestamp + Actions */}
                        <div className="flex items-center justify-between mt-1.5">
                          <span className="flex items-center gap-1 text-[10px] text-slate-500">
                            <Clock size={9} />
                            {getRelativeTime(n.created_at || n.event_time)}
                          </span>

                          <div className="flex items-center gap-1">
                            <button
                              onClick={(e) => handleInvestigate(n, e)}
                              className="flex items-center gap-0.5 text-[10px] text-cyan-400 hover:text-cyan-300 transition-colors px-1.5 py-0.5 rounded hover:bg-cyan-500/10"
                            >
                              <ExternalLink size={9} />
                              Investigate
                            </button>
                            {!n.read && (
                              <button
                                onClick={(e) => handleMarkRead(n.alert_id, e)}
                                disabled={actionLoading === n.alert_id}
                                className="flex items-center gap-0.5 text-[10px] text-slate-400 hover:text-green-400 transition-colors px-1.5 py-0.5 rounded hover:bg-green-500/10"
                              >
                                {actionLoading === n.alert_id ? (
                                  <Loader2 size={9} className="animate-spin" />
                                ) : (
                                  <CheckCircle2 size={9} />
                                )}
                                Read
                              </button>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}

                {hasMore && (
                  <div className="p-3 border-t border-slate-700/30 text-center">
                    <button
                      onClick={loadMore}
                      disabled={loadingMore}
                      className="flex items-center gap-1.5 mx-auto text-[12px] text-cyan-400 hover:text-cyan-300 disabled:text-slate-500"
                    >
                      {loadingMore ? (
                        <><Loader2 size={13} className="animate-spin" /> Loading...</>
                      ) : (
                        <><ChevronDown size={13} /> Load more</>
                      )}
                    </button>
                  </div>
                )}
              </>
            )}
          </div>

          {/* Footer */}
          <div className="p-3 border-t border-slate-700/60 bg-slate-800/30 text-center">
            <button
              onClick={() => { setOpen(false); navigate("/alerts"); }}
              className="text-[12px] text-cyan-400 hover:text-cyan-300"
            >
              View all alerts →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default NotificationBell;
