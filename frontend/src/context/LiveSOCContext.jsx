import { createContext, useContext, useEffect, useState, useRef, useCallback, useMemo } from "react";
import liveSocket from "../services/liveSocket";
import api from "../services/api";
import { useSettings } from "./SettingsContext";

const LiveSOCContext = createContext();

// =========================================================================
// Real-time Analytics Accumulator
// =========================================================================
const SEVERITY_NAMES = ["Critical", "High", "Medium", "Low", "Informational"];
const EPS_WINDOW_MS = 60000;
const MAX_FINGERPRINTS = 50000;
const CATCHUP_LIMIT = 2000;

const createEmptyHourlyBuckets = () => {
  const buckets = {};
  // Enterprise: maintain ALL 24 hourly buckets (00:00-23:59) so the chart never breaks on hour rollover
  for (let h = 0; h < 24; h++) {
    const label = `${String(h).padStart(2, "0")}:00`;
    buckets[label] = { time: label, Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
  }
  return buckets;
};

const createInitialAccumulator = () => ({
  totalEvents: 0,
  severityCounts: { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 },
  seenHosts: new Set(),
  hostCounts: {},
  epsTimestamps: [],
  hourlyBuckets: createEmptyHourlyBuckets(),
  recentAlerts: [],
  liveEvents: [],
  seenFingerprints: new Set(),
  fingerprintQueue: [],
  collector: { status: "Stopped", running: false, live_events: 0, history_events: 0 },
  // Backend canonical host count — overridden by dashboard_stats broadcast.
  // Used by computeAnalyticsFromAcc so the Dashboard always shows the
  // authoritative SQL-distinct host count, not the live-stream approximation.
  _backendHosts: 0,
});

const applyAlertEventToAccumulator = (acc, event) => {
  // ──────────────────────────────────────────────────────────────────────
  // IMPORTANT: This function updates the LIVE STREAM and DERIVED metrics
  // only. The canonical total (totalEvents) and severity counts come from
  // the backend REST snapshot and periodic dashboard_stats broadcast.
  // We must NOT increment totalEvents or severityCounts here because
  // those values are authoritative totals maintained by the backend
  // (SQLite COUNT queries). Incrementing them from WS events causes
  // double-counting: the collector persists to SQLite AND broadcasts
  // over WS, so the backend total already includes every WS event.
  // ──────────────────────────────────────────────────────────────────────

  // Fingerprint dedup for events without _seq
  const fp = event?.metadata?.fingerprint;
  if (fp) {
    if (acc.seenFingerprints.has(fp)) return false;
    acc.seenFingerprints.add(fp);
    acc.fingerprintQueue.push(fp);
    if (acc.fingerprintQueue.length > MAX_FINGERPRINTS) {
      const oldest = acc.fingerprintQueue.shift();
      acc.seenFingerprints.delete(oldest);
    }
  }

  // Keep a deduplicated live stream of every new event (all severities).
  // This is used by the Alerts table for live overlay — NOT for counting.
  acc.liveEvents.unshift(event);
  if (acc.liveEvents.length > 2000) acc.liveEvents.length = 2000;

  // Host tracking for top-hosts chart (derived from live stream)
  const host = event?.event?.host || event?.event?.computer || "";
  if (host) {
    acc.seenHosts.add(host);
    acc.hostCounts[host] = (acc.hostCounts[host] || 0) + 1;
  }

  // EPS rolling window (client-side rate calculation)
  const eventTimeStr = event?.event?.time;
  if (eventTimeStr) {
    const eventTime = new Date(eventTimeStr).getTime();
    if (!Number.isNaN(eventTime)) {
      acc.epsTimestamps.push(eventTime);
    }
  }

  // Hourly bucket for trend chart (derived from live stream)
  if (eventTimeStr) {
    const rawSeverity = event?.detection?.severity || "Informational";
    const severity = rawSeverity.charAt(0).toUpperCase() + rawSeverity.slice(1).toLowerCase();
    const normalizedSev = SEVERITY_NAMES.includes(severity) ? severity : "Informational";
    const eventDate = new Date(eventTimeStr);
    if (!Number.isNaN(eventDate.getTime())) {
      const hour = eventDate.getHours();
      const hourLabel = `${String(hour).padStart(2, "0")}:00`;
      if (acc.hourlyBuckets[hourLabel]) {
        acc.hourlyBuckets[hourLabel][normalizedSev] += 1;
      } else {
        acc.hourlyBuckets[hourLabel] = { time: hourLabel, Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0, [normalizedSev]: 1 };
      }
    }
  }

  // Prepend high/critical to recent alerts (newest first) for dashboard
  const rawSev = event?.detection?.severity || "Informational";
  const sevNorm = rawSev.charAt(0).toUpperCase() + rawSev.slice(1).toLowerCase();
  const normSev = SEVERITY_NAMES.includes(sevNorm) ? sevNorm : "Informational";
  if (normSev === "High" || normSev === "Critical") {
    acc.recentAlerts.unshift(event);
    if (acc.recentAlerts.length > 2000) acc.recentAlerts.pop();
  }
  return true;
};

const pruneEpsTimestamps = (timestamps) => {
  const cutoff = Date.now() - EPS_WINDOW_MS;
  let i = 0;
  while (i < timestamps.length && timestamps[i] < cutoff) i++;
  return i > 0 ? timestamps.slice(i) : timestamps;
};

const computeAnalyticsFromAcc = (acc) => {
  const cutoff = Date.now() - EPS_WINDOW_MS;
  const recentTimestamps = acc.epsTimestamps.filter((t) => t >= cutoff);
  const eps = acc.totalEvents > 0 ? Number((recentTimestamps.length / 60).toFixed(2)) : 0;
  const totalHigh = (acc.severityCounts["High"] || 0) + (acc.severityCounts["Critical"] || 0);
  const topHosts = Object.entries(acc.hostCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);
  // All 24 hourly buckets always exist — never need to create them here
  const sortedHours = Object.keys(acc.hourlyBuckets).sort();
  const eventsPerHour = {};
  sortedHours.forEach((key) => { eventsPerHour[key] = { ...acc.hourlyBuckets[key] }; });
  return {
    summary: {
      total_events: acc.totalEvents,
      high: totalHigh,
      hosts: acc._backendHosts || acc.seenHosts.size,
      eps: eps,
      critical: acc.severityCounts["Critical"] || 0,
    },
    severity: { ...acc.severityCounts },
    events_per_hour: eventsPerHour,
    top_hosts: topHosts,
    collector: { ...acc.collector },
    recentAlerts: acc.recentAlerts,
    liveEvents: acc.liveEvents,
  };
};

// =========================================================================
// Provider
// =========================================================================
export function LiveSOCProvider({ children }) {
  const { settings } = useSettings();

  const [connected, setConnected] = useState(false);
  const [connectionState, setConnectionState] = useState("disconnected");
  const [latestEvent, setLatestEvent] = useState(null);
  const [notifications, setNotifications] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [analyticsLoading, setAnalyticsLoading] = useState(true);
  // Real alert triage status changes (Task 17) broadcast by the server.
  // Consumers (e.g. the Alerts page) apply them to their local row state so
  // every live client sees the update immediately.
  const [alertStatusUpdates, setAlertStatusUpdates] = useState([]);
  // Monotonic counter incremented each time the backend broadcasts a
  // notification_update frame.  NotificationBell uses this as a dependency
  // to re-fetch unread count and notification list — no polling needed.
  const [notificationUpdateTick, setNotificationUpdateTick] = useState(0);

  const accRef = useRef(createInitialAccumulator());
  const epsPruneInterval = useRef(null);
  const hourRolloverInterval = useRef(null);
  const previousHourRef = useRef(new Date().getHours());

  // Notification presentation is a UI preference (Settings → Real-time System
  // Notifications). This ref only gates whether new alerts surface in the bell
  // and toast — telemetry accumulation, WebSocket ingestion and analytics
  // below are NEVER gated, so turning notifications off cannot disable the
  // security pipeline.
  const notificationsEnabledRef = useRef(settings.notifications);
  useEffect(() => {
    notificationsEnabledRef.current = settings.notifications;
    // Turning notifications OFF also dismisses any in-flight toast.
    const timer = setTimeout(() => {
      if (!settings.notifications) setLatestEvent(null);
    }, 0);
    return () => clearTimeout(timer);
  }, [settings.notifications]);
  // Newest event since the last analytics flush — setLatestEvent is deferred
  // to the 100ms batch so a burst of WebSocket events renders once per batch
  // instead of once per event (toast shows the latest alert either way).
  const latestEventRef = useRef(null);

  // -----------------------------------------------------------------------
  // REST/WebSocket synchronization state
  // -----------------------------------------------------------------------
  // lastSeqRef: highest live sequence the client has applied. Every event
  // carries a monotonically increasing _seq from the server; anything with
  // _seq <= lastSeqRef.current is already counted and is skipped, which makes
  // replay (reconnect catch-up, duplicate WS frames) harmless.
  const lastSeqRef = useRef(0);
  // snapshotSeqRef: the sequence boundary covered by the last REST snapshot
  // totals. While the initial snapshot is in flight, incoming WS events are
  // buffered so they can be applied exactly once after the boundary is known.
  const snapshotSeqRef = useRef(null);
  const pendingRef = useRef([]);
  const catchUpInFlightRef = useRef(false);

  const renderAnalytics = useCallback(() => {
    setAnalytics(computeAnalyticsFromAcc(accRef.current));
  }, []);

  // ------------------------------------------------------------------
  // Apply one event with the seq watermark: returns true if applied.
  // ------------------------------------------------------------------
  const applyWithSeq = useCallback((event) => {
    const seq = event?._seq;
    if (typeof seq === "number" && seq > 0) {
      if (seq <= lastSeqRef.current) return false; // already applied, avoid double-counting
      lastSeqRef.current = seq;
    }
    const acc = accRef.current;
    return applyAlertEventToAccumulator(acc, event);
  }, [lastSeqRef]);

  // ------------------------------------------------------------------
  // Catch-up: retrieve and apply every event after our watermark once.
  // Called after reconnect (and opportunistically when the server's
  // periodic dashboard_stats broadcast reveals we are behind).
  // ------------------------------------------------------------------
  const catchUp = useCallback(async () => {
    if (catchUpInFlightRef.current) return;
    catchUpInFlightRef.current = true;
    try {
      const res = await api.get("/live/events", {
        params: { after_seq: lastSeqRef.current, limit: CATCHUP_LIMIT },
      });
      const data = res.data || {};
      const events = data.events || [];
      const serverSeq = data.current_seq || lastSeqRef.current;

      let applied = 0;
      for (const event of events) {
        if (applyWithSeq(event)) applied += 1;
      }
      // Advance to the server watermark even if some events were already
      // known — nothing newer than this can ever be re-delivered.
      if (serverSeq > lastSeqRef.current) lastSeqRef.current = serverSeq;

      if (applied > 0) {
        renderAnalytics();
        // Latest applied event powers the toast for freshly missed events —
        // only when notification presentation is enabled.
        if (notificationsEnabledRef.current) {
          setLatestEvent(events[events.length - 1] || null);
        }
      }
    } catch {
      // Silent — next reconnect or dashboard_stats drift retries.
    } finally {
      catchUpInFlightRef.current = false;
    }
  }, [applyWithSeq, renderAnalytics]);

  // ------------------------------------------------------------------
  // Initial REST snapshot → authoritative state
  // ------------------------------------------------------------------
  const fetchInitialAnalytics = useCallback(async () => {
    try {
      const res = await api.get("/analytics/dashboard");
      const data = res.data;
      const acc = accRef.current;
      acc.totalEvents = data.summary?.total_events || 0;
      acc._backendHosts = data.summary?.hosts || 0;
      if (data.severity_distribution) {
        data.severity_distribution.forEach((s) => { acc.severityCounts[s.name] = s.value || 0; });
      }
      if (data.top_hosts) {
        data.top_hosts.forEach(([host, count]) => { acc.seenHosts.add(host); acc.hostCounts[host] = count; });
      }
      if (data.collector_status) acc.collector = { ...data.collector_status };
      if (data.cyber_threat_horizon?.data) {
        data.cyber_threat_horizon.data.forEach((entry) => {
          if (entry.series) {
            acc.hourlyBuckets[entry.hour] = {
              time: entry.hour, Critical: entry.series.Critical || 0, High: entry.series.High || 0,
              Medium: entry.series.Medium || 0, Low: entry.series.Low || 0, Informational: entry.series.Informational || 0,
            };
          }
        });
      }
      if (data.recent_critical_alerts) {
        data.recent_critical_alerts.forEach((alert) => {
          // Map simplified REST alerts to full event format RecentAlerts component expects
          acc.recentAlerts.push({
            event: { time: alert.time, host: alert.host, event_id: alert.event_id },
            detection: { severity: alert.severity, detection: alert.message }
          });
        });
      }

      // Establish the sync boundary: everything with _seq <= current_seq is
      // already included in these totals — do not re-apply it.
      const boundarySeq = Number(data.current_seq || 0);
      snapshotSeqRef.current = boundarySeq;
      lastSeqRef.current = Math.max(lastSeqRef.current, boundarySeq);

      // Apply any WS events that arrived while the snapshot was in flight —
      // exactly once, since applyWithSeq skips anything <= the watermark.
      const pending = pendingRef.current;
      pendingRef.current = [];
      let applied = 0;
      for (const event of pending) {
        if (applyWithSeq(event)) applied += 1;
      }

      setAnalytics(computeAnalyticsFromAcc(acc));
      setAnalyticsLoading(false);
      if (applied > 0) renderAnalytics();
    } catch (err) {
      console.error("Failed to fetch initial analytics:", err);
      // REST failed — establish the boundary at 0 (nothing was counted) and
      // apply whatever buffered WS events arrived, then run catch-up to pull
      // the rest of the live stream.
      snapshotSeqRef.current = 0;
      const pending = pendingRef.current;
      pendingRef.current = [];
      let applied = 0;
      for (const event of pending) {
        if (applyWithSeq(event)) applied += 1;
      }
      const computed = computeAnalyticsFromAcc(accRef.current);
      setAnalytics(computed);
      setAnalyticsLoading(false);
      if (applied > 0) renderAnalytics();
      catchUp();
    }
  }, [applyWithSeq, renderAnalytics, catchUp]);

  // ------------------------------------------------------------------
  // WS message handlers
  // ------------------------------------------------------------------
  const handleDashboardStats = useCallback((data) => {
    const acc = accRef.current;
    const sd = data.data || data;

    // ──────────────────────────────────────────────────────────────────
    // CANONICAL BACKEND SYNC: The backend is the sole source of truth
    // for totalEvents and severityCounts. We override the local
    // accumulator values on every broadcast (every 2s) so the frontend
    // never drifts from the authoritative database totals.
    // WS events update the live stream / EPS / hourly buckets only.
    // ──────────────────────────────────────────────────────────────────
    if (sd.totalEvents !== undefined) {
      acc.totalEvents = sd.totalEvents;
    }

    // Sync severity counts from backend broadcast
    if (sd.critical !== undefined) acc.severityCounts["Critical"] = sd.critical || 0;
    if (sd.highSeverity !== undefined && sd.critical !== undefined) {
      acc.severityCounts["High"] = (sd.highSeverity - (sd.critical || 0)) || 0;
    }
    if (sd.medium !== undefined) acc.severityCounts["Medium"] = sd.medium || 0;
    if (sd.low !== undefined) acc.severityCounts["Low"] = sd.low || 0;
    if (sd.informational !== undefined) acc.severityCounts["Informational"] = sd.informational || 0;

    // Sync host count from backend canonical
    if (sd.windowsHosts !== undefined) {
      acc._backendHosts = sd.windowsHosts;
    }

    if (sd.collector) acc.collector = { ...acc.collector, ...sd.collector };
    if (sd.recentCriticalAlerts && sd.recentCriticalAlerts.length > 0) {
      const existing = new Set(acc.recentAlerts.map((a) =>
        a?.metadata?.fingerprint || (a?.event?.time || a?.time) + (a?.event?.event_id || a?.event_id || "")
      ));
      sd.recentCriticalAlerts.forEach((alert) => {
        const key = alert?.metadata?.fingerprint || alert?.time + (alert?.event_id || "");
        if (!existing.has(key)) { acc.recentAlerts.push(alert); existing.add(key); }
      });
      acc.recentAlerts.sort((a, b) => new Date(b.time || 0) - new Date(a.time || 0));
      if (acc.recentAlerts.length > 2000) acc.recentAlerts.length = 2000;
    }
    // Drift detection: if the server watermark is ahead of us we missed
    // events (e.g. while disconnected) — run catch-up instead of polling.
    const serverSeq = Number(sd.currentSeq || 0);
    if (serverSeq > lastSeqRef.current && snapshotSeqRef.current !== null) {
      catchUp();
    }
    // Recompute analytics after syncing canonical values
    renderAnalytics();
  }, [catchUp, renderAnalytics]);

  const handleAlertStatus = useCallback((data) => {
    if (!data || !data.status) return;
    // Keep the in-memory live stream in sync so live overlay rows show the
    // persisted status instead of the stale "New" default.
    const acc = accRef.current;
    const matches = (event) =>
      (data.alert_id != null && event?._id === data.alert_id) ||
      (data.fingerprint && event?.metadata?.fingerprint === data.fingerprint);
    if (acc.liveEvents.some(matches)) {
      acc.liveEvents = acc.liveEvents.map((event) =>
        matches(event)
          ? { ...event, event: { ...(event.event || {}), status: data.status } }
          : event
      );
      renderAnalytics();
    }
    // Surface the update to pages holding REST-served rows (the Alerts table).
    setAlertStatusUpdates((prev) => [...prev.slice(-99), data]);
  }, [renderAnalytics]);

  const handleAlertEvent = useCallback((event) => {
    // While the initial snapshot is in flight, buffer — the totals aren't
    // authoritative yet and applying now could double count.
    if (snapshotSeqRef.current === null) {
      pendingRef.current.push(event);
      if (pendingRef.current.length > 2000) pendingRef.current.shift();
      return;
    }

    const isNew = applyWithSeq(event);
    if (!isNew) return;

    // Notification presentation only — the accumulator update above (totals,
    // live stream, EPS, hourly buckets) always runs regardless of the setting.
    const notify = notificationsEnabledRef.current;
    if (notify) latestEventRef.current = event;

    const severity = event?.detection?.severity || "";
    if (notify && (severity.toLowerCase() === "high" || severity.toLowerCase() === "critical")) {
      setNotifications((prev) => { const u = [event, ...prev]; return u.slice(0, 100); });
    }
    if (!accRef.current._batchTimer) {
      accRef.current._batchTimer = setTimeout(() => {
        accRef.current._batchTimer = null;
        accRef.current.epsTimestamps = pruneEpsTimestamps(accRef.current.epsTimestamps);
        if (notify && latestEventRef.current) setLatestEvent(latestEventRef.current);
        renderAnalytics();
      }, 100);
    }
  }, [applyWithSeq, renderAnalytics]);

  const handleWsMessage = useCallback((msg) => {
    if (!msg || !msg.type) return;
    switch (msg.type) {
      case "connection":
        console.log("[WEBSOCKET_AUTH] Connection status:", msg.status);
        setConnected(msg.status === "connected");
        setConnectionState(msg.status);
        if (msg.status === "connected") liveSocket.reconnectAttempts = 0;
        break;
      case "system":
        // Handshake from the server. The REST snapshot response is the sole
        // authority for the sync boundary — its totals were computed from the
        // exact event set covered by its current_seq. The WS handshake's
        // current_seq is only informational; establishing the boundary here
        // would race the in-flight REST fetch and double-count (events applied
        // against the WS watermark that the REST totals already include).
        setConnected(true);
        setConnectionState("connected");
        break;
      case "alert":
      case "incident":
        handleAlertEvent(msg);
        break;
      case "alert_status":
        handleAlertStatus(msg.data);
        break;
      case "dashboard_stats":
        handleDashboardStats(msg);
        break;
      case "metrics":
        if (msg.data) handleDashboardStats(msg);
        break;
      case "notification_update":
        // Backend just created notification records for a new alert.
        // Bump the tick so NotificationBell re-fetches its unread count
        // and notification list in real time.
        setNotificationUpdateTick((prev) => prev + 1);
        break;
      default: break;
    }
  }, [handleAlertEvent, handleAlertStatus, handleDashboardStats]);

  // ------------------------------------------------------------------
  // Reconnect catch-up: when the socket (re)connects after a gap, fetch
  // and apply the missed events exactly once via /live/events.
  // ------------------------------------------------------------------
  const handleConnectionChange = useCallback((status) => {
    if (status === "connected" && snapshotSeqRef.current !== null) {
      catchUp();
    }
  }, [catchUp]);

  // Store the connection-change listener in a ref so the cleanup function
  // can unsubscribe the *same* reference (avoiding leaked anonymous listeners).
  const handleConnectionChangeRef = useRef(handleConnectionChange);
  handleConnectionChangeRef.current = handleConnectionChange;

  const connectionListener = useCallback((msg) => {
    if (msg && msg.type === "connection") handleConnectionChangeRef.current(msg.status);
  }, []);

  // Track whether connect() was initiated for the current mount cycle. React
  // StrictMode (dev) runs effect → cleanup → effect on mount; the socket is a
  // module singleton, so only the FIRST setup must initiate the connection.
  // The second setup still re-subscribes and re-fetches below.
  const socketStartedRef = useRef(false);
  // Deferred teardown scheduled by the previous cleanup. StrictMode's
  // simulated unmount schedules it, and the immediate remount cancels it
  // before it fires — so a still-CONNECTING socket is never closed
  // mid-handshake. On a genuine unmount (logout) nothing cancels it and
  // destroy() runs, shutting the socket down cleanly.
  const teardownTimerRef = useRef(null);

  useEffect(() => {
    // A remount happened (StrictMode dev double-mount, or a quick unmount +
    // remount in the SPA): cancel the teardown the previous cleanup scheduled.
    if (teardownTimerRef.current) {
      clearTimeout(teardownTimerRef.current);
      teardownTimerRef.current = null;
    }

    if (!socketStartedRef.current) {
      socketStartedRef.current = true;
      liveSocket.connect();
      console.log("[WEBSOCKET_AUTH] LiveSocket connect initiated");
    } else {
      console.log("[WEBSOCKET_AUTH] Skip duplicate connect - StrictMode double-mount prevented");
    }

    fetchInitialAnalytics();
    liveSocket.subscribe(handleWsMessage);
    liveSocket.subscribe(connectionListener);
    // Connection state is pushed by the WebSocket itself (connect / close /
    // reconnect notifications handled above) — no separate status poll is
    // needed for the Live badge. EPS keeps refreshing on a fixed cadence so
    // the "Events / Sec" counter decays correctly even while the stream is
    // idle (a pure client-side computation that WebSocket + REST
    // synchronization do not provide).
    epsPruneInterval.current = setInterval(() => {
      const acc = accRef.current;
      acc.epsTimestamps = pruneEpsTimestamps(acc.epsTimestamps);
      setAnalytics((prev) => prev ? { ...computeAnalyticsFromAcc(acc) } : computeAnalyticsFromAcc(acc));
    }, 10000);
    // Hour rollover detection: check every 30s if the hour changed, ensure next-hour bucket exists
    hourRolloverInterval.current = setInterval(() => {
      const nowHour = new Date().getHours();
      if (nowHour !== previousHourRef.current) {
        previousHourRef.current = nowHour;
        const label = `${String(nowHour).padStart(2, "0")}:00`;
        const acc = accRef.current;
        if (!acc.hourlyBuckets[label]) {
          acc.hourlyBuckets[label] = { time: label, Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
        }
        // Trigger a render so chart picks up the new bucket
        setAnalytics((prev) => prev ? { ...computeAnalyticsFromAcc(acc) } : computeAnalyticsFromAcc(acc));
      }
    }, 30000);
    return () => {
      clearInterval(epsPruneInterval.current);
      clearInterval(hourRolloverInterval.current);
      if (accRef.current._batchTimer) clearTimeout(accRef.current._batchTimer);
      liveSocket.unsubscribe(handleWsMessage);
      liveSocket.unsubscribe(connectionListener);
      if (liveSocket.heartbeat) clearInterval(liveSocket.heartbeat);
      if (liveSocket.reconnectTimeout) clearTimeout(liveSocket.reconnectTimeout);
      // Reset notification state so the next authenticated user starts with
      // a clean slate — prevents cross-user notification leakage if the
      // provider remounts without a full page reload (SPA login flow).
      setNotifications([]);
      setLatestEvent(null);
      setNotificationUpdateTick(0);
      // Do NOT destroy the socket synchronously here. In dev, React StrictMode
      // immediately re-runs this effect right after cleanup; closing the
      // socket here would kill a still-CONNECTING socket ("WebSocket is closed
      // before the connection is established", close code 1006) and the
      // remount would have no socket to reuse. Instead, defer the teardown to
      // a 0ms timer: if the effect re-runs (StrictMode remount) the timer is
      // cancelled at the top of this effect and the socket lives on; if the
      // provider genuinely unmounts (logout) nothing cancels the timer, it
      // fires, and destroy() shuts the socket down cleanly.
      teardownTimerRef.current = setTimeout(() => {
        teardownTimerRef.current = null;
        socketStartedRef.current = false;
        // Full teardown when the authenticated layout unmounts (logout):
        // close the socket and cancel the reconnect loop so it cannot hammer
        // the server with unauthenticated handshakes while logged out. The
        // socket is reusable — a new login simply connect()s again.
        liveSocket.destroy();
      }, 0);
    };
  }, [fetchInitialAnalytics, handleWsMessage, connectionListener]);

  const clearNotifications = useCallback(() => { setNotifications([]); setLatestEvent(null); }, []);
  const forceResync = useCallback(() => { catchUp(); }, [catchUp]);

  const metrics = useMemo(() => {
    if (!analytics) return { totalEvents: 0, highSeverity: 0, windowsHosts: 0, eventsPerSec: 0, trendData: {}, severityDistribution: {} };
    return {
      totalEvents: analytics.summary?.total_events || 0,
      highSeverity: analytics.summary?.high || 0,
      windowsHosts: analytics.summary?.hosts || 0,
      eventsPerSec: analytics.summary?.eps || 0,
      trendData: analytics.events_per_hour || {},
      severityDistribution: analytics.severity || {},
    };
  }, [analytics]);

  const value = useMemo(() => ({
    connected, connectionState, latestEvent, notifications,
    metrics, analytics, analyticsLoading, alertStatusUpdates,
    notificationUpdateTick,
    unread: notifications.length,
    clearNotifications, forceResync,
  }), [connected, connectionState, latestEvent, notifications, metrics, analytics, analyticsLoading, alertStatusUpdates, notificationUpdateTick, clearNotifications, forceResync]);

  return (
    <LiveSOCContext.Provider value={value}>
      {children}
    </LiveSOCContext.Provider>
  );
}

export function useLiveSOC() {
  const context = useContext(LiveSOCContext);
  if (!context) throw new Error("useLiveSOC must be consumed inside a LiveSOCProvider.");
  return context;
}