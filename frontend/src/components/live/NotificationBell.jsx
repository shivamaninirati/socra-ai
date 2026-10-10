import {
  Bell,
  CheckCheck,
  X,
  AlertTriangle,
  Shield,
  Clock,
  Hash,
  Target,
  ChevronDown,
  AlertCircle,
  Loader2,
  ExternalLink,
  CheckCircle2,
} from "lucide-react";
import { useEffect, useState, useCallback, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useLiveSOC } from "../../context/LiveSOCContext";
import api from "../../services/api";

const PAGE_SIZE = 20;
const BASELINE_PAGE_SIZE = 200;
const TOAST_DURATION_MS = 4500;
const MAX_SEEN_TOAST_KEYS = 5000;
const TOAST_STORAGE_PREFIX = "socra:notification-toast-seen:v2:";
const TOAST_WATERMARK_SUFFIX = ":watermark";

function hashText(value) {
  let hash = 2166136261;
  const text = String(value || "");
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(36);
}

function getStableUserIdentity(token) {
  // Prefer a stable account identifier from the JWT rather than hashing the
  // entire token, because a refreshed token for the same user would otherwise
  // reset the toast ledger and replay old notifications.
  try {
    if (token) {
      const payloadPart = token.split(".")[1];
      if (payloadPart) {
        const normalized = payloadPart.replace(/-/g, "+").replace(/_/g, "/");
        const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
        const payload = JSON.parse(window.atob(padded));
        const identity = payload.user_id ?? payload.id ?? payload.sub ?? payload.username ?? payload.email;
        if (identity !== undefined && identity !== null && String(identity).trim()) {
          return `user:${String(identity).trim().toLowerCase()}`;
        }
      }
    }
  } catch {
    // Fall back to user metadata or a token hash below.
  }

  for (const key of ["user", "currentUser", "user_data", "current_user"]) {
    try {
      const raw = window.localStorage.getItem(key);
      if (!raw) continue;
      const user = JSON.parse(raw);
      const identity = user?.user_id ?? user?.id ?? user?.username ?? user?.email;
      if (identity !== undefined && identity !== null && String(identity).trim()) {
        return `user:${String(identity).trim().toLowerCase()}`;
      }
    } catch {
      // Continue to the next known user metadata key.
    }
  }

  return token ? `token:${hashText(token)}` : "anonymous";
}

function getToastStorageKey() {
  try {
    const token =
      window.localStorage.getItem("token") ||
      window.localStorage.getItem("access_token") ||
      "";
    return `${TOAST_STORAGE_PREFIX}${hashText(getStableUserIdentity(token))}`;
  } catch {
    return `${TOAST_STORAGE_PREFIX}session`;
  }
}

function readPersistedToastKeys(storageKey) {
  try {
    const parsed = JSON.parse(window.localStorage.getItem(storageKey) || "[]");
    return Array.isArray(parsed)
      ? parsed.filter((key) => typeof key === "string").slice(-MAX_SEEN_TOAST_KEYS)
      : [];
  } catch {
    return [];
  }
}

function persistToastKeys(storageKey, keys) {
  try {
    window.localStorage.setItem(
      storageKey,
      JSON.stringify([...keys].slice(-MAX_SEEN_TOAST_KEYS)),
    );
  } catch {
    // Notifications still work for this session when browser storage is blocked.
  }
}

function readPersistedToastWatermark(storageKey) {
  try {
    const parsed = JSON.parse(
      window.localStorage.getItem(`${storageKey}${TOAST_WATERMARK_SUFFIX}`) || "null",
    );
    if (!parsed || !Number.isFinite(Number(parsed.timestamp))) return null;
    return {
      timestamp: Number(parsed.timestamp),
      numericId: parsed.numericId !== null && parsed.numericId !== undefined && parsed.numericId !== "" && Number.isFinite(Number(parsed.numericId))
        ? Number(parsed.numericId)
        : null,
    };
  } catch {
    return null;
  }
}

function getNotificationOrder(notification) {
  const rawTime =
    notification?.event_time ?? notification?.created_at ?? notification?.eventTime ?? notification?.event?.time;
  const timestamp = rawTime ? new Date(rawTime).getTime() : NaN;
  const rawId = notification?.alert_id ?? notification?._id ?? notification?.id;
  const numericId = rawId !== undefined && rawId !== null && String(rawId).trim() !== ""
    ? Number(rawId)
    : NaN;
  if (!Number.isFinite(timestamp)) return null;
  return {
    timestamp,
    numericId: Number.isFinite(numericId) ? numericId : null,
  };
}

function compareNotificationOrder(left, right) {
  if (!left) return right ? -1 : 0;
  if (!right) return 1;
  if (left.timestamp !== right.timestamp) return left.timestamp > right.timestamp ? 1 : -1;
  if (left.numericId !== null && right.numericId !== null && left.numericId !== right.numericId) {
    return left.numericId > right.numericId ? 1 : -1;
  }
  return 0;
}

function advancePersistedToastWatermark(storageKey, notifications) {
  const current = readPersistedToastWatermark(storageKey);
  let newest = current;
  for (const notification of notifications || []) {
    const order = getNotificationOrder(notification);
    if (order && compareNotificationOrder(order, newest) > 0) newest = order;
  }
  if (newest && (!current || compareNotificationOrder(newest, current) > 0)) {
    try {
      window.localStorage.setItem(
        `${storageKey}${TOAST_WATERMARK_SUFFIX}`,
        JSON.stringify(newest),
      );
    } catch {
      // The stable-key ledger still prevents most duplicate toasts if storage is blocked.
    }
  }
  return newest;
}

function isNewerThanPersistedWatermark(notification, watermark) {
  const order = getNotificationOrder(notification);
  // With no timestamp watermark (e.g. an initially empty database), use the
  // persistent seen-key set to identify genuinely new items.
  if (!watermark) return true;
  if (!order) return false;
  return compareNotificationOrder(order, watermark) > 0;
}

/**
 * Return a stable key for deduplicating events across notification refreshes.
 * The event/database ID is preferred when a fingerprint is not supplied.
 */
function getNotificationKey(notification) {
  if (!notification || typeof notification !== "object") return null;

  const id = notification.alert_id ?? notification._id ?? notification.id;
  if (id !== undefined && id !== null && String(id) !== "") {
    return `id:${String(id)}`;
  }

  const fingerprint =
    notification.fingerprint || notification.metadata?.fingerprint;
  if (fingerprint) return `fp:${String(fingerprint)}`;

  const eventId = notification.event_id ?? notification.event?.event_id ?? "";
  const eventTime =
    notification.event_time ?? notification.eventTime ?? notification.event?.time ?? "";
  const host = notification.host ?? notification.event?.host ?? "";
  const processName =
    notification.process_name ?? notification.event?.process_name ?? "";

  if (eventId || eventTime) {
    return `event:${String(eventId)}|${String(eventTime)}|${String(host)}|${String(processName)}`;
  }

  return null;
}

function normalizedSeverity(notification) {
  return String(notification?.severity || "").trim().toLowerCase();
}

function isNotificationSeverity(notification) {
  const severity = normalizedSeverity(notification);
  return severity === "high" || severity === "critical";
}

function NotificationBell() {
  const { notificationUpdateTick } = useLiveSOC();
  const navigate = useNavigate();

  const [open, setOpen] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [summary, setSummary] = useState({
    critical: 0,
    high: 0,
    system: 0,
    total_attention: 0,
  });
  const [unreadCount, setUnreadCount] = useState(0);
  const [totalToday, setTotalToday] = useState(0);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState(null);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(false);
  const [actionLoading, setActionLoading] = useState(null);
  const [toast, setToast] = useState(null);
  const [toastBaselineReady, setToastBaselineReady] = useState(false);

  const panelRef = useRef(null);
  const openRef = useRef(open);
  const latestTickRef = useRef(notificationUpdateTick);
  const lastHandledTickRef = useRef(0);
  const toastStorageKeyRef = useRef(null);
  if (toastStorageKeyRef.current === null) {
    toastStorageKeyRef.current = getToastStorageKey();
  }
  const notificationsRef = useRef(notifications);
  notificationsRef.current = notifications;
  // Used only if the initial baseline request fails; never use a timed
  // suppression window after Mark all read, because the very next real alert
  // must be allowed to notify immediately.
  const suppressNextUpdateToastRef = useRef(false);
  const seenToastKeysRef = useRef(null);
  if (seenToastKeysRef.current === null) {
    seenToastKeysRef.current = new Set(
      readPersistedToastKeys(toastStorageKeyRef.current),
    );
  }
  const toastQueueRef = useRef([]);
  const activeToastRef = useRef(null);
  const toastTimerRef = useRef(null);
  const processToastQueueRef = useRef(null);
  const toastGenerationRef = useRef(0);
  const summaryRequestVersionRef = useRef(0);
  const unreadRequestVersionRef = useRef(0);
  const markAllReadInProgressRef = useRef(false);

  // Keep refs current without making async notification checks depend on UI open state.
  openRef.current = open;
  latestTickRef.current = notificationUpdateTick;

  const rememberToastKey = useCallback((key) => {
    if (!key) return;
    const keys = seenToastKeysRef.current;
    if (keys.has(key)) return;
    keys.add(key);
    while (keys.size > MAX_SEEN_TOAST_KEYS) {
      const oldestKey = keys.values().next().value;
      if (oldestKey === undefined) break;
      keys.delete(oldestKey);
    }
    persistToastKeys(toastStorageKeyRef.current, keys);
  }, []);

  // Present queued new-alert toasts one by one. The queue prevents a burst of
  // simultaneous HIGH/CRITICAL events from silently dropping all but one toast.
  processToastQueueRef.current = () => {
    if (activeToastRef.current || toastQueueRef.current.length === 0) return;

    const nextToast = toastQueueRef.current.shift();
    if (!nextToast) return;

    activeToastRef.current = nextToast;
    setToast(nextToast);

    if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
    toastTimerRef.current = setTimeout(() => {
      activeToastRef.current = null;
      setToast(null);
      toastTimerRef.current = null;
      processToastQueueRef.current?.();
    }, TOAST_DURATION_MS);
  };

  const enqueueNewAlertToast = useCallback((notification) => {
    if (!isNotificationSeverity(notification)) return;

    const key = getNotificationKey(notification);
    if (!key || seenToastKeysRef.current.has(key)) return;

    rememberToastKey(key);
    const severity = normalizedSeverity(notification);
    const title = notification.title || notification.detection || "Security alert";

    toastQueueRef.current.push({
      key,
      message: `${severity === "critical" ? "CRITICAL" : "HIGH"}: ${title}`,
      severity,
    });
    processToastQueueRef.current?.();
  }, [rememberToastKey]);

  const dismissToast = useCallback(() => {
    if (toastTimerRef.current) {
      clearTimeout(toastTimerRef.current);
      toastTimerRef.current = null;
    }
    activeToastRef.current = null;
    setToast(null);
    processToastQueueRef.current?.();
  }, []);

  // Mark-all-read must dismiss the current popup AND discard queued popups for
  // alerts that the user has just acknowledged. Do not advance the queue here.
  const clearAllToasts = useCallback(() => {
    // Invalidate notification-update work that started before the user cleared
    // the inbox. An older in-flight request must not resurrect a dismissed toast.
    toastGenerationRef.current += 1;
    if (toastTimerRef.current) {
      clearTimeout(toastTimerRef.current);
      toastTimerRef.current = null;
    }
    activeToastRef.current = null;
    toastQueueRef.current = [];
    setToast(null);
  }, []);

  // ----------------------------------------------------------------
  // Fetch notification summary (severity counts) from backend
  // ----------------------------------------------------------------
  const fetchSummary = useCallback(async () => {
    // Avoid a stale request restoring the old unread summary while a bulk-read
    // operation is running. A fresh request is made after the operation ends.
    if (markAllReadInProgressRef.current) return;
    const requestVersion = ++summaryRequestVersionRef.current;

    try {
      const res = await api.get("/notifications/summary");
      if (
        requestVersion !== summaryRequestVersionRef.current ||
        markAllReadInProgressRef.current
      ) return;
      setSummary(
        res.data || { critical: 0, high: 0, system: 0, total_attention: 0 },
      );
    } catch (err) {
      try {
        const res = await api.get("/notifications/unread-count");
        if (
          requestVersion !== summaryRequestVersionRef.current ||
          markAllReadInProgressRef.current
        ) return;
        const count = typeof res.data?.count === "number" ? res.data.count : 0;
        setSummary({ critical: 0, high: 0, system: 0, total_attention: count });
      } catch (fallbackError) {
        // Do not erase the last known summary during a temporary API failure.
        console.error("[NotificationBell] Failed to fetch summary:", fallbackError || err);
      }
    }
  }, []);

  const fetchUnreadCount = useCallback(async () => {
    if (markAllReadInProgressRef.current) return;
    const requestVersion = ++unreadRequestVersionRef.current;

    try {
      const res = await api.get("/notifications/unread-count");
      if (
        requestVersion !== unreadRequestVersionRef.current ||
        markAllReadInProgressRef.current
      ) return;
      setUnreadCount(Math.max(0, Number(res.data?.count) || 0));
    } catch (err) {
      console.error("[NotificationBell] Failed to fetch unread count:", err);
    }
  }, []);

  // ----------------------------------------------------------------
  // Fetch notifications. Appended pages are deduplicated by stable IDs.
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
      const data = res.data || {};
      const items = Array.isArray(data.items) ? data.items : [];

      if (append) {
        setNotifications((previous) => {
          const existingKeys = new Set(previous.map(getNotificationKey).filter(Boolean));
          const additions = items.filter((item) => {
            const key = getNotificationKey(item);
            if (!key) return true;
            if (existingKeys.has(key)) return false;
            existingKeys.add(key);
            return true;
          });
          return [...previous, ...additions];
        });
      } else {
        setNotifications(items);
      }

      setTotalToday(Number(data.total) || 0);
      setHasMore(Boolean(data.has_more));
      setPage(Number(data.page) || pageNum);
      setError(null);
    } catch (err) {
      console.error("[NotificationBell] Failed to fetch notifications:", err);
      if (!append) setError("Unable to load notifications.");
    } finally {
      if (append) setLoadingMore(false);
      else setLoading(false);
    }
  }, []);

  // Explicit type="button" on all panel controls prevents accidental form
  // submission/page reloads that can make Load more appear to click through.
  const loadMore = useCallback((event) => {
    event?.preventDefault();
    event?.stopPropagation();
    if (loadingMore || !hasMore) return;
    fetchNotifications(page + 1, true);
  }, [fetchNotifications, page, hasMore, loadingMore]);

  // ----------------------------------------------------------------
  // Baseline existing events without toasting historical notifications.
  // This prevents a popup just because the user opened or refreshed the app.
  // ----------------------------------------------------------------
  useEffect(() => {
    let cancelled = false;

    const establishBaseline = async () => {
      try {
        const startingTick = latestTickRef.current;
        const res = await api.get("/notifications/today", {
          params: { page: 1, page_size: BASELINE_PAGE_SIZE },
        });
        if (cancelled) return;
        const items = Array.isArray(res.data?.items) ? res.data.items : [];
        const priorWatermark = readPersistedToastWatermark(toastStorageKeyRef.current);

        if (priorWatermark) {
          // This is a component remount / page navigation, not a first install.
          // Surface only unread alerts newer than the previously persisted
          // watermark. Already-shown alerts are present in the persistent key
          // ledger, so refreshing or moving to another route won't replay them.
          const missedNewAlerts = [];
          for (const item of items) {
            const key = getNotificationKey(item);
            if (!key) continue;

            const isRead = item.read === true || item.read === 1;
            if (isRead) {
              rememberToastKey(key);
              continue;
            }

            if (
              isNotificationSeverity(item) &&
              !seenToastKeysRef.current.has(key) &&
              isNewerThanPersistedWatermark(item, priorWatermark)
            ) {
              missedNewAlerts.push(item);
            } else {
              // Historical or non-eligible records must never create a toast
              // on this or a later mount.
              rememberToastKey(key);
            }
          }
          // Results are newest-first; queue oldest-first for a natural sequence.
          missedNewAlerts.reverse().forEach(enqueueNewAlertToast);
        } else {
          // First install / empty ledger: treat current records as history.
          // Do not announce old alerts simply because the user refreshed.
          items.forEach((item) => rememberToastKey(getNotificationKey(item)));
        }

        // Persist a high-water mark as well as IDs. The IDs suppress known alerts;
        // the watermark prevents older alerts outside the baseline page from
        // generating popups on refresh or when the component remounts.
        advancePersistedToastWatermark(toastStorageKeyRef.current, items);
        // Ticks arriving after this request began remain eligible for processing
        // once the baseline is ready. Any already-queued candidates are protected
        // from duplicates by the persistent key ledger.
        lastHandledTickRef.current = startingTick;
      } catch (err) {
        // If the baseline request fails, treat the next successful update as a
        // baseline too; otherwise historical entries could cause false popups.
        suppressNextUpdateToastRef.current = true;
        console.warn("[NotificationBell] Could not establish toast baseline:", err);
      } finally {
        if (!cancelled) {
          setToastBaselineReady(true);
        }
      }
    };

    establishBaseline();
    return () => {
      cancelled = true;
    };
  }, [rememberToastKey]);

  // Initial summary fetch.
  useEffect(() => {
    fetchSummary();
    fetchUnreadCount();
  }, [fetchSummary, fetchUnreadCount]);

  // Load the list when the dropdown opens.
  useEffect(() => {
    if (open) {
      setPage(1);
      fetchNotifications(1, false);
    }
  }, [open, fetchNotifications]);

  // ----------------------------------------------------------------
  // React to backend notification_update WebSocket ticks even when the panel
  // is closed. Only entries absent from the initial baseline create a toast.
  // ----------------------------------------------------------------
  useEffect(() => {
    if (!toastBaselineReady || notificationUpdateTick <= lastHandledTickRef.current) return undefined;

    lastHandledTickRef.current = notificationUpdateTick;
    let cancelled = false;

    const toastGenerationAtStart = toastGenerationRef.current;
    const processNotificationUpdate = async () => {
      try {
        const [notificationResponse] = await Promise.all([
          api.get("/notifications/today", {
            // A wider snapshot catches bursts without treating items from an
            // older, unloaded page as newly arrived alerts.
            params: { page: 1, page_size: BASELINE_PAGE_SIZE },
          }),
          fetchSummary(),
          fetchUnreadCount(),
        ]);

        if (cancelled) return;

        const data = notificationResponse.data || {};
        const items = Array.isArray(data.items) ? data.items : [];
        const newlySeenEligible = [];
        const pendingKeys = new Set();
        const staleToastGeneration = toastGenerationAtStart !== toastGenerationRef.current;
        const suppressThisUpdate = suppressNextUpdateToastRef.current;
        const watermarkAtRequestStart = readPersistedToastWatermark(toastStorageKeyRef.current);
        suppressNextUpdateToastRef.current = false;

        for (const item of items) {
          const key = getNotificationKey(item);
          if (!key) continue;

          // Read items are historical notifications, not new popup candidates.
          // This also prevents a dismissed/read notification from reappearing
          // after refresh or a bulk-read WebSocket update.
          const isRead = item.read === true || item.read === 1;
          if (isRead || staleToastGeneration || suppressThisUpdate || markAllReadInProgressRef.current) {
            rememberToastKey(key);
            continue;
          }

          if (seenToastKeysRef.current.has(key) || pendingKeys.has(key)) continue;

          // Do not replay unseen historical records older than the persisted
          // watermark (for example, events outside the first 200 at startup).
          if (!isNewerThanPersistedWatermark(item, watermarkAtRequestStart)) {
            rememberToastKey(key);
            continue;
          }

          const severity = normalizedSeverity(item);
          if (severity === "high" || severity === "critical") {
            pendingKeys.add(key);
            newlySeenEligible.push(item);
          } else {
            rememberToastKey(key);
          }
        }

        // Persist the newest processed event order. On refresh or route remount,
        // older records cannot be mistaken for new alerts even if an ID was not
        // part of the startup page. Current update candidates used the previous
        // watermark above, so every genuinely new event in this batch is kept.
        advancePersistedToastWatermark(toastStorageKeyRef.current, items);

        // API results are normally newest first. Queue oldest-first so the newest
        // toast is the last one seen if several alerts arrive in one update burst.
        newlySeenEligible.reverse().forEach(enqueueNewAlertToast);

        if (openRef.current) {
          setNotifications(items);
          setTotalToday(Number(data.total) || 0);
          setPage(Number(data.page) || 1);
          setHasMore(Boolean(data.has_more));
          setError(null);
        }
      } catch (err) {
        console.error("[NotificationBell] Failed to process notification update:", err);
      }
    };

    processNotificationUpdate();
    return () => {
      cancelled = true;
    };
  }, [notificationUpdateTick, toastBaselineReady, fetchSummary, fetchUnreadCount, enqueueNewAlertToast, rememberToastKey]);

  // ----------------------------------------------------------------
  // Close on outside click
  // ----------------------------------------------------------------
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (panelRef.current && !panelRef.current.contains(event.target)) setOpen(false);
    };

    if (open) document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [open]);

  // ----------------------------------------------------------------
  // Actions: Mark as Read, Mark All Read, Investigate
  // ----------------------------------------------------------------
  const handleMarkRead = useCallback(async (alertId, event) => {
    event?.preventDefault();
    event?.stopPropagation();
    if (alertId === undefined || alertId === null) return;

    setActionLoading(alertId);
    try {
      await api.patch("/notifications/mark-read", { notification_id: alertId });
      setNotifications((previous) => previous.map((notification) =>
        notification.alert_id === alertId || notification.id === alertId
          ? { ...notification, read: true }
          : notification,
      ));
      await Promise.all([fetchSummary(), fetchUnreadCount()]);
    } catch (err) {
      console.error("[NotificationBell] Failed to mark as read:", err);
    } finally {
      setActionLoading(null);
    }
  }, [fetchSummary, fetchUnreadCount]);

  const handleMarkAllRead = useCallback(async (event) => {
    event?.preventDefault();
    event?.stopPropagation();
    if (loading || markAllReadInProgressRef.current) return;

    // Pause count refreshes and invalidate requests that may still return the
    // pre-clear unread count after this action has completed.
    markAllReadInProgressRef.current = true;
    summaryRequestVersionRef.current += 1;
    unreadRequestVersionRef.current += 1;

    // Persist all currently known alerts as seen before dismissing the toast
    // queue. This makes Mark all read survive React remounts and page refreshes.
    notificationsRef.current.forEach((notification) => {
      rememberToastKey(getNotificationKey(notification));
    });
    if (activeToastRef.current?.key) rememberToastKey(activeToastRef.current.key);
    toastQueueRef.current.forEach((queuedToast) => rememberToastKey(queuedToast.key));

    // Dismiss the active toast and discard queued toasts immediately. New alerts
    // with new stable IDs can still notify after this operation.
    clearAllToasts();

    // Optimistically reset the badge/header to zero so an old in-flight count
    // cannot leave the red badge visible after the user has cleared the inbox.
    setUnreadCount(0);
    setSummary({ critical: 0, high: 0, system: 0, total_attention: 0 });
    setNotifications((previous) =>
      previous.map((notification) => ({ ...notification, read: true })),
    );
    setLoading(true);

    let succeeded = false;
    try {
      await api.patch("/notifications/mark-all-read");
      succeeded = true;

      // Persist a server-side snapshot of the read-all boundary. This prevents
      // unread flags, WebSocket replays, or route remounts from reviving popups
      // for alerts that existed when the user pressed Mark all read.
      try {
        const snapshot = await api.get("/notifications/today", {
          params: { page: 1, page_size: BASELINE_PAGE_SIZE },
        });
        const snapshotItems = Array.isArray(snapshot.data?.items) ? snapshot.data.items : [];
        snapshotItems.forEach((notification) => {
          rememberToastKey(getNotificationKey(notification));
        });
        advancePersistedToastWatermark(toastStorageKeyRef.current, snapshotItems);
      } catch (snapshotError) {
        // At minimum suppress all rows already held by this component.
        notificationsRef.current.forEach((notification) => {
          rememberToastKey(getNotificationKey(notification));
        });
        advancePersistedToastWatermark(toastStorageKeyRef.current, notificationsRef.current);
        console.warn("[NotificationBell] Could not refresh toast baseline after mark-all-read:", snapshotError);
      }

      // Invalidate any older requests one more time after the server confirms
      // the persistent read-state change.
      summaryRequestVersionRef.current += 1;
      unreadRequestVersionRef.current += 1;
      setUnreadCount(0);
      setSummary({ critical: 0, high: 0, system: 0, total_attention: 0 });
      setNotifications((previous) => previous.map((notification) => ({ ...notification, read: true })));
    } catch (err) {
      console.error("[NotificationBell] Failed to mark all as read:", err);
      // Restore the actual persisted state if the request failed.
      await fetchNotifications(1, false);
    } finally {
      markAllReadInProgressRef.current = false;
      setLoading(false);
      // Refresh only after the mark-all operation is finished. This allows the
      // next genuine alert to be counted from zero (1, 2, 3...) without an older
      // request restoring the previous badge count. Any truly new event that
      // arrived during the request will still be reflected by the backend count.
      await Promise.all([fetchSummary(), fetchUnreadCount()]);
      if (!succeeded) {
        // Popup was dismissed by the user's explicit action; don't replay old
        // notifications. A future backend update may announce genuinely new IDs.
        clearAllToasts();
      }
    }
  }, [fetchSummary, fetchUnreadCount, fetchNotifications, loading, clearAllToasts, rememberToastKey]);

  const handleInvestigate = useCallback((notification, event) => {
    event?.preventDefault();
    event?.stopPropagation();
    setOpen(false);
    navigate("/alerts", {
      state: {
        highlightAlertId: notification.alert_id ?? notification.id,
        eventId: notification.event_id,
        eventTime: notification.event_time,
      },
    });
  }, [navigate]);



  // Clear toast timers and queued popups on unmount.
  useEffect(() => () => {
    if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
    toastTimerRef.current = null;
  }, []);

  // ----------------------------------------------------------------
  // Helpers
  // ----------------------------------------------------------------
  const getSeverityColor = (severity) => {
    switch (String(severity || "").toLowerCase()) {
      case "critical": return "text-red-400 bg-red-500/20 border-red-500/30";
      case "high": return "text-orange-400 bg-orange-500/20 border-orange-500/30";
      default: return "text-slate-400 bg-slate-500/20 border-slate-500/30";
    }
  };

  // This is the severity marker at the far left of the row (red/orange).
  // The separate cyan/blue dot beside the severity badge has been removed.
  const getSeverityDot = (severity) => {
    switch (String(severity || "").toLowerCase()) {
      case "critical": return "bg-red-500";
      case "high": return "bg-orange-500";
      default: return "bg-slate-500";
    }
  };

  const getRelativeTime = (timestamp) => {
    if (!timestamp) return "";
    const parsed = new Date(timestamp).getTime();
    if (!Number.isFinite(parsed)) return "";
    const diffMs = Math.max(0, Date.now() - parsed);
    const diffMin = Math.floor(diffMs / 60000);
    const diffHr = Math.floor(diffMin / 60);
    if (diffMin < 1) return "Just now";
    if (diffMin < 60) return `${diffMin}m ago`;
    if (diffHr < 24) return `${diffHr}h ago`;
    return "Yesterday";
  };

  // The bell badge represents unread notifications, not all active attention items.
  const badgeCount = Math.max(0, Number(unreadCount) || 0);
  const hasNotifications = notifications.length > 0 || totalToday > 0;
  const hasUnread = badgeCount > 0;

  let statusText = "";
  let statusClass = "";
  if (!hasNotifications && badgeCount === 0) {
    statusText = "No High or Critical alerts today";
    statusClass = "text-slate-500";
  } else if (hasNotifications && !hasUnread) {
    statusText = "All caught up";
    statusClass = "text-green-400 font-medium";
  } else if (hasUnread) {
    statusText = `${badgeCount} unread`;
    statusClass = "text-red-300 font-medium";
  }

  return (
    <div className="relative" ref={panelRef}>
      {/* Bell button with unread badge */}
      <button
        type="button"
        aria-label={badgeCount > 0 ? `Notifications, ${badgeCount} unread` : "Notifications"}
        aria-expanded={open}
        onClick={(event) => {
          event.preventDefault();
          event.stopPropagation();
          setOpen((previous) => !previous);
        }}
        className="relative w-[44px] h-[44px] flex items-center justify-center rounded-lg bg-slate-900/40 border border-slate-700 hover:bg-slate-800/60 transition-all duration-150"
      >
        <Bell size={20} className="text-cyan-400" />
        {badgeCount > 0 && (
          <span className="absolute -top-1 -right-1 min-w-[20px] h-5 px-1 rounded-full bg-red-600 text-white text-[10px] font-bold flex items-center justify-center shadow-lg shadow-red-500/30 ring-1 ring-slate-950">
            {badgeCount > 99 ? "99+" : badgeCount}
          </span>
        )}
      </button>

      {/* Red-accented toast for genuinely new HIGH/CRITICAL notifications */}
      {toast && (
        <div
          role="status"
          aria-live="assertive"
          className={`fixed top-20 right-4 z-[100] max-w-[calc(100vw-2rem)] rounded-lg border border-red-400/70 bg-red-950/95 px-3 py-2 shadow-2xl shadow-red-950/50 flex items-center gap-2 text-sm text-white ${
            toast.severity === "critical" ? "ring-1 ring-red-500/50" : ""
          }`}
        >
          <span className="h-2 w-2 rounded-full bg-red-500 shrink-0 animate-pulse" />
          <AlertTriangle size={15} className="text-red-300 shrink-0" />
          <span className="truncate max-w-[300px] font-semibold">{toast.message}</span>
          <button
            type="button"
            aria-label="Dismiss alert notification"
            onClick={dismissToast}
            className="ml-1 rounded p-1 text-white/70 hover:bg-white/10 hover:text-white shrink-0"
          >
            <X size={13} />
          </button>
        </div>
      )}

      {open && (
        <div className="absolute right-0 mt-2 w-[min(380px,calc(100vw-1rem))] max-h-[450px] rounded-xl border border-slate-700/80 bg-slate-900 shadow-2xl shadow-black/50 overflow-hidden z-50 flex flex-col">
          {/* Fixed header */}
          <div className="p-3 border-b border-slate-700/60 bg-slate-800/50 shrink-0">
            <div className="flex items-center justify-between mb-1.5">
              <h3 className="font-semibold text-white text-xs">Today&apos;s Notifications</h3>
              <div className="flex items-center gap-2">
                {badgeCount > 0 && (
                  <button
                    type="button"
                    onClick={handleMarkAllRead}
                    disabled={loading}
                    className={`flex items-center gap-1 text-[10px] transition-colors ${loading ? "text-slate-500 cursor-not-allowed" : "text-cyan-400 hover:text-cyan-300"}`}
                  >
                    <CheckCheck size={12} className={loading ? "animate-pulse" : ""} />
                    {loading ? "Marking..." : "Mark all read"}
                  </button>
                )}
                <button
                  type="button"
                  aria-label="Close notifications"
                  onClick={(event) => {
                    event.preventDefault();
                    event.stopPropagation();
                    setOpen(false);
                  }}
                  className="p-0.5 text-slate-400 hover:text-white rounded transition-colors"
                >
                  <X size={14} />
                </button>
              </div>
            </div>

            <div className="flex items-center gap-2 text-[10px] min-w-0">
              {summary.critical > 0 && (
                <span className="flex items-center gap-1 text-red-400 font-semibold shrink-0">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
                  {summary.critical} Critical
                </span>
              )}
              {summary.high > 0 && (
                <span className="flex items-center gap-1 text-orange-400 font-semibold shrink-0">
                  <span className="w-1.5 h-1.5 rounded-full bg-orange-500" />
                  {summary.high} High
                </span>
              )}
              {summary.system > 0 && (
                <span className="flex items-center gap-1 text-slate-400 shrink-0">
                  <span className="w-1.5 h-1.5 rounded-full bg-slate-500" />
                  {summary.system} System
                </span>
              )}
              <span className={`${statusClass} truncate`}>{statusText}</span>
              {totalToday > 0 && (
                <span className="text-slate-500 ml-auto shrink-0">{totalToday} today</span>
              )}
            </div>
          </div>

          {/* Only this section scrolls. Header and footer stay visible. */}
          <div className="flex-1 min-h-0 overflow-y-auto custom-scrollbar">
            {loading && notifications.length === 0 ? (
              <div className="p-8 text-center">
                <Loader2 size={24} className="mx-auto text-cyan-400 animate-spin" />
                <p className="mt-2 text-slate-400 text-sm">Loading...</p>
              </div>
            ) : error ? (
              <div className="p-6 text-center">
                <AlertCircle size={24} className="mx-auto text-red-400" />
                <p className="mt-2 text-red-400 text-sm">{error}</p>
                <button
                  type="button"
                  onClick={(event) => {
                    event.preventDefault();
                    event.stopPropagation();
                    fetchNotifications(1, false);
                  }}
                  className="mt-2 text-xs text-cyan-400 hover:text-cyan-300"
                >
                  Try again
                </button>
              </div>
            ) : notifications.length === 0 && !loading ? (
              <div className="p-6 text-center">
                <Shield size={28} className="mx-auto text-slate-600" />
                <p className="mt-2 text-slate-400 text-sm">No High or Critical alerts today</p>
                <p className="mt-1 text-slate-500 text-[11px]">
                  SOCRA AI will bring important threats to your attention
                </p>
              </div>
            ) : (
              <>
                {notifications.map((notification) => {
                  const notificationKey = getNotificationKey(notification) || `${notification.event_id || "event"}-${notification.event_time || "time"}`;
                  const alertId = notification.alert_id ?? notification.id;
                  return (
                    <div
                      key={notificationKey}
                      className={`p-2 border-b border-slate-700/30 hover:bg-slate-800/40 transition-colors duration-100 group ${
                        !notification.read ? "bg-slate-800/30" : ""
                      }`}
                    >
                      <div className="flex items-start gap-2">
                        {/* Keep the severity-colored row marker; remove the cyan dot beside the badge. */}
                        <div className={`w-2 h-2 rounded-full mt-1 flex-shrink-0 ${getSeverityDot(notification.severity)}`} />

                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-1.5 mb-0.5">
                            <span className={`text-[9px] font-bold px-1 py-0.5 rounded border uppercase tracking-wide ${getSeverityColor(notification.severity)}`}>
                              {notification.severity}
                            </span>
                          </div>

                          <p className="text-[12px] text-white font-medium truncate group-hover:text-cyan-100 transition-colors">
                            {notification.title || "Security alert"}
                          </p>

                          <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 mt-1 text-[10px] text-slate-400">
                            {notification.host && (
                              <span className="flex items-center gap-1">
                                <AlertTriangle size={9} className="text-slate-500" />
                                {notification.host}
                              </span>
                            )}
                            {notification.process_name && (
                              <span className="text-slate-300 font-mono text-[9px]">{notification.process_name}</span>
                            )}
                            {notification.process_id && (
                              <span className="text-slate-500 font-mono text-[9px]">PID: {notification.process_id}</span>
                            )}
                            {notification.mitre && (
                              <span className="flex items-center gap-1 text-purple-400">
                                <Target size={9} />{notification.mitre}
                              </span>
                            )}
                            {notification.event_id && (
                              <span className="flex items-center gap-1">
                                <Hash size={9} className="text-slate-500" />{notification.event_id}
                              </span>
                            )}
                          </div>

                          <div className="flex items-center justify-between mt-1 gap-1">
                            <span className="flex items-center gap-1 text-[9px] text-slate-500 shrink-0">
                              <Clock size={8} />
                              {getRelativeTime(notification.created_at || notification.event_time)}
                            </span>

                            <div className="flex items-center gap-0.5 shrink-0">
                              <button
                                type="button"
                                onClick={(event) => handleInvestigate(notification, event)}
                                className="flex items-center gap-0.5 text-[9px] text-cyan-400 hover:text-cyan-300 transition-colors px-1 py-0.5 rounded hover:bg-cyan-500/10"
                              >
                                <ExternalLink size={8} />
                                Investigate
                              </button>
                              {!notification.read && (
                                <button
                                  type="button"
                                  onClick={(event) => handleMarkRead(alertId, event)}
                                  disabled={actionLoading === alertId}
                                  className="flex items-center gap-0.5 text-[9px] text-slate-400 hover:text-green-400 transition-colors px-1 py-0.5 rounded hover:bg-green-500/10 disabled:opacity-50"
                                >
                                  {actionLoading === alertId ? (
                                    <Loader2 size={8} className="animate-spin" />
                                  ) : (
                                    <CheckCircle2 size={8} />
                                  )}
                                  Read
                                </button>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}

                {hasMore && (
                  <div className="p-2 border-t border-slate-700/30 text-center">
                    <button
                      type="button"
                      onClick={loadMore}
                      disabled={loadingMore || loading || !hasMore}
                      className="flex items-center gap-1 mx-auto text-[11px] text-cyan-400 hover:text-cyan-300 disabled:text-slate-500 disabled:cursor-not-allowed"
                    >
                      {loadingMore ? (
                        <><Loader2 size={12} className="animate-spin" /> Loading...</>
                      ) : (
                        <><ChevronDown size={12} /> Load more</>
                      )}
                    </button>
                  </div>
                )}
              </>
            )}
          </div>

          {/* Fixed footer outside the scrolling list */}
          <div className="p-3 border-t border-slate-700/60 bg-slate-800/30 text-center shrink-0">
            <button
              type="button"
              onClick={(event) => {
                event.preventDefault();
                event.stopPropagation();
                setOpen(false);
                navigate("/alerts");
              }}
              className="text-[11px] text-cyan-400 hover:text-cyan-300"
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
