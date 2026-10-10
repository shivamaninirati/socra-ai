# SOCRA AI — Implement High/Critical-Only Real-Time Notifications

## Objective

Design and implement the notification system so it stores and displays ONLY HIGH and CRITICAL security notifications.

When a new HIGH or CRITICAL alert is detected, the application must:
1. Persist the notification.
2. Display an immediate in-app popup/toast.
3. Update the notification bell with a red unread-count badge.
4. Show the notification in the bell dropdown.
5. Retain all today's HIGH and CRITICAL notifications in the dropdown, including notifications already marked as read.

Preserve the existing SOCRA AI dashboard design, authentication, collector, WebSocket, SQLite database, and working features.

## 1. Inspect the existing project first

Inspect the current Git status and diff. Preserve all uncommitted changes.

Locate and inspect:
- Notification bell and dropdown components.
- Toast/notification popup components, if any.
- Frontend notification state and API services.
- Live WebSocket message handling.
- Backend event and alert processing.
- `backend/app/services/live_soc_service.py`.
- `backend/app/services/storage_manager.py`.
- The actual SQLite storage module and schema.
- Notification routes, services, indexes, deduplication, and read-state logic.
- Existing event severity normalization.

Reuse existing notification infrastructure where possible. Identify defects before editing. Do not assume previous notification fixes are complete.

## 2. Strict severity filtering

Only create notification records for events with normalized severity:
- CRITICAL
- HIGH

Never create notification records for:
- MEDIUM
- LOW
- INFORMATIONAL
- Missing, malformed, or unknown severity values.

Normalize legitimate severity formats consistently, such as `Critical`, `critical`, `HIGH`, and supported nested event structures.

Use the existing genuine alert/event record. Do not manufacture alerts or treat every ordinary event as HIGH or CRITICAL.

If existing detection logic determines severity, preserve its behavior and use its final normalized severity. Do not invent a malicious verdict based solely on an event's existence.

Apply this filtering in the backend, not only in the React UI. Verify that lower-severity events cannot enter the notification table through another supported creation path.

## 3. Persist notifications safely

Store all genuine HIGH and CRITICAL notifications according to the existing retention policy.

Each notification should include, where available:
- Stable notification ID.
- Original alert/event reference.
- Normalized severity.
- Title or summary.
- Host.
- Event timestamp.
- Notification creation timestamp.
- Stable deduplication fingerprint.
- Read/unread state.

Use a stable fingerprint or equivalent idempotency mechanism so processing or receiving the same alert repeatedly does not create duplicate notifications.

Different alerts must remain distinct.

Use the existing SQLite schema where appropriate. Add a safe, backward-compatible migration only if necessary. Never clear or recreate the production database or delete existing event history.

Keep read state associated with the correct user under the existing authorization model.

## 4. Today's notification dropdown

The notification bell dropdown should be titled "Today's Notifications".

It must display ALL HIGH and CRITICAL notifications created during the current local calendar day, including both read and unread notifications.

Requirements:
- Show the newest notifications first.
- Display severity, title, time, host, and relevant alert/event reference when available.
- Visually distinguish CRITICAL from HIGH.
- Keep read notifications visible in today's history.
- Mark read notifications visually without deleting them.
- Provide a supported action to open the corresponding alert or investigation.
- Provide a mark-as-read action.
- Provide a clear empty state only when the authorized query succeeds and no qualifying notifications exist today.
- Distinguish loading, API errors, and live disconnection from an empty notification list.

Use a well-defined timezone for day boundaries, consistent with the application's existing date handling. Ensure midnight rollover updates the displayed today's list correctly.

Do not limit today's notifications to unread entries. The unread badge and today's notification history are different data views.

## 5. Immediate popup for new HIGH/CRITICAL events

When a NEW eligible notification is created and delivered while the app is open:

- Show a visible in-app toast/popup immediately.
- Display severity, title or summary, host if available, and time.
- Use prominent red styling for CRITICAL and amber/orange styling for HIGH.
- Include an action to view the related alert.
- Dismiss automatically after a reasonable interval, with an accessible manual close control.
- Avoid blocking the dashboard or chat interface.
- Do not show a new popup for an old notification loaded during startup or page refresh.
- Do not show duplicate popups when WebSocket events are repeated or a reconnect resends an event.
- Do not display popup notifications for MEDIUM, LOW, INFORMATIONAL, or unknown severities.

The popup should be separate from the notification dropdown. New events should generate a popup even if the dropdown is closed.

Use the existing toast infrastructure if available. Do not require browser-notification permission for the in-app toast.

## 6. Red notification bell and unread count

Display a small red badge on the bell when one or more qualifying HIGH/CRITICAL notifications are unread.

The badge must:
- Reflect the server's persisted unread count.
- Update when a new notification is created.
- Update when a notification is marked as read.
- Remain correct after refresh, WebSocket reconnection, and backend restart.
- Avoid double-incrementing on duplicate live messages.
- Show no count badge when the unread count is zero.
- Display a sensible capped label for very large counts while preserving the true count internally.

Do not make the badge count depend only on how many WebSocket messages the browser has received. Reconcile it with the backend's authoritative unread count.

## 7. Real-time event delivery

Trace and implement this flow:

Genuine Windows/Sysmon event
-> existing event normalization and detection
-> HIGH/CRITICAL classification
-> persisted notification
-> authenticated real-time delivery
-> red unread badge and immediate toast
-> today's notification dropdown.

Use the existing authenticated WebSocket where possible and a reliable API refresh fallback when disconnected.

Avoid duplicate notification writes or popups caused by:
- Reconnecting WebSockets.
- Repeated event processing.
- Dashboard refreshes.
- React StrictMode effects.
- Loading persisted notification history.
- Multiple active subscriptions.

Preserve WebSocket ticket security, origin validation, authentication, and authorization. Do not put long-lived JWTs in WebSocket URLs. Do not broadcast private notifications to unauthorized users.

## 8. Notification read behavior

- Opening the dropdown must not automatically mark every item as read unless that is already the explicit, established application behavior.
- Provide a clear mark-as-read interaction.
- When an item is marked read, update its persisted read state and reduce the unread badge.
- Keep the item visible in today's history.
- Ensure the unread count remains correct after refresh or reconnection.

If the application already has a read-state model, repair and reuse it rather than introducing a conflicting second system.

## 9. Testing

Use existing test conventions and isolated temporary databases.

Add or update tests proving:
1. HIGH creates exactly one notification.
2. CRITICAL creates exactly one notification.
3. MEDIUM, LOW, INFORMATIONAL, and unknown severity do not create notification records.
4. Reprocessing the same alert does not create duplicate records.
5. Distinct alerts are not merged incorrectly.
6. Today's dropdown query returns today's HIGH/CRITICAL read and unread entries.
7. Older notification records are excluded from today's view but are not destructively deleted.
8. Unread count reflects persisted unread state.
9. Marking an item read updates the count but retains the item in today's list.
10. A new eligible notification triggers a toast.
11. Old history loaded on page startup does not trigger repeated toasts.
12. Duplicate WebSocket messages and reconnections do not generate duplicate popups.
13. API failures do not produce a false "All clear".
14. User authorization remains enforced.
15. Database migration preserves existing production data.

Run relevant backend tests, frontend lint checks, and the production build. Report failures honestly.

## 10. Design and acceptance criteria

Preserve the existing SOCRA AI dark dashboard style, spacing, typography, and navigation.

Acceptance criteria:
- Only HIGH and CRITICAL generate or appear as notifications.
- Each new eligible event creates one persisted notification.
- An immediate in-app toast appears for each genuinely new eligible alert.
- The bell shows the correct red unread count.
- Today's dropdown contains all of today's HIGH and CRITICAL notifications, read and unread.
- Marking an item as read updates the badge without removing the item.
- Refreshing the browser does not duplicate notifications or popups.
- The application handles WebSocket reconnects and API failures correctly.

Do not modify collector buffer capacity, unrelated charts, AI model configuration, or chat functionality.

Before finishing, report the root causes, files changed, schema changes, test results, and exact manual verification steps. Do not commit or push changes.