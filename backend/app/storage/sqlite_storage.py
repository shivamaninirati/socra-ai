import sqlite3
import json
import logging
import queue
import threading
import time
import hashlib
from pathlib import Path

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Canonical helpers — kept in sync with app/services/event_processor.py so the
# persisted envelope columns (fingerprint, risk_score) always match what the
# live pipeline would have produced.
# --------------------------------------------------------------------------

def _sqlite_bind_safe(value):
    """Return a value that SQLite can bind as a column parameter.

    SQLite rejects Python list/dict/tuple/set values with
    "type 'list' is not supported". Structured values that reach a scalar
    column are serialized to JSON here so writes never fail on a raw
    container; scalar/None values pass through untouched (booleans/ints are
    kept as native types so they round-trip correctly).
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return json.dumps(value, default=str)


def _basename(value):
    """Strip directory branches from a path/name (parser-style)."""
    if not value:
        return ""
    return str(value).replace("/", "\\").split("\\")[-1].strip()


def _compute_fingerprint(event):
    """Same fingerprint as EventProcessor.generate_fingerprint."""
    value = (
        f"{event.get('host', '')}"
        f"{event.get('event_id', '')}"
        f"{event.get('time', '')}"
        f"{event.get('process_name', '')}"
    )
    return hashlib.sha256(value.encode()).hexdigest()


def _compute_risk_score(severity):
    """Same mapping as EventProcessor.calculate_risk."""
    mapping = {
        "Critical": 95,
        "High": 80,
        "Medium": 60,
        "Low": 30,
        "Informational": 10,
        "Unknown": 0,
    }
    return mapping.get(severity, 0)


def _attach_alert_fields(payload, row_id, status, changed_by=None, changed_at=None):
    """Attach the persisted alert identity + triage status to a served envelope.

    The frontend reads `event.status` (falling back to detection.status then
    "New") and keys status updates on the persisted row id (`_id`) or the
    metadata fingerprint. Every SQL-served event gets both, so the Alerts
    table, the details drawer and the status filter all see the real
    persisted status instead of the "New" default.
    """
    if not isinstance(payload, dict):
        return payload
    payload["_id"] = row_id
    event_block = payload.get("event")
    if isinstance(event_block, dict):
        event_block["status"] = status or "New"
    if changed_by is not None:
        payload["_status_changed_by"] = changed_by
        payload["_status_changed_at"] = changed_at
    return payload


def _ensure_optional_admin_bootstrap(cursor):
    """Optional, EXPLICIT admin bootstrap - never an insecure default.

    No account is ever auto-created with a fixed password. A database
    administrator is created ONLY when BOTH BOOTSTRAP_ADMIN_EMAIL and
    BOOTSTRAP_ADMIN_PASSWORD are configured in the environment (read through
    the application Settings, i.e. backend/.env or real environment).

    * BOOTSTRAP_ADMIN_EMAIL set + BOOTSTRAP_ADMIN_PASSWORD set  -> create the
      admin (PBKDF2-SHA256 hashed password, nothing printed).
    * BOOTSTRAP_ADMIN_EMAIL set + password missing/empty           -> skip with
      a warning (fail safe - never a blank/insecure account).
    * Neither set (the default)                                    -> no admin
      account is created; users register normally via /register.

    Existing accounts are never modified (no password resets here).
    """
    try:
        from app.core.config import settings as _settings

        bootstrap_email = (_settings.BOOTSTRAP_ADMIN_EMAIL or "").strip().lower()
        bootstrap_password = _settings.BOOTSTRAP_ADMIN_PASSWORD or ""
    except Exception:
        # Settings unavailable (e.g. a helper script without a .env) - the
        # safe behavior is to skip the optional bootstrap entirely.
        return

    if not bootstrap_email:
        return
    if not bootstrap_password:
        print(
            "[SQLite] BOOTSTRAP_ADMIN_EMAIL is set but BOOTSTRAP_ADMIN_PASSWORD "
            "is missing - skipping admin bootstrap (no account created)."
        )
        return

    try:
        cursor.execute(
            "SELECT id FROM users WHERE email = ?", (bootstrap_email,)
        )
        if cursor.fetchone():
            return  # Account already exists - never touch it.

        import uuid
        from datetime import datetime, timezone
        from app.auth.auth_service import hash_password

        # Reuse the local part of the email as username when it is free;
        # otherwise leave username NULL (login works by email either way).
        username = (bootstrap_email.split("@")[0] or "").strip() or None
        if username:
            cursor.execute(
                "SELECT id FROM users WHERE username = ?", (username,)
            )
            if cursor.fetchone():
                username = None

        password_hash = hash_password(bootstrap_password)
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        cursor.execute(
            """
            INSERT INTO users (
                id, email, username, password_hash, role, email_verified,
                status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 'admin', 1, 'active', ?, ?)
            """,
            (
                str(uuid.uuid4()),
                bootstrap_email,
                username,
                password_hash,
                now,
                now,
            ),
        )
        # Never print credentials - only state that an explicit admin was
        # created for the configured email.
        print(
            "[SQLite] Admin bootstrap: created configured administrator for "
            f"{bootstrap_email}"
        )
    except Exception as exc:
        print(f"[SQLite] Admin bootstrap failed (no account created): {exc}")


class SQLiteStorage:

    def __init__(self):

        db_dir = Path("data")
        db_dir.mkdir(exist_ok=True)

        self.db_path = db_dir / "socra.db"
        
        # SQLite optimizations to prevent locked errors
        self.sqlite_timeout = 30.0
        self.journal_mode = "WAL"  # Write-Ahead Logging for better concurrency
        
        # Single-writer queue architecture (enterprise pattern for embedded DBs)
        self.write_queue = queue.Queue(maxsize=10000)  # Backpressure if queue fills
        self.writer_thread = None
        self.running = True
        
        # Build the schema BEFORE starting the writer thread. On a brand-new
        # database the two connections used to race to create the file and
        # switch to WAL mode, surfacing as "database is locked" on fresh
        # installs. Schema-first startup is deterministic. Anything queued
        # during initialize() (one-time backfills) is drained once the writer
        # thread starts below.
        self.initialize()

        # Start the single database writer thread
        self._start_writer_thread()

    # ----------------------------------------------------
    # Database Initialization
    # ----------------------------------------------------

    def flush(self, timeout=2.0):
        """Block until all pending writes are committed.

        Sends a sync barrier and waits for the writer thread to process it.
        Used by endpoints that need read-after-write consistency (e.g. the
        chat endpoint so the frontend immediately sees persisted messages).
        """
        barrier = threading.Event()
        self.write_queue.put(("sync", {"barrier": barrier}), block=False)
        barrier.wait(timeout=timeout)

    def _process_save_event(self, conn, event):
        """Internal method to process event saves from writer thread.

        Persists the complete event envelope (event, detection, metadata, IOC)
        in raw_json plus denormalized columns (user, parent_process,
        metadata_json, ioc_json, risk_score, fingerprint) so Investigation,
        Timeline, Reports, AI, risk scoring and deduplication all have the data
        they need.
        """
        e = event.get("event", {}) or {}
        d = event.get("detection", {}) or {}
        meta = event.get("metadata") or {}
        ioc = event.get("ioc") or {}
        mitre = d.get("mitre")
        mitre_tactic = ""
        # Robust handling of all mitre data formats: list of dicts, list of strings, dict, string
        if isinstance(mitre, list):
            # Multi-technique mapping: take the first technique for
            # denormalized columns; the full list lives in raw_json.
            if mitre:
                first = mitre[0]
                if isinstance(first, dict):
                    mitre_tactic = first.get("tactic", "")
                    mitre = first.get("id", "")
                else:
                    mitre = str(first) if first else ""
            else:
                # Empty list - set to empty string
                mitre = ""
        elif isinstance(mitre, dict):
            mitre_tactic = mitre.get("tactic", "")
            mitre = mitre.get("id", "")
        elif not isinstance(mitre, str):
            # If it's still not a string, try to get an id from it, if that fails set to empty
            mitre = ""
        try:
            cursor = conn.cursor()
            record_number = e.get("record_number")
            computer = e.get("host")
            time_created = e.get("time")
            # Complete envelope in raw_json (metadata + IOC) so analytics like
            # risk_score stay real for events stored after this change.
            # ALWAYS store metadata and IOC — even empty dicts — so the full
            # envelope is preserved and query_events can reconstruct it.
            payload = {"event": e, "detection": d, "metadata": meta, "ioc": ioc}

            severity = d.get("severity") or ""
            risk_score = meta.get("risk_score")
            if not isinstance(risk_score, (int, float)):
                risk_score = _compute_risk_score(severity)
            fingerprint = meta.get("fingerprint") or _compute_fingerprint(e)
            user = e.get("user") or ""
            parent_process = e.get("parent_process") or _basename(e.get("parent_image") or "")
            process_id = e.get("process_id") or ""
            # Additional denormalized process fields for complete telemetry.
            parent_process_id = e.get("parent_process_id") or ""
            command_line = e.get("command_line") or ""
            parent_process_name = e.get("parent_process_name") or parent_process or ""

            # Ensure all scalar params are SQLite-compatible. Structured values
            # (list/dict/tuple) are serialized to JSON via _sqlite_bind_safe so
            # a container in any raw field can never raise
            # "type 'list' is not supported" on insert.
            params = (
                _sqlite_bind_safe(e.get("time")), _sqlite_bind_safe(e.get("host")),
                _sqlite_bind_safe(e.get("event_id")), _sqlite_bind_safe(severity),
                _sqlite_bind_safe(mitre), _sqlite_bind_safe(mitre_tactic),
                _sqlite_bind_safe(e.get("process_name")), _sqlite_bind_safe(e.get("source")),
                _sqlite_bind_safe(e.get("channel")), _sqlite_bind_safe(e.get("provider")),
                record_number, computer, time_created,
                _sqlite_bind_safe(user), _sqlite_bind_safe(parent_process),
                _sqlite_bind_safe(process_id),
                json.dumps(meta) if meta else None,
                json.dumps(ioc) if ioc else None,
                risk_score, fingerprint, json.dumps(payload),
                _sqlite_bind_safe(parent_process_id),
                _sqlite_bind_safe(command_line),
                _sqlite_bind_safe(parent_process_name),
            )

            cursor.execute("""
                INSERT INTO events (
                    event_time, host, event_id, severity, mitre, mitre_tactic, process_name, source, channel, provider,
                    record_number, computer, time_created, user, parent_process, process_id,
                    metadata_json, ioc_json, risk_score, fingerprint, raw_json,
                    parent_process_id, command_line, parent_process_name
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, params)
        except sqlite3.IntegrityError:
            # Duplicate event - expected, just skip
            pass
        except Exception as e:
            # Log detailed error information to diagnose what went wrong
            print(f"[SQLite] Failed to save event: {str(e)}")
            print(f"[SQLite] Event fingerprint: {fingerprint}")
            print(f"[SQLite] Event host: {e.get('host')}, event_id: {e.get('event_id')}")
            print(f"[SQLite] mitre value: {mitre}, type: {type(mitre)}")
            print(f"[SQLite] mitre_tactic value: {mitre_tactic}, type: {type(mitre_tactic)}")
            # Continue processing other events - don't let one bad event block the queue
            pass
    
    def _process_save_state(self, conn, state_data):
        """Internal method to process collector state saves from writer thread"""
        channel, last_record, computer, timestamp = state_data
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO collector_state 
                (channel, last_record_number, computer, last_updated)
                VALUES (?, ?, ?, ?)
            """, (channel, last_record, computer, timestamp))
        except Exception as e:
            print(f"[SQLite] Failed to save collector state: {e}")

    def _process_backfill_events(self, conn):
        """One-time backfill of the denormalized envelope columns for records
        stored before Task 6. raw_json is never rewritten — existing events
        stay byte-identical and readable; only the derived columns are filled.
        """
        print("[SQLite] Backfilling event envelope columns...")
        try:
            cursor = conn.cursor()

            # SQL-extractable fields straight from the stored envelope. Gated on
            # rows that still need them so the one-time pass never rescans the
            # full table on later startups.
            cursor.execute(
                "SELECT COUNT(*) FROM events WHERE user IS NULL OR parent_process IS NULL OR process_id IS NULL"
            )
            if cursor.fetchone()[0] > 0:
                cursor.execute("""
                    UPDATE events SET
                        user = json_extract(raw_json, '$.event.user'),
                        parent_process = json_extract(raw_json, '$.event.parent_process'),
                        process_id = json_extract(raw_json, '$.event.process_id'),
                        metadata_json = CASE
                            WHEN json_valid(json_extract(raw_json, '$.metadata'))
                            THEN json_extract(raw_json, '$.metadata') ELSE NULL END,
                        ioc_json = CASE
                            WHEN json_valid(json_extract(raw_json, '$.ioc'))
                            THEN json_extract(raw_json, '$.ioc') ELSE NULL END
                    WHERE user IS NULL OR parent_process IS NULL OR process_id IS NULL
                """)
                conn.commit()

            # Task 15: denormalized MITRE tactic for the Dashboard aggregation.
            # Only rows inside the current day's analytics window are ever
            # aggregated, so the backfill is bounded to that window (new rows
            # get mitre_tactic from the save path) — history is never rescanned.
            from datetime import datetime as _dt
            today_start = f"{_dt.utcnow().date().isoformat()}T00:00:00"
            cursor.execute(
                "SELECT COUNT(*) FROM events WHERE mitre_tactic IS NULL AND event_time >= ?",
                (today_start,),
            )
            if cursor.fetchone()[0] > 0:
                cursor.execute(
                    "UPDATE events SET mitre_tactic = "
                    "json_extract(raw_json, '$.detection.mitre.tactic') "
                    "WHERE mitre_tactic IS NULL AND event_time >= ?",
                    (today_start,),
                )
                conn.commit()

            # Fingerprint + risk score need Python (sha256 / severity mapping).
            cursor.execute(
                "SELECT id, event_time, host, event_id, process_name, severity, raw_json "
                "FROM events WHERE fingerprint IS NULL OR risk_score IS NULL"
            )
            rows = cursor.fetchall()

            updates = []
            for row_id, event_time, host, event_id, process_name, severity, raw_json in rows:
                try:
                    payload = json.loads(raw_json)
                except Exception:
                    continue
                meta = payload.get("metadata") or {}
                fingerprint = meta.get("fingerprint") or _compute_fingerprint({
                    "host": host,
                    "event_id": event_id,
                    "time": event_time,
                    "process_name": process_name,
                })
                risk_score = meta.get("risk_score")
                if not isinstance(risk_score, (int, float)):
                    det_severity = (payload.get("detection") or {}).get("severity") or severity
                    risk_score = _compute_risk_score(det_severity)
                updates.append((int(risk_score), fingerprint, row_id))
                if len(updates) >= 5000:
                    cursor.executemany(
                        "UPDATE events SET risk_score = ?, fingerprint = ? WHERE id = ?",
                        updates,
                    )
                    updates = []
            if updates:
                cursor.executemany(
                    "UPDATE events SET risk_score = ?, fingerprint = ? WHERE id = ?",
                    updates,
                )
            conn.commit()
            print(f"[SQLite] Backfill complete: processed {len(rows)} rows")
        except Exception as e:
            print(f"[SQLite] Backfill error: {e}")

    def _process_clean_process_names(self, conn):
        """Task 27 — strip enterprise metadata suffixes ('app.exe, version: X,
        time stamp: Y') from the stored process_name column.

        Safe and idempotent: it only ever shortens a value to the actual
        process name and never touches the raw envelope in raw_json. Later
        startups are no-ops because cleaned rows no longer match the pattern.
        """
        print("[SQLite] Cleaning process-name metadata suffixes (Task 27)...")
        try:
            import re as _re

            suffix_re = _re.compile(r",\s*(version|time\s*stamp|timestamp)\s*:")
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, process_name FROM events "
                "WHERE process_name LIKE '%, version:%' "
                "   OR process_name LIKE '%, time stamp:%' "
                "   OR process_name LIKE '%, timestamp:%'"
            )
            rows = cursor.fetchall()
            updates = []
            for row_id, process_name in rows:
                cleaned = suffix_re.split(
                    (process_name or "").strip(), maxsplit=1
                )[0].strip().rstrip(",").strip()
                if cleaned and cleaned != process_name:
                    updates.append((cleaned, row_id))
            if updates:
                cursor.executemany(
                    "UPDATE events SET process_name = ? WHERE id = ?",
                    updates,
                )
                conn.commit()
            print(
                f"[SQLite] Process-name cleanup complete: {len(updates)} rows updated"
            )
        except Exception as e:
            print(f"[SQLite] Process-name cleanup error: {e}")

    def _process_update_alert_status(self, conn, data):
        """Internal method to persist an alert status change from the writer
        thread (single-writer architecture, same as every other write).
        """
        alert_id, status, changed_by, changed_at = data
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE events SET status = ?, status_changed_by = ?, "
                "status_changed_at = ? WHERE id = ?",
                (status, changed_by, changed_at, alert_id),
            )
            conn.commit()
        except Exception as e:
            print(f"[SQLite] Failed to update alert status: {e}")

    def _process_save_case(self, conn, case):
        """Internal method to persist a case from the writer thread (Task 20)."""
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO cases (
                    case_id, status, priority, title, host, event_id, user,
                    process, assigned_to, alert_id, investigation_id,
                    event_json, timeline_json, notes_json, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                case.get("case_id"),
                case.get("status"),
                case.get("priority"),
                case.get("title"),
                case.get("host"),
                case.get("event_id"),
                case.get("user"),
                case.get("process"),
                case.get("assigned_to"),
                case.get("alert_id"),
                case.get("investigation_id"),
                json.dumps(case.get("event") or {}),
                json.dumps(case.get("timeline") or []),
                json.dumps(case.get("notes") or []),
                case.get("created_at"),
                case.get("updated_at"),
            ))
            conn.commit()
        except Exception as e:
            print(f"[SQLite] Failed to save case: {e}")

    def _process_save_investigation(self, conn, investigation):
        """Internal method to persist an investigation from the writer thread"""
        try:
            # Process mitre field to ensure it's always a string (never list/dict)
            mitre = investigation.get("mitre")
            if isinstance(mitre, list):
                if mitre:
                    first = mitre[0]
                    if isinstance(first, dict):
                        mitre = first.get("id", "")
                    else:
                        mitre = str(first) if first else ""
                else:
                    mitre = ""
            elif isinstance(mitre, dict):
                mitre = mitre.get("id", "")
            elif not isinstance(mitre, str):
                try:
                    mitre = str(mitre)
                except Exception:
                    mitre = ""

            # Ensure all params are SQLite-safe types
            def _safe(val):
                if isinstance(val, (list, dict, set, tuple)):
                    return json.dumps(val)
                return val

            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO investigations (
                    id, alert_id, status, severity, host, user, process,
                    parent_process, event_id, timestamp, mitre, risk_score,
                    confidence, event_json, ioc_json, notes_json,
                    related_events_json, process_tree_json, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                investigation.get("id"),
                investigation.get("alert_id"),
                investigation.get("status"),
                investigation.get("severity"),
                investigation.get("host"),
                investigation.get("user"),
                investigation.get("process"),
                investigation.get("parent_process"),
                investigation.get("event_id"),
                investigation.get("timestamp"),
                mitre,  # Processed mitre value - guaranteed string
                _safe(investigation.get("risk_score")),
                _safe(investigation.get("confidence")),
                json.dumps(investigation.get("event") or {}),
                json.dumps(investigation.get("ioc") or {}),
                json.dumps(investigation.get("notes") or []),
                json.dumps(investigation.get("related_events") or []),
                json.dumps(investigation.get("process_tree") or []),
                investigation.get("created_at"),
                investigation.get("updated_at"),
            ))
            conn.commit()
        except Exception as e:
            print(f"[SQLite] Failed to save investigation: {e}")

    def initialize(self):

        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            
            # Apply SQLite performance optimizations to prevent locked errors
            conn.execute(f"PRAGMA journal_mode={self.journal_mode}")
            conn.execute("PRAGMA busy_timeout=30000")  # 30 second busy timeout
            conn.execute("PRAGMA cache_size=-64000")   # 64MB cache
            conn.execute("PRAGMA foreign_keys=ON")
            
            cursor = conn.cursor()

            # Create base events table if it doesn't exist yet
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_time TEXT,
                    host TEXT,
                    event_id TEXT,
                    severity TEXT,
                    mitre TEXT,
                    mitre_tactic TEXT,
                    process_name TEXT,
                    source TEXT,
                    channel TEXT,
                    provider TEXT,
                    record_number INTEGER,
                    computer TEXT,
                    time_created TEXT,
                    user TEXT,
                    parent_process TEXT,
                    metadata_json TEXT,
                    ioc_json TEXT,
                    risk_score INTEGER,
                    fingerprint TEXT,
                    raw_json TEXT
                )
            """)
            
            # Migration: Add missing columns if they don't exist (for existing databases)
            existing_columns = []
            cursor.execute("PRAGMA table_info(events)")
            for col in cursor.fetchall():
                existing_columns.append(col[1])
            
            # Add deduplication columns if missing
            if 'record_number' not in existing_columns:
                cursor.execute("ALTER TABLE events ADD COLUMN record_number INTEGER")
                print("[SQLite Migration] Added record_number column")
            if 'computer' not in existing_columns:
                cursor.execute("ALTER TABLE events ADD COLUMN computer TEXT")
                print("[SQLite Migration] Added computer column")
            if 'time_created' not in existing_columns:
                cursor.execute("ALTER TABLE events ADD COLUMN time_created TEXT")
                print("[SQLite Migration] Added time_created column")

            # Migration (Task 6): denormalized complete-envelope columns so the
            # full event data (user, parent process, metadata, IOC, risk score,
            # fingerprint) is queryable without touching raw_json. Backward
            # compatible: existing rows simply keep NULL until the queued
            # backfill fills them, and raw_json stays the source of truth.
            # mitre_tactic (Task 15) is the same pattern: only the current
            # day's window is ever aggregated, so its backfill is bounded to
            # rows in that window (see _process_backfill_events).
            for col, col_type in (
                ("user", "TEXT"),
                ("parent_process", "TEXT"),
                ("process_id", "TEXT"),
                ("metadata_json", "TEXT"),
                ("ioc_json", "TEXT"),
                ("risk_score", "INTEGER"),
                ("fingerprint", "TEXT"),
                ("mitre_tactic", "TEXT"),
                # Task 17: real alert triage status. One row = one alert, so the
                # status lives directly on the event row (NULL == "New").
                ("status", "TEXT"),
                ("status_changed_by", "TEXT"),
                ("status_changed_at", "TEXT"),
                # Normalization fix: additional process fields for complete telemetry.
                ("parent_process_id", "TEXT"),
                ("command_line", "TEXT"),
                ("parent_process_name", "TEXT"),
            ):
                if col not in existing_columns:
                    cursor.execute(f"ALTER TABLE events ADD COLUMN {col} {col_type}")
                    print(f"[SQLite Migration] Added {col} column")

            for col in ("user", "parent_process", "process_id", "fingerprint", "risk_score", "parent_process_id", "command_line", "parent_process_name"):
                cursor.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_{col} ON events({col})"
                )

            # Task 17: alert status filter is a plain indexed equality on the
            # events row (NULL rows are the implicit "New" default).
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_status ON events(status)"
            )
            
            # Create unique index for duplicate prevention — record identity
            # (channel + computer + record_number + time_created). SQLite allows
            # multiple NULL record_numbers under a UNIQUE index, so rows without
            # a record number are protected by the fingerprint trigger below
            # (Task 18). Existing historical rows are NEVER modified or deleted.
            try:
                cursor.execute("""
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_event 
                    ON events (channel, computer, record_number, time_created)
                """)
                print("[SQLite] Unique index created for duplicate prevention")
            except Exception as e:
                print(f"[SQLite] Unique index already exists: {e}")

            # Task 18 — fingerprint uniqueness for events without a record
            # number. A plain UNIQUE index cannot be created because historical
            # rows legitimately share fingerprints (same event re-collected by
            # earlier pipeline versions), and "do not delete legitimate events"
            # forbids pre-deduplicating them. A BEFORE INSERT trigger aborts any
            # NEW insert whose fingerprint already exists among NULL-record rows
            # — the strongest protection SQLite offers without touching existing
            # data. All writes funnel through the single writer thread, and the
            # trigger's EXISTS check runs atomically with the INSERT on the same
            # connection, so queued/concurrent identical inserts are rejected.
            cursor.execute("DROP TRIGGER IF EXISTS trg_events_dedup_fingerprint")
            cursor.execute("""
                CREATE TRIGGER trg_events_dedup_fingerprint
                BEFORE INSERT ON events
                WHEN NEW.record_number IS NULL OR NEW.record_number = ''
                BEGIN
                    SELECT RAISE(ABORT, 'duplicate event (fingerprint)')
                    WHERE EXISTS (
                        SELECT 1 FROM events
                        WHERE fingerprint = NEW.fingerprint
                          AND (record_number IS NULL OR record_number = '')
                    );
                END
            """)
            print("[SQLite] Fingerprint dedup trigger created (Task 18)")

            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_time ON events(event_time)"
            )

            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_host ON events(host)"
            )

            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_eventid ON events(event_id)"
            )

            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_severity ON events(severity)"
            )

            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_mitre ON events(mitre)"
            )

            # Task 15: covering index over the narrow analytics columns so the
            # Dashboard's server-side aggregation (COUNT / GROUP BY over
            # event_time / severity / host / process_name / event_id /
            # mitre_tactic) runs entirely from the index without touching the
            # wide raw_json envelopes.
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_analytics ON events(
                    event_time, severity, host, computer, process_name,
                    event_id, mitre_tactic
                )
            """)

            # Case-insensitive indexes for SQL-pushdown search equality lookups
            # (host:, eventid:, severity:, mitre:, provider:, channel:, source:)
            for col in ("host", "event_id", "severity", "mitre", "process_name", "provider", "channel", "source"):
                cursor.execute(
                    f"CREATE INDEX IF NOT EXISTS idx_{col}_nocase ON events({col} COLLATE NOCASE)"
                )
            
            # Create table to track collector's last processed record IDs for resumability
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collector_state (
                    channel TEXT PRIMARY KEY,
                    last_record_number INTEGER,
                    computer TEXT,
                    last_updated TEXT
                )
            """)

            # Persisted investigation records (Task 5 - real investigation workspace)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS investigations (
                    id TEXT PRIMARY KEY,
                    alert_id TEXT,
                    status TEXT,
                    severity TEXT,
                    host TEXT,
                    user TEXT,
                    process TEXT,
                    parent_process TEXT,
                    event_id TEXT,
                    timestamp TEXT,
                    mitre TEXT,
                    risk_score INTEGER,
                    confidence INTEGER,
                    event_json TEXT,
                    ioc_json TEXT,
                    notes_json TEXT,
                    related_events_json TEXT,
                    process_tree_json TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_investigation_alert ON investigations(alert_id)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_investigation_created ON investigations(created_at)"
            )

            # Persisted case records (Task 20 - real case management). One case
            # per investigation/alert; statuses follow the case lifecycle.
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    status TEXT,
                    priority TEXT,
                    title TEXT,
                    host TEXT,
                    event_id TEXT,
                    user TEXT,
                    process TEXT,
                    assigned_to TEXT,
                    alert_id TEXT,
                    investigation_id TEXT,
                    event_json TEXT,
                    timeline_json TEXT,
                    notes_json TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_case_alert ON cases(alert_id)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_case_investigation ON cases(investigation_id)"
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS chat_conversations (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    title TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    context_json TEXT
                )
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_chat_user ON chat_conversations(user_id)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_chat_updated ON chat_conversations(updated_at)"
            )
            
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS chat_messages (
                    id TEXT PRIMARY KEY,
                    conversation_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    metadata_json TEXT,
                    FOREIGN KEY (conversation_id) REFERENCES chat_conversations(id) ON DELETE CASCADE
                )
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_message_conversation ON chat_messages(conversation_id)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_message_timestamp ON chat_messages(timestamp)"
            )

            # Migration: add status column to chat_messages if missing
            cursor.execute("PRAGMA table_info(chat_messages)")
            msg_cols = [col[1] for col in cursor.fetchall()]
            if 'status' not in msg_cols:
                cursor.execute("ALTER TABLE chat_messages ADD COLUMN status TEXT DEFAULT 'completed'")
                print("[SQLite Migration] Added status column to chat_messages")
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_message_status ON chat_messages(status)"
            )
            # Migration: add last_message_content + last_message_at to conversations for fast list rendering
            cursor.execute("PRAGMA table_info(chat_conversations)")
            conv_cols = [col[1] for col in cursor.fetchall()]
            if 'last_message_content' not in conv_cols:
                cursor.execute("ALTER TABLE chat_conversations ADD COLUMN last_message_content TEXT")
                print("[SQLite Migration] Added last_message_content to chat_conversations")
            if 'last_message_at' not in conv_cols:
                cursor.execute("ALTER TABLE chat_conversations ADD COLUMN last_message_at TEXT")
                print("[SQLite Migration] Added last_message_at to chat_conversations")
            if 'message_count' not in conv_cols:
                cursor.execute("ALTER TABLE chat_conversations ADD COLUMN message_count INTEGER DEFAULT 0")
                print("[SQLite Migration] Added message_count to chat_conversations")

            # Migration: fix old UTC timestamps missing 'Z' suffix
            # Without the Z suffix, JavaScript interprets them as local time
            # causing timestamps to appear hours in the past.
            for table, col in [("chat_conversations", "created_at"),
                               ("chat_conversations", "updated_at"),
                               ("chat_conversations", "last_message_at"),
                               ("chat_messages", "timestamp")]:
                try:
                    cursor.execute(
                        f"UPDATE {table} SET {col} = {col} || 'Z' "
                        f"WHERE {col} IS NOT NULL AND {col} NOT LIKE '%Z'"
                    )
                    if cursor.rowcount > 0:
                        print(f"[SQLite Migration] Fixed {cursor.rowcount} {table}.{col} timestamps (added Z suffix)")
                except Exception:
                    pass  # Column may not exist yet

            # --- Auth tables ---
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    username TEXT UNIQUE,
                    full_name TEXT,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'analyst',
                    email_verified INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'pending_verification',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_login TEXT
                )
            """)
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_user_email ON users(email)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_user_username ON users(username)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_user_status ON users(status)"
            )
            
            # Optional, EXPLICIT admin bootstrap (never a fixed default
            # password). Creates an admin ONLY when BOOTSTRAP_ADMIN_EMAIL and
            # BOOTSTRAP_ADMIN_PASSWORD are configured; disabled by default.
            _ensure_optional_admin_bootstrap(cursor)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS auth_otps (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    otp_hash TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    attempts INTEGER DEFAULT 0,
                    used INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_otp_user ON auth_otps(user_id)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_otp_purpose ON auth_otps(purpose)"
            )

            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_case_created ON cases(created_at)"
            )

            # --- Search history table (user-isolated) ---
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS search_history (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    query TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT NOT NULL,
                    use_count INTEGER DEFAULT 1
                )
            """)
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_search_history_user ON search_history(user_id, last_used_at DESC)"
            )

            # --- Notifications table (user-isolated, per-event deduped) ---
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    fingerprint TEXT,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    host TEXT,
                    process_name TEXT,
                    mitre TEXT,
                    event_time TEXT NOT NULL,
                    read INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    alert_id INTEGER,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_notif_user_time ON notifications(user_id, created_at DESC)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_notif_user_read ON notifications(user_id, read)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_notif_fingerprint ON notifications(fingerprint)"
            )
            # Unique constraint on (user_id, fingerprint) for deduplication.
            # INSERT OR IGNORE in _process_save_notification relies on this.
            cursor.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_notif_user_fp ON notifications(user_id, fingerprint)"
            )
            # Migration: add alert_id column if missing (for existing databases)
            notif_cols = [col[1] for col in cursor.execute("PRAGMA table_info(notifications)").fetchall()]
            if 'alert_id' not in notif_cols:
                cursor.execute("ALTER TABLE notifications ADD COLUMN alert_id INTEGER")
                print("[SQLite Migration] Added alert_id column to notifications")

            # --- Notification lifecycle migration ---
            # Adds status, acknowledged_at, resolved_at for the Security
            # Attention Memory lifecycle: NEW → ACKNOWLEDGED → RESOLVED.
            for col, col_type, default in (
                ("status", "TEXT", "new"),
                ("notification_type", "TEXT", "security"),
                ("acknowledged_at", "TEXT", None),
                ("resolved_at", "TEXT", None),
            ):
                if col not in notif_cols:
                    default_sql = f" DEFAULT '{default}'" if default else ""
                    cursor.execute(f"ALTER TABLE notifications ADD COLUMN {col} {col_type}{default_sql}")
                    print(f"[SQLite Migration] Added {col} column to notifications")

            # Backfill: mark all existing notifications as 'new'
            cursor.execute(
                "UPDATE notifications SET status = 'new' WHERE status IS NULL"
            )
            # Index for status-based queries
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_notif_user_status ON notifications(user_id, status)"
            )



            # --- Notification read state (user-isolated, derived notifications) ---
            # Lightweight table that tracks which events each user has read.
            # Notifications are DERIVED from the authoritative events table,
            # not duplicated.  This table only stores the user-specific read
            # state, keeping the data model DRY and always up-to-date.
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS notification_read_state (
                    user_id TEXT NOT NULL,
                    alert_id INTEGER NOT NULL,
                    read_at TEXT NOT NULL,
                    PRIMARY KEY (user_id, alert_id),
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (alert_id) REFERENCES events(id) ON DELETE CASCADE
                )
            """)
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_nrs_user ON notification_read_state(user_id)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_nrs_user_alert ON notification_read_state(user_id, alert_id)"
            )

            conn.commit()

            conn.commit()

        # One-time backfill for records stored before the envelope columns
        # existed. Queued on the writer thread so startup never blocks; skipped
        # entirely once every row has a fingerprint.
        try:
            with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT COUNT(*) FROM events "
                    "WHERE fingerprint IS NULL OR risk_score IS NULL OR process_id IS NULL"
                )
                needs_backfill = cursor.fetchone()[0] > 0
            if needs_backfill:
                self.write_queue.put(("backfill_events", None), block=False)
                print("[SQLite] Event envelope backfill queued")
        except Exception as e:
            print(f"[SQLite] Could not check/queue event backfill: {e}")

        # Task 27 — strip enterprise metadata suffixes from stored process
        # names ('app.exe, version: ...'). Queued on the writer thread like
        # every other write; idempotent, so later startups find nothing to do.
        try:
            with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT COUNT(*) FROM events "
                    "WHERE process_name LIKE '%, version:%' "
                    "   OR process_name LIKE '%, time stamp:%' "
                    "   OR process_name LIKE '%, timestamp:%'"
                )
                if cursor.fetchone()[0] > 0:
                    self.write_queue.put(("clean_process_names", None), block=False)
                    print("[SQLite] Process-name cleanup queued (Task 27)")
        except Exception as e:
            print(f"[SQLite] Could not check/queue process-name cleanup: {e}")

    # ----------------------------------------------------
    # Save Event
    # ----------------------------------------------------

    def save_event(self, event):
        """Queue an event to be saved by the single writer thread (non-blocking)"""
        # Queue the write - never blocks long (backpressure at 10k items)
        try:
            self.write_queue.put(("save_event", event), block=False)
            return True
        except queue.Full:
            print(f"[SQLite WARNING] Write queue full - dropping event to prevent memory bloat")
            return False

    # ----------------------------------------------------
    # Get Events
    # ----------------------------------------------------

    def get_events(self, limit=100000):

        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:

            cursor = conn.cursor()

            cursor.execute("""

                SELECT id, status, status_changed_by, status_changed_at, raw_json

                FROM events

                ORDER BY event_time DESC

                LIMIT ?

            """, (limit,))

            rows = cursor.fetchall()

        return [

            _attach_alert_fields(
                json.loads(row[4]), row[0], row[1], row[2], row[3]
            )

            for row in rows

        ]

    # ----------------------------------------------------
    # Get Today's Events Only (For Analytics)
    # ----------------------------------------------------
    def get_todays_events(self):
        from datetime import datetime
        
        # Get today's date at midnight UTC
        today = datetime.utcnow().date()
        today_start = f"{today.isoformat()}T00:00:00"
        logger.debug("SQLiteStorage.get_todays_events() - Querying events after: %s", today_start)

        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            
            # First check total events in database
            cursor.execute("SELECT COUNT(*) FROM events")
            total_events = cursor.fetchone()[0]
            logger.debug("SQLiteStorage.get_todays_events() - Total events in DB: %d", total_events)
            
            # Get all events from today onwards
            cursor.execute("""
                SELECT id, status, status_changed_by, status_changed_at, raw_json
                FROM events
                WHERE event_time >= ?
                ORDER BY event_time DESC
            """, (today_start,))
            
            rows = cursor.fetchall()
            logger.debug("SQLiteStorage.get_todays_events() - Today's events found: %d", len(rows))

        return [
            _attach_alert_fields(
                json.loads(row[4]), row[0], row[1], row[2], row[3]
            )
            for row in rows
        ]

    # ----------------------------------------------------
    # Today's Analytics (SQL pushdown - Dashboard)
    # ----------------------------------------------------
    def count_todays_events(self):
        """Cheap SQL COUNT of today's events (used by analytics sub-endpoints)."""
        from datetime import datetime
        today_start = f"{datetime.utcnow().date().isoformat()}T00:00:00"
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM events WHERE event_time >= ?", (today_start,)
            ).fetchone()
        return row[0] if row else 0

    def get_todays_analytics(self):
        """Server-side Dashboard aggregation - COUNT/GROUP BY pushed into SQLite.

        Computes every metric the Dashboard needs (totals, severity, hosts,
        hourly trend, top processes/event-ids, MITRE tactics, recent
        high/critical alerts) entirely with SQL aggregation over the indexed
        denormalized columns. No event envelopes are loaded into Python; the
        only rows read into Python are the bounded recent high/critical set
        (LIMIT 1000).

        The normalized severity CASE mirrors analytics_engine's
        _normalize_severity (any value that is not a canonical severity name -
        including stored 'Unknown' - counts as Informational), and the hour
        buckets honour the same current-local-hour cap as the previous
        Python implementation, so the numbers are identical to the real
        database.
        """
        from datetime import datetime
        today_start = f"{datetime.utcnow().date().isoformat()}T00:00:00"
        current_hour = datetime.now().hour

        severity_case = (
            "CASE TRIM(lower(COALESCE(severity, ''))) "
            "WHEN 'critical' THEN 'Critical' "
            "WHEN 'high' THEN 'High' "
            "WHEN 'medium' THEN 'Medium' "
            "WHEN 'low' THEN 'Low' "
            "WHEN 'informational' THEN 'Informational' "
            "ELSE 'Informational' END"
        )
        host_expr = "COALESCE(NULLIF(host, ''), computer)"

        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            c = conn.cursor()

            c.execute(
                "SELECT COUNT(*) FROM events WHERE event_time >= ?", (today_start,)
            )
            total = c.fetchone()[0]

            c.execute(
                f"SELECT {severity_case}, COUNT(*) FROM events "
                f"WHERE event_time >= ? GROUP BY {severity_case}",
                (today_start,),
            )
            severity_counts = dict(c.fetchall())

            c.execute(
                f"SELECT COUNT(DISTINCT {host_expr}) FROM events "
                "WHERE event_time >= ?",
                (today_start,),
            )
            hosts_distinct = c.fetchone()[0]

            c.execute(
                f"SELECT {host_expr}, COUNT(*) FROM events "
                f"WHERE event_time >= ? GROUP BY {host_expr} "
                # Tie-break by oldest event time (asc) to match the previous
                # Python most_common() ordering (live store holds today's
                # events oldest-first).
                "ORDER BY COUNT(*) DESC, MIN(event_time) ASC LIMIT 10",
                (today_start,),
            )
            top_hosts = [[r[0], r[1]] for r in c.fetchall()]

            c.execute(
                f"SELECT {severity_case}, CAST(substr(event_time, 12, 2) AS INTEGER), COUNT(*) "
                "FROM events WHERE event_time >= ? "
                "AND CAST(substr(event_time, 12, 2) AS INTEGER) <= ? "
                f"GROUP BY {severity_case}, CAST(substr(event_time, 12, 2) AS INTEGER)",
                (today_start, current_hour),
            )
            hourly = [(sev, hour, n) for sev, hour, n in c.fetchall()]

            c.execute(
                "SELECT process_name, COUNT(*) FROM events "
                "WHERE event_time >= ? AND process_name IS NOT NULL "
                "AND process_name NOT IN ('-', 'None', 'null', '') "
                "GROUP BY process_name "
                "ORDER BY COUNT(*) DESC, MIN(event_time) ASC LIMIT 10",
                (today_start,),
            )
            top_processes = [[r[0], r[1]] for r in c.fetchall()]

            c.execute(
                "SELECT CAST(event_id AS TEXT), COUNT(*) FROM events "
                "WHERE event_time >= ? AND event_id IS NOT NULL "
                "AND CAST(event_id AS TEXT) NOT IN ('', '-', 'None', 'null') "
                "GROUP BY CAST(event_id AS TEXT) "
                "ORDER BY COUNT(*) DESC, MIN(event_time) ASC LIMIT 10",
                (today_start,),
            )
            top_event_ids = [[r[0], r[1]] for r in c.fetchall()]

            c.execute(
                "SELECT mitre_tactic, COUNT(*) FROM events "
                "WHERE event_time >= ? AND mitre_tactic IS NOT NULL "
                "AND mitre_tactic != '' GROUP BY mitre_tactic",
                (today_start,),
            )
            mitre = dict(c.fetchall())

            # Events without a tactic (non-dict / missing MITRE) - the
            # /analytics/mitre endpoint reports those as 'Unknown'.
            c.execute(
                "SELECT COUNT(*) FROM events "
                "WHERE event_time >= ? AND (mitre_tactic IS NULL OR mitre_tactic = '')",
                (today_start,),
            )
            mitre_missing = c.fetchone()[0]

            # Bounded: only high/critical envelopes, newest first, max 1000.
            # Stored severity values are canonical (the detection engine
            # normalizes them), so a plain IN filter is exactly equivalent to
            # the normalized-severity check and uses idx_severity directly.
            c.execute(
                "SELECT raw_json FROM events "
                "WHERE event_time >= ? AND severity IN ('High', 'Critical') "
                "ORDER BY event_time DESC LIMIT 1000",
                (today_start,),
            )
            critical_rows = c.fetchall()

        critical_alerts = []
        for (raw_json,) in critical_rows:
            try:
                payload = json.loads(raw_json)
            except Exception:
                continue
            e = payload.get("event") or {}
            d = payload.get("detection") or {}
            sev = (d.get("severity") or "").strip().capitalize()
            if sev not in ("Critical", "High", "Medium", "Low", "Informational"):
                sev = "Informational"
            critical_alerts.append({
                "time": e.get("time", ""),
                "host": e.get("host") or e.get("computer") or "Unknown",
                "severity": sev,
                "event_id": str(e.get("event_id") or "N/A"),
                "message": d.get("detection", ""),
            })

        return {
            "total": total,
            "severity_counts": severity_counts,
            "hosts_distinct": hosts_distinct,
            "top_hosts": top_hosts,
            "hourly": hourly,
            "top_processes": top_processes,
            "top_event_ids": top_event_ids,
            "mitre": mitre,
            "mitre_missing": mitre_missing,
            "critical_alerts": critical_alerts,
        }

    # ----------------------------------------------------
    # SQL-Pushdown Paginated Query (complete dataset access)
    # ----------------------------------------------------

    def query_events(self, filters=None):
        """Server-side paginated query executed entirely in SQLite.

        This is the scalable path for the Alerts module: instead of loading the
        full history dataset into memory on every request, filtering, counting
        and pagination are pushed down to the database (which indexes the
        event_time / host / event_id / severity / mitre columns). The complete
        matching dataset remains reachable page by page.

        Args:
            filters: dict with optional keys
                time_from   ISO string — only events with event_time >= time_from
                time_to     ISO string — only events with event_time <= time_to
                host        exact host
                event_id    exact event id
                process_name exact process basename
                mitre       exact mitre id
                severity    canonical severity ('Informational' also matches
                            empty/Unknown stored values)
                user        exact user (resolved via json_extract on raw_json)
                status      alert status (model defaults every event to 'New')
                limit, offset  pagination

        Returns:
            dict: {total, severity_counts, results}
        """
        filters = filters or {}
        where = []
        params = []

        time_from = filters.get("time_from")
        if time_from:
            where.append("event_time >= ?")
            params.append(time_from)

        time_to = filters.get("time_to")
        if time_to:
            where.append("event_time <= ?")
            params.append(time_to)

        host = filters.get("host")
        if host and host != "All":
            where.append("host = ?")
            params.append(host)

        eid = filters.get("event_id")
        if eid and eid != "All":
            where.append("event_id = ?")
            params.append(eid)

        proc = filters.get("process_name")
        if proc and proc != "All":
            where.append("process_name = ?")
            params.append(proc)

        pid = filters.get("process_id")
        if pid and pid != "All":
            where.append("process_id = ?")
            params.append(pid)

        mitre = filters.get("mitre")
        if mitre and mitre != "All":
            where.append("mitre = ?")
            params.append(mitre)

        severity = filters.get("severity")
        if severity and severity != "All":
            if severity == "Informational":
                where.append(
                    "(severity IS NULL OR severity IN ('', 'Unknown', 'None', 'unknown', 'none', 'Informational', 'informational', 'info'))"
                )
            else:
                where.append("severity = ?")
                params.append(severity)

        user = filters.get("user")
        if user and user != "All":
            where.append("json_extract(raw_json, '$.event.user') = ?")
            params.append(user)

        status = filters.get("status")
        if status and status != "All":
            # Real persisted alert status (Task 17): NULL rows are the
            # implicit "New" default, so New matches both NULL and 'New'.
            if status == "New":
                where.append("(status IS NULL OR status = 'New')")
            else:
                where.append("status = ?")
                params.append(status)

        where_sql = (" WHERE " + " AND ".join(where)) if where else ""
        limit = max(1, min(int(filters.get("limit", 50)), 100000))
        offset = max(0, int(filters.get("offset", 0)))

        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cur = conn.cursor()

            cur.execute(f"SELECT COUNT(*) FROM events{where_sql}", params)
            total = cur.fetchone()[0]

            cur.execute(
                f"""
                SELECT
                    CASE WHEN severity IS NULL OR severity IN ('', 'Unknown', 'None', 'unknown', 'none', 'info')
                        THEN 'Informational' ELSE severity END AS sev,
                    COUNT(*)
                FROM events{where_sql}
                GROUP BY sev
                """,
                params,
            )
            severity_counts = {}
            for sev, count in cur.fetchall():
                key = str(sev).capitalize()
                severity_counts[key] = severity_counts.get(key, 0) + count

            cur.execute(
                f"""
                SELECT id, status, status_changed_by, status_changed_at, raw_json
                FROM events{where_sql}
                ORDER BY event_time DESC
                LIMIT ? OFFSET ?
                """,
                params + [limit, offset],
            )
            rows = cur.fetchall()

        return {
            "total": total,
            "severity_counts": severity_counts,
            "results": [
                _attach_alert_fields(
                    json.loads(r[4]), r[0], r[1], r[2], r[3]
                )
                for r in rows
            ],
        }

    # ----------------------------------------------------
    # Filter Vocabulary Aggregates (complete dataset)
    # ----------------------------------------------------
    def get_filter_aggregates(self):
        """Full distinct filter vocabulary with counts, computed server-side.

        Each category is a single GROUP BY over the whole events table using
        the indexed denormalized columns — no event envelope is ever loaded
        into Python memory, so this stays cheap even with millions of rows.
        The value predicates mirror FilterCacheService.ingest_event so the
        cached vocabulary stays byte-for-byte consistent with these counts.

        Raw XML payloads, event messages, and overly long strings are
        excluded so autocomplete suggestions contain only clean, structured
        metadata useful for SOC investigation.

        Returns:
            dict with keys: processes, event_ids, hosts, users, mitre_ids,
            severities, pids — each a list of {"value", "count"} sorted by
            count descending.
        """
        # Maximum length for a suggestion value. Anything longer is almost
        # certainly raw telemetry (XML payload, command line, event message)
        # rather than a clean searchable field.
        _MAX_LEN = 150

        def _agg(column, excluded, extra_where=""):
            """Run a DISTINCT GROUP BY, excluding known sentinel values and
            any value that looks like raw XML/payload content.
            """
            with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
                cur = conn.cursor()
                placeholders = ", ".join(["?"] * len(excluded))
                # Build the WHERE clause: exclude sentinels, nulls, overly
                # long strings, and anything containing XML tags.
                where_parts = [
                    f"{column} IS NOT NULL",
                    f"{column} NOT IN ({placeholders})",
                    f"LENGTH({column}) <= ?",
                    # Exclude strings containing XML tags / angle brackets
                    f"{column} NOT LIKE '%<%' ESCAPE '\\'",
                    # Exclude strings with newlines (multi-line payloads)
                    f"{column} NOT LIKE '%' || CHAR(10) || '%'",
                    f"{column} NOT LIKE '%' || CHAR(13) || '%'",
                ]
                if extra_where:
                    where_parts.append(extra_where)
                where_clause = " AND ".join(where_parts)
                params = list(excluded) + [_MAX_LEN]
                cur.execute(
                    f"""
                    SELECT {column}, COUNT(*)
                    FROM events
                    WHERE {where_clause}
                    GROUP BY {column}
                    ORDER BY COUNT(*) DESC, {column} ASC
                    """,
                    params,
                )
                return [{"value": row[0], "count": row[1]} for row in cur.fetchall()]

        return {
            "processes": _agg("process_name", ["", "-", "None", "none", "Not available in event"]),
            # Event IDs must be numeric (no XML payloads leaking in)
            "event_ids": _agg("event_id", ["", "None", "none"], extra_where="event_id GLOB '[0-9]*'"),
            "hosts": _agg("host", ["", "-", "None", "none"]),
            "users": _agg("user", ["", "-", "None", "none", "SYSTEM", "system"]),
            "mitre_ids": _agg("mitre", ["", "N/A", "n/a", "Unknown", "unknown", "Unmapped", "None", "none"]),
            "severities": _agg("severity", ["", "None", "none"]),
            "pids": _agg("process_id", ["", "-", "None", "none", "0", "Not available"]),
        }

    # ----------------------------------------------------
    # SQL-Pushdown Search (keyword / SEQL WHERE clause)
    # ----------------------------------------------------
    def search_events(self, where_sql: str, params: list, limit: int = 100000, offset: int = 0):
        """Execute a pre-built WHERE clause directly inside SQLite with proper pagination.

        Used by the search engine so keyword / SEQL queries never load the
        full dataset into Python memory — only matching rows are read.

        Args:
            where_sql: raw SQL fragment after WHERE (e.g. "INSTR(LOWER(raw_json), LOWER(?)) > 0").
                The caller owns the AST->SQL translation, so AND/OR/NOT nesting is preserved.
            params: bound parameters for the WHERE fragment.
            limit: maximum rows to return (results are ordered by time descending).
            offset: number of rows to skip (for pagination).

        Returns:
            dict: {"total": int, "results": [parsed event dicts, newest first]}
        """
        limit = max(1, min(int(limit), 100000))
        offset = max(0, int(offset))
        where_upper = where_sql.upper()
        # Free-text / contains conditions (LIKE over raw_json or json_extract)
        # cannot use any index, so both the total and the page need a scan.
        needs_full_scan = any(
            token in where_upper
            for token in ("LIKE", "JSON_EXTRACT", "INSTR", "GLOB")
        )

        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cur = conn.cursor()

            if needs_full_scan:
                # Walk the event_time index newest-first. Dense matches (e.g.
                # MANI) stop after a handful of rows; a zero-match walk exhausts
                # the index and yields the true total for free (no second scan).
                # Only when the walk hits the page cap is an extra COUNT needed.
                cur.execute(
                    f"""
                    SELECT id, status, status_changed_by, status_changed_at, raw_json
                    FROM events INDEXED BY idx_time
                    WHERE {where_sql}
                    ORDER BY event_time DESC
                    LIMIT ? OFFSET ?
                    """,
                    params + [limit, offset],
                )
                rows = cur.fetchall()
                if len(rows) < limit:
                    # Walked the whole index — total is exactly what we got.
                    return {
                        "total": len(rows),
                        "results": [
                            _attach_alert_fields(
                                json.loads(r[4]), r[0], r[1], r[2], r[3]
                            )
                            for r in rows
                        ],
                    }
                # More matches exist beyond the page cap: count them once.
                cur.execute(
                    f"SELECT COUNT(*) FROM events WHERE {where_sql}", params
                )
                total = cur.fetchone()[0]
                return {
                    "total": total,
                    "results": [
                        _attach_alert_fields(
                            json.loads(r[4]), r[0], r[1], r[2], r[3]
                        )
                        for r in rows
                    ],
                }

            # Indexable equality conditions: total via the covering NOCASE
            # index is cheap, then pick the cheapest page plan.
            cur.execute(f"SELECT COUNT(*) FROM events WHERE {where_sql}", params)
            total = cur.fetchone()[0]

            # Walk the event_time index newest-first only when the page is a
            # tiny fraction of the match set (limit <= 1% of total). Dense
            # matches then stop the walk almost immediately. For sparse match
            # sets or large pages the natural plan (field index or full scan +
            # cheap sort) is faster — the walk would traverse the whole index.
            use_time_walk = total >= 50 and limit <= max(total // 100, 1)
            if use_time_walk:
                cur.execute(
                    f"""
                    SELECT id, status, status_changed_by, status_changed_at, raw_json
                    FROM events INDEXED BY idx_time
                    WHERE {where_sql}
                    ORDER BY event_time DESC
                    LIMIT ? OFFSET ?
                    """,
                    params + [limit, offset],
                )
            else:
                cur.execute(
                    f"""
                    SELECT id, status, status_changed_by, status_changed_at, raw_json
                    FROM events
                    WHERE {where_sql}
                    ORDER BY event_time DESC
                    LIMIT ? OFFSET ?
                    """,
                    params + [limit, offset],
                )
            rows = cur.fetchall()
        return {
            "total": total,
            "results": [
                _attach_alert_fields(
                    json.loads(r[4]), r[0], r[1], r[2], r[3]
                )
                for r in rows
            ],
        }

    # ----------------------------------------------------
    # Alert Status (Task 17: real alert triage status)
    # ----------------------------------------------------

    def update_alert_status(self, alert_id, status, changed_by):
        """Persist an analyst's alert status change.

        Queued on the single writer thread (same architecture as every other
        write) and flushed before returning, so the caller can read the row
        back and broadcast it immediately — the change is durable before the
        API responds.

        Args:
            alert_id: events.id of the alert row
            status: canonical status (New / Investigating / Contained /
                Resolved / Closed)
            changed_by: authenticated analyst username

        Returns:
            dict {"alert_id", "status", "changed_by", "changed_at"} for the
            updated row, or None when no such alert row exists.
        """
        from datetime import datetime
        changed_at = datetime.utcnow().isoformat() + "Z"
        try:
            self.write_queue.put(
                ("update_alert_status", (int(alert_id), status, changed_by, changed_at)),
                block=False,
            )
            self.flush(timeout=30.0)
        except queue.Full:
            print("[SQLite WARNING] Could not queue alert status update")
            return None
        record = self.get_alert_status(int(alert_id))
        if not record:
            return None
        return record

    def get_alert_status(self, alert_id):
        """Read the persisted status record for one alert row."""
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            row = conn.execute(
                "SELECT id, status, status_changed_by, status_changed_at "
                "FROM events WHERE id = ?",
                (int(alert_id),),
            ).fetchone()
        if not row:
            return None
        return {
            "alert_id": row[0],
            "status": row[1] or "New",
            "changed_by": row[2],
            "changed_at": row[3],
        }

    def get_alert_statuses(self, alert_ids):
        """Batch status lookup for a set of alert row ids.

        Returns {alert_id: {"alert_id", "status", "changed_by", "changed_at"}}.
        """
        alert_ids = [int(i) for i in alert_ids]
        if not alert_ids:
            return {}
        result = {}
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cur = conn.cursor()
            for i in range(0, len(alert_ids), 500):
                chunk = alert_ids[i:i + 500]
                placeholders = ", ".join(["?"] * len(chunk))
                cur.execute(
                    f"SELECT id, status, status_changed_by, status_changed_at "
                    f"FROM events WHERE id IN ({placeholders})",
                    chunk,
                )
                for row in cur.fetchall():
                    result[row[0]] = {
                        "alert_id": row[0],
                        "status": row[1] or "New",
                        "changed_by": row[2],
                        "changed_at": row[3],
                    }
        return result

    def get_alert_status_counts(self):
        """Real per-status counts from the persisted alert rows.

        Rows without a status (NULL) are the implicit "New" default, matching
        exactly how the read paths resolve a missing status.

        Returns dict with the five canonical statuses, each with a count.
        """
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            rows = conn.execute(
                "SELECT COALESCE(status, 'New'), COUNT(*) FROM events GROUP BY status"
            ).fetchall()
        counts = dict(rows)
        return {
            name: counts.get(name, 0)
            for name in ("New", "Investigating", "Contained", "Resolved", "Closed")
        }

    def find_alert_id_by_fingerprint(self, fingerprint):
        """Resolve the newest persisted alert row for an event fingerprint.

        Used by the status-change endpoint when the client only has the live
        envelope (fingerprint) and no events.id yet.
        """
        if not fingerprint:
            return None
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            row = conn.execute(
                "SELECT id FROM events WHERE fingerprint = ? "
                "ORDER BY id DESC LIMIT 1",
                (fingerprint,),
            ).fetchone()
        return row[0] if row else None

    # ----------------------------------------------------
    # Live-forwarder helpers (Task 14: persistent standalone collector)
    # ----------------------------------------------------

    def max_event_id(self):
        """Highest events.id currently persisted (0 when the table is empty).

        Used by the API's live forwarder to resume broadcasting only NEW rows
        written by the standalone collector, so historical events are never
        re-broadcast after an API restart.
        """
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cur = conn.cursor()
            cur.execute("SELECT COALESCE(MAX(id), 0) FROM events")
            return int(cur.fetchone()[0] or 0)

    def get_events_after_id(self, after_id, limit=500):
        """Return [(id, envelope), ...] for rows with id > after_id, oldest
        first, each envelope parsed from raw_json (the exact shape the
        collector persisted: {event, detection, metadata?, ioc?}).
        """
        limit = max(1, min(int(limit), 100000))
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT id, status, status_changed_by, status_changed_at, raw_json "
                "FROM events WHERE id > ? ORDER BY id ASC LIMIT ?",
                (int(after_id), limit),
            )
            rows = cur.fetchall()
        result = []
        for row in rows:
            try:
                envelope = _attach_alert_fields(
                    json.loads(row[4]), row[0], row[1], row[2], row[3]
                )
                result.append((int(row[0]), envelope))
            except Exception:
                continue
        return result

    # ----------------------------------------------------
    # Count
    # ----------------------------------------------------

    def count(self):

        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:

            cursor = conn.cursor()

            cursor.execute(

                "SELECT COUNT(*) FROM events"

            )

            return cursor.fetchone()[0]

    # ----------------------------------------------------
    # Clear Database
    # ----------------------------------------------------

    def clear(self):
        """Clear all data from database - queue a clear operation to writer thread"""
        try:
            self.write_queue.put(("clear", None), block=False)
            print("[SQLite] Clear operation queued")
        except queue.Full:
            print("[SQLite] Could not queue clear operation")
    
    # ----------------------------------------------------
    # Flush Barrier
    # ----------------------------------------------------

    def flush(self, timeout=120.0):
        """Block until every previously queued write is committed to disk.

        The writer thread batches commits on idle ticks, so Queue.join() alone
        can return before data is durable. This queues a sync barrier behind
        all pending operations and waits for it, guaranteeing everything queued
        before the call is visible to other connections.
        """
        deadline = time.time() + timeout
        try:
            self.write_queue.put(("sync", None), block=True, timeout=max(1.0, timeout))
            while time.time() < deadline:
                try:
                    self.write_queue.join()
                    return True
                except Exception:
                    time.sleep(0.05)
            return False
        except queue.Full:
            return False

    # ----------------------------------------------------
    # Collector State Persistence (for resumability)
    # ----------------------------------------------------
    def save_collector_state(self, channel, last_record, computer):
        """Queue collector state to be saved by the single writer thread"""
        from datetime import datetime
        # Queue the state save
        try:
            timestamp = datetime.utcnow().isoformat() + "Z"
            self.write_queue.put(("save_state", (channel, last_record, computer, timestamp)), block=False)
        except queue.Full:
            print(f"[SQLite WARNING] Could not queue collector state save")
    
    def load_collector_state(self):
        """Load all saved collector states on startup"""
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                    SELECT channel, last_record_number, computer 
                    FROM collector_state
                """)
            rows = cursor.fetchall()
            state = {}
            for row in rows:
                state[row[0]] = {
                    "last_record": row[1],
                    "computer": row[2]
                }
            if state:
                print(f"[SQLite] Loaded collector state from {len(state)} channels: {state}")
            else:
                print("[SQLite] No saved collector state found")
            return state

    # ----------------------------------------------------
    # Investigation Persistence (Task 5)
    # ----------------------------------------------------

    def save_investigation(self, investigation):
        """Queue an investigation to be persisted by the single writer thread."""
        try:
            self.write_queue.put(("save_investigation", investigation), block=False)
            return True
        except queue.Full:
            print("[SQLite WARNING] Could not queue investigation save")
            return False

    _INVESTIGATION_COLUMNS = (
        "id", "alert_id", "status", "severity", "host", "user", "process",
        "parent_process", "event_id", "timestamp", "mitre", "risk_score",
        "confidence", "event_json", "ioc_json", "notes_json",
        "related_events_json", "process_tree_json", "created_at", "updated_at",
    )

    def _investigation_from_row(self, row):
        def _loads(value, default):
            try:
                return json.loads(value) if value else default
            except Exception:
                return default

        return {
            "id": row[0],
            "alert_id": row[1],
            "status": row[2],
            "severity": row[3],
            "host": row[4],
            "user": row[5],
            "process": row[6],
            "parent_process": row[7],
            "event_id": row[8],
            "timestamp": row[9],
            "mitre": row[10],
            "risk_score": row[11],
            "confidence": row[12],
            "event": _loads(row[13], {}),
            "ioc": _loads(row[14], {}),
            "notes": _loads(row[15], []),
            "related_events": _loads(row[16], []),
            "process_tree": _loads(row[17], []),
            "created_at": row[18],
            "updated_at": row[19],
        }

    def get_investigation(self, investigation_id):
        """Load a single persisted investigation by id."""
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"SELECT {', '.join(self._INVESTIGATION_COLUMNS)} FROM investigations WHERE id = ?",
                (investigation_id,),
            )
            row = cursor.fetchone()
        return self._investigation_from_row(row) if row else None

    def get_investigations(self):
        """Load all persisted investigations, newest first."""
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"SELECT {', '.join(self._INVESTIGATION_COLUMNS)} FROM investigations ORDER BY created_at DESC"
            )
            rows = cursor.fetchall()
        return [self._investigation_from_row(row) for row in rows]

    def find_investigation_by_alert(self, alert_id):
        """Find an existing investigation for an alert id (fingerprint)."""
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"SELECT {', '.join(self._INVESTIGATION_COLUMNS)} FROM investigations WHERE alert_id = ? ORDER BY created_at DESC LIMIT 1",
                (alert_id,),
            )
            row = cursor.fetchone()
        return self._investigation_from_row(row) if row else None

    # ----------------------------------------------------
    # Case Persistence (Task 20 - real case management)
    # ----------------------------------------------------

    def save_case(self, case):
        """Queue a case to be persisted by the single writer thread."""
        try:
            self.write_queue.put(("save_case", case), block=False)
            return True
        except queue.Full:
            print("[SQLite WARNING] Could not queue case save")
            return False

    _CASE_COLUMNS = (
        "case_id", "status", "priority", "title", "host", "event_id", "user",
        "process", "assigned_to", "alert_id", "investigation_id",
        "event_json", "timeline_json", "notes_json", "created_at", "updated_at",
    )

    def _case_from_row(self, row):
        def _loads(value, default):
            try:
                return json.loads(value) if value else default
            except Exception:
                return default

        return {
            "case_id": row[0],
            "status": row[1],
            "priority": row[2],
            "title": row[3],
            "host": row[4],
            "event_id": row[5],
            "user": row[6],
            "process": row[7],
            "assigned_to": row[8],
            "alert_id": row[9],
            "investigation_id": row[10],
            "event": _loads(row[11], {}),
            "timeline": _loads(row[12], []),
            "notes": _loads(row[13], []),
            "created_at": row[14],
            "updated_at": row[15],
        }

    def get_case(self, case_id):
        """Load a single persisted case by id."""
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"SELECT {', '.join(self._CASE_COLUMNS)} FROM cases WHERE case_id = ?",
                (case_id,),
            )
            row = cursor.fetchone()
        return self._case_from_row(row) if row else None

    def get_cases(self):
        """Load all persisted cases, newest first."""
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"SELECT {', '.join(self._CASE_COLUMNS)} FROM cases ORDER BY created_at DESC"
            )
            rows = cursor.fetchall()
        return [self._case_from_row(row) for row in rows]

    def get_case_by_alert(self, alert_id):
        """Return the most recent persisted case for an alert id, if any.

        Uses the alert_id index directly instead of scanning every case row in
        Python (the previous case_manager.find_by_alert loaded the full table
        on every escalation).
        """
        if not alert_id:
            return None
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"SELECT {', '.join(self._CASE_COLUMNS)} FROM cases "
                "WHERE alert_id = ? ORDER BY created_at DESC LIMIT 1",
                (alert_id,),
            )
            row = cursor.fetchone()
        return self._case_from_row(row) if row else None

    # ----------------------------------------------------
    # Internal SOCRA intelligence — IOC occurrence lookup (Threat Intel)
    # ----------------------------------------------------

    def find_internal_ioc_occurrences(self, value, days=7, event_summary_limit=10, related_limit=5):
        """Search persisted telemetry for occurrences of an indicator value.

        This backs the "SOCRA INTERNAL INTELLIGENCE" section of the Threat
        Intelligence page: every result is REAL local data (events, cases and
        investigations that mention the value) — nothing is fabricated. The
        search is a bounded SQL substring scan over the stored JSON envelopes
        (LIKE ... ESCAPE), restricted to the last ``days`` days of events, so
        matches are labeled occurrences (a substring match may include partial
        hits such as an IP that is a substring of another value).

        Returns:
            {
                "window_days": days,
                "events": [ {id, time, host, severity, event_id, detection,
                             status, mitre} ... ],
                "total_sightings": int,
                "hosts": [str, ...],
                "cases":  [ {case_id, title, status, priority, host,
                              alert_id, created_at} ... ],
                "investigations": [ {id, alert_id, status, severity, host,
                                      created_at} ... ],
            }
        """
        value = (value or "").strip()
        if not value:
            return {"window_days": days, "events": [], "total_sightings": 0,
                    "hosts": [], "cases": [], "investigations": []}

        # LIKE wildcard escaping: the indicator is matched literally, so any
        # literal % or _ inside it must not act as a wildcard.
        escaped = (
            value.replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        pattern = f"%{escaped}%"

        from datetime import datetime, timedelta
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()

        events = []
        total_sightings = 0
        hosts = []
        seen_hosts = set()
        try:
            with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT COUNT(*) FROM events "
                    "WHERE event_time >= ? AND raw_json LIKE ? ESCAPE '\\'",
                    (cutoff, pattern),
                )
                row = cursor.fetchone()
                total_sightings = int(row[0]) if row else 0

                cursor.execute(
                    "SELECT id, event_time, host, severity, event_id, status, raw_json "
                    "FROM events WHERE event_time >= ? AND raw_json LIKE ? ESCAPE '\\' "
                    "ORDER BY event_time DESC LIMIT ?",
                    (cutoff, pattern, event_summary_limit),
                )
                for row_id, event_time, host, severity, event_id, status, raw_json in cursor.fetchall():
                    detection = ""
                    mitre = ""
                    try:
                        payload = json.loads(raw_json) if raw_json else {}
                        det = payload.get("detection") or {}
                        detection = det.get("detection") or det.get("description") or ""
                        m = det.get("mitre")
                        if isinstance(m, dict):
                            mitre = m.get("id") or ""
                        elif isinstance(m, list) and m:
                            first = m[0]
                            mitre = first.get("id", "") if isinstance(first, dict) else str(first)
                        elif m:
                            mitre = str(m)
                    except Exception:
                        pass
                    events.append({
                        "id": row_id,
                        "time": event_time,
                        "host": host or "",
                        "severity": severity or "",
                        "event_id": str(event_id or ""),
                        "detection": detection,
                        "status": status or "New",
                        "mitre": mitre,
                    })
                    if host and host not in seen_hosts:
                        seen_hosts.add(host)
                        hosts.append(host)
        except Exception as e:
            print(f"[SQLite] Internal IOC occurrence search failed: {e}")
            return {"window_days": days, "events": [], "total_sightings": 0,
                    "hosts": [], "cases": [], "investigations": []}

        cases = []
        try:
            with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT case_id, title, status, priority, host, alert_id, created_at "
                    "FROM cases WHERE event_json LIKE ? ESCAPE '\\' "
                    "OR notes_json LIKE ? ESCAPE '\\' "
                    "OR title LIKE ? ESCAPE '\\' "
                    "ORDER BY created_at DESC LIMIT ?",
                    (pattern, pattern, pattern, related_limit),
                )
                for case_id, title, status, priority, host, alert_id, created_at in cursor.fetchall():
                    cases.append({
                        "case_id": case_id,
                        "title": title or "",
                        "status": status or "Open",
                        "priority": priority or "",
                        "host": host or "",
                        "alert_id": alert_id or "",
                        "created_at": created_at or "",
                    })
        except Exception as e:
            print(f"[SQLite] Internal IOC case search failed: {e}")

        investigations = []
        try:
            with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id, alert_id, status, severity, host, created_at "
                    "FROM investigations WHERE event_json LIKE ? ESCAPE '\\' "
                    "OR ioc_json LIKE ? ESCAPE '\\' "
                    "OR notes_json LIKE ? ESCAPE '\\' "
                    "ORDER BY created_at DESC LIMIT ?",
                    (pattern, pattern, pattern, related_limit),
                )
                for inv_id, alert_id, status, severity, host, created_at in cursor.fetchall():
                    investigations.append({
                        "id": inv_id,
                        "alert_id": alert_id or "",
                        "status": status or "",
                        "severity": severity or "",
                        "host": host or "",
                        "created_at": created_at or "",
                    })
        except Exception as e:
            print(f"[SQLite] Internal IOC investigation search failed: {e}")

        return {
            "window_days": days,
            "events": events,
            "total_sightings": total_sightings,
            "hosts": hosts,
            "cases": cases,
            "investigations": investigations,
        }

    # ----------------------------------------------------
    # Chat Persistence - AI Assistant conversation history
    # ----------------------------------------------------
    _CHAT_CONVERSATION_COLUMNS = (
        "id", "user_id", "title", "created_at", "updated_at", "context_json"
    )
    
    _CHAT_MESSAGE_COLUMNS = (
        "id", "conversation_id", "role", "content", "timestamp", "metadata_json"
    )
    
    def _conversation_from_row(self, row, extra_fields=None):
        """Convert a database row to a conversation dict."""
        def _loads(value, default):
            try:
                return json.loads(value) if value else default
            except Exception:
                return default
        
        conv = {
            "id": row[0],
            "user_id": row[1],
            "title": row[2],
            "created_at": row[3],
            "updated_at": row[4],
            "context": _loads(row[5], {})
        }
        if extra_fields:
            conv.update(extra_fields)
        return conv
    
    def _message_from_row(self, row):
        """Convert a database row to a message dict."""
        def _loads(value, default):
            try:
                return json.loads(value) if value else default
            except Exception:
                return default
        
        return {
            "id": row[0],
            "conversation_id": row[1],
            "role": row[2],
            "content": row[3],
            "timestamp": row[4],
            "metadata": _loads(row[5], {}),
            "status": row[6] if len(row) > 6 and row[6] else "completed"
        }
    
    def create_conversation(self, user_id, title=None, context=None):
        """Create a new chat conversation for a user."""
        import uuid
        from datetime import datetime
        
        conversation_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat() + "Z"
        
        conversation = {
            "id": conversation_id,
            "user_id": user_id,
            "title": title,
            "created_at": now,
            "updated_at": now,
            "context": context or {}
        }
        
        # Queue the save
        try:
            self.write_queue.put(("save_conversation", conversation), block=False)
            return conversation
        except queue.Full:
            print("[SQLite WARNING] Could not queue conversation save")
            return None
    
    def _process_save_conversation(self, conn, conversation):
        """Internal: process a conversation save from the writer thread."""
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO chat_conversations (id, user_id, title, created_at, updated_at, context_json)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            conversation["id"],
            conversation["user_id"],
            conversation["title"],
            conversation["created_at"],
            conversation["updated_at"],
            json.dumps(conversation["context"]) if conversation.get("context") else None
        ))
    
    def add_message(self, conversation_id, role, content, metadata=None, status="completed"):
        """Add a message to an existing conversation."""
        import uuid
        from datetime import datetime
        
        message_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat() + "Z"
        
        message = {
            "id": message_id,
            "conversation_id": conversation_id,
            "role": role,
            "content": content,
            "timestamp": now,
            "metadata": metadata or {},
            "status": status
        }
        
        # Update conversation's updated_at and last message metadata
        self.update_conversation_timestamp(conversation_id)
        self.update_conversation_last_message(conversation_id, content, now)
        
        # Queue the message save
        try:
            self.write_queue.put(("save_message", message), block=False)
            return message
        except queue.Full:
            print("[SQLite WARNING] Could not queue message save")
            return None
    
    def _process_save_message(self, conn, message):
        """Internal: process a message save from the writer thread."""
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO chat_messages (id, conversation_id, role, content, timestamp, metadata_json, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            message["id"],
            message["conversation_id"],
            message["role"],
            message["content"],
            message["timestamp"],
            json.dumps(message["metadata"]) if message.get("metadata") else None,
            message.get("status", "completed")
        ))
    
    def update_conversation_timestamp(self, conversation_id):
        """Update a conversation's last updated timestamp."""
        from datetime import datetime
        now = datetime.utcnow().isoformat() + "Z"
        
        try:
            self.write_queue.put(("update_conversation_timestamp", {
                "id": conversation_id,
                "updated_at": now
            }), block=False)
        except queue.Full:
            pass
    
    def _process_update_conversation_timestamp(self, conn, data):
        """Internal: update conversation timestamp."""
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE chat_conversations SET updated_at = ? WHERE id = ?
        """, (data["updated_at"], data["id"]))

    def update_conversation_last_message(self, conversation_id, content, timestamp):
        """Update the denormalized last-message fields on a conversation."""
        preview = (content or "")[:200]
        try:
            self.write_queue.put(("update_conversation_last_message", {
                "id": conversation_id,
                "last_message_content": preview,
                "last_message_at": timestamp,
            }), block=False)
        except queue.Full:
            pass

    def _process_update_conversation_last_message(self, conn, data):
        """Internal: update last message metadata on conversation."""
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE chat_conversations SET last_message_content = ?, last_message_at = ?,
                message_count = (
                    SELECT COUNT(*) FROM chat_messages WHERE conversation_id = ?
                )
            WHERE id = ?
        """, (data["last_message_content"], data["last_message_at"], data["id"], data["id"]))

    def update_message_status(self, message_id, status, content=None):
        """Update a message's status and optionally its content."""
        try:
            self.write_queue.put(("update_message_status", {
                "id": message_id,
                "status": status,
                "content": content,
            }), block=False)
        except queue.Full:
            pass

    def _process_update_message_status(self, conn, data):
        """Internal: update message status."""
        cursor = conn.cursor()
        if data.get("content") is not None:
            cursor.execute(
                "UPDATE chat_messages SET status = ?, content = ? WHERE id = ?",
                (data["status"], data["content"], data["id"])
            )
        else:
            cursor.execute(
                "UPDATE chat_messages SET status = ? WHERE id = ?",
                (data["status"], data["id"])
            )

    def delete_all_conversations(self, user_id):
        """Delete all conversations and messages for a user."""
        try:
            self.write_queue.put(("delete_all_conversations", {"user_id": user_id}), block=False)
            return True
        except queue.Full:
            return False

    def _process_delete_all_conversations(self, conn, data):
        """Internal: delete all conversations and messages for a user."""
        user_id = data["user_id"]
        cursor = conn.cursor()
        # Get all conversation IDs for this user
        cursor.execute("SELECT id FROM chat_conversations WHERE user_id = ?", (user_id,))
        conv_ids = [row[0] for row in cursor.fetchall()]
        if conv_ids:
            placeholders = ",".join("?" * len(conv_ids))
            cursor.execute(f"DELETE FROM chat_messages WHERE conversation_id IN ({placeholders})", conv_ids)
        cursor.execute("DELETE FROM chat_conversations WHERE user_id = ?", (user_id,))

    def get_user_conversations(self, user_id, limit=50):
        """Get all conversations for a specific user, newest first."""
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, user_id, title, created_at, updated_at, context_json 
                FROM chat_conversations 
                WHERE user_id = ? 
                ORDER BY updated_at DESC 
                LIMIT ?
            """, (user_id, limit))
            rows = cursor.fetchall()
        return [self._conversation_from_row(row) for row in rows]
    
    def get_conversation(self, conversation_id, user_id=None):
        """Get a single conversation, optionally verifying user ownership."""
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            query = "SELECT id, user_id, title, created_at, updated_at, context_json FROM chat_conversations WHERE id = ?"
            params = [conversation_id]
            
            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)
            
            cursor = conn.cursor()
            cursor.execute(query, params)
            row = cursor.fetchone()
        
        return self._conversation_from_row(row) if row else None
    
    def get_conversation_messages(self, conversation_id, user_id=None, limit=100):
        """Get all messages for a conversation, verifying user ownership if user_id is provided."""
        # First verify the conversation belongs to the user if specified
        if user_id:
            conv = self.get_conversation(conversation_id, user_id)
            if not conv:
                return []
        
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, conversation_id, role, content, timestamp, metadata_json, status 
                FROM chat_messages 
                WHERE conversation_id = ? 
                ORDER BY timestamp ASC 
                LIMIT ?
            """, (conversation_id, limit))
            rows = cursor.fetchall()
        
        return [self._message_from_row(row) for row in rows]
    
    def get_latest_conversation(self, user_id):
        """Get the most recently updated conversation for a user."""
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, user_id, title, created_at, updated_at, context_json 
                FROM chat_conversations 
                WHERE user_id = ? 
                ORDER BY updated_at DESC 
                LIMIT 1
            """, (user_id,))
            row = cursor.fetchone()
        
        return self._conversation_from_row(row) if row else None
    
    def clear_conversation(self, conversation_id, user_id):
        """Clear all messages from a conversation (user must own it)."""
        conv = self.get_conversation(conversation_id, user_id)
        if not conv:
            return False
        
        try:
            self.write_queue.put(("clear_conversation_messages", {"id": conversation_id}), block=False)
            return True
        except queue.Full:
            return False
    
    def _process_clear_conversation_messages(self, conn, data):
        """Internal: clear all messages for a conversation."""
        cursor = conn.cursor()
        cursor.execute("DELETE FROM chat_messages WHERE conversation_id = ?", (data["id"],))
    
    def delete_conversation(self, conversation_id, user_id):
        """Delete a conversation and all its messages (user must own it)."""
        conv = self.get_conversation(conversation_id, user_id)
        if not conv:
            return False
        
        try:
            self.write_queue.put(("delete_conversation", {"id": conversation_id}), block=False)
            return True
        except queue.Full:
            return False
    
    def _process_delete_conversation(self, conn, data):
        """Internal: delete a conversation and its messages."""
        cursor = conn.cursor()
        cursor.execute("DELETE FROM chat_messages WHERE conversation_id = ?", (data["id"],))
        cursor.execute("DELETE FROM chat_conversations WHERE id = ?", (data["id"],))
    

    def rename_conversation(self, conversation_id, user_id, new_title):
        """Rename a conversation (user must own it)."""
        conv = self.get_conversation(conversation_id, user_id)
        if not conv:
            return False
        from datetime import datetime
        now = datetime.utcnow().isoformat() + "Z"
        try:
            self.write_queue.put(("rename_conversation", {
                "id": conversation_id,
                "title": new_title,
                "updated_at": now
            }), block=False)
            return True
        except queue.Full:
            return False

    def _process_rename_conversation(self, conn, data):
        """Internal: rename a conversation."""
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE chat_conversations SET title = ?, updated_at = ? WHERE id = ?",
            (data["title"], data["updated_at"], data["id"])
        )

    def search_conversations(self, user_id, query, limit=20):
        """Search conversations by title or message content."""
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            like_pattern = f"%{query}%"
            cursor.execute("""
                SELECT DISTINCT c.id, c.user_id, c.title, c.created_at, c.updated_at, c.context_json
                FROM chat_conversations c
                LEFT JOIN chat_messages m ON m.conversation_id = c.id
                WHERE c.user_id = ?
                  AND (c.title LIKE ? OR m.content LIKE ?)
                ORDER BY c.updated_at DESC
                LIMIT ?
            """, (user_id, like_pattern, like_pattern, limit))
            rows = cursor.fetchall()
        return [self._conversation_from_row(row) for row in rows]

    def get_conversation_with_count(self, conversation_id, user_id=None):
        """Get a single conversation with message count."""
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            query = """
                SELECT c.id, c.user_id, c.title, c.created_at, c.updated_at, c.context_json,
                       COALESCE(c.message_count, 0) as message_count,
                       c.last_message_content,
                       c.last_message_at
                FROM chat_conversations c
                WHERE c.id = ?
            """
            params = [conversation_id]
            if user_id:
                query += " AND c.user_id = ?"
                params.append(user_id)
            cursor.execute(query, params)
            row = cursor.fetchone()
        if not row:
            return None
        conv = self._conversation_from_row(row[:6])
        conv["message_count"] = row[6]
        conv["last_message_content"] = row[7] or ""
        conv["last_message_at"] = row[8] or row[4]
        return conv

    def get_user_conversations_with_count(self, user_id, limit=50):
        """Get all conversations for a user with message counts and last message, newest first."""
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT c.id, c.user_id, c.title, c.created_at, c.updated_at, c.context_json,
                       COALESCE(c.message_count, 0) as message_count,
                       c.last_message_content,
                       c.last_message_at
                FROM chat_conversations c
                WHERE c.user_id = ?
                ORDER BY c.updated_at DESC
                LIMIT ?
            """, (user_id, limit))
            rows = cursor.fetchall()
        result = []
        for row in rows:
            conv = self._conversation_from_row(row[:6])
            conv["message_count"] = row[6]
            conv["last_message_content"] = row[7] or ""
            conv["last_message_at"] = row[8] or row[4]
            result.append(conv)
        return result

    def update_conversation_title(self, conversation_id, title):
        """Update a conversation title (used for auto-title)."""
        from datetime import datetime
        now = datetime.utcnow().isoformat() + "Z"
        try:
            self.write_queue.put(("rename_conversation", {
                "id": conversation_id,
                "title": title,
                "updated_at": now
            }), block=False)
        except queue.Full:
            pass

    # ------------------------------------------------------------------
    # Notifications
    # ------------------------------------------------------------------

    def create_notification(self, user_id, event_data, fingerprint=None):
        """Create a notification for a security event.

        Deduplication is handled by the UNIQUE index on (user_id, fingerprint)
        combined with INSERT OR IGNORE in _process_save_notification, so the
        check-and-insert is atomic — no race condition with the write queue.
        """
        from datetime import datetime
        now = datetime.utcnow().isoformat() + "Z"

        ev = event_data.get("event", {}) if isinstance(event_data, dict) else {}
        det = event_data.get("detection", {}) if isinstance(event_data, dict) else {}
        mitre = det.get("mitre", {})
        if isinstance(mitre, dict):
            mitre_label = mitre.get("id") or mitre.get("technique") or ""
        else:
            mitre_label = str(mitre) if mitre else ""

        title = det.get("detection") or det.get("description") or "Security event detected"
        severity = det.get("severity") or "Informational"
        host = ev.get("host") or ev.get("computer") or ""
        process = ev.get("process_name") or ev.get("image") or ""
        event_time = ev.get("time") or now
        event_id = ev.get("event_id") or ""

        fp = fingerprint or (event_data.get("metadata", {}).get("fingerprint") if isinstance(event_data, dict) else None)
        # Fallback: compute a fingerprint from event identity fields so the
        # unique index on (user_id, fingerprint) never sees NULL (SQLite
        # allows multiple NULLs under UNIQUE, which would defeat dedup).
        if not fp:
            fp = _compute_fingerprint({
                "host": host,
                "event_id": event_id,
                "time": event_time,
                "process_name": process,
            })

        # The _id field is the persisted database row id set by _attach_alert_fields.
        # Store it so the frontend can navigate to the exact alert on click.
        alert_id = event_data.get("_id") if isinstance(event_data, dict) else None

        try:
            self.write_queue.put(("save_notification", {
                "user_id": user_id,
                "event_id": str(event_id),
                "fingerprint": fp,
                "severity": severity,
                "title": title,
                "host": host,
                "process_name": process,
                "mitre": mitre_label,
                "event_time": event_time,
                "alert_id": alert_id,
                "created_at": now,
            }), block=False)
            return True
        except queue.Full:
            return None

    def _process_save_notification(self, conn, data):
        """Internal: save a notification record.

        Uses INSERT OR IGNORE so the unique index on (user_id, fingerprint)
        silently drops duplicate notifications instead of raising IntegrityError.
        This replaces the racy pre-check that read from a separate connection
        while writes were still queued.
        """
        # Ensure mitre is always a string (never list/dict) for SQLite
        mitre_val = data.get("mitre")
        if isinstance(mitre_val, (list, dict)):
            if isinstance(mitre_val, list) and mitre_val:
                first = mitre_val[0]
                mitre_val = first.get("id", "") if isinstance(first, dict) else str(first)
            elif isinstance(mitre_val, dict):
                mitre_val = mitre_val.get("id", "")
            else:
                mitre_val = str(mitre_val) if mitre_val else ""
        elif mitre_val is None:
            mitre_val = ""

        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR IGNORE INTO notifications (user_id, event_id, fingerprint, severity, title,
                                      host, process_name, mitre, event_time, created_at, alert_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            _sqlite_bind_safe(data.get("user_id")),
            _sqlite_bind_safe(str(data.get("event_id", ""))),
            _sqlite_bind_safe(data.get("fingerprint")),
            _sqlite_bind_safe(data.get("severity")),
            _sqlite_bind_safe(data.get("title")),
            _sqlite_bind_safe(data.get("host")),
            _sqlite_bind_safe(data.get("process_name")),
            _sqlite_bind_safe(mitre_val),
            _sqlite_bind_safe(data.get("event_time")),
            _sqlite_bind_safe(data.get("created_at")),
            _sqlite_bind_safe(data.get("alert_id")),
        ))

    def get_today_notifications(self, user_id):
        """Get today's notifications for a user, newest first."""
        from datetime import datetime, timezone
        # Use ISO 8601 format with T00:00:00Z so string comparison matches
        # created_at values like '2026-08-26T14:30:00.123456Z' correctly.
        today_start = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        ).isoformat().replace("+00:00", "Z")
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, user_id, event_id, fingerprint, severity, title,
                       host, process_name, mitre, event_time, read, created_at,
                       alert_id
                FROM notifications
                WHERE user_id = ? AND created_at >= ?
                ORDER BY created_at DESC
                LIMIT 100
            """, (user_id, today_start))
            rows = cursor.fetchall()
        return [self._notification_from_row(row) for row in rows]

    def get_unread_count(self, user_id):
        """Get the count of unread notifications for today."""
        from datetime import datetime, timezone
        today_start = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        ).isoformat().replace("+00:00", "Z")
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) FROM notifications
                WHERE user_id = ? AND read = 0 AND created_at >= ?
            """, (user_id, today_start))
            return cursor.fetchone()[0]

    def get_all_today_notifications(self):
        """Get ALL today's notifications (for legacy users without a database user_id)."""
        from datetime import datetime, timezone
        today_start = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        ).isoformat().replace("+00:00", "Z")
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, user_id, event_id, fingerprint, severity, title,
                       host, process_name, mitre, event_time, read, created_at,
                       alert_id
                FROM notifications
                WHERE created_at >= ?
                ORDER BY created_at DESC
                LIMIT 100
            """, (today_start,))
            rows = cursor.fetchall()
        return [self._notification_from_row(row) for row in rows]

    def get_all_unread_count(self):
        """Get ALL unread notification count (for legacy users)."""
        from datetime import datetime, timezone
        today_start = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        ).isoformat().replace("+00:00", "Z")
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) FROM notifications
                WHERE created_at >= ? AND read = 0
            """, (today_start,))
            return cursor.fetchone()[0]

    def mark_notification_read(self, notification_id, user_id):
        """Mark a single notification as read."""
        try:
            self.write_queue.put(("mark_notification_read", {
                "id": notification_id,
                "user_id": user_id,
            }), block=False)
            return True
        except queue.Full:
            return False

    def _process_mark_notification_read(self, conn, data):
        """Internal: mark a notification as read."""
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?",
            (data["id"], data["user_id"])
        )

    def mark_all_notifications_read(self, user_id):
        """Mark all of a user's notifications as read."""
        try:
            self.write_queue.put(("mark_all_notifications_read", {
                "user_id": user_id,
            }), block=False)
            return True
        except queue.Full:
            return False

    def _process_mark_all_notifications_read(self, conn, data):
        """Internal: mark all notifications as read for a user."""
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE notifications SET read = 1 WHERE user_id = ? AND read = 0",
            (data["user_id"],)
        )

    @staticmethod
    def _notification_from_row(row):
        """Convert a database row to a notification dict."""
        return {
            "id": row[0],
            "user_id": row[1],
            "event_id": row[2],
            "fingerprint": row[3],
            "severity": row[4],
            "title": row[5],
            "host": row[6],
            "process_name": row[7],
            "mitre": row[8],
            "event_time": row[9],
            "read": bool(row[10]),
            "created_at": row[11],
            "alert_id": row[12] if len(row) > 12 else None,
        }

    # ------------------------------------------------------------------
    # Derived Notifications (from authoritative events table)
    # ------------------------------------------------------------------
    #
    # Instead of duplicating every alert into a separate notifications table,
    # we derive notifications on-the-fly from the events table joined with a
    # lightweight per-user read state.  This guarantees the notification panel
    # always reflects the complete security event stream without backfill
    # gaps.

    def get_derived_notifications(self, user_id, page=1, page_size=50,
                                  severity_filter=None):
        """Return today's notifications derived from the events table.

        Each notification is an alert from today joined with the user's
        read state.  The response includes pagination metadata.

        Returns dict: {items, total, unread_count, page, page_size, has_more}
        """
        from datetime import datetime, timezone
        today_start = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        ).isoformat().replace("+00:00", "Z")

        offset = (page - 1) * page_size

        # Build severity filter — default to Critical/High only.
        # Normal telemetry (Informational/Low/Medium) must NOT appear as notifications.
        NOTIFICATION_SEVERITIES = ("Critical", "High")
        effective_severities = [
            s for s in (severity_filter or NOTIFICATION_SEVERITIES)
            if s in NOTIFICATION_SEVERITIES
        ] or list(NOTIFICATION_SEVERITIES)
        placeholders = ",".join("?" for _ in effective_severities)
        severity_clause = f"AND e.severity IN ({placeholders})"
        severity_params = list(effective_severities)

        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Total count
            count_sql = (
                "SELECT COUNT(*) FROM events e "
                f"WHERE e.event_time >= ? {severity_clause}"
            )
            cursor.execute(count_sql, [today_start] + severity_params)
            total = cursor.fetchone()[0]

            # Unread count
            unread_sql = (
                "SELECT COUNT(*) FROM events e "
                "LEFT JOIN notification_read_state nrs "
                "  ON nrs.alert_id = e.id AND nrs.user_id = ? "
                f"WHERE e.event_time >= ? AND nrs.alert_id IS NULL {severity_clause}"
            )
            cursor.execute(unread_sql, [user_id, today_start] + severity_params)
            unread_count = cursor.fetchone()[0]

            # Page of notifications
            data_sql = (
                "SELECT e.id, e.severity, e.host, e.process_name, e.mitre, "
                "       e.event_time, e.event_id, e.process_id, "
                "       json_extract(e.raw_json, '$.detection.detection') AS title, "
                "       CASE WHEN nrs.alert_id IS NOT NULL THEN 1 ELSE 0 END AS read_flag "
                "FROM events e "
                "LEFT JOIN notification_read_state nrs "
                "  ON nrs.alert_id = e.id AND nrs.user_id = ? "
                f"WHERE e.event_time >= ? {severity_clause} "
                "ORDER BY e.event_time DESC "
                "LIMIT ? OFFSET ?"
            )
            cursor.execute(data_sql, [user_id, today_start] + severity_params + [page_size, offset])
            rows = cursor.fetchall()

        items = []
        for row in rows:
            raw_title = row["title"] or "Security event detected"
            # Normalise severity for consistent display
            raw_sev = row["severity"] or ""
            sev = raw_sev.strip().capitalize()
            if sev not in ("Critical", "High", "Medium", "Low", "Informational"):
                sev = "Informational"

            items.append({
                "id": row["id"],
                "alert_id": row["id"],
                "severity": sev,
                "title": raw_title,
                "host": row["host"] or "",
                "process_name": row["process_name"] or "",
                "process_id": row["process_id"] or "",
                "mitre": row["mitre"] or "",
                "event_time": row["event_time"] or "",
                "event_id": row["event_id"] or "",
                "read": bool(row["read_flag"]),
            })

        return {
            "items": items,
            "total": total,
            "unread_count": unread_count,
            "page": page,
            "page_size": page_size,
            "has_more": offset + page_size < total,
        }

    def get_derived_unread_count(self, user_id):
        """Get the count of unread notifications for today (derived).

        Only counts Critical/High severity events — normal telemetry is excluded.
        """
        from datetime import datetime, timezone
        today_start = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        ).isoformat().replace("+00:00", "Z")

        NOTIFICATION_SEVERITIES = ("Critical", "High")
        placeholders = ",".join("?" for _ in NOTIFICATION_SEVERITIES)
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"SELECT COUNT(*) FROM events e "
                f"LEFT JOIN notification_read_state nrs "
                f"  ON nrs.alert_id = e.id AND nrs.user_id = ? "
                f"WHERE e.event_time >= ? AND nrs.alert_id IS NULL "
                f"AND e.severity IN ({placeholders})",
                [user_id, today_start] + list(NOTIFICATION_SEVERITIES),
            )
            return cursor.fetchone()[0]

    def get_derived_total_today(self):
        """Get total number of today's HIGH/CRITICAL events.

        Only counts notification-worthy security alerts, not all telemetry.
        """
        from datetime import datetime, timezone
        today_start = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        ).isoformat().replace("+00:00", "Z")

        NOTIFICATION_SEVERITIES = ("Critical", "High")
        placeholders = ",".join("?" for _ in NOTIFICATION_SEVERITIES)
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"SELECT COUNT(*) FROM events WHERE event_time >= ? "
                f"AND severity IN ({placeholders})",
                [today_start] + list(NOTIFICATION_SEVERITIES),
            )
            return cursor.fetchone()[0]

    def mark_derived_read(self, user_id, alert_id):
        """Mark a single notification as read for a user.

        Updates the notifications table directly — the source of truth
        for notification read state.
        """
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        try:
            self.write_queue.put(("mark_derived_read", {
                "user_id": user_id,
                "alert_id": alert_id,
                "read_at": now,
            }), block=False)
            return True
        except queue.Full:
            return False

    def _process_mark_derived_read(self, conn, data):
        """Internal: mark a single notification as read in the notifications table."""
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE notifications SET read = 1 WHERE id = ? AND user_id = ?",
            (data["alert_id"], data["user_id"]),
        )
        # Also update in notification_read_state for backward compatibility
        cursor.execute(
            "INSERT OR IGNORE INTO notification_read_state "
            "(user_id, alert_id, read_at) VALUES (?, ?, ?)",
            (data["user_id"], data["alert_id"], data["read_at"]),
        )
        conn.commit()

    def mark_all_derived_read(self, user_id):
        """Mark all of today's notifications as read for a user.

        Updates the notifications table directly — the source of truth
        for notification read state.
        """
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        today_start = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        ).isoformat().replace("+00:00", "Z")
        try:
            self.write_queue.put(("mark_all_derived_read", {
                "user_id": user_id,
                "read_at": now,
                "today_start": today_start,
            }), block=False)
            return True
        except queue.Full:
            return False

    def _process_mark_all_derived_read(self, conn, data):
        """Internal: mark all of today's HIGH/CRITICAL notifications as read.

        Updates the notifications table directly — the source of truth
        for notification read state.  Only marks Critical and High severity
        notifications.  Normal telemetry is excluded.
        """
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE notifications SET read = 1 "
            "WHERE user_id = ? AND read = 0 "
            "AND severity IN ('Critical', 'High')",
            (data["user_id"],),
        )
        # Also bulk-update notification_read_state for backward compatibility
        cursor.execute(
            "INSERT OR IGNORE INTO notification_read_state (user_id, alert_id, read_at) "
            "SELECT ?, id, ? FROM events WHERE event_time >= ? "
            "AND severity IN ('Critical', 'High')",
            (data["user_id"], data["read_at"], data["today_start"]),
        )
        conn.commit()

    # ------------------------------------------------------------------
    # Security Attention Memory — Lifecycle
    # ------------------------------------------------------------------

    def get_notification_summary(self, user_id):
        """Return severity counts for ACTIVE (unread, non-resolved) notifications.

        Only counts notifications that are NOT read AND NOT resolved.
        Returns dict: {critical, high, system, total_attention}
        """
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT
                    SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) AS critical,
                    SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) AS high,
                    SUM(CASE WHEN notification_type = 'system' THEN 1 ELSE 0 END) AS system_count,
                    COUNT(*) AS total
                FROM notifications
                WHERE user_id = ? AND read = 0 AND status != 'resolved'
            """, (user_id,))
            row = cursor.fetchone()
            if not row:
                return {"critical": 0, "high": 0, "system": 0, "total_attention": 0}
            return {
                "critical": row[0] or 0,
                "high": row[1] or 0,
                "system": row[2] or 0,
                "total_attention": row[3] or 0,
            }

    def acknowledge_notification(self, user_id, notification_id):
        """Mark a notification as acknowledged."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        try:
            self.write_queue.put(("acknowledge_notification", {
                "user_id": user_id,
                "notification_id": notification_id,
                "acknowledged_at": now,
            }), block=False)
            return True
        except queue.Full:
            return False

    def _process_acknowledge_notification(self, conn, data):
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE notifications SET status = 'acknowledged', "
            "acknowledged_at = ?, read = 1 "
            "WHERE id = ? AND user_id = ?",
            (data["acknowledged_at"], data["notification_id"], data["user_id"]),
        )
        conn.commit()

    def resolve_notification(self, user_id, notification_id):
        """Mark a notification as resolved."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        try:
            self.write_queue.put(("resolve_notification", {
                "user_id": user_id,
                "notification_id": notification_id,
                "resolved_at": now,
            }), block=False)
            return True
        except queue.Full:
            return False

    def _process_resolve_notification(self, conn, data):
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE notifications SET status = 'resolved', "
            "resolved_at = ?, read = 1 "
            "WHERE id = ? AND user_id = ?",
            (data["resolved_at"], data["notification_id"], data["user_id"]),
        )
        conn.commit()

    # ------------------------------------------------------------------
    # User Management (Authentication)
    # ------------------------------------------------------------------

    def create_user(self, email: str, full_name: str, password_hash: str,
                    status: str = "pending_verification", role: str = "analyst") -> dict:
        """Create a new user account. Returns the created user dict."""
        import uuid
        from datetime import datetime
        now = datetime.utcnow().isoformat() + "Z"
        user_id = str(uuid.uuid4())

        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT INTO users (id, email, full_name, password_hash, role,
                                      email_verified, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)
                """, (user_id, email, full_name, password_hash, role, status, now, now))
                conn.commit()
                return {
                    "id": user_id, "email": email, "full_name": full_name,
                    "role": role, "status": status, "email_verified": False,
                    "created_at": now,
                }
            except sqlite3.IntegrityError:
                return None

    def get_user_by_email(self, email: str) -> dict:
        """Get a user by email address."""
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, email, username, full_name, password_hash, role, "
                "email_verified, status, created_at, updated_at, last_login "
                "FROM users WHERE email = ?",
                (email,)
            )
            row = cursor.fetchone()
        if not row:
            return None
        return {
            "id": row[0], "email": row[1], "username": row[2],
            "full_name": row[3], "password_hash": row[4], "role": row[5],
            "email_verified": bool(row[6]), "status": row[7],
            "created_at": row[8], "updated_at": row[9],            "last_login": row[10],
        }

    def get_user_by_username(self, username: str) -> dict:
        """Get a user by username."""
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, email, username, full_name, password_hash, role, "
                "email_verified, status, created_at, updated_at, last_login "
                "FROM users WHERE username = ?",
                (username,)
            )
            row = cursor.fetchone()
        if not row:
            return None
        return {
            "id": row[0], "email": row[1], "username": row[2],
            "full_name": row[3], "password_hash": row[4], "role": row[5],
            "email_verified": bool(row[6]), "status": row[7], "created_at": row[8],
            "updated_at": row[9], "last_login": row[10],
        }

    def get_all_users(self) -> list:
        """Get all users (for notification broadcasting to all analysts)."""
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, email, username, full_name, role, status "
                "FROM users WHERE status = 'active'"
            )
            rows = cursor.fetchall()
        return [
            {
                "id": row[0], "email": row[1], "username": row[2],
                "full_name": row[3], "role": row[4], "status": row[5],
            }
            for row in rows
        ]

    def activate_user(self, user_id: str):
        """Activate a user after email verification."""
        from datetime import datetime
        now = datetime.utcnow().isoformat() + "Z"
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET email_verified = 1, status = 'active', updated_at = ? WHERE id = ?",
                (now, user_id)
            )
            conn.commit()

    def update_user_password(self, user_id: str, password_hash: str):
        """Update a user's password hash."""
        from datetime import datetime
        now = datetime.utcnow().isoformat() + "Z"
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?",
                (password_hash, now, user_id)
            )
            conn.commit()

    def update_user_last_login(self, user_id: str):
        """Update user's last login timestamp."""
        from datetime import datetime
        now = datetime.utcnow().isoformat() + "Z"
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET last_login = ? WHERE id = ?",
                (now, user_id)
            )
            conn.commit()

    # ------------------------------------------------------------------
    # Search history (user-isolated)
    # ------------------------------------------------------------------

    def add_search_history(self, user_id: str, query: str):
        """Save or update a search query in the user's history.

        If the same query already exists for this user, bump its use_count
        and last_used_at instead of inserting a duplicate.
        """
        from datetime import datetime
        import uuid
        now = datetime.utcnow().isoformat() + "Z"
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id FROM search_history WHERE user_id = ? AND query = ?",
                (user_id, query),
            )
            existing = cursor.fetchone()
            if existing:
                cursor.execute(
                    "UPDATE search_history SET last_used_at = ?, use_count = use_count + 1 WHERE id = ?",
                    (now, existing[0]),
                )
            else:
                cursor.execute(
                    "INSERT INTO search_history (id, user_id, query, created_at, last_used_at, use_count)"
                    " VALUES (?, ?, ?, ?, ?, 1)",
                    (str(uuid.uuid4()), user_id, query, now, now),
                )
            conn.commit()

    def get_search_history(self, user_id: str, limit: int = 20):
        """Return the user's recent searches ordered by last used."""
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, query, created_at, last_used_at, use_count"
                " FROM search_history WHERE user_id = ?"
                " ORDER BY last_used_at DESC LIMIT ?",
                (user_id, limit),
            )
            rows = cursor.fetchall()
        return [
            {"id": r[0], "query": r[1], "created_at": r[2], "last_used_at": r[3], "use_count": r[4]}
            for r in rows
        ]

    def delete_search_history_item(self, user_id: str, history_id: str):
        """Delete a single search history entry (user must own it)."""
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM search_history WHERE id = ? AND user_id = ?",
                (history_id, user_id),
            )
            conn.commit()
            return cursor.rowcount > 0

    def clear_search_history(self, user_id: str):
        """Clear all search history for a user."""
        with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM search_history WHERE user_id = ?", (user_id,))
            conn.commit()

    # ------------------------------------------------------------------
    # Search: categorized results across all data sources
    # ------------------------------------------------------------------

    def search_all_categorized(self, query: str, user_id: str = None, page: int = 1, page_size: int = 50):
        """Search across events, alerts, cases and return categorized results.

        Returns a dict with counts and paginated results per category.
        """
        import time
        start_total = time.time()
        from app.search.search_engine import search_engine
        from app.search.query_parser import query_parser
        from app.mitre.mitre_engine import mitre_engine
        from app.core.logger import get_module_logger
        logger = get_module_logger("sqlite_storage.search")

        # Parse query - measure timing
        start_parse = time.time()
        parsed = query_parser.parse(query)
        ast = parsed["ast"]
        time_range = parsed.get("time_range")
        logger.info(f"Query parsing took: {(time.time() - start_parse)*1000:.2f}ms")

        # Events / alerts (same table, different status)
        start_events_search = time.time()
        where, params = search_engine._history_where(ast, time_range)
        offset = (page - 1) * page_size
        # Calculate proper limit for pagination - only fetch what we need for the current page
        # Include offset in search_events to do true server-side pagination (not client-side slicing)
        event_result = self.search_events(where, params, limit=page_size, offset=offset)
        event_total = event_result["total"]
        events = event_result["results"]
        logger.info(f"Event search (page {page}, {page_size} results) took: {(time.time() - start_events_search)*1000:.2f}ms, found {event_total} total events")

        # Categorize events into events vs alerts
        start_categorize = time.time()
        event_items = []
        alert_items = []
        hosts = set()
        processes = set()
        users_set = set()
        event_ids = set()
        mitre_ids = set()

        for item in events:
            ev = item.get("event", {})
            det = item.get("detection", {})
            host = ev.get("host") or ev.get("computer") or ""
            if host:
                hosts.add(host)
            proc = ev.get("process_name") or ""
            if proc:
                processes.add(proc)
            user = ev.get("user") or ""
            if user:
                users_set.add(user)
            eid = str(ev.get("event_id", ""))
            if eid:
                event_ids.add(eid)
            mitre_val = det.get("mitre")
            mid = ""
            if isinstance(mitre_val, list):
                # Canonical shape: list of MITRE blocks - index the first id.
                first = mitre_val[0] if mitre_val else {}
                mid = first.get("id", "") if isinstance(first, dict) else str(first or "")
            elif isinstance(mitre_val, dict):
                mid = mitre_val.get("id", "")
            elif isinstance(mitre_val, str):
                mid = mitre_val
            if mid and mid not in ("N/A", "Unknown", "Unmapped"):
                mitre_ids.add(mid)

            status = ev.get("status") or det.get("status") or "New"
            if status != "New" or det.get("severity") in ("Critical", "High"):
                alert_items.append(item)
            else:
                event_items.append(item)
        logger.info(f"Event categorization took: {(time.time() - start_categorize)*1000:.2f}ms")

        # MITRE technique details from the engine's lookup table
        start_mitre = time.time()
        mitre_details = []
        try:
            technique_map = mitre_engine.technique_map
        except Exception:
            technique_map = {}
        for mid in mitre_ids:
            entry = technique_map.get(mid)
            if entry:
                mitre_details.append({
                    "id": mid,
                    "name": entry.get("technique", mid),
                    "tactic": entry.get("tactic", ""),
                })
            else:
                mitre_details.append({"id": mid, "name": mid, "tactic": ""})
        logger.info(f"MITRE processing took: {(time.time() - start_mitre)*1000:.2f}ms")

        # Cases search - optimize with server-side pagination and proper offset
        start_cases = time.time()
        case_items = []
        case_total = 0
        try:
            with sqlite3.connect(self.db_path, timeout=self.sqlite_timeout) as conn:
                cursor = conn.cursor()
                like = f"%{query}%"
                cursor.execute(
                    "SELECT COUNT(*) FROM cases WHERE title LIKE ? OR case_id LIKE ?"
                    " OR description LIKE ?",
                    (like, like, like),
                )
                case_total = cursor.fetchone()[0]
                # Add offset to cases search for true pagination
                cursor.execute(
                    "SELECT * FROM cases WHERE title LIKE ? OR case_id LIKE ?"
                    " OR description LIKE ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (like, like, like, page_size, offset),
                )
                rows = cursor.fetchall()
                cols = [d[0] for d in cursor.description] if cursor.description else []
                case_items = [dict(zip(cols, row)) for row in rows]
        except Exception as e:
            logger.error(f"Case search failed: {e}")
            pass
        logger.info(f"Case search took: {(time.time() - start_cases)*1000:.2f}ms")

        # Already paginated on server-side, no need to re-slice
        paginated_events = event_items + alert_items

        total_time = (time.time() - start_total)*1000
        logger.info(f"Total search_all_categorized execution: {total_time:.2f}ms for query: '{query}'")

        return {
            "events": {"total": event_total, "results": paginated_events[:page_size]},
            "alerts": {"total": len(alert_items), "results": alert_items[:page_size]},
            "hosts": sorted(hosts),
            "processes": sorted(processes)[:50],
            "users": sorted(users_set)[:50],
            "event_ids": sorted(event_ids),
            "mitre": mitre_details,
            "cases": {"total": case_total, "results": case_items},
            "total": event_total + case_total,
        }

    # Add the new operations to the writer thread's switch statement
    def _start_writer_thread(self):
        """Start the single database writer thread - eliminates all lock contention"""
        def writer_loop():
            print("[SQLite] Single database writer thread started")
            
            # Create a single long-lived connection for all writes. Retry the
            # initial connect + pragmas briefly: right after a fresh database
            # is created a concurrent connection can still hold the file, and
            # the writer thread must never die silently at startup.
            import time as _time
            write_conn = None
            for _attempt in range(20):
                try:
                    write_conn = sqlite3.connect(self.db_path, timeout=self.sqlite_timeout)
                    write_conn.execute(f"PRAGMA journal_mode={self.journal_mode}")
                    write_conn.execute("PRAGMA busy_timeout=30000")
                    write_conn.execute("PRAGMA cache_size=-64000")
                    write_conn.execute("PRAGMA foreign_keys=ON")
                    break
                except sqlite3.OperationalError as _exc:
                    if write_conn is not None:
                        try:
                            write_conn.close()
                        except Exception:
                            pass
                        write_conn = None
                    if "locked" in str(_exc).lower() and _attempt < 19:
                        _time.sleep(0.5)
                        continue
                    print(f"[SQLite] Writer thread could not open database: {_exc}")
                    raise

            with write_conn:
                while self.running:
                    try:
                        # Wait up to 0.1s for an item, then loop back
                        item = self.write_queue.get(timeout=0.1)
                        
                        if item is None:  # Shutdown signal
                            write_conn.commit()
                            break
                            
                        # Process the queued write operation
                        op_type, data = item
                        
                        if op_type == "save_event":
                            self._process_save_event(write_conn, data)
                        elif op_type == "save_state":
                            self._process_save_state(write_conn, data)
                        elif op_type == "save_investigation":
                            self._process_save_investigation(write_conn, data)
                        elif op_type == "update_alert_status":
                            self._process_update_alert_status(write_conn, data)
                        elif op_type == "save_case":
                            self._process_save_case(write_conn, data)
                        elif op_type == "backfill_events":
                            self._process_backfill_events(write_conn)
                        elif op_type == "clean_process_names":
                            self._process_clean_process_names(write_conn)
                        elif op_type == "save_conversation":
                            self._process_save_conversation(write_conn, data)
                        elif op_type == "save_message":
                            self._process_save_message(write_conn, data)
                        elif op_type == "update_conversation_timestamp":
                            self._process_update_conversation_timestamp(write_conn, data)
                        elif op_type == "rename_conversation":
                            self._process_rename_conversation(write_conn, data)
                        elif op_type == "clear_conversation_messages":
                            self._process_clear_conversation_messages(write_conn, data)
                        elif op_type == "delete_conversation":
                            self._process_delete_conversation(write_conn, data)
                        elif op_type == "delete_all_conversations":
                            self._process_delete_all_conversations(write_conn, data)
                        elif op_type == "update_message_status":
                            self._process_update_message_status(write_conn, data)
                        elif op_type == "update_conversation_last_message":
                            self._process_update_conversation_last_message(write_conn, data)
                        elif op_type == "save_notification":
                            self._process_save_notification(write_conn, data)
                        elif op_type == "mark_notification_read":
                            self._process_mark_notification_read(write_conn, data)
                        elif op_type == "mark_all_notifications_read":
                            self._process_mark_all_notifications_read(write_conn, data)
                        elif op_type == "mark_derived_read":
                            self._process_mark_derived_read(write_conn, data)
                        elif op_type == "mark_all_derived_read":
                            self._process_mark_all_derived_read(write_conn, data)
                        elif op_type == "acknowledge_notification":
                            self._process_acknowledge_notification(write_conn, data)
                        elif op_type == "resolve_notification":
                            self._process_resolve_notification(write_conn, data)
                        elif op_type == "sync":
                            # Flush barrier: commit everything queued before it.
                            write_conn.commit()
                            # Signal the caller that all prior writes are persisted.
                            barrier = data.get("barrier") if isinstance(data, dict) else None
                            if barrier is not None:
                                barrier.set()
                        elif op_type == "clear":
                            cursor = write_conn.cursor()
                            cursor.execute("DELETE FROM events")
                            cursor.execute("DELETE FROM collector_state")
                            cursor.execute("DELETE FROM chat_conversations")
                            cursor.execute("DELETE FROM chat_messages")
                            write_conn.commit()
                            print("[SQLite] Database cleared")
                            
                        # Mark task as done
                        self.write_queue.task_done()
                        
                    except queue.Empty:
                        # Periodically commit to persist writes
                        write_conn.commit()
                        continue
                    except Exception as e:
                        # A failed operation must never kill the writer thread or
                        # silently drop the item: log which op failed, mark the
                        # queue item done, and (for sync barriers) release the
                        # caller so flush() can never hang waiting on an error.
                        print(f"[SQLite] Writer thread error ({op_type}): {e}")
                        if op_type == "sync" and isinstance(data, dict):
                            barrier = data.get("barrier")
                            if barrier is not None:
                                barrier.set()
                        try:
                            self.write_queue.task_done()
                        except Exception:
                            pass
                        continue
                        
            print("[SQLite] Database writer thread stopped")
        
        self.writer_thread = threading.Thread(target=writer_loop, daemon=True)
        self.writer_thread.start()


sqlite_storage = SQLiteStorage()