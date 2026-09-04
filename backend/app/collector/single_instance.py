"""
SOCRA AI — single-instance guard for the persistent Windows collector.

Prevents multiple collector processes from running at the same time. Two
layers are used because the collector may run either in the interactive user
session (manual run / scheduled logon task) or in session 0 (Windows service):

1. Named mutex (fast, primary guard within a session).
2. PID file with an OS-level "is the process alive?" check (guards across
   sessions, where a session-local mutex is invisible).

The FastAPI process uses :func:`external_collector_running` to detect a
standalone collector and skip its own in-process collection — this is how
duplicate collectors are prevented when the backend starts while a standalone
collector is already alive.

Runtime status (privilege errors, counters) is written by the standalone
runner to ``backend/data/collector_status.json`` and read back here so the API
can surface real collector telemetry (e.g. on ``/live/status``).
"""

import ctypes
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

# Session-local named mutex. A "Global\\" prefix would be visible across
# sessions but requires SeCreateGlobalPrivilege (admin/services only) — the
# PID-file check below covers the cross-session case instead.
MUTEX_NAME = "SOCRA_AI_Collector_Mutex"

BACKEND_ROOT = Path(__file__).resolve().parents[2]
PID_FILE = BACKEND_ROOT / "data" / "collector.pid"
STATUS_FILE = BACKEND_ROOT / "data" / "collector_status.json"

ERROR_ALREADY_EXISTS = 183  # ERROR_ALREADY_EXISTS (winerror.h)


class SingleInstanceError(RuntimeError):
    """Raised when another collector instance is already running."""


def _pid_alive(pid):
    """Return True when ``pid`` refers to a live OS process.

    Uses PROCESS_QUERY_LIMITED_INFORMATION, which works for processes of other
    users without requiring elevation (unlike os.kill(pid, 0) on Windows).
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    kernel32 = ctypes.windll.kernel32
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if handle:
        kernel32.CloseHandle(handle)
        return True
    return False


def _try_open_mutex(name):
    """Return a handle to the named mutex if it exists, else None."""
    try:
        import win32event

        return win32event.OpenMutex(win32event.MUTEX_ALL_ACCESS, False, name)
    except Exception:
        return None


def external_collector_running():
    """Return True when a standalone collector process is currently alive."""
    if _try_open_mutex(MUTEX_NAME) is not None:
        return True
    try:
        if PID_FILE.exists():
            data = json.loads(PID_FILE.read_text(encoding="utf-8"))
            if _pid_alive(data.get("pid")):
                return True
    except Exception:
        pass
    return False


def acquire_single_instance():
    """Claim the single-instance guard for this process.

    Returns the mutex handle (owned by the caller, released with
    :func:`release_single_instance`). Raises :class:`SingleInstanceError` when
    another collector is already running — checked via the PID file first
    (cross-session) and the named mutex second (same-session race).
    """
    # Cross-session guard: a live PID in the file means a collector is running
    # somewhere (e.g. a service in session 0 whose mutex we cannot see).
    if PID_FILE.exists():
        try:
            data = json.loads(PID_FILE.read_text(encoding="utf-8"))
            if _pid_alive(data.get("pid")):
                raise SingleInstanceError(
                    "Another SOCRA AI collector is already running "
                    f"(pid {data.get('pid')})."
                )
        except SingleInstanceError:
            raise
        except Exception:
            pass

    # Same-session guard: create (or attach to) the named mutex.
    try:
        import win32api
        import win32event

        mutex = win32event.CreateMutex(None, False, MUTEX_NAME)
        if win32api.GetLastError() == ERROR_ALREADY_EXISTS:
            try:
                win32event.CloseHandle(mutex)
            except Exception:
                pass
            raise SingleInstanceError(
                "Another SOCRA AI collector is already running (mutex "
                f"'{MUTEX_NAME}' is held)."
            )
    except SingleInstanceError:
        raise
    except Exception as exc:  # pragma: no cover - mutex unavailable edge case
        mutex = None
        print(f"[Collector] Could not create single-instance mutex: {exc}")

    try:
        PID_FILE.parent.mkdir(parents=True, exist_ok=True)
        PID_FILE.write_text(
            json.dumps(
                {
                    "pid": os.getpid(),
                    "mutex": MUTEX_NAME,
                    "started_at": datetime.now(timezone.utc).isoformat(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    except Exception as exc:  # pragma: no cover - disk edge case
        print(f"[Collector] Could not write PID file {PID_FILE}: {exc}")

    return mutex


def release_single_instance(mutex):
    """Release the mutex handle and remove the PID file."""
    if mutex is not None:
        try:
            import win32event

            win32event.CloseHandle(mutex)
        except Exception:
            pass
    try:
        if PID_FILE.exists():
            PID_FILE.unlink()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Runtime status file (written by the standalone runner, read by the API)
# ---------------------------------------------------------------------------


def read_collector_status():
    """Return the latest collector runtime status dict, or None when the
    standalone collector has never reported one (or is not running).

    A stale status file left behind by a hard-killed collector is detected via
    the recorded PID and is reported as not running instead of presented as
    live telemetry.
    """
    try:
        if STATUS_FILE.exists():
            data = json.loads(STATUS_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                alive = _pid_alive(data.get("pid"))
                data["external_running"] = alive and external_collector_running()
                if not alive:
                    data["running"] = False
                    data["message"] = (
                        "Collector is not running (stale status from pid %s)."
                        % data.get("pid")
                    )
                return data
    except Exception:
        pass
    return None


def write_collector_status(payload):
    """Atomically persist a collector runtime status snapshot."""
    try:
        payload = dict(payload or {})
        payload["updated_at"] = datetime.now(timezone.utc).isoformat()
        payload["pid"] = os.getpid()
        STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATUS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        tmp.replace(STATUS_FILE)
    except Exception as exc:
        print(f"[Collector] Could not write status file {STATUS_FILE}: {exc}")


def clear_collector_status():
    try:
        if STATUS_FILE.exists():
            STATUS_FILE.unlink()
    except Exception:
        pass
