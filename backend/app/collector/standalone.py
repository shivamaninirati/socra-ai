"""
SOCRA AI — standalone persistent Windows collector runner.

Runs the EXISTING :class:`CollectorService` (untouched) as its own process so
telemetry collection continues independently of the frontend and of the
FastAPI process. The API process detects this standalone collector and skips
its own in-process collection, forwarding newly persisted events over the
WebSocket instead (see app/services/live_forwarder.py).

Features:
  * single-instance guard (named mutex + PID file) — no duplicate collectors
  * Windows Security Event Log privilege detection with the exact required
    message ("Administrator privileges required for Security Event Log
    collection.") instead of silently pretending collection is working
  * file logging (existing collector print() output is captured too)
  * live runtime status file (backend/data/collector_status.json) consumed by
    the API's /live/status endpoint
  * graceful shutdown on Ctrl+C / SIGTERM / service stop

Entry points:
  python run_collector.py                     (foreground manual run)
  python -m app.collector.standalone          (same)
  Windows service: see app/collector/windows_service.py
"""

import asyncio
import os
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[2]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.collector.collector_service import CollectorService  # noqa: E402
from app.collector.privilege_check import (  # noqa: E402
    PRIVILEGE_ERROR_MESSAGE,
    security_log_access,
)
from app.collector.single_instance import (  # noqa: E402
    SingleInstanceError,
    acquire_single_instance,
    clear_collector_status,
    release_single_instance,
    write_collector_status,
)

LOG_FILE = BACKEND_ROOT / "data" / "collector.log"
STATUS_INTERVAL_SECONDS = 2.0


class _Tee:
    """Write to a log file and, when a console exists, echo there too."""

    def __init__(self, file, console):
        self.file = file
        self.console = console

    def write(self, s):
        try:
            self.file.write(s)
        except Exception:
            pass
        if self.console:
            try:
                self.console.write(s)
                self.console.flush()
            except Exception:
                pass

    def flush(self):
        try:
            self.file.flush()
        except Exception:
            pass
        if self.console:
            try:
                self.console.flush()
            except Exception:
                pass


class _ThrottledTee(_Tee):
    """Tee that collapses repeated identical lines.

    The Windows reader re-prints the Security-channel privilege error once per
    poll cycle (pre-existing behavior that must stay untouched), so a
    long-running non-elevated collector would otherwise balloon its log file
    with the same line every second. Identical lines are only written once per
    throttle window while still echoing to the console.
    """

    THROTTLE_SECONDS = 10.0

    def __init__(self, file, console):
        super().__init__(file, console)
        self._last_line = None
        self._last_written = 0.0

    def write(self, s):
        line = s.rstrip("\r\n")
        now = time.monotonic()
        if (
            line
            and line == self._last_line
            and (now - self._last_written) < self.THROTTLE_SECONDS
        ):
            return
        if line:
            self._last_line = line
            self._last_written = now
        super().write(s)


def _setup_logging():
    """Redirect stdout/stderr so the existing collector's print() output is
    captured to backend/data/collector.log while still appearing on the
    console for manual runs."""
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    log_stream = open(LOG_FILE, "a", encoding="utf-8", buffering=1)
    sys.stdout = _ThrottledTee(log_stream, sys.__stdout__)
    sys.stderr = sys.stdout


def _report_privilege_status(ok, detail):
    """Clearly report Security Event Log access instead of silently pretending
    collection is working."""
    if ok:
        print("[Collector] Security Event Log channel accessible (elevated).")
        return None
    print("=" * 72)
    print(f"[Collector] !! {detail}")
    print(
        "[Collector] System/Application channels will still be collected; "
        "Security channel events are skipped until this process runs elevated "
        "(e.g. Task Scheduler 'Run with highest privileges' or an "
        "administrator shell)."
    )
    print("=" * 72)
    return detail


async def _status_writer(collector, privilege_error):
    """Periodically persist a runtime status snapshot for the API to read."""
    while True:
        try:
            stats = collector.stats()
            write_collector_status(
                {
                    "running": collector.running,
                    "started_at": collector.started_at,
                    "uptime": stats.get("uptime"),
                    "total_collected": stats.get("total_collected"),
                    "total_processed": stats.get("total_processed"),
                    "total_failed": stats.get("total_failed"),
                    "live_events": stats.get("live_events"),
                    "history_events": stats.get("history_events"),
                    "last_collection_time": stats.get("last_collection_time"),
                    "last_error": stats.get("last_error"),
                    "channels": stats.get("channels"),
                    "security_log_accessible": privilege_error is None,
                    "privilege_error": privilege_error,
                    "message": (
                        PRIVILEGE_ERROR_MESSAGE if privilege_error else None
                    ),
                }
            )
        except Exception as exc:
            print(f"[Collector] Status writer error: {exc}")
        await asyncio.sleep(STATUS_INTERVAL_SECONDS)


async def _amain(collector, privilege_error):
    status_task = asyncio.create_task(_status_writer(collector, privilege_error))
    try:
        # CollectorService.start() returns when stop() sets running=False.
        await collector.start()
    finally:
        status_task.cancel()
        try:
            await status_task
        except asyncio.CancelledError:
            pass


def run_standalone(stop_event=None):
    """Run the persistent collector until stopped.

    Args:
        stop_event: optional threading.Event; when set, the collector shuts
            down gracefully (used by the Windows service wrapper).

    Returns:
        int exit code (0 = clean stop, 1 = another instance already running).
    """
    os.chdir(BACKEND_ROOT)  # sqlite uses a relative "data/" path
    _setup_logging()

    try:
        mutex = acquire_single_instance()
    except SingleInstanceError as exc:
        print(f"[Collector] {exc}")
        print("[Collector] Refusing to start a duplicate collector.")
        return 1

    try:
        print("=" * 72)
        print(f"[Collector] Standalone collector starting (pid {os.getpid()})")
        print("=" * 72)

        # Explicit Security Event Log privilege check (never silent).
        ok, detail = security_log_access()
        privilege_error = _report_privilege_status(ok, detail)

        collector = CollectorService()
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        if stop_event is not None:
            # Service path: watch the stop event from a helper thread.
            def _watcher():
                while not stop_event.wait(1.0):
                    pass
                print("[Collector] Stop requested - shutting down.")
                collector.stop()

            threading.Thread(target=_watcher, daemon=True).start()
        else:
            # Foreground path: handle Ctrl+C / SIGTERM.
            def _handle_signal(signum, frame):  # noqa: ARG001
                print(f"[Collector] Signal {signum} received - shutting down.")
                collector.stop()

            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    signal.signal(sig, _handle_signal)
                except (ValueError, OSError):
                    pass

        try:
            loop.run_until_complete(_amain(collector, privilege_error))
        except KeyboardInterrupt:
            collector.stop()
            print("[Collector] Interrupted - shutting down.")
        finally:
            try:
                loop.close()
            except Exception:
                pass

        print("[Collector] Standalone collector stopped cleanly.")
        return 0
    finally:
        clear_collector_status()
        release_single_instance(mutex)


def main(argv=None):
    """CLI entry point for `python run_collector.py`."""
    argv = argv if argv is not None else sys.argv[1:]
    if any(arg in ("-h", "--help") for arg in argv):
        print(
            "SOCRA AI standalone Windows collector.\n\n"
            "Usage: python run_collector.py\n\n"
            "Runs the persistent collector in the foreground. Install it as a\n"
            "background mechanism with: python install_collector.py task|service"
        )
        return 0
    return run_standalone()


if __name__ == "__main__":
    sys.exit(main())
