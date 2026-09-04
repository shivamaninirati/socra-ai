"""
SOCRA AI — Windows Service wrapper for the persistent collector.

Wraps :func:`app.collector.standalone.run_standalone` so the collector can be
installed as a real Windows service (survives logoff, starts with the system
when configured with an elevated account, auto-restarts on failure via the
installer).

Requires an elevated shell to install:

    python app/collector/windows_service.py install
    python app/collector/windows_service.py start
    python app/collector/windows_service.py stop
    python app/collector/windows_service.py remove

The service runs the exact same CollectorService as the foreground runner —
no duplicate code paths, no second collector implementation.
"""

import os
import sys
import threading
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[2]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil
except ImportError as exc:  # pragma: no cover - non-Windows / missing pywin32
    servicemanager = None
    win32event = None
    win32service = None
    win32serviceutil = None
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None

from app.collector.standalone import run_standalone  # noqa: E402


class SocraAICollectorService(win32serviceutil.ServiceFramework):
    """Windows service that hosts the SOCRA AI persistent collector."""

    _svc_name_ = "SocraAICollector"
    _svc_display_name_ = "SOCRA AI Windows Collector"
    _svc_description_ = (
        "Persistent Windows Event Log collector for SOCRA AI. Runs "
        "independently of the SOCRA AI backend so telemetry collection "
        "continues across backend restarts."
    )

    def __init__(self, args):
        super().__init__(args)
        self._stop_event = threading.Event()
        self._thread = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self._stop_event.set()

    def SvcDoRun(self):
        if servicemanager is not None:
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._thread.join()
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)

    def _run(self):
        try:
            run_standalone(stop_event=self._stop_event)
        except Exception as exc:
            if servicemanager is not None:
                servicemanager.LogErrorMsg(
                    f"SOCRA AI collector service failed: {exc}"
                )
            raise
        finally:
            self._stop_event.set()


def _main(argv=None):
    if _IMPORT_ERROR is not None:
        print(
            "win32 modules are unavailable - cannot manage the Windows "
            f"service. ({_IMPORT_ERROR})"
        )
        return 1
    # Ensure a stable working directory for the service process.
    os.chdir(BACKEND_ROOT)
    win32serviceutil.HandleCommandLine(SocraAICollectorService, argv=argv)
    return 0


if __name__ == "__main__":
    sys.exit(_main())
