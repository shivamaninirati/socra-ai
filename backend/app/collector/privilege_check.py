"""
SOCRA AI — Windows Security Event Log privilege detection.

The Security channel can only be opened by an elevated process. The existing
WindowsEventReader deliberately swallows the open failure (error 1314 /
ERROR_PRIVILEGE_NOT_HELD) and returns [] so collection continues for the
channels it *can* read. That silent behavior makes the collector look healthy
while the most security-relevant events are never read.

This module probes the channel up-front so the collector can clearly report:

    "Administrator privileges required for Security Event Log collection."

instead of pretending Security collection is working. It is a small, additive
helper — the existing collector code is preserved untouched.
"""

import win32evtlog

PRIVILEGE_ERROR_MESSAGE = "Administrator privileges required for Security Event Log collection."

# ERROR_PRIVILEGE_NOT_HELD (Windows SDK winerror.h)
ERROR_PRIVILEGE_NOT_HELD = 1314


def security_log_access():
    """Probe access to the Windows Security Event Log channel.

    Returns:
        (ok, detail): ``ok`` is True when the Security channel can be opened.
        Otherwise ``ok`` is False and ``detail`` is the exact
        PRIVILEGE_ERROR_MESSAGE when the failure is a privilege error, or the
        raw error text for any other failure.
    """
    handle = None
    try:
        handle = win32evtlog.OpenEventLog(None, "Security")
        return True, None
    except win32evtlog.error as exc:
        winerror = getattr(exc, "winerror", None)
        if winerror is None and exc.args:
            winerror = exc.args[0] if isinstance(exc.args[0], int) else None
        if winerror == ERROR_PRIVILEGE_NOT_HELD:
            return False, PRIVILEGE_ERROR_MESSAGE
        return False, f"Security Event Log access failed: {exc}"
    finally:
        if handle is not None:
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception:
                pass
