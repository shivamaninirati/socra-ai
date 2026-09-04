"""
SOCRA AI — install the persistent Windows collector as a background mechanism.

Two Windows-native options are provided:

  task     Windows Task Scheduler logon task (SAFEST — no admin required,
           runs when the current user logs on, ignores new instances if one
           is already running).
  service  Windows service via pywin32 (requires an elevated shell, runs
           regardless of logon, auto-restarts on failure).

Both start the exact same standalone runner (backend/run_collector.py), which
reuses the existing CollectorService — no duplicate collector code.

Usage:
  python install_collector.py task                # install scheduled task
  python install_collector.py task --remove       # remove scheduled task
  python install_collector.py service             # install service (admin)
  python install_collector.py service --remove    # remove service (admin)
  python install_collector.py status              # what is installed/running
  python install_collector.py task --dry-run      # preview without touching OS
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.collector.single_instance import (  # noqa: E402
    external_collector_running,
    read_collector_status,
)

TASK_NAME = "SOCRA_AI_Collector"
SERVICE_NAME = "SocraAICollector"


def _python_exe():
    return sys.executable


def _runner_script():
    return BACKEND_ROOT / "run_collector.py"


def _service_script():
    return BACKEND_ROOT / "app" / "collector" / "windows_service.py"


# ---------------------------------------------------------------------------
# Scheduled task (safest)
# ---------------------------------------------------------------------------

def build_task_xml():
    """Task Scheduler XML: logon-triggered task running the standalone runner
    with a single-instance policy (IgnoreNew) so task-level re-triggers never
    spawn a second collector."""
    user = "\\".join(
        part for part in (os.environ.get("USERDOMAIN"), os.environ.get("USERNAME")) if part
    ) or "INTERACTIVE"
    python = _python_exe()
    runner = _runner_script()
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>SOCRA AI persistent Windows Event Log collector (backend/run_collector.py)</Description>
    <Author>{user}</Author>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <Enabled>true</Enabled>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"{python}"</Command>
      <Arguments>"{runner}"</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def install_task(dry_run=False):
    xml_path = BACKEND_ROOT / "data" / "collector_task.xml"
    xml_path.parent.mkdir(parents=True, exist_ok=True)
    xml_path.write_text(build_task_xml(), encoding="utf-16")

    cmd = ["schtasks", "/create", "/tn", TASK_NAME, "/xml", str(xml_path), "/f"]
    if dry_run:
        print("[install] Dry run - would execute:")
        print("  " + " ".join(cmd))
        print("[install] Task XML written to", xml_path)
        return 0

    print("[install] Registering scheduled task", TASK_NAME, "...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    sys.stdout.write(result.stdout or "")
    sys.stderr.write(result.stderr or "")
    if result.returncode != 0:
        print("[install] Task registration failed.")
        return 1
    print("[install] Scheduled task installed. It will run", _runner_script())
    print("[install] (It starts at next logon - or start it now with "
          f"'schtasks /run /tn {TASK_NAME}'.)")
    return 0


def remove_task(dry_run=False):
    cmd = ["schtasks", "/delete", "/tn", TASK_NAME, "/f"]
    if dry_run:
        print("[install] Dry run - would execute: " + " ".join(cmd))
        return 0
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("[install] Task removal failed or task not present.")
        return 1
    print("[install] Scheduled task removed.")
    return 0


# ---------------------------------------------------------------------------
# Windows service (admin)
# ---------------------------------------------------------------------------

def install_service(dry_run=False):
    if dry_run:
        print("[install] Dry run - would execute:")
        print(f"  {sys.executable} {_service_script()} install")
        print(f"  sc failure {SERVICE_NAME} reset= 0 actions= restart/5000")
        return 0
    cmd = [sys.executable, str(_service_script()), "install"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    sys.stdout.write(result.stdout or "")
    sys.stderr.write(result.stderr or "")
    if result.returncode != 0:
        print("[install] Service installation failed (run from an elevated shell).")
        return 1
    # Auto-restart the service on unexpected failure.
    subprocess.run(
        ["sc", "failure", SERVICE_NAME, "reset=", "0", "actions=", "restart/5000"],
        capture_output=True,
        text=True,
    )
    print("[install] Windows service installed:", SERVICE_NAME)
    print("[install] Start it with: python app/collector/windows_service.py start")
    return 0


def remove_service(dry_run=False):
    if dry_run:
        print("[install] Dry run - would execute: "
              f"{sys.executable} {_service_script()} remove")
        return 0
    cmd = [sys.executable, str(_service_script()), "remove"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    sys.stdout.write(result.stdout or "")
    sys.stderr.write(result.stderr or "")
    if result.returncode != 0:
        print("[install] Service removal failed (run from an elevated shell).")
        return 1
    print("[install] Windows service removed.")
    return 0


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def status():
    print("SOCRA AI collector status")
    print("=" * 40)

    if external_collector_running():
        print("Collector process:  RUNNING (standalone)")
    else:
        print("Collector process:  not running")

    info = read_collector_status()
    if info:
        for key in (
            "pid", "running", "uptime", "total_collected", "total_processed",
            "total_failed", "live_events", "history_events",
            "security_log_accessible", "privilege_error", "message",
            "last_error", "updated_at",
        ):
            value = info.get(key)
            if value not in (None, "", False):
                print(f"  {key}: {value}")

    task = subprocess.run(
        ["schtasks", "/query", "/tn", TASK_NAME],
        capture_output=True,
        text=True,
    )
    print(f"Scheduled task '{TASK_NAME}':",
          "installed" if task.returncode == 0 else "not installed")

    service = subprocess.run(
        ["sc", "query", SERVICE_NAME],
        capture_output=True,
        text=True,
    )
    state = ""
    if service.returncode == 0:
        for line in service.stdout.splitlines():
            if "STATE" in line:
                state = line.split(":", 1)[-1].strip()
    print(f"Windows service '{SERVICE_NAME}':",
          state if state else "not installed")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Install the SOCRA AI persistent collector as a scheduled "
        "task or Windows service."
    )
    parser.add_argument(
        "command",
        choices=["task", "service", "status"],
        help="What to install / report on.",
    )
    parser.add_argument(
        "--remove",
        action="store_true",
        help="Remove the mechanism instead of installing it.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be executed without touching the OS.",
    )
    args = parser.parse_args(argv)

    if args.command == "status":
        return status()
    if args.command == "task":
        return remove_task(args.dry_run) if args.remove else install_task(args.dry_run)
    return remove_service(args.dry_run) if args.remove else install_service(args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
