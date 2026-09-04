"""
SOCRA AI — start the standalone persistent Windows collector (foreground).

Usage:
    python run_collector.py

This is the same collector the scheduled task / Windows service start; run it
manually to test, or install it as a background mechanism with:

    python install_collector.py task       # scheduled task (safest)
    python install_collector.py service    # Windows service (admin)
"""

import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.collector.standalone import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
