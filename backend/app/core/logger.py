"""
SOCRA AI — Enterprise Logging Configuration

Provides structured logging with rotation, configurable levels,
and separate console/file outputs. All modules should use:

    from app.core.logger import logger
    logger.info("Message here")
"""

import logging
import sys
import os
from logging.handlers import RotatingFileHandler


def setup_logger(
    name: str = "SOCRA",
    log_level: str = "INFO",
    log_file: str = "socra.log",
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
) -> logging.Logger:
    """
    Configure and return the application logger.

    Args:
        name: Logger name
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file
        max_bytes: Max size per log file before rotation
        backup_count: Number of rotated log files to keep
    """
    _logger = logging.getLogger(name)

    # Prevent duplicate handlers on re-initialization
    if _logger.handlers:
        return _logger

    level = getattr(logging, log_level.upper(), logging.INFO)
    _logger.setLevel(level)

    # ── Log Format ───────────────────────────────────────────
    log_format = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s.%(module)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # ── Console Handler ──────────────────────────────────────
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(log_format)
    _logger.addHandler(console_handler)

    # ── File Handler with Rotation ───────────────────────────
    try:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(log_format)
        _logger.addHandler(file_handler)
    except (OSError, PermissionError) as e:
        _logger.warning(f"Could not create log file '{log_file}': {e}")

    # Prevent logs from propagating to root logger
    _logger.propagate = False

    return _logger


def get_module_logger(module_name: str) -> logging.Logger:
    """
    Get a child logger for a specific module.

    Usage:
        from app.core.logger import get_module_logger
        logger = get_module_logger("collector")
    """
    return logging.getLogger(f"SOCRA.{module_name}")


# ── Initialize default logger ────────────────────────────────
# Use lazy import to avoid circular dependency with config
try:
    from app.core.config import settings
    logger = setup_logger(
        log_level=settings.LOG_LEVEL,
        log_file=settings.LOG_FILE,
        max_bytes=settings.LOG_MAX_BYTES,
        backup_count=settings.LOG_BACKUP_COUNT,
    )
except Exception:
    # Fallback if config is not available yet
    logger = setup_logger()