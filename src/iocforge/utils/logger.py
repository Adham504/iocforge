"""Logging configuration for IOCForge.

A single rotating file handler writes to ``logs/application.log`` while a
console handler echoes a friendlier view to stderr. All modules obtain their
logger via :func:`get_logger` so configuration stays centralized.
"""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

_CONFIGURED = False

_LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def configure_logging(
    level: str = "INFO",
    log_dir: Optional[Path] = None,
    log_file: str = "application.log",
) -> None:
    """Configure the root ``iocforge`` logger exactly once.

    Parameters
    ----------
    level:
        Logging level name (e.g. ``"DEBUG"``).
    log_dir:
        Directory where the log file is written. Created if missing.
    log_file:
        Base file name for the rotating log handler.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return

    root = logging.getLogger("iocforge")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT)

    # Console handler (concise).
    console = logging.StreamHandler()
    console.setLevel(getattr(logging, level.upper(), logging.INFO))
    console.setFormatter(formatter)
    root.addHandler(console)

    # File handler (rotating, verbose).
    if log_dir is None:
        log_dir = Path("logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(
        log_dir / log_file,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    root.propagate = False
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced child logger of the ``iocforge`` root logger."""
    if not name.startswith("iocforge"):
        name = f"iocforge.{name}"
    return logging.getLogger(name)
