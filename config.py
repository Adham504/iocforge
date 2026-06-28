"""Top-level convenience shim re-exporting the configuration API.

The canonical implementation lives in ``iocforge.config.settings``. This module
exists so users can simply ``from config import get_settings`` when running from
the project root, as referenced in the project specification.
"""
from iocforge.config.settings import (  # noqa: F401
    DEFAULT_OUTPUT_DIR,
    LOG_DIR,
    PROJECT_ROOT,
    Settings,
    get_settings,
)

__all__ = [
    "Settings",
    "get_settings",
    "PROJECT_ROOT",
    "LOG_DIR",
    "DEFAULT_OUTPUT_DIR",
]
