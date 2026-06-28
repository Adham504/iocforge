"""Lightweight ANSI color helpers for terminal output.

Colors are applied only when writing to an interactive terminal and when the
user has not opted out via the ``NO_COLOR`` convention
(https://no-color.org/). This keeps piped/redirected output and report files
free of escape codes.
"""
from __future__ import annotations

import os
import sys
from typing import Optional

from iocforge.core.models import RiskLevel

# --- Raw ANSI codes ---------------------------------------------------------
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

_FG = {
    "black": "\033[30m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "white": "\033[37m",
    "bright_red": "\033[91m",
    "bright_green": "\033[92m",
    "bright_yellow": "\033[93m",
    "bright_magenta": "\033[95m",
    "bright_cyan": "\033[96m",
    "grey": "\033[90m",
}

# Map each risk level to a terminal color (mirrors the HTML report palette).
_RISK_COLOR = {
    RiskLevel.UNKNOWN: "grey",
    RiskLevel.CLEAN: "green",
    RiskLevel.LOW: "yellow",
    RiskLevel.MEDIUM: "bright_yellow",
    RiskLevel.HIGH: "bright_red",
    RiskLevel.CRITICAL: "bright_magenta",
}


def supports_color(stream: object = None) -> bool:
    """Return ``True`` if ANSI color should be emitted to ``stream``."""
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR") is not None:
        return True
    stream = stream or sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)())


def colorize(
    text: str,
    color: Optional[str] = None,
    *,
    bold: bool = False,
    enabled: bool = True,
) -> str:
    """Wrap ``text`` in ANSI codes for ``color`` (and optional bold)."""
    if not enabled or (not color and not bold):
        return text
    prefix = ""
    if bold:
        prefix += BOLD
    if color and color in _FG:
        prefix += _FG[color]
    if not prefix:
        return text
    return f"{prefix}{text}{RESET}"


def risk_color(level: RiskLevel) -> str:
    """Return the color name associated with a :class:`RiskLevel`."""
    return _RISK_COLOR.get(level, "grey")
