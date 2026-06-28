"""Cybersecurity-themed ASCII banner rendering."""
from __future__ import annotations

from typing import Iterable

BANNER_ART = r"""
██╗ ██████╗  ██████╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██║██╔═══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
██║██║   ██║██║     █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
██║██║   ██║██║     ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
██║╚██████╔╝╚██████╗██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
╚═╝ ╚═════╝  ╚═════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
"""

TAGLINE = "Extract • Analyze • Enrich • Understand"


def render_banner(
    version: str,
    author: str,
    loaded_apis: Iterable[str],
    supported_ioc_count: int,
    enrichment_enabled: bool,
) -> str:
    """Build the startup banner as a single printable string.

    Parameters
    ----------
    version:
        Application version string.
    author:
        Author / maintainer placeholder.
    loaded_apis:
        Names of configured Threat Intelligence providers.
    supported_ioc_count:
        Number of IOC types the tool can extract.
    enrichment_enabled:
        Whether network enrichment is active.
    """
    apis = list(loaded_apis)
    apis_str = ", ".join(apis) if apis else "None (offline mode)"
    status = "ONLINE" if enrichment_enabled and apis else "OFFLINE"

    lines = [
        BANNER_ART.rstrip("\n"),
        f"                  {TAGLINE}",
        "",
        f"  Version           : {version}",
        f"  Author            : {author}",
        f"  Loaded APIs       : {apis_str}",
        f"  Enrichment Status : {status}",
        f"  Supported IOCs    : {supported_ioc_count} types",
        "",
    ]
    return "\n".join(lines)
