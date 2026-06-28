"""Centralized configuration for IOCForge.

All runtime configuration is loaded from environment variables (optionally
sourced from a ``.env`` file). API keys are *never* hardcoded; they are read
from the environment and exposed through the immutable :class:`Settings`
dataclass.

Usage
-----
>>> from iocforge.config import get_settings
>>> settings = get_settings()
>>> settings.virustotal_api_key
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional

try:  # pragma: no cover - optional dependency
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover
    # python-dotenv is optional; environment variables still work without it.
    pass


# Project root resolves to the directory that contains ``src/`` and ``logs/``.
PROJECT_ROOT: Path = Path(__file__).resolve().parents[3]
LOG_DIR: Path = PROJECT_ROOT / "logs"
DEFAULT_OUTPUT_DIR: Path = PROJECT_ROOT / "reports"


def _get_bool(name: str, default: bool = False) -> bool:
    """Parse a boolean from an environment variable."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _get_float(name: str, default: float) -> float:
    """Parse a float from an environment variable, falling back on default."""
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    """Immutable application settings.

    Attributes
    ----------
    virustotal_api_key:
        API key for VirusTotal v3.
    otx_api_key:
        API key for AlienVault OTX.
    abuseipdb_api_key:
        API key for AbuseIPDB.
    enable_enrichment:
        Master switch — when ``False`` all network enrichment is skipped.
    request_timeout:
        Per-request HTTP timeout (seconds).
    rate_limit_delay:
        Delay (seconds) inserted between enrichment requests to respect
        free-tier rate limits.
    log_level:
        Logging verbosity (DEBUG/INFO/WARNING/ERROR).
    """

    virustotal_api_key: Optional[str] = None
    otx_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None

    # ThreatFox / URLHaus / MalwareBazaar (abuse.ch) share an Auth-Key.
    abusech_api_key: Optional[str] = None

    enable_enrichment: bool = True
    request_timeout: float = 20.0
    rate_limit_delay: float = 1.0
    max_enrichment_workers: int = 4

    log_level: str = "INFO"
    log_dir: Path = field(default_factory=lambda: LOG_DIR)
    output_dir: Path = field(default_factory=lambda: DEFAULT_OUTPUT_DIR)

    # --- Capability helpers -------------------------------------------------
    @property
    def loaded_apis(self) -> list[str]:
        """Return the human-readable names of configured providers."""
        apis: list[str] = []
        if self.virustotal_api_key:
            apis.append("VirusTotal")
        if self.otx_api_key:
            apis.append("AlienVault OTX")
        if self.abuseipdb_api_key:
            apis.append("AbuseIPDB")
        # abuse.ch endpoints work without keys for many queries.
        apis.append("ThreatFox/URLHaus (abuse.ch)")
        return apis

    @property
    def has_any_api(self) -> bool:
        """Whether at least one keyed provider is configured."""
        return any(
            [self.virustotal_api_key, self.otx_api_key, self.abuseipdb_api_key]
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Build (and cache) a :class:`Settings` instance from the environment."""
    return Settings(
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY") or None,
        otx_api_key=os.getenv("OTX_API_KEY") or None,
        abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY") or None,
        abusech_api_key=os.getenv("ABUSECH_API_KEY") or None,
        enable_enrichment=_get_bool("ENABLE_ENRICHMENT", default=True),
        request_timeout=_get_float("REQUEST_TIMEOUT", 20.0),
        rate_limit_delay=_get_float("RATE_LIMIT_DELAY", 1.0),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
    )
