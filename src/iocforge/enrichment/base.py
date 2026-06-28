"""Base class for Threat Intelligence enrichers."""
from __future__ import annotations

import abc
from typing import Optional, Set

import requests

from iocforge.core.models import EnrichmentResult, IOCType, RiskLevel
from iocforge.utils.logger import get_logger

logger = get_logger(__name__)


class BaseEnricher(abc.ABC):
    """Interface for a single TI provider.

    Subclasses declare which IOC types they support and implement
    :meth:`_query` to return a normalized :class:`EnrichmentResult`.
    """

    #: Display name of the provider.
    name: str = "base"

    #: IOC types this provider can enrich.
    supported_types: Set[IOCType] = set()

    def __init__(
        self,
        api_key: Optional[str] = None,
        timeout: float = 20.0,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.session = session or requests.Session()

    # --- Public API ---------------------------------------------------------
    @property
    def is_available(self) -> bool:
        """Whether this provider is usable (e.g. has the required API key)."""
        return True

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in self.supported_types

    def enrich(self, value: str, ioc_type: IOCType) -> EnrichmentResult:
        """Enrich a single IOC, never raising — errors are captured in-result."""
        try:
            return self._query(value, ioc_type)
        except requests.RequestException as exc:
            logger.warning("%s network error for %s: %s", self.name, value, exc)
            return EnrichmentResult(
                provider=self.name, ioc_value=value, error=str(exc)
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("%s unexpected error for %s", self.name, value)
            return EnrichmentResult(
                provider=self.name, ioc_value=value, error=str(exc)
            )

    # --- Subclass hooks -----------------------------------------------------
    @abc.abstractmethod
    def _query(self, value: str, ioc_type: IOCType) -> EnrichmentResult:
        """Perform the actual provider lookup."""

    # --- Helpers ------------------------------------------------------------
    @staticmethod
    def _risk_from_detections(malicious: int, total: int) -> RiskLevel:
        """Map a detection ratio onto a :class:`RiskLevel`."""
        if total <= 0:
            return RiskLevel.UNKNOWN
        if malicious == 0:
            return RiskLevel.CLEAN
        ratio = malicious / total
        if malicious >= 10 or ratio >= 0.5:
            return RiskLevel.CRITICAL
        if malicious >= 5 or ratio >= 0.25:
            return RiskLevel.HIGH
        if malicious >= 2 or ratio >= 0.1:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
