"""Enrichment manager — coordinates all TI providers concurrently."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from iocforge.config.settings import Settings, get_settings
from iocforge.core.models import Indicator, IOCType
from iocforge.enrichment.abuseipdb import AbuseIPDBEnricher
from iocforge.enrichment.base import BaseEnricher
from iocforge.enrichment.otx import OTXEnricher
from iocforge.enrichment.threatfox import MalwareBazaarEnricher, ThreatFoxEnricher
from iocforge.enrichment.virustotal import VirusTotalEnricher
from iocforge.utils.logger import get_logger

logger = get_logger(__name__)

# IOC types that make sense to enrich over the network.
ENRICHABLE_TYPES = {
    IOCType.IPV4,
    IOCType.IPV6,
    IOCType.DOMAIN,
    IOCType.URL,
    IOCType.MD5,
    IOCType.SHA1,
    IOCType.SHA256,
}


class EnrichmentManager:
    """Builds the active provider set and enriches indicators."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        enrichers: Optional[List[BaseEnricher]] = None,
    ) -> None:
        self.settings = settings or get_settings()
        self._enrichers = enrichers or self._build_default_enrichers()
        self.active = [e for e in self._enrichers if e.is_available]
        logger.info(
            "Enrichment providers active: %s",
            ", ".join(e.name for e in self.active) or "none",
        )

    def _build_default_enrichers(self) -> List[BaseEnricher]:
        s = self.settings
        return [
            VirusTotalEnricher(s.virustotal_api_key, s.request_timeout),
            AbuseIPDBEnricher(s.abuseipdb_api_key, s.request_timeout),
            OTXEnricher(s.otx_api_key, s.request_timeout),
            ThreatFoxEnricher(s.abusech_api_key, s.request_timeout),
            MalwareBazaarEnricher(s.abusech_api_key, s.request_timeout),
        ]

    @property
    def provider_names(self) -> List[str]:
        return [e.name for e in self.active]

    def enrich_indicator(self, indicator: Indicator) -> Indicator:
        """Enrich one indicator with every provider that supports its type."""
        for enricher in self.active:
            if not enricher.supports(indicator.ioc_type):
                continue
            result = enricher.enrich(indicator.value, indicator.ioc_type)
            indicator.enrichment.append(result)
            if self.settings.rate_limit_delay:
                time.sleep(self.settings.rate_limit_delay)
        return indicator

    def enrich_all(self, indicators: List[Indicator]) -> List[Indicator]:
        """Enrich every enrichable indicator, in parallel across indicators."""
        if not self.active or not self.settings.enable_enrichment:
            logger.info("Enrichment skipped (disabled or no providers).")
            return indicators

        targets = [i for i in indicators if i.ioc_type in ENRICHABLE_TYPES]
        logger.info("Enriching %d indicators...", len(targets))

        workers = max(1, min(self.settings.max_enrichment_workers, len(targets) or 1))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(self.enrich_indicator, ioc): ioc for ioc in targets
            }
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    logger.error("Enrichment task failed: %s", exc)
        return indicators
