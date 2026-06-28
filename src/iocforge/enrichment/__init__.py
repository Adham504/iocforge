"""Threat Intelligence enrichment subsystem.

Each provider implements :class:`~iocforge.enrichment.base.BaseEnricher`. The
:class:`~iocforge.enrichment.manager.EnrichmentManager` decides which providers
support a given IOC type and aggregates their results.
"""

from iocforge.enrichment.base import BaseEnricher
from iocforge.enrichment.manager import EnrichmentManager

__all__ = ["BaseEnricher", "EnrichmentManager"]
