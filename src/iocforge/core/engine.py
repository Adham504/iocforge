"""The IOCForge analysis engine — orchestrates the full pipeline.

Pipeline
--------
    files ──▶ ParserFactory ──▶ text
                                  │
                                  ▼
                          ExtractorRegistry ──▶ raw IOCs
                                  │
                                  ▼
                          Indicator objects (deduped, counted)
                                  │
                                  ▼
                          EnrichmentManager (optional, networked)
                                  │
                                  ▼
                             AnalysisReport
"""
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional

from iocforge import __version__
from iocforge.config.settings import Settings, get_settings
from iocforge.core.models import AnalysisReport, Indicator, IOCType
from iocforge.enrichment.manager import EnrichmentManager
from iocforge.extractors.registry import ExtractorRegistry, get_default_registry
from iocforge.parsers.base import ParsedDocument
from iocforge.parsers.factory import ParserFactory
from iocforge.utils.logger import get_logger

logger = get_logger(__name__)


class IOCForgeEngine:
    """High-level façade for analyzing files end-to-end."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        registry: Optional[ExtractorRegistry] = None,
        parser_factory: Optional[ParserFactory] = None,
        enrichment_manager: Optional[EnrichmentManager] = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.registry = registry or get_default_registry()
        self.parser_factory = parser_factory or ParserFactory()
        self.enrichment_manager = enrichment_manager

    @property
    def supported_ioc_count(self) -> int:
        return len(self.registry.supported_types)

    # --- Pipeline steps -----------------------------------------------------
    def _gather_documents(self, paths: List[Path]) -> List[ParsedDocument]:
        documents: List[ParsedDocument] = []
        for path in paths:
            doc = self.parser_factory.parse(path)
            documents.extend(doc.flatten())
        return documents

    def _extract(self, documents: List[ParsedDocument]) -> Dict[IOCType, List[Indicator]]:
        # value -> Indicator (accumulating counts and sources)
        accumulator: Dict[IOCType, Dict[str, Indicator]] = defaultdict(dict)

        for doc in documents:
            if not doc.text:
                continue
            counts = Counter()
            found = self.registry.extract_all(doc.text)
            for ioc_type, values in found.items():
                for value in values:
                    # Count raw occurrences for frequency reporting.
                    occ = doc.text.count(value) or 1
                    counts[(ioc_type, value)] += occ

            for (ioc_type, value), occ in counts.items():
                bucket = accumulator[ioc_type]
                if value in bucket:
                    bucket[value].count += occ
                    bucket[value].sources.append(doc.source)
                else:
                    bucket[value] = Indicator(
                        value=value,
                        ioc_type=ioc_type,
                        sources=[doc.source],
                        count=occ,
                    )

        return {
            ioc_type: sorted(items.values(), key=lambda i: (-i.count, i.value))
            for ioc_type, items in accumulator.items()
        }

    # --- Public API ---------------------------------------------------------
    def analyze(
        self,
        paths: List[str | Path],
        enrich: Optional[bool] = None,
    ) -> AnalysisReport:
        """Analyze ``paths`` and return a populated :class:`AnalysisReport`."""
        resolved = [Path(p) for p in paths]
        logger.info("Starting analysis of %d input(s)", len(resolved))

        documents = self._gather_documents(resolved)
        logger.info("Parsed %d document(s)", len(documents))

        indicators = self._extract(documents)
        total = sum(len(v) for v in indicators.values())
        logger.info("Extracted %d unique IOC(s)", total)

        should_enrich = self.settings.enable_enrichment if enrich is None else enrich
        if should_enrich:
            manager = self.enrichment_manager or EnrichmentManager(self.settings)
            flat = [ioc for group in indicators.values() for ioc in group]
            manager.enrich_all(flat)

        report = AnalysisReport(
            indicators=indicators,
            source_files=[str(p) for p in resolved],
            tool_version=__version__,
        )
        logger.info(
            "Analysis complete: %d IOC(s), %d flagged malicious",
            report.total_iocs,
            len(report.malicious_indicators()),
        )
        return report
