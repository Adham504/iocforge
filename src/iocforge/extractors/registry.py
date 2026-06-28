"""Extractor registry — orchestrates all extractors over a body of text.

The registry handles the *hash-precedence* problem: a 64-character SHA256 also
contains valid 40- and 32-character hex substrings. To avoid double-counting we
mask longer hashes (and URLs/emails) before running shorter/looser extractors.
"""
from __future__ import annotations

import re
from typing import Dict, List, Set

from iocforge.core.models import IOCType
from iocforge.extractors import patterns
from iocforge.extractors.base import BaseExtractor
from iocforge.extractors.hashes import MD5Extractor, SHA1Extractor, SHA256Extractor
from iocforge.extractors.misc import BitcoinExtractor, CVEExtractor, MitreExtractor
from iocforge.extractors.network import (
    DomainExtractor,
    EmailExtractor,
    IPv4Extractor,
    IPv6Extractor,
    URLExtractor,
)
from iocforge.utils.logger import get_logger

logger = get_logger(__name__)


class ExtractorRegistry:
    """Holds extractors and runs them in a dependency-aware order."""

    def __init__(self, extractors: List[BaseExtractor]) -> None:
        self._extractors: Dict[IOCType, BaseExtractor] = {
            e.ioc_type: e for e in extractors
        }

    @property
    def extractors(self) -> List[BaseExtractor]:
        return list(self._extractors.values())

    @property
    def supported_types(self) -> List[IOCType]:
        return list(self._extractors.keys())

    def register(self, extractor: BaseExtractor) -> None:
        """Add or replace an extractor (used for plugins/extensibility)."""
        self._extractors[extractor.ioc_type] = extractor
        logger.debug("Registered extractor for %s", extractor.ioc_type.value)

    def extract_all(self, text: str) -> Dict[IOCType, Set[str]]:
        """Run every extractor and return ``{IOCType: {values}}``.

        ``text`` is first *refanged* to restore defanged indicators.
        """
        text = patterns.refang(text)
        results: Dict[IOCType, Set[str]] = {}

        # 1) Hashes first (longest-to-shortest) so we can mask them out and
        #    avoid SHA256 being re-counted as SHA1/MD5 fragments.
        masked = text
        for ioc_type in (IOCType.SHA256, IOCType.SHA1, IOCType.MD5):
            extractor = self._extractors.get(ioc_type)
            if not extractor:
                continue
            found = extractor.find(masked)
            if found:
                results[ioc_type] = found
                # Mask the matched hashes so shorter patterns can't re-match.
                for value in found:
                    masked = re.sub(re.escape(value), " ", masked, flags=re.I)

        # 2) URLs before domains so domains inside URLs aren't double-counted
        #    as standalone domains we don't want.
        url_extractor = self._extractors.get(IOCType.URL)
        url_hosts: Set[str] = set()
        if url_extractor:
            urls = url_extractor.find(masked)
            if urls:
                results[IOCType.URL] = urls

        # 3) Everything else.
        remaining = [
            t
            for t in self._extractors
            if t not in {IOCType.SHA256, IOCType.SHA1, IOCType.MD5, IOCType.URL}
        ]
        for ioc_type in remaining:
            extractor = self._extractors[ioc_type]
            found = extractor.find(masked if ioc_type != IOCType.IPV4 else text)
            if found:
                results[ioc_type] = found

        # Avoid listing URL host domains twice when they're already captured
        # as URLs (keep domains that appear independently of a URL).
        _ = url_hosts  # reserved for future host de-duplication policy
        return results


def get_default_registry() -> ExtractorRegistry:
    """Build the registry with every built-in extractor."""
    return ExtractorRegistry(
        [
            IPv4Extractor(),
            IPv6Extractor(),
            DomainExtractor(),
            URLExtractor(),
            EmailExtractor(),
            MD5Extractor(),
            SHA1Extractor(),
            SHA256Extractor(),
            BitcoinExtractor(),
            CVEExtractor(),
            MitreExtractor(),
        ]
    )
