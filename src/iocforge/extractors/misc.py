"""Bonus IOC extractors: Bitcoin wallets, CVE IDs, MITRE ATT&CK IDs."""
from __future__ import annotations

from typing import List

from iocforge.core.models import IOCType
from iocforge.extractors import patterns
from iocforge.extractors.base import BaseExtractor


class BitcoinExtractor(BaseExtractor):
    """Extract Bitcoin wallet addresses (legacy + bech32)."""

    ioc_type = IOCType.BITCOIN

    def extract(self, text: str) -> List[str]:
        return patterns.BITCOIN.findall(text)

    def normalize(self, candidate: str) -> str:
        return candidate.strip()


class CVEExtractor(BaseExtractor):
    """Extract CVE identifiers."""

    ioc_type = IOCType.CVE

    def extract(self, text: str) -> List[str]:
        return patterns.CVE.findall(text)

    def normalize(self, candidate: str) -> str:
        return candidate.strip().upper()


class MitreExtractor(BaseExtractor):
    """Extract MITRE ATT&CK technique IDs (e.g. T1059.001)."""

    ioc_type = IOCType.MITRE

    def extract(self, text: str) -> List[str]:
        return patterns.MITRE.findall(text)

    def normalize(self, candidate: str) -> str:
        return candidate.strip().upper()
