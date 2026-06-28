"""File-hash extractors: MD5, SHA1, SHA256.

The order of registration matters: SHA256 (64) and SHA1 (40) must be removed
from the text before MD5 (32) so a 64-char hash isn't mis-detected as two MD5s.
The registry handles this by stripping longer hashes first (see registry.py).
"""
from __future__ import annotations

from typing import List

from iocforge.core.models import IOCType
from iocforge.extractors import patterns
from iocforge.extractors.base import BaseExtractor
from iocforge.extractors.false_positives import is_benign_hash


class _HashExtractor(BaseExtractor):
    """Common behaviour for hex-digest hashes."""

    def normalize(self, candidate: str) -> str:
        return candidate.strip().lower()

    def is_valid(self, candidate: str) -> bool:
        # All-zero or all-same-char digests are almost always placeholders.
        if len(set(candidate)) <= 1:
            return False
        # Known-benign digests (e.g. the empty-file hash) are not real IoCs.
        if is_benign_hash(candidate):
            return False
        return True


class MD5Extractor(_HashExtractor):
    ioc_type = IOCType.MD5

    def extract(self, text: str) -> List[str]:
        return patterns.MD5.findall(text)


class SHA1Extractor(_HashExtractor):
    ioc_type = IOCType.SHA1

    def extract(self, text: str) -> List[str]:
        return patterns.SHA1.findall(text)


class SHA256Extractor(_HashExtractor):
    ioc_type = IOCType.SHA256

    def extract(self, text: str) -> List[str]:
        return patterns.SHA256.findall(text)
