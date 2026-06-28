"""Abstract base class for IOC extractors.

Following the Open/Closed Principle, new IOC types are added by subclassing
:class:`BaseExtractor` and registering the subclass — no existing code needs to
change.
"""
from __future__ import annotations

import abc
from typing import Iterable, List, Set

from iocforge.core.models import IOCType


class BaseExtractor(abc.ABC):
    """Interface every IOC extractor must implement."""

    #: The IOC type produced by this extractor.
    ioc_type: IOCType

    @abc.abstractmethod
    def extract(self, text: str) -> List[str]:
        """Return raw candidate IOC strings found in ``text``.

        Implementations should perform pattern matching only. Validation and
        false-positive removal happens in :meth:`is_valid`.
        """

    def is_valid(self, candidate: str) -> bool:  # noqa: D401
        """Return ``True`` if ``candidate`` is a genuine IOC (not a false positive)."""
        return True

    def normalize(self, candidate: str) -> str:
        """Canonicalize a candidate (e.g. lowercase a domain)."""
        return candidate.strip()

    def find(self, text: str) -> Set[str]:
        """Extract, normalize, validate and de-duplicate IOCs from ``text``."""
        results: Set[str] = set()
        for candidate in self.extract(text):
            normalized = self.normalize(candidate)
            if normalized and self.is_valid(normalized):
                results.add(normalized)
        return results

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"<{self.__class__.__name__} type={self.ioc_type.value}>"


def dedupe_preserve_order(items: Iterable[str]) -> List[str]:
    """Return items with duplicates removed, preserving first-seen order."""
    seen: Set[str] = set()
    ordered: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered
