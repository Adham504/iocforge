"""Core domain models and the analysis engine.

``IOCForgeEngine`` is imported lazily (via :pep:`562` ``__getattr__``) to avoid
an import cycle: the engine depends on the extractor/enrichment packages, which
in turn import :mod:`iocforge.core.models`. Importing ``models`` must therefore
not eagerly import ``engine``.
"""
from typing import TYPE_CHECKING

from iocforge.core.models import (
    AnalysisReport,
    EnrichmentResult,
    Indicator,
    IOCType,
    RiskLevel,
)

if TYPE_CHECKING:  # pragma: no cover
    from iocforge.core.engine import IOCForgeEngine

__all__ = [
    "IOCType",
    "RiskLevel",
    "Indicator",
    "EnrichmentResult",
    "AnalysisReport",
    "IOCForgeEngine",
]


def __getattr__(name: str):
    if name == "IOCForgeEngine":
        from iocforge.core.engine import IOCForgeEngine

        return IOCForgeEngine
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
