"""Base reporter interface."""
from __future__ import annotations

import abc
from pathlib import Path

from iocforge.core.models import AnalysisReport


class BaseReporter(abc.ABC):
    """Render an :class:`AnalysisReport` to a file."""

    #: File extension (with dot) produced by this reporter.
    extension: str = ""

    @abc.abstractmethod
    def render(self, report: AnalysisReport) -> str:
        """Return the report rendered as a string."""

    def write(self, report: AnalysisReport, output: Path) -> Path:
        """Render and write the report to ``output``; return the final path."""
        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(self.render(report), encoding="utf-8")
        return output
