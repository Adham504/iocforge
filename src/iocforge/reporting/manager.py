"""Report manager — writes all requested formats in one call."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from iocforge.core.models import AnalysisReport
from iocforge.reporting.base import BaseReporter
from iocforge.reporting.csv_reporter import CSVReporter
from iocforge.reporting.html_reporter import HTMLReporter
from iocforge.reporting.json_reporter import JSONReporter
from iocforge.reporting.summary_reporter import SummaryReporter
from iocforge.utils.logger import get_logger

logger = get_logger(__name__)


class ReportManager:
    """Coordinates the available reporters."""

    def __init__(self) -> None:
        self._reporters: Dict[str, BaseReporter] = {
            "json": JSONReporter(),
            "csv": CSVReporter(),
            "html": HTMLReporter(),
            "summary": SummaryReporter(),
        }

    @property
    def formats(self) -> List[str]:
        return list(self._reporters.keys())

    def render(self, report: AnalysisReport, fmt: str) -> str:
        return self._reporters[fmt].render(report)

    def write_all(
        self,
        report: AnalysisReport,
        output_dir: Path,
        basename: str = "iocforge_report",
        formats: List[str] | None = None,
    ) -> Dict[str, Path]:
        """Write the requested formats and return ``{format: path}``."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        chosen = formats or self.formats
        written: Dict[str, Path] = {}
        for fmt in chosen:
            reporter = self._reporters.get(fmt)
            if reporter is None:
                logger.warning("Unknown report format requested: %s", fmt)
                continue
            path = output_dir / f"{basename}{reporter.extension}"
            reporter.write(report, path)
            written[fmt] = path
            logger.info("Wrote %s report -> %s", fmt, path)
        return written
