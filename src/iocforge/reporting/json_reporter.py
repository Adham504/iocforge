"""JSON report writer."""
from __future__ import annotations

import json

from iocforge.core.models import AnalysisReport
from iocforge.reporting.base import BaseReporter


class JSONReporter(BaseReporter):
    """Serialize the report to pretty-printed JSON."""

    extension = ".json"

    def render(self, report: AnalysisReport) -> str:
        return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
