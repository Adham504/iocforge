"""CSV report writer — one row per indicator."""
from __future__ import annotations

import csv
import io

from iocforge.core.models import AnalysisReport
from iocforge.reporting.base import BaseReporter


class CSVReporter(BaseReporter):
    """Flat CSV with type, value, count, risk and enrichment summary."""

    extension = ".csv"

    _HEADERS = [
        "type",
        "value",
        "count",
        "risk_level",
        "sources",
        "providers",
        "summary",
    ]

    def render(self, report: AnalysisReport) -> str:
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(self._HEADERS)

        for ioc in sorted(
            report.all_indicators(),
            key=lambda i: (-i.risk_level.rank, i.ioc_type.value, i.value),
        ):
            providers = "; ".join(e.provider for e in ioc.enrichment)
            summaries = " | ".join(
                e.summary for e in ioc.enrichment if e.summary
            )
            writer.writerow(
                [
                    ioc.ioc_type.label,
                    ioc.value,
                    ioc.count,
                    ioc.risk_level.value,
                    "; ".join(sorted(set(ioc.sources))),
                    providers,
                    summaries,
                ]
            )
        return buffer.getvalue()
