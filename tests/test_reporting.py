"""Unit tests for report rendering."""
from __future__ import annotations

import json
from pathlib import Path

from iocforge.core.models import (
    AnalysisReport,
    EnrichmentResult,
    Indicator,
    IOCType,
    RiskLevel,
)
from iocforge.reporting.csv_reporter import CSVReporter
from iocforge.reporting.html_reporter import HTMLReporter
from iocforge.reporting.json_reporter import JSONReporter
from iocforge.reporting.manager import ReportManager
from iocforge.reporting.summary_reporter import SummaryReporter


def _sample_report() -> AnalysisReport:
    ip = Indicator(
        value="45.137.21.53",
        ioc_type=IOCType.IPV4,
        sources=["report.txt"],
        count=3,
        enrichment=[
            EnrichmentResult(
                provider="AbuseIPDB",
                ioc_value="45.137.21.53",
                risk_level=RiskLevel.CRITICAL,
                summary="Abuse confidence 95%",
            )
        ],
    )
    domain = Indicator(value="evil.ru", ioc_type=IOCType.DOMAIN, count=1)
    return AnalysisReport(
        indicators={IOCType.IPV4: [ip], IOCType.DOMAIN: [domain]},
        source_files=["report.txt"],
        tool_version="1.0.0",
    )


def test_json_reporter_valid_json():
    out = JSONReporter().render(_sample_report())
    data = json.loads(out)
    assert data["metadata"]["total_iocs"] == 2
    assert "45.137.21.53" in data["Threat_Intelligence"]


def test_csv_reporter_has_rows():
    out = CSVReporter().render(_sample_report())
    assert "45.137.21.53" in out
    assert "evil.ru" in out
    assert out.splitlines()[0].startswith("type,value")


def test_html_reporter_self_contained():
    out = HTMLReporter().render(_sample_report())
    assert "<svg" in out          # inline charts
    assert "45.137.21.53" in out
    assert "http://" not in out.split("</style>")[0]  # no external CSS links
    assert "https://" not in out.split("</style>")[0]


def test_html_reporter_interactive_features():
    """The enhanced report ships search, filtering, sorting, copy and theme."""
    out = HTMLReporter().render(_sample_report())
    for hook in (
        "searchIOCs",   # live search
        "filterRisk",   # risk filter chips
        "sortTable",    # column sorting
        "copyVal",      # copy-to-clipboard
        "toggleTheme",  # light/dark toggle
        'class="gauge"',  # risk-score gauge
        "Risk Score",
    ):
        assert hook in out, f"missing UI feature: {hook}"


def test_html_reporter_no_unresolved_placeholders():
    """No leftover str.format placeholders should leak into the output."""
    import re

    out = HTMLReporter().render(_sample_report())
    # Single-brace python placeholders like {generated} must all be resolved.
    assert not re.search(r"\{[a-z_]+\}", out)


def test_summary_reporter_lists_malicious():
    out = SummaryReporter().render(_sample_report())
    assert "Flagged indicators" in out
    assert "45.137.21.53" in out


def test_manager_writes_all_formats(tmp_path: Path):
    written = ReportManager().write_all(_sample_report(), tmp_path, "rep")
    for fmt in ("json", "csv", "html", "summary"):
        assert written[fmt].exists()
