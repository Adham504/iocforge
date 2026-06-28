"""Plain-text executive summary report (with optional colorized console view)."""
from __future__ import annotations

from iocforge.core.models import AnalysisReport, RiskLevel
from iocforge.reporting.base import BaseReporter
from iocforge.utils.colors import colorize, risk_color, supports_color


class SummaryReporter(BaseReporter):
    """Concise human-readable overview suitable for the console or a .txt file."""

    extension = ".txt"

    def render(self, report: AnalysisReport) -> str:
        lines: list[str] = []
        lines.append("=" * 64)
        lines.append("IOCForge — Analysis Summary")
        lines.append("=" * 64)
        lines.append(f"Generated : {report.generated_at}")
        lines.append(f"Version   : {report.tool_version}")
        lines.append(f"Sources   : {', '.join(report.source_files)}")
        lines.append(f"Total IOCs: {report.total_iocs}")
        lines.append("")

        lines.append("IOCs by type")
        lines.append("-" * 64)
        by_type = report.counts_by_type()
        if by_type:
            for label, count in sorted(by_type.items(), key=lambda x: -x[1]):
                lines.append(f"  {label:<16} {count}")
        else:
            lines.append("  (none)")
        lines.append("")

        lines.append("IOCs by risk")
        lines.append("-" * 64)
        by_risk = report.counts_by_risk()
        if by_risk:
            for label, count in sorted(by_risk.items(), key=lambda x: -x[1]):
                lines.append(f"  {label:<16} {count}")
        else:
            lines.append("  (none)")
        lines.append("")

        malicious = report.malicious_indicators()
        lines.append(f"Flagged indicators (MEDIUM+): {len(malicious)}")
        lines.append("-" * 64)
        if malicious:
            for ioc in malicious[:25]:
                summary = next(
                    (e.summary for e in ioc.enrichment if e.summary), ""
                )
                lines.append(
                    f"  [{ioc.risk_level.value.upper():<8}] "
                    f"{ioc.ioc_type.label:<8} {ioc.value}"
                )
                if summary:
                    lines.append(f"             └─ {summary}")
            if len(malicious) > 25:
                lines.append(f"  ... and {len(malicious) - 25} more")
        else:
            lines.append("  No malicious indicators detected.")
        lines.append("=" * 64)
        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    # Colorized console rendering (TTY only; the .txt file stays plain).  #
    # ------------------------------------------------------------------ #
    def render_console(self, report: AnalysisReport, color: bool | None = None) -> str:
        """Render the summary with ANSI colors for terminal display.

        Risk levels are color-coded (CLEAN=green … CRITICAL=magenta), headings
        are bold/cyan. When ``color`` is ``None`` it is auto-detected from the
        terminal; pass ``False`` to force plain text.
        """
        on = supports_color() if color is None else color

        def head(text: str) -> str:
            return colorize(text, "cyan", bold=True, enabled=on)

        def rule(char: str = "=") -> str:
            return colorize(char * 64, "grey", enabled=on)

        lines: list[str] = []
        lines.append(rule("="))
        lines.append(head("IOCForge — Analysis Summary"))
        lines.append(rule("="))
        lines.append(f"{colorize('Generated', 'grey', enabled=on)} : {report.generated_at}")
        lines.append(f"{colorize('Version', 'grey', enabled=on)}   : {report.tool_version}")
        lines.append(
            f"{colorize('Sources', 'grey', enabled=on)}   : "
            f"{', '.join(report.source_files)}"
        )
        lines.append(
            f"{colorize('Total IOCs', 'grey', enabled=on)}: "
            f"{colorize(str(report.total_iocs), 'bright_cyan', bold=True, enabled=on)}"
        )
        lines.append("")

        lines.append(head("IOCs by type"))
        lines.append(rule("-"))
        by_type = report.counts_by_type()
        if by_type:
            for label, count in sorted(by_type.items(), key=lambda x: -x[1]):
                lines.append(
                    f"  {label:<16} "
                    f"{colorize(str(count), 'bright_cyan', enabled=on)}"
                )
        else:
            lines.append("  (none)")
        lines.append("")

        lines.append(head("IOCs by risk"))
        lines.append(rule("-"))
        by_risk = report.counts_by_risk()
        if by_risk:
            # Sort by severity (worst first) for a more useful console view.
            def _rank(item: tuple[str, int]) -> int:
                try:
                    return RiskLevel(item[0]).rank
                except ValueError:
                    return -1

            for label, count in sorted(by_risk.items(), key=_rank, reverse=True):
                try:
                    clr = risk_color(RiskLevel(label))
                except ValueError:
                    clr = "grey"
                colored_label = colorize(
                    f"{label.upper():<16}", clr, bold=True, enabled=on
                )
                lines.append(f"  {colored_label} {count}")
        else:
            lines.append("  (none)")
        lines.append("")

        malicious = report.malicious_indicators()
        flagged_label = f"Flagged indicators (MEDIUM+): {len(malicious)}"
        lines.append(
            colorize(flagged_label, "bright_red" if malicious else "green",
                     bold=True, enabled=on)
        )
        lines.append(rule("-"))
        if malicious:
            for ioc in malicious[:25]:
                summary = next(
                    (e.summary for e in ioc.enrichment if e.summary), ""
                )
                clr = risk_color(ioc.risk_level)
                badge = colorize(
                    f"[{ioc.risk_level.value.upper():<8}]", clr, bold=True, enabled=on
                )
                lines.append(
                    f"  {badge} "
                    f"{colorize(f'{ioc.ioc_type.label:<8}', 'grey', enabled=on)} "
                    f"{ioc.value}"
                )
                if summary:
                    lines.append(
                        colorize(f"             └─ {summary}", "grey", enabled=on)
                    )
            if len(malicious) > 25:
                lines.append(f"  ... and {len(malicious) - 25} more")
        else:
            lines.append(
                colorize("  ✓ No malicious indicators detected.", "green", enabled=on)
            )
        lines.append(rule("="))
        return "\n".join(lines)
