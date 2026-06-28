"""IOCForge command-line interface built with Typer.

Examples
--------
    iocforge analyze sample.pdf
    iocforge analyze logs.txt report.html --no-enrich
    iocforge analyze threat_report.pdf --format html --format json -o out/
    iocforge info
    iocforge --version
"""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import typer

from iocforge import __author__, __version__
from iocforge.config.settings import get_settings
from iocforge.core.engine import IOCForgeEngine
from iocforge.reporting.manager import ReportManager
from iocforge.reporting.summary_reporter import SummaryReporter
from iocforge.utils.banner import render_banner
from iocforge.utils.colors import colorize, supports_color
from iocforge.utils.logger import configure_logging, get_logger

app = typer.Typer(
    name="iocforge",
    help="IOCForge — Extract. Analyze. Enrich. Understand.",
    add_completion=False,
    no_args_is_help=True,
)

logger = get_logger(__name__)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"IOCForge {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show the application version and exit.",
    ),
) -> None:
    """IOCForge root command."""


def _print_banner() -> None:
    settings = get_settings()
    engine_types = IOCForgeEngine(settings).supported_ioc_count
    banner = render_banner(
        version=__version__,
        author=__author__,
        loaded_apis=settings.loaded_apis,
        supported_ioc_count=engine_types,
        enrichment_enabled=settings.enable_enrichment,
    )
    on = supports_color()
    if on:
        # Tint the ASCII art cyan and highlight the ONLINE/OFFLINE status.
        colored_lines = []
        for line in banner.splitlines():
            if any(c in line for c in "█╗╔╝╚║═"):
                colored_lines.append(colorize(line, "bright_cyan", bold=True, enabled=on))
            elif "Extract •" in line:
                colored_lines.append(colorize(line, "cyan", enabled=on))
            elif "ONLINE" in line:
                colored_lines.append(line.replace("ONLINE", colorize("ONLINE", "green", bold=True, enabled=on)))
            elif "OFFLINE" in line:
                colored_lines.append(line.replace("OFFLINE", colorize("OFFLINE", "yellow", bold=True, enabled=on)))
            else:
                colored_lines.append(line)
        banner = "\n".join(colored_lines)
    typer.echo(banner, color=on or None)


@app.command()
def analyze(
    files: List[Path] = typer.Argument(
        ...,
        exists=True,
        readable=True,
        help="One or more input files to analyze (TXT, LOG, CSV, JSON, HTML, "
        "PDF, DOCX, ZIP).",
    ),
    output_dir: Path = typer.Option(
        Path("reports"),
        "--output-dir",
        "-o",
        help="Directory where reports are written.",
    ),
    formats: Optional[List[str]] = typer.Option(
        None,
        "--format",
        "-f",
        help="Report formats: json, csv, html, summary. Repeatable. "
        "Defaults to all.",
    ),
    basename: str = typer.Option(
        "iocforge_report", "--name", help="Base file name for reports."
    ),
    enrich: bool = typer.Option(
        True,
        "--enrich/--no-enrich",
        help="Enable or disable Threat Intelligence enrichment.",
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress the startup banner."
    ),
    log_level: str = typer.Option(
        None, "--log-level", help="Override log level (DEBUG/INFO/WARNING/ERROR)."
    ),
) -> None:
    """Analyze one or more files and generate IOC reports."""
    settings = get_settings()
    configure_logging(
        level=log_level or settings.log_level, log_dir=settings.log_dir
    )

    if not quiet:
        _print_banner()

    engine = IOCForgeEngine(settings)
    report = engine.analyze(files, enrich=enrich)

    # Always show the console summary (colorized when the terminal supports it).
    # ``color=`` keeps codes when forced (FORCE_COLOR) and strips them when piped.
    typer.echo(
        "\n" + SummaryReporter().render_console(report) + "\n",
        color=supports_color() or None,
    )

    manager = ReportManager()
    written = manager.write_all(
        report, output_dir=output_dir, basename=basename, formats=formats
    )

    typer.secho("Reports written:", fg=typer.colors.GREEN, bold=True)
    for fmt, path in written.items():
        typer.echo(f"  • {fmt:<8} {path}")


@app.command()
def info() -> None:
    """Show configuration, loaded APIs and supported capabilities."""
    settings = get_settings()
    _print_banner()
    engine = IOCForgeEngine(settings)
    typer.echo("Supported IOC types:")
    for t in engine.registry.supported_types:
        typer.echo(f"  • {t.label}")
    typer.echo("\nSupported input formats:")
    typer.echo("  " + ", ".join(engine.parser_factory.supported_extensions))
    typer.echo("\nReport formats: " + ", ".join(ReportManager().formats))


@app.command()
def formats() -> None:
    """List the supported input file formats."""
    factory = IOCForgeEngine().parser_factory
    typer.echo("Supported input extensions:")
    typer.echo("  " + ", ".join(factory.supported_extensions))


def main() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
