"""Integration tests for the analysis engine (enrichment disabled)."""
from __future__ import annotations

from pathlib import Path

from iocforge.config.settings import Settings
from iocforge.core.engine import IOCForgeEngine


def _offline_engine() -> IOCForgeEngine:
    return IOCForgeEngine(Settings(enable_enrichment=False))


def test_engine_extracts_from_examples(examples_dir: Path):
    engine = _offline_engine()
    report = engine.analyze(
        [examples_dir / "sample_report.txt"], enrich=False
    )
    values = {i.value for i in report.all_indicators()}
    assert "45.137.21.53" in values
    assert "192.168.1.10" not in values  # private filtered
    assert "127.0.0.1" not in values     # loopback filtered
    assert "CVE-2024-3094" in values
    assert "T1059.001" in values


def test_engine_deduplicates_across_files(examples_dir: Path):
    engine = _offline_engine()
    report = engine.analyze(
        [examples_dir / "sample_report.txt", examples_dir / "sample_logs.log"],
        enrich=False,
    )
    sha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    matches = [i for i in report.all_indicators() if i.value == sha]
    assert len(matches) == 1
    # Appears in both files -> at least 2 sources.
    assert len(set(matches[0].sources)) >= 2


def test_report_serialization_schema(examples_dir: Path):
    engine = _offline_engine()
    report = engine.analyze([examples_dir / "sample_iocs.json"], enrich=False)
    data = report.to_dict()
    assert "indicators" in data
    assert "statistics" in data
    assert "Threat_Intelligence" in data
    assert data["metadata"]["tool"] == "IOCForge"
