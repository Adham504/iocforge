"""Unit tests for enrichment providers using mocked HTTP responses."""
from __future__ import annotations

from unittest.mock import MagicMock

from iocforge.core.models import (
    EnrichmentResult,
    Indicator,
    IOCType,
    RiskLevel,
)
from iocforge.enrichment.abuseipdb import AbuseIPDBEnricher
from iocforge.enrichment.base import BaseEnricher
from iocforge.enrichment.otx import OTXEnricher
from iocforge.enrichment.virustotal import VirusTotalEnricher


def _mock_session(json_payload: dict, status: int = 200) -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.json.return_value = json_payload
    response.raise_for_status.return_value = None
    session = MagicMock()
    session.get.return_value = response
    session.post.return_value = response
    return session


def test_risk_from_detections_mapping():
    assert BaseEnricher._risk_from_detections(0, 70) is RiskLevel.CLEAN
    assert BaseEnricher._risk_from_detections(1, 70) is RiskLevel.LOW
    assert BaseEnricher._risk_from_detections(3, 70) is RiskLevel.MEDIUM
    assert BaseEnricher._risk_from_detections(6, 70) is RiskLevel.HIGH
    assert BaseEnricher._risk_from_detections(40, 70) is RiskLevel.CRITICAL


def test_virustotal_parses_detection_stats():
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 12,
                    "suspicious": 1,
                    "harmless": 50,
                    "undetected": 7,
                },
                "reputation": -30,
                "categories": {"x": "malware"},
                "total_votes": {"malicious": 5},
            }
        }
    }
    enricher = VirusTotalEnricher(api_key="key", session=_mock_session(payload))
    result = enricher.enrich("evil.ru", IOCType.DOMAIN)
    assert result.risk_level is RiskLevel.CRITICAL
    assert result.raw["malicious"] == 12


def test_virustotal_handles_404():
    enricher = VirusTotalEnricher(api_key="key", session=_mock_session({}, 404))
    result = enricher.enrich("clean.com", IOCType.DOMAIN)
    assert result.risk_level is RiskLevel.UNKNOWN


def test_abuseipdb_confidence_mapping():
    payload = {"data": {"abuseConfidenceScore": 95, "totalReports": 42}}
    enricher = AbuseIPDBEnricher(api_key="key", session=_mock_session(payload))
    result = enricher.enrich("45.137.21.53", IOCType.IPV4)
    assert result.risk_level is RiskLevel.CRITICAL
    assert result.raw["abuse_confidence_score"] == 95


def test_unavailable_without_key():
    assert VirusTotalEnricher(api_key=None).is_available is False
    assert AbuseIPDBEnricher(api_key=None).is_available is False


# --- Regression tests: empty-file hash should NOT be flagged malicious ------


def test_otx_pulses_without_malware_context_are_low_not_high():
    """Empty-file hash appears in many pulses but has no malware/APT context."""
    payload = {
        "pulse_info": {
            "count": 25,  # high pulse count …
            "pulses": [{"tags": ["test"]}],  # … but no malware_families/adversary
        }
    }
    enricher = OTXEnricher(api_key="key", session=_mock_session(payload))
    result = enricher.enrich(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        IOCType.SHA256,
    )
    # Previously this returned HIGH; now a count-only signal caps at LOW.
    assert result.risk_level is RiskLevel.LOW


def test_otx_whitelisted_indicator_is_clean():
    payload = {
        "pulse_info": {
            "count": 30,
            "pulses": [],
            "validation": [{"source": "whitelist", "name": "Public DNS"}],
        }
    }
    enricher = OTXEnricher(api_key="key", session=_mock_session(payload))
    result = enricher.enrich("8.8.8.8", IOCType.IPV4)
    assert result.risk_level is RiskLevel.CLEAN
    assert result.raw["whitelisted"] is True


def test_otx_with_real_malware_context_escalates():
    payload = {
        "pulse_info": {
            "count": 8,
            "pulses": [
                {"malware_families": [{"display_name": "Emotet"}], "adversary": "TA542"}
            ],
        }
    }
    enricher = OTXEnricher(api_key="key", session=_mock_session(payload))
    result = enricher.enrich("evil.example", IOCType.DOMAIN)
    assert result.risk_level is RiskLevel.HIGH


def test_aggregate_authoritative_clean_suppresses_lone_low():
    """VirusTotal 0/75 (CLEAN) must win over a lone OTX LOW signal."""
    ioc = Indicator(
        value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ioc_type=IOCType.SHA256,
        enrichment=[
            EnrichmentResult(
                provider="VirusTotal",
                ioc_value="e3b0...",
                risk_level=RiskLevel.CLEAN,
                summary="0/75 engines flagged this as malicious",
            ),
            EnrichmentResult(
                provider="AlienVault OTX",
                ioc_value="e3b0...",
                risk_level=RiskLevel.LOW,
                summary="Referenced in 25 OTX pulse(s) (no malware context)",
            ),
        ],
    )
    assert ioc.risk_level is RiskLevel.CLEAN


def test_aggregate_real_threat_still_surfaces():
    """A genuine MEDIUM+ verdict is NOT suppressed by an authoritative CLEAN."""
    ioc = Indicator(
        value="45.137.21.53",
        ioc_type=IOCType.IPV4,
        enrichment=[
            EnrichmentResult(
                provider="VirusTotal",
                ioc_value="45.137.21.53",
                risk_level=RiskLevel.CLEAN,
            ),
            EnrichmentResult(
                provider="AbuseIPDB",
                ioc_value="45.137.21.53",
                risk_level=RiskLevel.HIGH,
            ),
        ],
    )
    assert ioc.risk_level is RiskLevel.HIGH


def test_empty_file_hashes_are_dropped_at_extraction():
    from iocforge.extractors.hashes import SHA1Extractor, SHA256Extractor

    empty_sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    empty_sha256 = (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert empty_sha1 not in SHA1Extractor().find(f"hash {empty_sha1}")
    assert empty_sha256 not in SHA256Extractor().find(f"hash {empty_sha256}")
