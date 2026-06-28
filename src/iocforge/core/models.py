"""Domain models for IOCForge.

These dataclasses are the lingua franca shared between extractors, the
enrichment layer, and the reporting layer. Keeping them dependency-free makes
the data model easy to test and serialize.
"""
from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class IOCType(str, enum.Enum):
    """Enumeration of every IOC type IOCForge can extract."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    BITCOIN = "bitcoin"
    CVE = "cve"
    MITRE = "mitre"

    @classmethod
    def hash_types(cls) -> tuple["IOCType", ...]:
        """Return the file-hash IOC types."""
        return (cls.MD5, cls.SHA1, cls.SHA256)

    @property
    def label(self) -> str:
        """Human-readable label."""
        return {
            IOCType.IPV4: "IPv4",
            IOCType.IPV6: "IPv6",
            IOCType.DOMAIN: "Domain",
            IOCType.URL: "URL",
            IOCType.EMAIL: "Email",
            IOCType.MD5: "MD5",
            IOCType.SHA1: "SHA1",
            IOCType.SHA256: "SHA256",
            IOCType.BITCOIN: "Bitcoin Wallet",
            IOCType.CVE: "CVE ID",
            IOCType.MITRE: "MITRE ATT&CK",
        }[self]


class RiskLevel(str, enum.Enum):
    """Risk classification derived from enrichment results."""

    UNKNOWN = "unknown"
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def color(self) -> str:
        """A hex color used by the HTML report for color-coding."""
        return {
            RiskLevel.UNKNOWN: "#6c757d",
            RiskLevel.CLEAN: "#2ecc71",
            RiskLevel.LOW: "#f1c40f",
            RiskLevel.MEDIUM: "#e67e22",
            RiskLevel.HIGH: "#e74c3c",
            RiskLevel.CRITICAL: "#8e44ad",
        }[self]

    @property
    def rank(self) -> int:
        """Sortable severity rank (higher is worse)."""
        return {
            RiskLevel.UNKNOWN: 0,
            RiskLevel.CLEAN: 1,
            RiskLevel.LOW: 2,
            RiskLevel.MEDIUM: 3,
            RiskLevel.HIGH: 4,
            RiskLevel.CRITICAL: 5,
        }[self]


@dataclass
class EnrichmentResult:
    """Normalized enrichment data returned by a single TI provider."""

    provider: str
    ioc_value: str
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    score: Optional[float] = None
    summary: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["risk_level"] = self.risk_level.value
        return data


@dataclass
class Indicator:
    """A single extracted Indicator of Compromise.

    Attributes
    ----------
    value:
        The canonical IOC string (already normalized/defanged-restored).
    ioc_type:
        The :class:`IOCType` of this indicator.
    sources:
        File names / parsers where this indicator was found.
    count:
        Number of times the indicator appeared across all input.
    enrichment:
        Per-provider enrichment results.
    """

    value: str
    ioc_type: IOCType
    sources: List[str] = field(default_factory=list)
    count: int = 1
    enrichment: List[EnrichmentResult] = field(default_factory=list)

    #: Providers whose verdicts are treated as authoritative (multi-engine /
    #: large-corpus consensus). A strong CLEAN from one of these suppresses a
    #: lone weak LOW signal from a heuristic provider.
    _AUTHORITATIVE_PROVIDERS = {"VirusTotal", "AbuseIPDB"}

    @property
    def risk_level(self) -> RiskLevel:
        """Aggregate the per-provider verdicts into a single risk level.

        The naive "worst wins" approach over-flags benign indicators: a
        heuristic provider (e.g. OTX pulse counts) may report a weak ``LOW``
        for an artifact that an authoritative multi-engine provider (e.g.
        VirusTotal with ``0/75`` detections) has explicitly rated ``CLEAN``.

        Rules:

        1. Ignore providers that returned an error or ``UNKNOWN``.
        2. If an *authoritative* provider says ``CLEAN`` and no provider
           reports ``MEDIUM`` or worse, the indicator is ``CLEAN`` — a lone
           ``LOW`` heuristic signal is suppressed.
        3. Otherwise the aggregate is the worst *meaningful* verdict.
        """
        verdicts = [
            e.risk_level
            for e in self.enrichment
            if e.error is None and e.risk_level is not RiskLevel.UNKNOWN
        ]
        if not verdicts:
            return RiskLevel.UNKNOWN

        worst = max(verdicts, key=lambda r: r.rank)

        # Rule 2: authoritative CLEAN suppresses a lone LOW.
        authoritative_clean = any(
            e.risk_level is RiskLevel.CLEAN
            and e.provider in self._AUTHORITATIVE_PROVIDERS
            and e.error is None
            for e in self.enrichment
        )
        if authoritative_clean and worst.rank <= RiskLevel.LOW.rank:
            return RiskLevel.CLEAN

        return worst

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "type": self.ioc_type.value,
            "count": self.count,
            "sources": sorted(set(self.sources)),
            "risk_level": self.risk_level.value,
            "enrichment": [e.to_dict() for e in self.enrichment],
        }


@dataclass
class AnalysisReport:
    """The complete result of analyzing one or more input files."""

    indicators: Dict[IOCType, List[Indicator]] = field(default_factory=dict)
    source_files: List[str] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    tool_version: str = ""

    # --- Aggregation helpers ------------------------------------------------
    def all_indicators(self) -> List[Indicator]:
        """Flatten every indicator into a single list."""
        return [ioc for group in self.indicators.values() for ioc in group]

    @property
    def total_iocs(self) -> int:
        return len(self.all_indicators())

    def counts_by_type(self) -> Dict[str, int]:
        """Return ``{type_label: count}`` for charts and summaries."""
        return {
            t.label: len(self.indicators.get(t, []))
            for t in IOCType
            if self.indicators.get(t)
        }

    def counts_by_risk(self) -> Dict[str, int]:
        """Return ``{risk_label: count}`` across all indicators."""
        result: Dict[str, int] = {}
        for ioc in self.all_indicators():
            key = ioc.risk_level.value
            result[key] = result.get(key, 0) + 1
        return result

    def malicious_indicators(self) -> List[Indicator]:
        """Indicators rated MEDIUM or worse, sorted by severity."""
        flagged = [
            i
            for i in self.all_indicators()
            if i.risk_level.rank >= RiskLevel.MEDIUM.rank
        ]
        return sorted(flagged, key=lambda i: i.risk_level.rank, reverse=True)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to the schema described in the project specification."""
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for ioc_type, items in self.indicators.items():
            grouped.setdefault(ioc_type.label, [])
            grouped[ioc_type.label].extend(i.to_dict() for i in items)

        threat_intel: Dict[str, Any] = {}
        for ioc in self.all_indicators():
            if ioc.enrichment:
                threat_intel[ioc.value] = {
                    "type": ioc.ioc_type.value,
                    "risk_level": ioc.risk_level.value,
                    "providers": [e.to_dict() for e in ioc.enrichment],
                }

        return {
            "metadata": {
                "tool": "IOCForge",
                "version": self.tool_version,
                "generated_at": self.generated_at,
                "source_files": self.source_files,
                "total_iocs": self.total_iocs,
            },
            "indicators": grouped,
            "statistics": {
                "by_type": self.counts_by_type(),
                "by_risk": self.counts_by_risk(),
            },
            "Threat_Intelligence": threat_intel,
        }
