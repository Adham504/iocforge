"""AbuseIPDB enricher — best-in-class free IP reputation data.

AbuseIPDB provides a far richer free signal for IP addresses than OTX (abuse
confidence score, report count, ISP, country, usage type), so it is the
recommended provider for IPv4/IPv6 enrichment.
"""
from __future__ import annotations

from typing import Set

from iocforge.core.models import EnrichmentResult, IOCType, RiskLevel
from iocforge.enrichment.base import BaseEnricher

_BASE = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBEnricher(BaseEnricher):
    name = "AbuseIPDB"
    supported_types: Set[IOCType] = {IOCType.IPV4, IOCType.IPV6}

    @property
    def is_available(self) -> bool:
        return bool(self.api_key)

    def _query(self, value: str, ioc_type: IOCType) -> EnrichmentResult:
        headers = {"Key": self.api_key or "", "Accept": "application/json"}
        params = {"ipAddress": value, "maxAgeInDays": "90"}
        resp = self.session.get(
            _BASE, headers=headers, params=params, timeout=self.timeout
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})

        confidence = int(data.get("abuseConfidenceScore", 0))
        if confidence >= 80:
            risk = RiskLevel.CRITICAL
        elif confidence >= 50:
            risk = RiskLevel.HIGH
        elif confidence >= 20:
            risk = RiskLevel.MEDIUM
        elif confidence > 0:
            risk = RiskLevel.LOW
        else:
            risk = RiskLevel.CLEAN

        return EnrichmentResult(
            provider=self.name,
            ioc_value=value,
            risk_level=risk,
            score=float(confidence),
            summary=f"Abuse confidence {confidence}% "
            f"({data.get('totalReports', 0)} reports)",
            raw={
                "abuse_confidence_score": confidence,
                "total_reports": data.get("totalReports"),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "usage_type": data.get("usageType"),
                "is_tor": data.get("isTor"),
                "last_reported_at": data.get("lastReportedAt"),
            },
        )
