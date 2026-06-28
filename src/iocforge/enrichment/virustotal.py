"""VirusTotal v3 enricher.

Supports IPs, domains, URLs and file hashes. Returns reputation, the
malicious/total detection ratio, last-analysis date, categories and the count
of malicious votes.
"""
from __future__ import annotations

import base64
from typing import Set

from iocforge.core.models import EnrichmentResult, IOCType, RiskLevel
from iocforge.enrichment.base import BaseEnricher

_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalEnricher(BaseEnricher):
    name = "VirusTotal"
    supported_types: Set[IOCType] = {
        IOCType.IPV4,
        IOCType.IPV6,
        IOCType.DOMAIN,
        IOCType.URL,
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
    }

    @property
    def is_available(self) -> bool:
        return bool(self.api_key)

    def _endpoint(self, value: str, ioc_type: IOCType) -> str:
        if ioc_type in {IOCType.IPV4, IOCType.IPV6}:
            return f"{_BASE}/ip_addresses/{value}"
        if ioc_type is IOCType.DOMAIN:
            return f"{_BASE}/domains/{value}"
        if ioc_type is IOCType.URL:
            url_id = base64.urlsafe_b64encode(value.encode()).decode().strip("=")
            return f"{_BASE}/urls/{url_id}"
        # Hashes.
        return f"{_BASE}/files/{value}"

    def _query(self, value: str, ioc_type: IOCType) -> EnrichmentResult:
        headers = {"x-apikey": self.api_key or ""}
        resp = self.session.get(
            self._endpoint(value, ioc_type), headers=headers, timeout=self.timeout
        )
        if resp.status_code == 404:
            return EnrichmentResult(
                provider=self.name,
                ioc_value=value,
                risk_level=RiskLevel.UNKNOWN,
                summary="Not found in VirusTotal",
            )
        resp.raise_for_status()
        attributes = resp.json().get("data", {}).get("attributes", {})

        stats = attributes.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) or 0
        risk = self._risk_from_detections(malicious + suspicious, total)

        categories = attributes.get("categories", {})
        reputation = attributes.get("reputation")
        last_analysis = attributes.get("last_analysis_date")

        summary = (
            f"{malicious}/{total} engines flagged this as malicious"
            if total
            else "No analysis data"
        )

        return EnrichmentResult(
            provider=self.name,
            ioc_value=value,
            risk_level=risk,
            score=float(malicious),
            summary=summary,
            raw={
                "reputation": reputation,
                "detection_ratio": f"{malicious}/{total}",
                "malicious": malicious,
                "suspicious": suspicious,
                "total_engines": total,
                "last_analysis_date": last_analysis,
                "categories": list(categories.values())[:10]
                if isinstance(categories, dict)
                else categories,
                "malicious_votes": attributes.get("total_votes", {}).get(
                    "malicious"
                ),
            },
        )
