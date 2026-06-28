"""abuse.ch ThreatFox + MalwareBazaar enrichers.

ThreatFox (IOC reputation) and MalwareBazaar (file-hash intel) are free
abuse.ch services. ThreatFox covers IPs/domains/URLs/hashes while
MalwareBazaar specializes in file hashes (malware family, signature, tags).

As of late 2024 abuse.ch requires a free Auth-Key for its APIs; if one is not
configured the enricher reports itself as unavailable.
"""
from __future__ import annotations

from typing import Set

from iocforge.core.models import EnrichmentResult, IOCType, RiskLevel
from iocforge.enrichment.base import BaseEnricher

_THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
_MALWAREBAZAAR = "https://mb-api.abuse.ch/api/v1/"


class ThreatFoxEnricher(BaseEnricher):
    name = "ThreatFox"
    supported_types: Set[IOCType] = {
        IOCType.IPV4,
        IOCType.DOMAIN,
        IOCType.URL,
        IOCType.MD5,
        IOCType.SHA1,
        IOCType.SHA256,
    }

    @property
    def is_available(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> dict:
        return {"Auth-Key": self.api_key} if self.api_key else {}

    def _query(self, value: str, ioc_type: IOCType) -> EnrichmentResult:
        payload = {"query": "search_ioc", "search_term": value}
        resp = self.session.post(
            _THREATFOX, json=payload, headers=self._headers(), timeout=self.timeout
        )
        resp.raise_for_status()
        body = resp.json()
        if body.get("query_status") != "ok" or not body.get("data"):
            return EnrichmentResult(
                provider=self.name,
                ioc_value=value,
                risk_level=RiskLevel.CLEAN,
                summary="No ThreatFox match",
            )

        entries = body["data"]
        malware = sorted({e.get("malware_printable") for e in entries if e.get("malware_printable")})
        threat_types = sorted({e.get("threat_type") for e in entries if e.get("threat_type")})
        tags: set[str] = set()
        for e in entries:
            for t in e.get("tags") or []:
                tags.add(str(t))

        return EnrichmentResult(
            provider=self.name,
            ioc_value=value,
            risk_level=RiskLevel.HIGH,
            score=float(len(entries)),
            summary=f"ThreatFox: {', '.join(malware) or 'known malicious IOC'}",
            raw={
                "matches": len(entries),
                "malware_families": malware[:10],
                "threat_types": threat_types[:10],
                "tags": sorted(tags)[:15],
            },
        )


class MalwareBazaarEnricher(BaseEnricher):
    name = "MalwareBazaar"
    supported_types: Set[IOCType] = {IOCType.MD5, IOCType.SHA1, IOCType.SHA256}

    @property
    def is_available(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> dict:
        return {"Auth-Key": self.api_key} if self.api_key else {}

    def _query(self, value: str, ioc_type: IOCType) -> EnrichmentResult:
        data = {"query": "get_info", "hash": value}
        resp = self.session.post(
            _MALWAREBAZAAR, data=data, headers=self._headers(), timeout=self.timeout
        )
        resp.raise_for_status()
        body = resp.json()
        if body.get("query_status") != "ok" or not body.get("data"):
            return EnrichmentResult(
                provider=self.name,
                ioc_value=value,
                risk_level=RiskLevel.CLEAN,
                summary="No MalwareBazaar match",
            )

        info = body["data"][0]
        return EnrichmentResult(
            provider=self.name,
            ioc_value=value,
            risk_level=RiskLevel.CRITICAL,
            score=100.0,
            summary=f"Known malware: {info.get('signature') or 'unclassified'}",
            raw={
                "file_name": info.get("file_name"),
                "file_type": info.get("file_type"),
                "signature": info.get("signature"),
                "tags": info.get("tags"),
                "first_seen": info.get("first_seen"),
                "delivery_method": info.get("delivery_method"),
            },
        )
