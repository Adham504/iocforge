"""AlienVault OTX enricher.

Retrieves pulse counts, threat/malware families, APT/adversary groups and tags
for IPs, domains, URLs and hashes.
"""
from __future__ import annotations

from typing import Set

from iocforge.core.models import EnrichmentResult, IOCType, RiskLevel
from iocforge.enrichment.base import BaseEnricher

_BASE = "https://otx.alienvault.com/api/v1/indicators"


class OTXEnricher(BaseEnricher):
    name = "AlienVault OTX"
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

    def _section(self, ioc_type: IOCType) -> str:
        return {
            IOCType.IPV4: "IPv4",
            IOCType.IPV6: "IPv6",
            IOCType.DOMAIN: "domain",
            IOCType.URL: "url",
            IOCType.MD5: "file",
            IOCType.SHA1: "file",
            IOCType.SHA256: "file",
        }[ioc_type]

    def _query(self, value: str, ioc_type: IOCType) -> EnrichmentResult:
        section = self._section(ioc_type)
        url = f"{_BASE}/{section}/{value}/general"
        headers = {"X-OTX-API-KEY": self.api_key or ""}
        resp = self.session.get(url, headers=headers, timeout=self.timeout)
        if resp.status_code == 404:
            return EnrichmentResult(
                provider=self.name,
                ioc_value=value,
                risk_level=RiskLevel.UNKNOWN,
                summary="Not found in OTX",
            )
        resp.raise_for_status()
        data = resp.json()

        pulse_info = data.get("pulse_info", {})
        pulse_count = int(pulse_info.get("count", 0))
        pulses = pulse_info.get("pulses", [])

        # OTX's own false-positive / whitelist signal. When present this means
        # the indicator was reviewed and considered benign (e.g. the empty-file
        # hash, public DNS resolvers, CDN ranges), regardless of pulse count.
        validation = pulse_info.get("validation") or data.get("validation") or []
        is_whitelisted = bool(validation)
        if isinstance(data.get("false_positive"), list) and data["false_positive"]:
            is_whitelisted = True

        malware_families: set[str] = set()
        adversaries: set[str] = set()
        tags: set[str] = set()
        for pulse in pulses:
            for mf in pulse.get("malware_families", []) or []:
                name = mf.get("display_name") if isinstance(mf, dict) else mf
                if name:
                    malware_families.add(str(name))
            if pulse.get("adversary"):
                adversaries.add(str(pulse["adversary"]))
            for tag in pulse.get("tags", []) or []:
                tags.add(str(tag))

        # --- Conservative, evidence-based risk scoring -----------------------
        # Pulse *count* alone is a weak signal: ubiquitous-but-benign artifacts
        # (empty-file hashes, public resolvers) appear in many pulses. So we
        # cap a count-only signal at LOW and only escalate when OTX provides
        # corroborating evidence (named malware family or APT/adversary).
        has_corroboration = bool(malware_families or adversaries)

        if is_whitelisted:
            # OTX flagged this indicator as a known false positive / whitelisted.
            risk = RiskLevel.CLEAN
        elif pulse_count == 0:
            risk = RiskLevel.CLEAN
        elif has_corroboration:
            # Real attribution present -> trust the pulse volume more.
            if pulse_count >= 5 or len(adversaries) >= 1:
                risk = RiskLevel.HIGH
            else:
                risk = RiskLevel.MEDIUM
        else:
            # Referenced in pulses but with no malware/APT context: treat as a
            # low-confidence informational signal, never HIGH on its own.
            risk = RiskLevel.LOW

        if is_whitelisted:
            summary = "Whitelisted / known false positive in OTX"
        elif pulse_count:
            evidence = ", ".join(sorted(malware_families)) or "no malware context"
            summary = f"Referenced in {pulse_count} OTX pulse(s) ({evidence})"
        else:
            summary = "No OTX pulses reference this indicator"

        return EnrichmentResult(
            provider=self.name,
            ioc_value=value,
            risk_level=risk,
            score=float(pulse_count),
            summary=summary,
            raw={
                "pulse_count": pulse_count,
                "whitelisted": is_whitelisted,
                "validation": validation,
                "malware_families": sorted(malware_families)[:10],
                "apt_groups": sorted(adversaries)[:10],
                "tags": sorted(tags)[:15],
            },
        )
