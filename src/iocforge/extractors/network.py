"""Network IOC extractors: IPv4, IPv6, Domain, URL, Email."""
from __future__ import annotations

import ipaddress
from typing import List
from urllib.parse import urlparse

from iocforge.core.models import IOCType
from iocforge.extractors import patterns
from iocforge.extractors.base import BaseExtractor
from iocforge.extractors.false_positives import is_fake_domain, is_public_ip


class IPv4Extractor(BaseExtractor):
    """Extract public IPv4 addresses."""

    ioc_type = IOCType.IPV4

    def extract(self, text: str) -> List[str]:
        return patterns.IPV4.findall(text)

    def is_valid(self, candidate: str) -> bool:
        return is_public_ip(candidate)


class IPv6Extractor(BaseExtractor):
    """Extract public IPv6 addresses."""

    ioc_type = IOCType.IPV6

    def extract(self, text: str) -> List[str]:
        return patterns.IPV6.findall(text)

    def normalize(self, candidate: str) -> str:
        candidate = candidate.split("%")[0].strip()
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            return candidate

    def is_valid(self, candidate: str) -> bool:
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            return False
        return isinstance(ip, ipaddress.IPv6Address) and is_public_ip(candidate)


class DomainExtractor(BaseExtractor):
    """Extract domain names, skipping fake/example domains and bare files."""

    ioc_type = IOCType.DOMAIN

    def extract(self, text: str) -> List[str]:
        return patterns.DOMAIN.findall(text)

    def normalize(self, candidate: str) -> str:
        return candidate.strip().strip(".").lower()

    def is_valid(self, candidate: str) -> bool:
        if len(candidate) > 253:
            return False
        # A pure IPv4 would also match the domain regex via the last label.
        try:
            ipaddress.ip_address(candidate)
            return False
        except ValueError:
            pass
        return not is_fake_domain(candidate)


class URLExtractor(BaseExtractor):
    """Extract URLs."""

    ioc_type = IOCType.URL

    def extract(self, text: str) -> List[str]:
        return patterns.URL.findall(text)

    def normalize(self, candidate: str) -> str:
        # Strip common trailing punctuation that bleeds into matches.
        return candidate.rstrip(".,;:!?\"')]}>").strip()

    def is_valid(self, candidate: str) -> bool:
        try:
            parsed = urlparse(candidate)
        except ValueError:
            return False
        if not parsed.scheme or not parsed.netloc:
            return False
        host = parsed.hostname or ""
        # Allow IP-based URLs; only filter clearly-fake hostnames.
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return not is_fake_domain(host)


class EmailExtractor(BaseExtractor):
    """Extract email addresses."""

    ioc_type = IOCType.EMAIL

    def extract(self, text: str) -> List[str]:
        return patterns.EMAIL.findall(text)

    def normalize(self, candidate: str) -> str:
        return candidate.strip().lower()

    def is_valid(self, candidate: str) -> bool:
        try:
            _, domain = candidate.rsplit("@", 1)
        except ValueError:
            return False
        return not is_fake_domain(domain)
