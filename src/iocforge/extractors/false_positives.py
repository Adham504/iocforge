"""False-positive reduction helpers.

Uses Python's :mod:`ipaddress` for robust IP validation instead of brittle
regex-only checks, and maintains curated lists of fake/benign domains.
"""
from __future__ import annotations

import ipaddress
from typing import Set

# Well-known benign file hashes that are NOT indicators of compromise.
# These are the digests of an *empty* (zero-byte) file in each algorithm.
# They appear in countless malware reports/OTX pulses as a harmless byproduct,
# which previously caused them to be mis-rated as malicious.
EMPTY_FILE_HASHES: Set[str] = {
    # empty-file MD5
    "d41d8cd98f00b204e9800998ecf8427e",
    # empty-file SHA1
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    # empty-file SHA256
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}

# A broader set of known-benign / placeholder hashes to ignore entirely.
KNOWN_BENIGN_HASHES: Set[str] = set(EMPTY_FILE_HASHES) | {
    # single newline ("\n") digests — frequently seen test artifacts
    "68b329da9893e34099c7d8ad5cb9c940",  # md5 of "\n"
    "adc83b19e793491b1c6ea0fd8b46cd9f32e592fc",  # sha1 of "\n"
    "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",  # sha256 "\n"
}


def is_benign_hash(value: str) -> bool:
    """Return ``True`` for hashes that are never genuine IoCs (e.g. empty file)."""
    return value.strip().lower() in KNOWN_BENIGN_HASHES


# Domains frequently used in examples, documentation, and test fixtures.
FAKE_DOMAINS: Set[str] = {
    "example.com",
    "example.org",
    "example.net",
    "example.edu",
    "test.com",
    "test.test",
    "domain.com",
    "yourdomain.com",
    "mydomain.com",
    "localhost",
    "localhost.localdomain",
    "foo.com",
    "bar.com",
    "foobar.com",
    "company.com",
    "email.com",
    "website.com",
    "sample.com",
    "invalid",
    "local",
    "lan",
    "home",
    "internal",
}

# Public-suffix-like noise that should never be treated as a domain on its own.
NON_DOMAIN_TLDS: Set[str] = {
    "py", "js", "ts", "md", "txt", "log", "csv", "json", "html", "htm",
    "exe", "dll", "doc", "docx", "pdf", "zip", "tar", "gz", "png", "jpg",
    "jpeg", "gif", "css", "php", "asp", "aspx", "jsp", "xml", "yml", "yaml",
    "ini", "cfg", "sh", "bat", "ps1", "go", "rs", "java", "class", "jar",
    "bin", "dat", "tmp", "bak", "old", "sql", "db",
}


def is_public_ip(value: str) -> bool:
    """Return ``True`` only for globally-routable, non-reserved IP addresses.

    Filters out (per the specification):
    private ranges, loopback, reserved, multicast, broadcast, link-local,
    unspecified and localhost addresses.
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_link_local
        or ip.is_unspecified
    ):
        return False

    # IPv4 broadcast.
    if isinstance(ip, ipaddress.IPv4Address) and value == "255.255.255.255":
        return False

    return ip.is_global


def is_fake_domain(domain: str) -> bool:
    """Return ``True`` if the domain is a known placeholder/benign example."""
    domain = domain.lower().rstrip(".")
    if domain in FAKE_DOMAINS:
        return True

    # Match a fake domain as a registrable suffix (e.g. mail.example.com).
    for fake in FAKE_DOMAINS:
        if domain.endswith("." + fake):
            return True

    tld = domain.rsplit(".", 1)[-1]
    if tld in NON_DOMAIN_TLDS:
        return True

    return False
