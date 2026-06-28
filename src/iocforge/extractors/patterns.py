"""Compiled regular expressions and normalization helpers for IOC extraction.

Many indicators in threat reports are *defanged* (e.g. ``hxxp://1[.]2[.]3[.]4``)
to prevent accidental clicks. :func:`refang` restores them before matching.
"""
from __future__ import annotations

import re

# --- Defang / refang ------------------------------------------------------
_REFANG_REPLACEMENTS = [
    (re.compile(r"h[xX]{2}p(s?)://", re.IGNORECASE), r"http\1://"),
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
    (re.compile(r"\{\.\}"), "."),
    (re.compile(r"\[dot\]", re.IGNORECASE), "."),
    (re.compile(r"\s+dot\s+", re.IGNORECASE), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[@\]"), "@"),
    (re.compile(r"\[at\]", re.IGNORECASE), "@"),
    (re.compile(r"\s+at\s+", re.IGNORECASE), "@"),
    (re.compile(r"\[//\]"), "//"),
]


def refang(text: str) -> str:
    """Convert defanged indicators back to their canonical form."""
    for pattern, replacement in _REFANG_REPLACEMENTS:
        text = pattern.sub(replacement, text)
    return text


# --- Core patterns --------------------------------------------------------
# IPv4 with optional CIDR awareness; validated later with ipaddress.
IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

# A comprehensive IPv6 matcher that handles "::" zero-compression and embedded
# IPv4 suffixes. Every candidate is still validated with ``ipaddress`` before
# being accepted, so the regex can afford to be permissive.
IPV6 = re.compile(
    r"""(?<![:.\w])(
        (?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}        # full 8 groups
      | (?:[A-F0-9]{1,4}:){1,7}:                   # leading groups then ::
      | (?:[A-F0-9]{1,4}:){1,6}:[A-F0-9]{1,4}
      | (?:[A-F0-9]{1,4}:){1,5}(?::[A-F0-9]{1,4}){1,2}
      | (?:[A-F0-9]{1,4}:){1,4}(?::[A-F0-9]{1,4}){1,3}
      | (?:[A-F0-9]{1,4}:){1,3}(?::[A-F0-9]{1,4}){1,4}
      | (?:[A-F0-9]{1,4}:){1,2}(?::[A-F0-9]{1,4}){1,5}
      | [A-F0-9]{1,4}:(?::[A-F0-9]{1,4}){1,6}
      | :(?:(?::[A-F0-9]{1,4}){1,7}|:)             # leading ::
      | (?:[A-F0-9]{1,4}:){1,4}:                    # trailing :: variants
        (?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)
    )(?:%[0-9A-Za-z]+)?(?![:.\w])""",
    re.IGNORECASE | re.VERBOSE,
)

# URLs (http/https/ftp). Captures until whitespace or common delimiters.
URL = re.compile(
    r"\b(?:https?|ftp)://[^\s\"'<>\)\]\}]+",
    re.IGNORECASE,
)

# Email addresses.
EMAIL = re.compile(
    r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,63}\b",
    re.IGNORECASE,
)

# Domains (a sequence of labels ending in a TLD). Validated against TLD length.
DOMAIN = re.compile(
    r"\b(?:[A-Z0-9](?:[A-Z0-9\-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}\b",
    re.IGNORECASE,
)

# File hashes — bounded by non-hex word boundaries to avoid mid-string matches.
MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Bitcoin: legacy (1/3) base58 and bech32 (bc1).
BITCOIN = re.compile(
    r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\b"
)

# CVE identifiers, e.g. CVE-2024-12345.
CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# MITRE ATT&CK technique IDs, e.g. T1059 or T1059.001.
MITRE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
