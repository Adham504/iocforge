"""Unit tests for IOC extractors and false-positive reduction."""
from __future__ import annotations

from iocforge.core.models import IOCType
from iocforge.extractors.false_positives import is_public_ip
from iocforge.extractors.hashes import MD5Extractor, SHA1Extractor, SHA256Extractor
from iocforge.extractors.misc import BitcoinExtractor, CVEExtractor, MitreExtractor
from iocforge.extractors.network import (
    DomainExtractor,
    EmailExtractor,
    IPv4Extractor,
    IPv6Extractor,
    URLExtractor,
)
from iocforge.extractors.registry import get_default_registry


def test_ipv4_filters_private_and_loopback():
    ext = IPv4Extractor()
    found = ext.find("Public 8.8.8.8, private 192.168.1.1, loopback 127.0.0.1")
    assert "8.8.8.8" in found
    assert "192.168.1.1" not in found
    assert "127.0.0.1" not in found


def test_is_public_ip_rules():
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("10.0.0.1") is False
    assert is_public_ip("169.254.0.1") is False  # link-local
    assert is_public_ip("224.0.0.1") is False     # multicast
    assert is_public_ip("255.255.255.255") is False  # broadcast
    assert is_public_ip("not-an-ip") is False


def test_ipv6_extraction():
    ext = IPv6Extractor()
    found = ext.find("callback 2001:db8:dead:beef::1337 ok")
    # 2001:db8::/32 is documentation range (reserved) -> filtered.
    # Use a global example instead:
    found2 = ext.find("addr 2606:4700:4700::1111 here")
    assert "2606:4700:4700::1111" in found2


def test_domain_skips_fakes_and_files():
    ext = DomainExtractor()
    found = ext.find("real evil-domain.ru fake example.com file script.py")
    assert "evil-domain.ru" in found
    assert "example.com" not in found
    assert "script.py" not in found


def test_url_extraction_and_cleanup():
    ext = URLExtractor()
    found = ext.find("see http://evil-domain.ru/path.php), then stop")
    assert "http://evil-domain.ru/path.php" in found


def test_email_extraction():
    ext = EmailExtractor()
    found = ext.find("attacker@evil-domain.ru and admin@example.com")
    assert "attacker@evil-domain.ru" in found
    assert "admin@example.com" not in found  # fake domain


def test_hash_extractors():
    # Use genuine (non empty-file) digests so they aren't filtered as benign.
    md5 = "44d88612fea8a8f36de82e1278abb02f"
    sha1 = "3395856ce81f2b7382dee72602f798b642f14140"
    sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    assert md5 in MD5Extractor().find(md5)
    assert sha1 in SHA1Extractor().find(sha1)
    assert sha256 in SHA256Extractor().find(sha256)


def test_misc_extractors():
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in BitcoinExtractor().find(
        "wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    )
    assert "CVE-2021-44228" in CVEExtractor().find("exploit cve-2021-44228 used")
    assert "T1059.001" in MitreExtractor().find("technique T1059.001 seen")


def test_registry_no_hash_double_counting():
    sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    registry = get_default_registry()
    results = registry.extract_all(f"hash {sha256}")
    assert sha256 in results.get(IOCType.SHA256, set())
    # The 64-char hash must NOT be re-counted as MD5/SHA1 fragments.
    assert not results.get(IOCType.MD5)
    assert not results.get(IOCType.SHA1)


def test_registry_refangs_defanged_text():
    registry = get_default_registry()
    results = registry.extract_all("c2 at hxxp://bad-evil[.]net/gate.php")
    urls = results.get(IOCType.URL, set())
    assert any("bad-evil.net" in u for u in urls)
