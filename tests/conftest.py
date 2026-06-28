"""Shared pytest fixtures."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure the src/ layout is importable without an editable install.
SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


@pytest.fixture
def sample_text() -> str:
    return (
        "Malicious IP 45.137.21.53 and benign 192.168.1.1, loopback 127.0.0.1. "
        "URL http://evil-domain.ru/x.php domain evil-domain.ru "
        "email attacker@evil-domain.ru fake admin@example.com "
        "md5 44d88612fea8a8f36de82e1278abb02f "
        "sha256 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f "
        "wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa "
        "cve CVE-2021-44228 mitre T1059.001 "
        "defanged hxxp://bad[.]example-evil[.]net/gate ipv6 2001:db8:dead:beef::1337"
    )


@pytest.fixture
def examples_dir() -> Path:
    return EXAMPLES
