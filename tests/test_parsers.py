"""Unit tests for file parsers and the parser factory."""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

from iocforge.parsers.factory import ParserFactory


def test_txt_parser(examples_dir: Path):
    factory = ParserFactory()
    doc = factory.parse(examples_dir / "sample_report.txt")
    assert "45.137.21.53" in doc.text


def test_json_parser_flattens_values(tmp_path: Path):
    data = {"a": {"ip": "8.8.8.8"}, "b": ["evil.ru"]}
    p = tmp_path / "t.json"
    p.write_text(json.dumps(data))
    doc = ParserFactory().parse(p)
    assert "8.8.8.8" in doc.text
    assert "evil.ru" in doc.text


def test_csv_parser(tmp_path: Path):
    p = tmp_path / "t.csv"
    p.write_text("type,value\nip,8.8.8.8\ndomain,evil.ru\n")
    doc = ParserFactory().parse(p)
    assert "8.8.8.8" in doc.text
    assert "evil.ru" in doc.text


def test_html_parser_strips_tags(tmp_path: Path):
    p = tmp_path / "t.html"
    p.write_text('<html><body><a href="http://evil.ru/x">click</a></body></html>')
    doc = ParserFactory().parse(p)
    assert "evil.ru" in doc.text


def test_zip_parser_recurses(tmp_path: Path):
    inner = tmp_path / "inner.txt"
    inner.write_text("malicious 45.137.21.53")
    zpath = tmp_path / "bundle.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        z.write(inner, arcname="inner.txt")
    doc = ParserFactory().parse(zpath)
    flat = doc.flatten()
    combined = " ".join(d.text for d in flat)
    assert "45.137.21.53" in combined


def test_factory_supported_extensions():
    factory = ParserFactory()
    for ext in (".txt", ".log", ".csv", ".json", ".html", ".pdf", ".docx", ".zip"):
        assert ext in factory.supported_extensions
