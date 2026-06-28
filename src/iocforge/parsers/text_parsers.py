"""Parsers for text-like formats: TXT, LOG, CSV, JSON, HTML."""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from iocforge.parsers.base import BaseParser, ParsedDocument
from iocforge.utils.logger import get_logger

logger = get_logger(__name__)


def _read_text(path: Path) -> str:
    """Read a file as UTF-8 text, tolerating decoding errors."""
    return path.read_text(encoding="utf-8", errors="replace")


class PlainTextParser(BaseParser):
    """Handle ``.txt`` and ``.log`` files (and anything text-like)."""

    extensions = (".txt", ".log", ".text", ".md", ".ini", ".cfg", ".conf")

    def parse(self, path: Path) -> ParsedDocument:
        return ParsedDocument(source=str(path), text=_read_text(path))


class CSVParser(BaseParser):
    """Flatten CSV rows into newline-separated text."""

    extensions = (".csv", ".tsv")

    def parse(self, path: Path) -> ParsedDocument:
        raw = _read_text(path)
        delimiter = "\t" if path.suffix.lower() == ".tsv" else ","
        lines: list[str] = []
        try:
            reader = csv.reader(io.StringIO(raw), delimiter=delimiter)
            for row in reader:
                lines.append(" ".join(cell for cell in row if cell))
        except csv.Error:
            logger.warning("CSV parse error for %s; falling back to raw text", path)
            lines.append(raw)
        return ParsedDocument(source=str(path), text="\n".join(lines))


class JSONParser(BaseParser):
    """Recursively stringify JSON keys and values."""

    extensions = (".json", ".ndjson", ".jsonl")

    def parse(self, path: Path) -> ParsedDocument:
        raw = _read_text(path)
        chunks: list[str] = []

        def walk(obj: object) -> None:
            if isinstance(obj, dict):
                for key, value in obj.items():
                    chunks.append(str(key))
                    walk(value)
            elif isinstance(obj, list):
                for item in obj:
                    walk(item)
            else:
                chunks.append(str(obj))

        try:
            walk(json.loads(raw))
        except json.JSONDecodeError:
            # Handle JSON-lines or invalid JSON by treating each line.
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    walk(json.loads(line))
                except json.JSONDecodeError:
                    chunks.append(line)
        return ParsedDocument(source=str(path), text="\n".join(chunks))


class HTMLParser(BaseParser):
    """Strip HTML tags, keeping visible text and href/src attributes."""

    extensions = (".html", ".htm", ".xhtml")

    def parse(self, path: Path) -> ParsedDocument:
        raw = _read_text(path)
        text = self._strip_html(raw)
        return ParsedDocument(source=str(path), text=text)

    @staticmethod
    def _strip_html(html: str) -> str:
        try:
            from bs4 import BeautifulSoup  # type: ignore

            soup = BeautifulSoup(html, "html.parser")
            # Preserve URLs hiding in attributes.
            attrs: list[str] = []
            for tag in soup.find_all(True):
                for attr in ("href", "src", "data-url", "action"):
                    if tag.has_attr(attr):
                        attrs.append(str(tag[attr]))
            return soup.get_text(separator="\n") + "\n" + "\n".join(attrs)
        except Exception:
            # Lightweight regex fallback if bs4 is unavailable.
            import re

            no_tags = re.sub(r"<[^>]+>", " ", html)
            return re.sub(r"&[a-zA-Z]+;", " ", no_tags)
