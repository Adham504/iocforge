"""Parser factory — auto-selects the correct parser for a file."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from iocforge.parsers.base import BaseParser, ParsedDocument
from iocforge.parsers.document_parsers import DOCXParser, PDFParser, ZIPParser
from iocforge.parsers.text_parsers import (
    CSVParser,
    HTMLParser,
    JSONParser,
    PlainTextParser,
)
from iocforge.utils.logger import get_logger

logger = get_logger(__name__)


class UnsupportedFileError(Exception):
    """Raised when no parser can handle the supplied file."""


class ParserFactory:
    """Maps file extensions to parser instances."""

    def __init__(self) -> None:
        self._parsers: List[BaseParser] = [
            PlainTextParser(),
            CSVParser(),
            JSONParser(),
            HTMLParser(),
            PDFParser(),
            DOCXParser(),
        ]
        # ZIP parser needs a reference back to this factory for recursion.
        self._parsers.append(ZIPParser(self))

        self._by_ext: Dict[str, BaseParser] = {}
        for parser in self._parsers:
            for ext in parser.extensions:
                self._by_ext[ext] = parser

    @property
    def supported_extensions(self) -> List[str]:
        return sorted(self._by_ext.keys())

    def supports(self, path: Path) -> bool:
        return path.suffix.lower() in self._by_ext

    def get_parser(self, path: Path) -> BaseParser:
        parser = self._by_ext.get(path.suffix.lower())
        if parser is None:
            # Fall back to plain text for unknown but readable files.
            logger.warning(
                "No dedicated parser for %s; treating as plain text", path.suffix
            )
            return PlainTextParser()
        return parser

    def parse(self, path: Path) -> ParsedDocument:
        """Parse ``path`` into a :class:`ParsedDocument`."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Input file does not exist: {path}")
        parser = self.get_parser(path)
        logger.info("Parsing %s with %s", path.name, parser.__class__.__name__)
        return parser.parse(path)


def parse_file(path: str | Path) -> ParsedDocument:
    """Convenience wrapper around :class:`ParserFactory`."""
    return ParserFactory().parse(Path(path))
