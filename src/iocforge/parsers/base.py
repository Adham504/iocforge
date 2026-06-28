"""Base parser definitions."""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


@dataclass
class ParsedDocument:
    """The text content extracted from one logical input file."""

    source: str
    text: str
    children: List["ParsedDocument"] = field(default_factory=list)

    def flatten(self) -> List["ParsedDocument"]:
        """Return this document and all nested children (e.g. from a ZIP)."""
        docs = [self]
        for child in self.children:
            docs.extend(child.flatten())
        return docs


class BaseParser(abc.ABC):
    """Interface every file parser implements."""

    #: File extensions (lowercase, with dot) this parser handles.
    extensions: tuple[str, ...] = ()

    @abc.abstractmethod
    def parse(self, path: Path) -> ParsedDocument:
        """Read ``path`` and return its textual content."""

    def can_parse(self, path: Path) -> bool:
        return path.suffix.lower() in self.extensions
