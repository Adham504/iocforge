"""File parsing subsystem.

Parsers turn input files of various formats into plain text that extractors can
process. The :class:`~iocforge.parsers.factory.ParserFactory` auto-selects the
right parser based on file extension / content.
"""

from iocforge.parsers.factory import ParserFactory, parse_file

__all__ = ["ParserFactory", "parse_file"]
