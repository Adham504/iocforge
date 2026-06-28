"""IOC extraction subsystem.

Each IOC type has its own extractor class implementing the
:class:`~iocforge.extractors.base.BaseExtractor` interface. The
:class:`~iocforge.extractors.registry.ExtractorRegistry` wires them together so
the engine can run them all over a body of text.
"""

from iocforge.extractors.base import BaseExtractor
from iocforge.extractors.registry import ExtractorRegistry, get_default_registry

__all__ = ["BaseExtractor", "ExtractorRegistry", "get_default_registry"]
