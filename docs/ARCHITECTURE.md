# IOCForge — Architecture

This document explains how IOCForge is structured and why, so contributors can
extend it confidently.

## Layered design

```
            ┌────────────────────────────────────────────┐
            │                   cli/                      │  user interface
            └───────────────────┬────────────────────────┘
                                │ uses
            ┌───────────────────▼────────────────────────┐
            │              core/engine.py                 │  orchestration
            └───┬──────────┬───────────┬──────────┬───────┘
                │          │           │          │
       ┌────────▼──┐ ┌─────▼─────┐ ┌───▼───────┐ ┌▼──────────┐
       │ parsers/  │ │extractors/│ │enrichment/│ │reporting/ │
       └───────────┘ └───────────┘ └───────────┘ └───────────┘
                │          │           │          │
            ┌───▼──────────▼───────────▼──────────▼───┐
            │              core/models.py             │  shared data model
            └─────────────────────────────────────────┘
                                │
            ┌───────────────────▼────────────────────┐
            │           config/  +  utils/            │  cross-cutting
            └─────────────────────────────────────────┘
```

## Responsibilities

| Layer | Responsibility | Key abstraction | Extension point |
|---|---|---|---|
| `parsers/` | file → text | `BaseParser` | `ParserFactory` |
| `extractors/` | text → raw IOCs (+ FP filtering) | `BaseExtractor` | `ExtractorRegistry` |
| `enrichment/` | IOC → Threat Intelligence | `BaseEnricher` | `EnrichmentManager` |
| `reporting/` | report → file | `BaseReporter` | `ReportManager` |
| `core/` | domain model + orchestration | `Indicator`, `IOCForgeEngine` | — |
| `cli/` | command-line UX | Typer `app` | new `@app.command()` |
| `config/` | settings + secrets | `Settings` | env variables |
| `utils/` | logging + banner | — | — |

## Key design decisions

1. **Strategy + Registry pattern everywhere.** Each variation (an IOC type, a
   file format, a TI provider, a report format) is a small class behind an
   abstract base, collected by a registry/factory/manager. This satisfies the
   Open/Closed Principle: new behavior is *added*, never *patched in*.

2. **`ipaddress` for IP validation.** Rather than trusting regex to reject
   private/reserved IPs, candidates are validated with the standard library,
   which understands every RFC special-use range.

3. **Hash-precedence masking.** SHA256 (64 hex) contains valid SHA1 (40) and
   MD5 (32) substrings; the registry extracts longest-first and masks matches
   so a single hash is never triple-counted.

4. **Fail-soft enrichment.** Network errors are captured *inside* the result
   object — a single unreachable provider never aborts the run.

5. **Self-contained HTML.** Charts are inline SVG and all CSS is embedded, so
   reports render offline and inside sandboxed iframes (no CDN/JS needed).

6. **Lazy engine import.** `core/__init__.py` exposes `IOCForgeEngine` via
   `__getattr__` to break the models ↔ engine import cycle.

## Adding a provider (worked example)

```python
# src/iocforge/enrichment/urlhaus.py
from iocforge.enrichment.base import BaseEnricher
from iocforge.core.models import IOCType, EnrichmentResult, RiskLevel

class URLHausEnricher(BaseEnricher):
    name = "URLHaus"
    supported_types = {IOCType.URL, IOCType.DOMAIN}

    def _query(self, value, ioc_type):
        resp = self.session.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": value}, timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()
        online = data.get("query_status") == "ok"
        return EnrichmentResult(
            provider=self.name, ioc_value=value,
            risk_level=RiskLevel.HIGH if online else RiskLevel.CLEAN,
            summary="Listed in URLHaus" if online else "Not in URLHaus",
            raw=data)
```

Then register it in `EnrichmentManager._build_default_enrichers`. Done.
