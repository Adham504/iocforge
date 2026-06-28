<div align="center">

```
██╗ ██████╗  ██████╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██║██╔═══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
██║██║   ██║██║     █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
██║██║   ██║██║     ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
██║╚██████╔╝╚██████╗██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
╚═╝ ╚═════╝  ╚═════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

# IOCForge

**Extract • Analyze • Enrich • Understand**

An advanced, production-ready Threat Intelligence utility that extracts
Indicators of Compromise (IoCs) from many file formats, removes false
positives, enriches them with live Threat Intelligence APIs, and produces
rich JSON / CSV / HTML / summary reports.

<!-- Generate this GIF with:  vhs docs/demo.tape  (see docs/شرح_عرض_الـGIF.md) -->
![IOCForge demo](docs/img/demo.gif)

![python](https://img.shields.io/badge/python-3.9%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![status](https://img.shields.io/badge/status-beta-orange)
![tests](https://img.shields.io/badge/tests-pytest-success)

</div>

---

## ✨ Features

- **Multi-format input** — TXT, LOG, CSV, JSON, HTML, PDF, DOCX, and ZIP
  archives (recursively). The right parser is chosen automatically.
- **11 IOC types** — IPv4, IPv6, Domains, URLs, Emails, MD5, SHA1, SHA256,
  Bitcoin wallets, CVE IDs, and MITRE ATT&CK technique IDs.
- **Defang/refang aware** — restores `hxxp://`, `[.]`, `[at]`, etc. before
  extraction.
- **Smart false-positive reduction** — private / loopback / reserved /
  multicast / broadcast / link-local IPs are filtered with Python's
  `ipaddress` library (not brittle regex). Fake/example domains, invalid
  hashes, ubiquitous-but-benign digests (e.g. the **empty-file hash**), and
  duplicates are removed.
- **Threat Intelligence enrichment** — VirusTotal, AlienVault OTX, AbuseIPDB,
  ThreatFox & MalwareBazaar (abuse.ch). Runs concurrently and degrades
  gracefully when keys are missing.
- **Evidence-weighted risk scoring** — verdicts from multiple providers are
  aggregated intelligently: an authoritative multi-engine **CLEAN** (e.g.
  VirusTotal `0/75`) suppresses a lone weak heuristic signal, so benign
  artifacts are not falsely flagged. OTX pulse counts only escalate risk when
  backed by real malware-family / APT context.
- **Color-coded console + reports** — the terminal summary is ANSI-colored by
  risk level (respects `NO_COLOR` / non-TTY), and the HTML report is
  color-coded Clean → Critical.
- **Four report formats** — machine-readable JSON, spreadsheet CSV, a
  console/plain-text executive summary, and a **self-contained interactive
  HTML dashboard**. The dashboard works fully offline (inline CSS / SVG / JS —
  no CDNs) and features:
  - an executive **verdict banner** and animated **risk-score gauge**,
  - KPI stat cards, an animated bar chart and a hoverable risk donut,
  - **live search**, **risk filter chips**, **per-column sorting**, and
    **one-click copy** for any indicator,
  - a **light / dark theme toggle**, sticky table headers, collapsible
    sections, type icons, keyboard focus styles and a print stylesheet.
- **Professional CLI** built with Typer, with an ASCII banner, `--version`,
  and `info` / `formats` subcommands.
- **Secure config** — API keys loaded from `.env`, never hardcoded.
- **Extensible architecture** — add new extractors, parsers, enrichers, or
  reporters by implementing one base class and registering it.
- **Tested** — a pytest suite covers extractors, parsers, the engine,
  enrichment (mocked), and reporting.

---

## 📦 Installation

```bash
# 1) Clone
git clone https://github.com/your-username/iocforge.git
cd iocforge

# 2) Create a virtual environment
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 3) Install
pip install -r requirements.txt
# …or install as a package (gives you the `iocforge` command):
pip install -e .

# 4) Configure API keys (optional, for enrichment)
cp .env.example .env
# then edit .env and paste your keys
```

> **No API keys?** No problem. IOCForge still extracts, cleans, and reports
> every IOC offline — enrichment simply gets skipped.

---

## 🚀 Quick Start

```bash
# Analyze a single file (all report formats, enrichment on)
iocforge analyze examples/sample_report.txt

# Offline extraction only, multiple files
iocforge analyze logs.log report.html data.json --no-enrich

# Pick specific formats and an output directory
iocforge analyze threat_report.pdf -f html -f json -o out/

# Show capabilities & loaded APIs
iocforge info

# Version / help
iocforge --version
iocforge --help
```

If you have **not** installed the package, run via the module instead:

```bash
PYTHONPATH=src python -m iocforge.cli.main analyze examples/sample_report.txt --no-enrich
```

---

## 🧪 Usage Examples

```bash
# Extract IOCs from a malware analysis PDF and enrich them
iocforge analyze cases/incident-42.pdf -o cases/reports

# Bulk-process a ZIP of artifacts (recurses into supported files)
iocforge analyze evidence_bundle.zip

# Generate only the HTML dashboard
iocforge analyze report.html -f html
```

Sample console output (summary):

```
IOCs by type
  Domain           5
  URL              3
  MITRE ATT&CK     3
  ...
Flagged indicators (MEDIUM+): 2
  [CRITICAL] IPv4     45.137.21.53
             └─ Abuse confidence 95% (42 reports)
```

---

## 🖼️ Screenshots

> _Placeholders — drop real screenshots into `docs/img/` before publishing._

| ASCII Banner | HTML Dashboard | CSV in Excel |
|---|---|---|
| `docs/img/banner.png` | `docs/img/html_report.png` | `docs/img/csv_report.png` |

---

## 🏗️ Project Architecture

```
iocforge/
├── src/iocforge/
│   ├── cli/            # Typer command-line interface
│   ├── config/         # Settings dataclass + .env loading
│   ├── core/           # Domain models + analysis engine (the orchestrator)
│   ├── parsers/        # File → text (TXT/LOG/CSV/JSON/HTML/PDF/DOCX/ZIP)
│   ├── extractors/     # text → raw IOCs (+ false-positive reduction)
│   ├── enrichment/     # IOCs → Threat Intelligence (VT/OTX/AbuseIPDB/abuse.ch)
│   ├── reporting/      # AnalysisReport → JSON/CSV/HTML/summary
│   └── utils/          # logging + ASCII banner
├── tests/              # pytest suite
├── examples/           # sample input files
├── docs/               # extra documentation
├── config.py           # convenience shim for `from config import get_settings`
├── pyproject.toml      # packaging + tool config
├── requirements.txt
├── .env.example
└── LICENSE
```

### Data flow

```
 ┌────────┐   ┌──────────────┐   ┌───────────────────┐   ┌──────────────────┐   ┌──────────────┐
 │ files  │──▶│ ParserFactory│──▶│ ExtractorRegistry │──▶│ EnrichmentManager│──▶│ ReportManager│
 └────────┘   └──────────────┘   └───────────────────┘   └──────────────────┘   └──────────────┘
   any           plain text          Indicator objects        risk scoring         JSON/CSV/HTML
   format                            (deduped + counted)       (concurrent)         /summary
```

### Design principles

- **SOLID** — each extractor / parser / enricher / reporter is a small class
  behind an abstract base (Open/Closed, Single-Responsibility).
- **Dependency inversion** — the engine depends on interfaces, so providers can
  be swapped or mocked (the test suite mocks every network call).
- **PEP 8 + type hints + dataclasses + docstrings** throughout.

---

## 🔌 Threat Intelligence Providers

| Provider | IOC types | Key required | Notes |
|---|---|---|---|
| **VirusTotal** v3 | IP, domain, URL, hashes | yes | reputation, detection ratio, categories, votes |
| **AbuseIPDB** | IP | yes | best free IP reputation (confidence score, ISP, country) |
| **AlienVault OTX** | IP, domain, URL, hashes | yes | pulses, malware families, APT groups, tags |
| **ThreatFox** (abuse.ch) | IP, domain, URL, hashes | Auth-Key | malware family + threat type |
| **MalwareBazaar** (abuse.ch) | hashes | Auth-Key | malware signature, tags, delivery method |

> **Recommendation:** for IP enrichment, **AbuseIPDB** gives the richest free
> signal, so IOCForge prefers it for IPs while still cross-checking VirusTotal
> and OTX. For file hashes, **MalwareBazaar** + **VirusTotal** give the best
> coverage.

---

## ⚙️ Configuration

All configuration is environment-driven (`.env` or real env vars):

| Variable | Default | Meaning |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | – | VirusTotal v3 key |
| `OTX_API_KEY` | – | AlienVault OTX key |
| `ABUSEIPDB_API_KEY` | – | AbuseIPDB key |
| `ABUSECH_API_KEY` | – | abuse.ch Auth-Key (ThreatFox/MalwareBazaar) |
| `ENABLE_ENRICHMENT` | `true` | master switch for network calls |
| `REQUEST_TIMEOUT` | `20` | per-request timeout (s) |
| `RATE_LIMIT_DELAY` | `1` | delay between requests (s) |
| `LOG_LEVEL` | `INFO` | DEBUG/INFO/WARNING/ERROR |

---

## 🪵 Logging

A rotating log is written to `logs/application.log` (5 MB × 3 backups) and a
concise view is echoed to the console. Levels: DEBUG, INFO, WARNING, ERROR.

---

## ✅ Testing

```bash
pip install -r requirements-dev.txt
pytest                  # run the suite
pytest --cov=iocforge   # with coverage
```

The suite covers extraction & false-positive logic, every parser (including
ZIP recursion), the end-to-end engine, mocked enrichment providers, and all
four reporters.

---

## 🗺️ Roadmap

- [ ] STIX 2.1 / TAXII export
- [ ] YARA & Sigma rule generation from extracted IOCs
- [ ] Streamlit web dashboard
- [ ] REST API (FastAPI) + Docker image
- [ ] MISP, Microsoft Sentinel, Splunk, Elastic & QRadar integrations
- [ ] URLHaus & Shodan enrichers
- [ ] WHOIS / passive-DNS context
- [ ] Caching layer to avoid repeat lookups

---

## 🔭 Future Extensibility

The architecture is designed so each of the items above is a *drop-in*:

- **New IOC type** → subclass `BaseExtractor`, register it in the registry.
- **New input format** → subclass `BaseParser`, add it to `ParserFactory`.
- **New TI provider** → subclass `BaseEnricher`, add it to `EnrichmentManager`.
- **New output format** → subclass `BaseReporter`, add it to `ReportManager`.

No existing code needs to change (Open/Closed Principle).

---

## 🌍 Arabic Developer Guide

A full beginner-friendly Arabic explanation of every file, function, and
important code block lives in **[`docs/شرح_الكود_بالعربية.md`](docs/شرح_الكود_بالعربية.md)**.

---

## ⚠️ Disclaimer

IOCForge is intended for **authorized** security research, DFIR, and threat
intelligence work only. You are responsible for complying with the terms of
service of any API you query and with all applicable laws.

---

## 📄 License

Released under the [MIT License](LICENSE).
# iocforge
# iocforge
