# IOCForge — Quick Start

A 5-minute path from zero to your first report.

## 1. Install

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[parsers]"        # installs the `iocforge` command + parsers
```

## 2. (Optional) Add API keys for enrichment

```bash
cp .env.example .env
# edit .env and paste any keys you have (all optional)
```

| Key | Where to get a FREE key |
|---|---|
| `VIRUSTOTAL_API_KEY` | https://www.virustotal.com/gui/my-apikey |
| `ABUSEIPDB_API_KEY`  | https://www.abuseipdb.com/account/api |
| `OTX_API_KEY`        | https://otx.alienvault.com/api |
| `ABUSECH_API_KEY`    | https://auth.abuse.ch/ |

> No keys? IOCForge still extracts & reports everything offline — use `--no-enrich`.

## 3. Run

```bash
# Offline (no keys needed)
iocforge analyze examples/sample_report.txt --no-enrich

# With enrichment (needs keys in .env)
iocforge analyze examples/sample_report.txt

# Multiple files + choose formats + output folder
iocforge analyze a.pdf b.log c.json -f html -f json -o reports/
```

## 4. Read the output

Reports land in `reports/` (or your `-o` folder):

- `iocforge_report.html`  → open in a browser (interactive dashboard)
- `iocforge_report.json`  → machine-readable
- `iocforge_report.csv`   → open in Excel
- `iocforge_report.txt`   → quick summary

## Useful commands

```bash
iocforge --help
iocforge --version
iocforge info        # shows loaded APIs + capabilities
iocforge formats     # lists supported input formats
```
