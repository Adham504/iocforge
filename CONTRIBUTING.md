# Contributing to IOCForge

Thanks for your interest in improving IOCForge! 🎉

## Getting set up

```bash
git clone https://github.com/your-username/iocforge.git
cd iocforge
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,parsers]"   # or: pip install -r requirements-dev.txt
```

## Before you open a PR

```bash
ruff check src tests        # lint
black src tests             # format
mypy src                    # type-check
pytest --cov=iocforge       # tests + coverage
```

## Guidelines

- Follow PEP 8, keep functions small, and add type hints + docstrings.
- New behavior should be added behind the existing base classes
  (`BaseExtractor`, `BaseParser`, `BaseEnricher`, `BaseReporter`) — see
  `docs/ARCHITECTURE.md`.
- Every new feature needs a test. Network calls **must** be mocked.
- Never commit secrets. `.env` is git-ignored; use `.env.example` for new keys.

## Reporting issues

Please include: the command you ran, the input file type, the expected vs.
actual behavior, and any relevant lines from `logs/application.log`.
