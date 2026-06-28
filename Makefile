# Convenience commands for IOCForge development.
.PHONY: help install dev test cov lint format type run clean

help:
	@echo "install  - install runtime deps"
	@echo "dev      - install dev + parser extras (editable)"
	@echo "test     - run the test suite"
	@echo "cov      - run tests with coverage"
	@echo "lint     - ruff lint"
	@echo "format   - black format"
	@echo "type     - mypy type-check"
	@echo "run      - analyze the bundled examples (offline)"
	@echo "clean    - remove caches and generated reports"

install:
	pip install -r requirements.txt

dev:
	pip install -e ".[dev,parsers]"

test:
	pytest

cov:
	pytest --cov=iocforge --cov-report=term-missing

lint:
	ruff check src tests

format:
	black src tests

type:
	mypy src

run:
	iocforge analyze examples/sample_report.txt examples/sample_logs.log examples/sample_iocs.json --no-enrich

clean:
	rm -rf reports .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
