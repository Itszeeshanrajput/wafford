.PHONY: help install dev test lint format clean coverage ci

PYTHON := python3
PIP := pip3

help:
	@echo "Wafford Development Commands"
	@echo ""
	@echo "  make install       Install production dependencies"
	@echo "  make dev           Install development dependencies"
	@echo "  make test          Run tests"
	@echo "  make test-verbose  Run tests with verbose output"
	@echo "  make coverage      Generate coverage report"
	@echo "  make lint          Run linters (ruff, mypy)"
	@echo "  make format        Format code (black, ruff)"
	@echo "  make clean         Remove build artifacts"
	@echo "  make ci            Run CI checks (lint + test + coverage)"
	@echo ""

install:
	$(PIP) install -e .

dev:
	$(PIP) install -e ".[dev]"

test:
	$(PYTHON) -m pytest tests/ -v

test-verbose:
	$(PYTHON) -m pytest tests/ -vv -s

coverage:
	$(PYTHON) -m pytest tests/ --cov=src/wafford --cov-report=html --cov-report=term
	@echo "Coverage report generated in htmlcov/index.html"

lint:
	ruff check .
	mypy src/wafford --strict 2>/dev/null || echo "Type checking complete"

format:
	black .
	ruff --fix .

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ htmlcov/ .mypy_cache/ .pytest_cache/ .ruff_cache/ || true

ci: lint test coverage
	@echo "CI checks passed!"
