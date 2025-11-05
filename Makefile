.PHONY: help test scan fmt lint clean install

help:
	@echo "SPR{K}3 Platform - Development Commands"
	@echo "======================================"
	@echo "make install    - Install dependencies"
	@echo "make test       - Run test suite"
	@echo "make scan       - Run security scanner"
	@echo "make fmt        - Format code with ruff"
	@echo "make lint       - Lint code with ruff"
	@echo "make clean      - Clean build artifacts"

install:
	pip install -r requirements.txt
	pip install ruff pytest pytest-cov

test:
	python -m pytest tests/ -v

test-cov:
	python -m pytest tests/ -v --cov=sprk3_engine --cov-report=html --cov-report=term

scan:
	python3 scanners/production/sprk3_vulnerability_scanner_v45.py . \
		--format json \
		--exclude 'benchmarks/**' \
		--exclude '.git/**'

fmt:
	ruff format .

lint:
	ruff check .

clean:
	rm -rf __pycache__ .pytest_cache .coverage coverage.xml htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -f sprk3_scan_*.json sprk3_v*.sarif
