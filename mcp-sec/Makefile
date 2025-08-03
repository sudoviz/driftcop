# Makefile for MCP Security Scanner
.PHONY: help install install-dev test lint format clean build upload-test upload docker

# Default target
help:
	@echo "MCP Security Scanner - Development Commands"
	@echo "==========================================="
	@echo ""
	@echo "Setup commands:"
	@echo "  install      Install package"
	@echo "  install-dev  Install package in development mode"
	@echo "  setup        Run setup script"
	@echo ""
	@echo "Development commands:"
	@echo "  test         Run tests"
	@echo "  test-cov     Run tests with coverage"
	@echo "  lint         Run linting"
	@echo "  format       Format code"
	@echo "  type-check   Run type checking"
	@echo ""
	@echo "Build commands:"
	@echo "  clean        Clean build artifacts"
	@echo "  build        Build wheel and source distribution"
	@echo "  build-wheel  Build wheel only"
	@echo "  build-exe    Build standalone executable"
	@echo ""
	@echo "Release commands:"
	@echo "  upload-test  Upload to test PyPI"
	@echo "  upload       Upload to PyPI"
	@echo "  docker       Build Docker image"
	@echo ""
	@echo "CLI commands:"
	@echo "  scan-server  Example: scan a server"
	@echo "  scan-workspace Example: scan workspace"
	@echo "  scan-deps    Example: scan dependencies"

# Setup
setup:
	@chmod +x setup.sh
	@./setup.sh

install:
	pip install .

install-dev:
	pip install -e ".[dev]"

# Testing
test:
	python -m pytest tests/ -v

test-cov:
	python -m pytest tests/ --cov=mcp_sec --cov-report=html --cov-report=term

test-watch:
	python -m pytest tests/ -f

# Code quality
lint:
	@echo "Running ruff..."
	ruff check src tests
	@echo "Running mypy..."
	mypy src/mcp_sec

format:
	@echo "Formatting with ruff..."
	ruff format src tests
	@echo "Sorting imports..."
	ruff check --select I --fix src tests

type-check:
	mypy src/mcp_sec

# Build
clean:
	python package.py --clean

build: clean
	python package.py --wheel --sdist

build-wheel: clean
	python package.py --wheel

build-exe:
	python package.py --standalone

# Release
upload-test: build
	twine check dist/*
	twine upload --repository testpypi dist/*

upload: build
	twine check dist/*
	twine upload dist/*

# Docker
docker:
	python package.py --docker

docker-run:
	docker run -v $(PWD):/workspace mcp-sec:latest --help

# Development examples
scan-server:
	mcp-sec scan-server https://api.github.com/repos/modelcontextprotocol/servers/contents/examples/filesystem/manifest.json

scan-workspace:
	mcp-sec scan-workspace examples/test-workspace

scan-deps:
	mcp-sec scan-deps examples/test-workspace

# CI/CD simulation
ci-test:
	make lint
	make type-check
	make test-cov
	make build

# Quick development cycle
dev: format lint test

# Release preparation
prepare-release:
	@echo "Preparing release..."
	@echo "1. Update version in pyproject.toml"
	@echo "2. Update CHANGELOG.md"
	@echo "3. Run: make ci-test"
	@echo "4. Run: git tag v<version>"
	@echo "5. Run: make upload"

# Install pre-commit hooks
install-hooks:
	pre-commit install

# Generate requirements files
requirements:
	pip-compile pyproject.toml -o requirements.txt
	pip-compile --extra dev pyproject.toml -o requirements-dev.txt

# Security scan
security-scan:
	bandit -r src/
	safety check
	pip-audit

# Documentation
docs:
	@echo "Generating documentation..."
	mkdir -p docs
	python -c "import mcp_sec; help(mcp_sec)" > docs/api.txt
	cp FEATURES.md docs/
	cp README.md docs/

# Package info
info:
	@echo "Package Information:"
	@echo "==================="
	@python -c "import tomllib; f=open('pyproject.toml','rb'); data=tomllib.load(f); print(f\"Name: {data['project']['name']}\"); print(f\"Version: {data['project']['version']}\"); print(f\"Description: {data['project']['description']}\"); f.close()"
	@echo ""
	@echo "Dependencies:"
	@python -c "import tomllib; f=open('pyproject.toml','rb'); data=tomllib.load(f); [print(f\"  {dep}\") for dep in data['project']['dependencies']]; f.close()"

# Check installation
check:
	@echo "Checking mcp-sec installation..."
	@which mcp-sec || echo "mcp-sec not in PATH"
	@mcp-sec --version || echo "mcp-sec not working"
	@echo "Python version: $(shell python --version)"
	@echo "Pip version: $(shell pip --version)"

# Benchmark
benchmark:
	@echo "Running benchmarks..."
	python -m pytest tests/benchmark/ -v --benchmark-only

# Performance profiling
profile:
	python -m cProfile -o profile.stats -m mcp_sec.cli scan-workspace examples/test-workspace
	python -c "import pstats; p = pstats.Stats('profile.stats'); p.sort_stats('cumulative'); p.print_stats(20)"

# Memory profiling
memory-profile:
	python -m memory_profiler examples/profile_memory.py