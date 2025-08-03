# Drift Cop - Packaging Guide

This document explains how to package and distribute the Drift Cop CLI tool.

## Quick Install (End Users)

### One-line install:
```bash
curl -sSL https://raw.githubusercontent.com/drift-cop/driftcop/main/install.sh | bash
```

### Manual install:
```bash
pip install driftcop
```

### From source:
```bash
git clone https://github.com/drift-cop/driftcop.git
cd driftcop
chmod +x setup.sh && ./setup.sh
```

## Distribution Formats

Drift Cop can be packaged in multiple formats:

### 1. Python Wheel (.whl)
Standard Python package format for PyPI distribution.

```bash
# Build wheel
python package.py --wheel

# Install wheel
pip install dist/driftcop-*.whl
```

### 2. Source Distribution (.tar.gz)
Source code package for PyPI.

```bash
# Build source distribution  
python package.py --sdist

# Install from source
pip install dist/driftcop-*.tar.gz
```

### 3. Standalone Executable
Self-contained executable with all dependencies bundled.

```bash
# Build executable (requires PyInstaller)
python package.py --standalone

# Run executable
./dist/driftcop --help
```

### 4. Docker Image
Containerized version for consistent deployment.

```bash
# Build Docker image
python package.py --docker

# Run in Docker
docker run -v $(pwd):/workspace driftcop:latest scan-workspace /workspace
```

## Development Setup

### Prerequisites
- Python 3.9+
- pip
- git (optional)

### Setup Development Environment

1. **Clone repository:**
   ```bash
   git clone https://github.com/drift-cop/driftcop.git
   cd driftcop
   ```

2. **Run setup script:**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

3. **Activate environment:**
   ```bash
   source activate_driftcop.sh
   ```

### Development Commands

Using the Makefile:

```bash
# Install in development mode
make install-dev

# Run tests
make test

# Run linting
make lint

# Format code
make format

# Build packages
make build

# Clean build artifacts
make clean
```

Using the package script directly:

```bash
# Clean and build everything
python package.py --clean --wheel --sdist

# Install in editable mode
python package.py --install

# Test installation
python package.py --test
```

## Build System

The project uses a modern Python build system with multiple backend support:

### Standard setuptools (Recommended)
```bash
# Use the setuptools configuration
cp pyproject_setuptools.toml pyproject.toml
python -m build
```

### Poetry (Legacy)
```bash
# Use the original Poetry configuration
poetry build
poetry install
```

## Release Process

### Automated Release
```bash
# Create and run release script
python package.py --release-script
chmod +x release.sh
./release.sh 0.1.1
```

### Manual Release Steps

1. **Update version:**
   ```bash
   # Update pyproject.toml version
   sed -i 's/version = "0.1.0"/version = "0.1.1"/' pyproject.toml
   ```

2. **Run tests:**
   ```bash
   make ci-test
   ```

3. **Build distributions:**
   ```bash
   make build
   ```

4. **Upload to test PyPI:**
   ```bash
   make upload-test
   ```

5. **Upload to PyPI:**
   ```bash
   make upload
   ```

6. **Create git tag:**
   ```bash
   git tag v0.1.1
   git push origin v0.1.1
   ```

## Distribution Channels

### PyPI (Python Package Index)
Main distribution channel for Python packages.

- **Test PyPI:** https://test.pypi.org/project/driftcop/
- **Production PyPI:** https://pypi.org/project/driftcop/

### Homebrew (macOS)
Package manager for macOS users.

```bash
# Generate Homebrew formula
python package.py --homebrew

# Install via Homebrew (after submission)
brew install driftcop
```

### Snap (Linux)
Universal Linux package format.

```yaml
# snapcraft.yaml (example)
name: driftcop
version: '0.1.0'
summary: Security scanner for MCP servers
description: |
  Comprehensive security scanner for Model Context Protocol (MCP) servers
  with typosquatting detection, semantic analysis, and vulnerability scanning.

base: core22
confinement: strict
grade: stable

apps:
  driftcop:
    command: bin/driftcop
    plugs: [home, network]

parts:
  driftcop:
    plugin: python
    source: .
    python-requirements: [requirements.txt]
```

### AppImage (Linux)
Portable application format for Linux.

### Windows Installer
MSI package for Windows users.

## CI/CD Integration

### GitHub Actions
```yaml
# .github/workflows/package.yml
name: Package and Release

on:
  push:
    tags: ['v*']

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      
      - name: Install dependencies
        run: |
          pip install build twine
      
      - name: Build packages
        run: python package.py --clean --wheel --sdist
      
      - name: Upload to PyPI
        env:
          TWINE_USERNAME: __token__
          TWINE_PASSWORD: ${{ secrets.PYPI_TOKEN }}
        run: twine upload dist/*
```

### Docker Hub
```yaml
# .github/workflows/docker.yml
name: Docker Build

on:
  push:
    tags: ['v*']

jobs:
  docker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build Docker image
        run: python package.py --docker
      
      - name: Push to Docker Hub
        run: |
          docker tag driftcop:latest driftcop/driftcop:latest
          docker tag driftcop:latest driftcop/driftcop:${{ github.ref_name }}
          docker push driftcop/driftcop:latest
          docker push driftcop/driftcop:${{ github.ref_name }}
```

## Platform-Specific Considerations

### Windows
- Use `.exe` extension for executables
- Handle path separators correctly
- Consider Windows Defender exclusions for security tools

### macOS
- Code signing may be required for distribution
- Homebrew is the preferred package manager
- Consider notarization for App Store distribution

### Linux
- Multiple distribution formats (deb, rpm, snap, AppImage)
- Consider different Python versions across distributions
- Handle dependency differences

## Security Considerations

### Package Signing
```bash
# Sign packages with GPG
gpg --detach-sign --armor dist/driftcop-0.1.0.tar.gz
gpg --detach-sign --armor dist/driftcop-0.1.0-py3-none-any.whl
```

### Supply Chain Security
- Use pinned dependencies
- Verify checksums
- Sign releases
- Use Sigstore for transparency logs

### Vulnerability Scanning
```bash
# Scan dependencies
make security-scan

# Check for known vulnerabilities
pip-audit
safety check
bandit -r src/
```

## Testing Packages

### Local Testing
```bash
# Test wheel installation
pip install dist/driftcop-*.whl
driftcop --help

# Test source installation
pip install dist/driftcop-*.tar.gz
driftcop --version
```

### Virtual Environment Testing
```bash
# Create clean environment
python -m venv test_env
source test_env/bin/activate
pip install dist/driftcop-*.whl
driftcop --help
deactivate
rm -rf test_env
```

### Docker Testing
```bash
# Test Docker image
docker run --rm driftcop:latest --version
docker run --rm -v $(pwd):/workspace mcp-sec:latest scan-workspace /workspace
```

## Troubleshooting

### Common Issues

1. **Missing dependencies:**
   - Ensure all dependencies are listed in pyproject.toml
   - Check for platform-specific dependencies

2. **Import errors:**
   - Verify package structure
   - Check PYTHONPATH settings
   - Ensure __init__.py files are present

3. **CLI not found:**
   - Verify entry_points configuration
   - Check PATH settings
   - Ensure scripts are executable

4. **Version conflicts:**
   - Use virtual environments
   - Pin dependency versions
   - Check for conflicting packages

### Debug Commands
```bash
# Check package info
pip show driftcop

# List installed files
pip show -f driftcop

# Check entry points
python -c "import pkg_resources; print(list(pkg_resources.iter_entry_points('console_scripts')))"

# Verify imports
python -c "import mcp_sec; print(mcp_sec.__version__)"
```

## Support

For packaging issues:
- Check the [Issues](https://github.com/drift-cop/driftcop/issues) page
- Review the [Documentation](https://drift-cop.github.io/driftcop)
- Contact the maintainers

For distribution questions:
- PyPI: Follow PyPI guidelines
- Homebrew: Submit formula to homebrew-core
- Snap: Use snapcraft store
- Docker: Use Docker Hub or GitHub Container Registry