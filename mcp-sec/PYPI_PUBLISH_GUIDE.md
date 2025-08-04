# Publishing Driftcop to PyPI - Complete Guide

## Prerequisites

### 1. PyPI Account Setup
1. **Create a PyPI account**: https://pypi.org/account/register/
2. **Create a Test PyPI account** (for testing): https://test.pypi.org/account/register/
3. **Enable 2FA** (required for PyPI): Go to Account Settings → Add 2FA

### 2. Generate API Tokens
1. Go to https://pypi.org/manage/account/token/
2. Create a new API token with scope "Entire account" (you can restrict it later)
3. Save the token securely - it starts with `pypi-`
4. Do the same for Test PyPI: https://test.pypi.org/manage/account/token/

### 3. Configure Authentication

Create `~/.pypirc` file:
```ini
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
username = __token__
password = pypi-YOUR-TOKEN-HERE

[testpypi]
username = __token__
password = pypi-YOUR-TEST-TOKEN-HERE
repository = https://test.pypi.org/legacy/
```

**Security**: Set proper permissions:
```bash
chmod 600 ~/.pypirc
```

## Step-by-Step Publishing Process

### Step 1: Prepare the Package

1. **Update version** in `src/mcp_sec/__init__.py`:
   ```python
   __version__ = "0.1.0"  # Update as needed
   ```

2. **Update version** in `pyproject.toml`:
   ```toml
   [tool.poetry]
   version = "0.1.0"  # Should match __init__.py
   ```

3. **Verify package metadata**:
   ```bash
   cd /Users/turingmindai/Documents/VSCodeProjects/mcp-server-security/mcp-sec
   cat pyproject.toml | grep -E "name|version|description|authors"
   ```

### Step 2: Clean and Build

```bash
# Clean previous builds
python package.py --clean

# Or manually:
rm -rf build/ dist/ *.egg-info

# Build the package
python -m pip install --upgrade build
python -m build
```

This creates:
- `dist/driftcop-0.1.0-py3-none-any.whl` (wheel)
- `dist/driftcop-0.1.0.tar.gz` (source distribution)

### Step 3: Test Locally

1. **Create a test virtual environment**:
   ```bash
   python -m venv test_env
   source test_env/bin/activate  # On Windows: test_env\Scripts\activate
   ```

2. **Install and test**:
   ```bash
   pip install dist/driftcop-0.1.0-py3-none-any.whl
   driftcop --version
   driftcop --help
   ```

3. **Run basic commands**:
   ```bash
   # Test basic functionality
   driftcop scan-manifest examples/vulnerable-manifest.json
   ```

4. **Deactivate and cleanup**:
   ```bash
   deactivate
   rm -rf test_env
   ```

### Step 4: Upload to Test PyPI (Recommended First)

1. **Install twine**:
   ```bash
   pip install --upgrade twine
   ```

2. **Check the package**:
   ```bash
   twine check dist/*
   ```

3. **Upload to Test PyPI**:
   ```bash
   twine upload --repository testpypi dist/*
   ```

4. **Test installation from Test PyPI**:
   ```bash
   pip install --index-url https://test.pypi.org/simple/ --no-deps driftcop
   ```

### Step 5: Upload to Production PyPI

Once you've verified everything works on Test PyPI:

```bash
# Upload to PyPI
twine upload dist/*

# Or if you didn't configure .pypirc:
twine upload dist/* --username __token__ --password pypi-YOUR-TOKEN-HERE
```

### Step 6: Verify Installation

```bash
# Wait a minute for PyPI to update, then:
pip install driftcop

# Verify it works
driftcop --version
```

## Using Poetry (Alternative Method)

Since the project uses Poetry, you can also use Poetry commands:

```bash
# Configure Poetry with PyPI token
poetry config pypi-token.pypi pypi-YOUR-TOKEN-HERE

# Build
poetry build

# Publish
poetry publish

# Or build and publish in one command
poetry publish --build
```

For Test PyPI with Poetry:
```bash
# Add test repository
poetry config repositories.test-pypi https://test.pypi.org/legacy/
poetry config pypi-token.test-pypi pypi-YOUR-TEST-TOKEN-HERE

# Publish to test
poetry publish -r test-pypi
```

## Post-Publishing Tasks

1. **Create a Git tag**:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

2. **Update README** with installation instructions:
   ```markdown
   ## Installation
   ```bash
   pip install driftcop
   ```
   ```

3. **Test installation on different systems**:
   - Linux
   - macOS  
   - Windows
   - Different Python versions (3.9+)

## Troubleshooting

### Common Issues

1. **"Package name already exists"**
   - The name might be taken. Check https://pypi.org/project/driftcop/
   - You may need to choose a different name

2. **Authentication errors**
   - Ensure you're using `__token__` as username
   - Token should start with `pypi-`
   - Check token permissions

3. **Missing dependencies**
   - Ensure all dependencies are in `pyproject.toml`
   - Test in a clean virtual environment

4. **Import errors after installation**
   - Check package structure in `pyproject.toml`:
     ```toml
     packages = [{include = "mcp_sec", from = "src"}]
     ```

### Validation Commands

```bash
# Check if name is available
pip search driftcop  # Note: pip search is currently disabled

# Check package contents
tar -tzf dist/driftcop-0.1.0.tar.gz | head -20

# Check wheel contents  
unzip -l dist/driftcop-0.1.0-py3-none-any.whl | head -20

# Verify metadata
twine check dist/*
```

## Automation with GitHub Actions

Create `.github/workflows/publish.yml`:

```yaml
name: Publish to PyPI

on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install build twine
    
    - name: Build package
      run: python -m build
    
    - name: Publish to PyPI
      env:
        TWINE_USERNAME: __token__
        TWINE_PASSWORD: ${{ secrets.PYPI_TOKEN }}
      run: twine upload dist/*
```

Add your PyPI token as a GitHub secret named `PYPI_TOKEN`.

## Next Steps

After successful publishing:

1. Monitor package statistics: https://pypi.org/project/driftcop/
2. Set up documentation (ReadTheDocs, GitHub Pages)
3. Add badges to README (version, downloads, Python versions)
4. Create a CHANGELOG.md
5. Set up continuous deployment
6. Consider platform-specific distributions (Homebrew, AUR, etc.)

## Resources

- PyPI Documentation: https://packaging.python.org/
- Poetry Publishing: https://python-poetry.org/docs/cli/#publish
- Twine Documentation: https://twine.readthedocs.io/
- Python Packaging Guide: https://packaging.python.org/en/latest/tutorials/packaging-projects/