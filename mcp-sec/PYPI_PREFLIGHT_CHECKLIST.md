# PyPI Publishing Pre-flight Checklist for Driftcop

## ✅ Package Availability
- [x] Package name "driftcop" is available on PyPI

## 📋 Before You Publish

### 1. Code Quality
- [ ] All tests pass: `make test`
- [ ] Code is linted: `make lint`
- [ ] Type checking passes: `make type-check`
- [ ] Security scan clean: `make security-scan`

### 2. Documentation
- [ ] README.md is up to date
- [ ] Installation instructions are clear
- [ ] Usage examples work
- [ ] CHANGELOG.md exists (if applicable)

### 3. Package Metadata
- [ ] Package name: `driftcop` ✓
- [ ] Version: `0.1.0` (in both `__init__.py` and `pyproject.toml`)
- [ ] Description is accurate
- [ ] Author information is correct
- [ ] License is specified
- [ ] Python version requirement: `^3.9`
- [ ] Homepage/repository URL is set

### 4. Dependencies
- [ ] All runtime dependencies listed in `pyproject.toml`
- [ ] No development dependencies in main dependencies
- [ ] Dependency versions are appropriate (not too restrictive)

### 5. Package Structure
- [ ] Entry point works: `driftcop = "mcp_sec.cli:app"`
- [ ] All necessary files included
- [ ] No sensitive files (tokens, .env, etc.)

## 🚀 Quick Start Commands

```bash
# 1. Navigate to project
cd /Users/turingmindai/Documents/VSCodeProjects/mcp-server-security/mcp-sec

# 2. Clean and build
python package.py --clean
python -m build

# 3. Test locally
python -m venv test_publish
source test_publish/bin/activate
pip install dist/driftcop-0.1.0-py3-none-any.whl
driftcop --version
deactivate
rm -rf test_publish

# 4. Upload to Test PyPI first
twine upload --repository testpypi dist/*

# 5. Test from Test PyPI
pip install --index-url https://test.pypi.org/simple/ --no-deps driftcop

# 6. Upload to Production PyPI
twine upload dist/*
```

## 🔑 Required Accounts
- [ ] PyPI account created
- [ ] 2FA enabled on PyPI
- [ ] API token generated
- [ ] ~/.pypirc configured (or ready to use token)

## 📦 After Publishing
- [ ] Verify on https://pypi.org/project/driftcop/
- [ ] Test installation: `pip install driftcop`
- [ ] Create git tag: `git tag v0.1.0 && git push origin v0.1.0`
- [ ] Update documentation with install instructions
- [ ] Announce release (if applicable)

## ⚠️ Important Notes
- First upload cannot be deleted (only yanked)
- Package name cannot be reused once taken
- Always test on Test PyPI first
- Keep your API tokens secure