#!/usr/bin/env python3
"""
Packaging script for MCP Security Scanner CLI

This script helps package mcp-sec as a standalone CLI tool that can be:
1. Installed via pip
2. Distributed as a wheel
3. Built as a standalone executable (using PyInstaller)
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
import argparse


def run_command(cmd, check=True):
    """Run a shell command and return the result."""
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if check and result.returncode != 0:
        print(f"Error: {result.stderr}")
        sys.exit(1)
    
    return result


def clean_build_artifacts():
    """Remove build artifacts and cache."""
    print("Cleaning build artifacts...")
    
    dirs_to_remove = [
        "build", "dist", "*.egg-info", ".eggs",
        "__pycache__", ".pytest_cache", ".coverage",
        "htmlcov", ".mypy_cache", ".ruff_cache"
    ]
    
    for pattern in dirs_to_remove:
        for path in Path(".").glob(pattern):
            if path.is_dir():
                shutil.rmtree(path)
                print(f"  Removed {path}")
            else:
                path.unlink()
                print(f"  Removed {path}")
    
    # Clean Python cache files
    for path in Path(".").rglob("*.pyc"):
        path.unlink()
    
    for path in Path(".").rglob("*.pyo"):
        path.unlink()


def build_wheel():
    """Build wheel distribution."""
    print("\nBuilding wheel distribution...")
    
    # Ensure build dependencies are installed
    run_command("pip install --upgrade build wheel setuptools")
    
    # Build the wheel
    run_command("python -m build --wheel")
    
    # List the built wheel
    wheels = list(Path("dist").glob("*.whl"))
    if wheels:
        print(f"\nWheel built successfully: {wheels[0]}")
        return wheels[0]
    else:
        print("Error: No wheel file found")
        sys.exit(1)


def build_sdist():
    """Build source distribution."""
    print("\nBuilding source distribution...")
    
    # Build the sdist
    run_command("python -m build --sdist")
    
    # List the built sdist
    sdists = list(Path("dist").glob("*.tar.gz"))
    if sdists:
        print(f"\nSource distribution built successfully: {sdists[0]}")
        return sdists[0]
    else:
        print("Error: No sdist file found")
        sys.exit(1)


def build_standalone_executable():
    """Build standalone executable using PyInstaller."""
    print("\nBuilding standalone executable...")
    
    # Ensure PyInstaller is installed
    run_command("pip install pyinstaller")
    
    # Create PyInstaller spec file
    spec_content = '''
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['src/mcp_sec/cli.py'],
    pathex=['src'],
    binaries=[],
    datas=[
        ('src/mcp_sec/config.py', 'mcp_sec'),
        ('src/mcp_sec/models.py', 'mcp_sec'),
    ],
    hiddenimports=[
        'mcp_sec',
        'mcp_sec.scanners',
        'mcp_sec.analyzers',
        'mcp_sec.crypto',
        'mcp_sec.reporters',
        'mcp_sec.tracking',
        'mcp_sec.extractors',
        'mcp_sec.lockfile',
        'mcp_sec.sigstore',
        'typer',
        'rich',
        'httpx',
        'pydantic',
        'jsonschema',
        'toml',
        'sklearn',
        'numpy',
        'openai',
        'sigstore',
        'cryptography',
        'tree_sitter',
        'tree_sitter_python',
        'tree_sitter_javascript',
        'tree_sitter_go',
        'tree_sitter_rust',
        'tree_sitter_java',
        'tree_sitter_c_sharp',
        'tree_sitter_ruby',
        'tree_sitter_php',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='mcp-sec',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
'''
    
    spec_file = Path("mcp-sec.spec")
    spec_file.write_text(spec_content)
    
    # Build the executable
    run_command("pyinstaller mcp-sec.spec --clean")
    
    # Check if executable was created
    exe_path = Path("dist/mcp-sec")
    if sys.platform == "win32":
        exe_path = Path("dist/mcp-sec.exe")
    
    if exe_path.exists():
        print(f"\nStandalone executable built successfully: {exe_path}")
        
        # Make it executable on Unix-like systems
        if sys.platform != "win32":
            exe_path.chmod(0o755)
        
        return exe_path
    else:
        print("Error: Executable not found")
        sys.exit(1)


def install_editable():
    """Install package in editable mode for development."""
    print("\nInstalling in editable mode...")
    run_command("pip install -e .[dev]")
    print("\nEditable installation complete. You can now use 'mcp-sec' command.")


def test_installation():
    """Test that the CLI is properly installed."""
    print("\nTesting installation...")
    
    # Test help command
    result = run_command("mcp-sec --help", check=False)
    
    if result.returncode == 0:
        print("✓ CLI is working properly")
        print("\nAvailable commands:")
        run_command("mcp-sec --help")
    else:
        print("✗ CLI test failed")
        print(result.stderr)


def create_docker_image():
    """Create Docker image for the CLI."""
    print("\nCreating Docker image...")
    
    dockerfile_content = '''FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    git \\
    gcc \\
    g++ \\
    make \\
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy package files
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install the package
RUN pip install --no-cache-dir .

# Create a non-root user
RUN useradd -m -u 1000 mcpsec
USER mcpsec

# Set entrypoint
ENTRYPOINT ["mcp-sec"]
CMD ["--help"]
'''
    
    dockerfile = Path("Dockerfile.cli")
    dockerfile.write_text(dockerfile_content)
    
    # Build Docker image
    run_command("docker build -f Dockerfile.cli -t mcp-sec:latest .")
    
    print("\nDocker image built successfully: mcp-sec:latest")
    print("\nUsage:")
    print("  docker run -v $(pwd):/workspace mcp-sec:latest scan-server https://example.com")
    print("  docker run -v $(pwd):/workspace mcp-sec:latest scan-workspace /workspace")


def create_homebrew_formula():
    """Create a Homebrew formula for macOS installation."""
    print("\nCreating Homebrew formula...")
    
    formula_content = '''class McpSec < Formula
  include Language::Python::Virtualenv

  desc "Security scanner for Model Context Protocol (MCP) servers"
  homepage "https://github.com/yourusername/mcp-security-scanner"
  url "https://files.pythonhosted.org/packages/source/m/mcp-sec/mcp-sec-0.1.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license "Apache-2.0"

  depends_on "python@3.11"

  resource "typer" do
    url "https://files.pythonhosted.org/packages/source/t/typer/typer-0.9.0.tar.gz"
    sha256 "50922fd79aea2f4751a8e0408ff10d2662bd0c8bbfa84755a699f3bada2978b2"
  end

  resource "rich" do
    url "https://files.pythonhosted.org/packages/source/r/rich/rich-13.7.0.tar.gz"
    sha256 "5cb5123b5cf9ee70584244246816e9114227e0b98ad9176eede6ad54bf5403fa"
  end

  # Add other dependencies here...

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "MCP Security Scanner", shell_output("#{bin}/mcp-sec --help")
  end
end
'''
    
    formula_file = Path("homebrew/mcp-sec.rb")
    formula_file.parent.mkdir(exist_ok=True)
    formula_file.write_text(formula_content)
    
    print(f"\nHomebrew formula template created: {formula_file}")
    print("Note: Update the SHA256 hash and dependencies before submitting to Homebrew")


def create_release_script():
    """Create a script for automating releases."""
    print("\nCreating release script...")
    
    script_content = '''#!/bin/bash
# Release script for mcp-sec

set -e

# Colors
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[0;33m'
NC='\\033[0m' # No Color

echo -e "${GREEN}MCP Security Scanner Release Script${NC}"
echo "===================================="

# Check if version is provided
if [ -z "$1" ]; then
    echo -e "${RED}Error: Version number required${NC}"
    echo "Usage: ./release.sh <version>"
    echo "Example: ./release.sh 0.1.1"
    exit 1
fi

VERSION=$1
echo -e "${YELLOW}Preparing release v${VERSION}...${NC}"

# Update version in pyproject.toml
sed -i.bak "s/version = \\".*\\"/version = \\"${VERSION}\\"/" pyproject.toml
rm pyproject.toml.bak

# Update version in __init__.py
sed -i.bak "s/__version__ = \\".*\\"/__version__ = \\"${VERSION}\\"/" src/mcp_sec/__init__.py
rm src/mcp_sec/__init__.py.bak

# Run tests
echo -e "${YELLOW}Running tests...${NC}"
python -m pytest tests/

# Build distributions
echo -e "${YELLOW}Building distributions...${NC}"
python package.py --clean --wheel --sdist

# Create git tag
echo -e "${YELLOW}Creating git tag...${NC}"
git add pyproject.toml src/mcp_sec/__init__.py
git commit -m "Release v${VERSION}"
git tag -a "v${VERSION}" -m "Release v${VERSION}"

echo -e "${GREEN}Release preparation complete!${NC}"
echo ""
echo "Next steps:"
echo "1. Push changes: git push origin main --tags"
echo "2. Upload to PyPI: twine upload dist/*"
echo "3. Create GitHub release"
echo "4. Update Homebrew formula"
'''
    
    script_file = Path("release.sh")
    script_file.write_text(script_content)
    script_file.chmod(0o755)
    
    print(f"\nRelease script created: {script_file}")


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Package MCP Security Scanner as a CLI tool"
    )
    
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Clean build artifacts"
    )
    
    parser.add_argument(
        "--wheel",
        action="store_true",
        help="Build wheel distribution"
    )
    
    parser.add_argument(
        "--sdist",
        action="store_true",
        help="Build source distribution"
    )
    
    parser.add_argument(
        "--standalone",
        action="store_true",
        help="Build standalone executable"
    )
    
    parser.add_argument(
        "--docker",
        action="store_true",
        help="Build Docker image"
    )
    
    parser.add_argument(
        "--install",
        action="store_true",
        help="Install in editable mode"
    )
    
    parser.add_argument(
        "--test",
        action="store_true",
        help="Test installation"
    )
    
    parser.add_argument(
        "--homebrew",
        action="store_true",
        help="Create Homebrew formula template"
    )
    
    parser.add_argument(
        "--release-script",
        action="store_true",
        help="Create release automation script"
    )
    
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run all packaging steps"
    )
    
    args = parser.parse_args()
    
    # If no options specified, show help
    if not any(vars(args).values()):
        parser.print_help()
        sys.exit(0)
    
    # Change to package directory
    package_dir = Path(__file__).parent
    os.chdir(package_dir)
    
    try:
        if args.clean or args.all:
            clean_build_artifacts()
        
        if args.wheel or args.all:
            build_wheel()
        
        if args.sdist or args.all:
            build_sdist()
        
        if args.standalone:
            build_standalone_executable()
        
        if args.docker:
            create_docker_image()
        
        if args.homebrew:
            create_homebrew_formula()
        
        if args.release_script:
            create_release_script()
        
        if args.install or args.all:
            install_editable()
        
        if args.test or args.all:
            test_installation()
        
        print("\n✓ Packaging complete!")
        
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()