#!/bin/bash
# Simple installation script for MCP Security Scanner

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}MCP Security Scanner - Quick Install${NC}"
echo "======================================="

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}Error: pip3 is required but not installed${NC}"
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
REQUIRED_VERSION="3.9"

if python3 -c "import sys; exit(0 if sys.version_info >= (3, 9) else 1)"; then
    echo -e "${GREEN}✓ Python $PYTHON_VERSION (compatible)${NC}"
else
    echo -e "${RED}✗ Python $REQUIRED_VERSION+ required (found $PYTHON_VERSION)${NC}"
    exit 1
fi

# Install from PyPI or local directory
echo ""
echo -e "${YELLOW}Installing mcp-sec...${NC}"

if [ -f "pyproject.toml" ] && [ -d "src" ]; then
    # Local development installation
    echo "Installing from local directory..."
    pip3 install -e .
else
    # PyPI installation
    echo "Installing from PyPI..."
    pip3 install mcp-sec
fi

# Verify installation
echo ""
echo -e "${YELLOW}Verifying installation...${NC}"

if command -v mcp-sec &> /dev/null; then
    VERSION=$(mcp-sec --version 2>/dev/null || echo "unknown")
    echo -e "${GREEN}✓ mcp-sec installed successfully${NC}"
    echo "Version: $VERSION"
else
    echo -e "${RED}✗ Installation failed${NC}"
    exit 1
fi

# Show quick usage
echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "Quick usage examples:"
echo "  mcp-sec --help                           # Show all commands"
echo "  mcp-sec scan-server <url>                # Scan a remote server"  
echo "  mcp-sec scan-workspace .                 # Scan current directory"
echo "  mcp-sec scan-deps .                      # Check dependencies"
echo ""
echo "For more information, visit: https://github.com/mcp-security/mcp-sec"