#!/bin/bash
# Setup script for MCP Security Scanner

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Drift Cop - Setup Script${NC}"
echo "==================================="
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print status
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓${NC} $2"
    else
        echo -e "${RED}✗${NC} $2"
        return 1
    fi
}

# Check Python version
echo -e "${YELLOW}Checking dependencies...${NC}"

if command_exists python3; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    
    if [ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -ge 9 ]; then
        print_status 0 "Python $PYTHON_VERSION found"
    else
        print_status 1 "Python 3.9+ required (found $PYTHON_VERSION)"
        exit 1
    fi
else
    print_status 1 "Python 3 not found"
    exit 1
fi

# Check pip
if command_exists pip3; then
    print_status 0 "pip3 found"
else
    echo -e "${YELLOW}Installing pip...${NC}"
    python3 -m ensurepip --upgrade
fi

# Check git (optional, for development)
if command_exists git; then
    print_status 0 "git found (optional)"
else
    echo -e "${YELLOW}Note: git not found (optional for development)${NC}"
fi

# Create virtual environment
echo ""
echo -e "${YELLOW}Setting up virtual environment...${NC}"

VENV_DIR="venv"
if [ -d "$VENV_DIR" ]; then
    echo "Virtual environment already exists. Removing old one..."
    rm -rf "$VENV_DIR"
fi

python3 -m venv "$VENV_DIR"
print_status $? "Virtual environment created"

# Activate virtual environment
source "$VENV_DIR/bin/activate"
print_status $? "Virtual environment activated"

# Upgrade pip in virtual environment
echo ""
echo -e "${YELLOW}Upgrading pip...${NC}"
pip install --upgrade pip setuptools wheel
print_status $? "pip upgraded"

# Install package
echo ""
echo -e "${YELLOW}Installing driftcop...${NC}"

# Check if we're in development mode
if [ -f "pyproject.toml" ] && [ -d "src" ]; then
    echo "Installing in development mode..."
    pip install -e ".[dev]"
    print_status $? "driftcop installed (development mode)"
else
    echo "Installing from PyPI..."
    pip install driftcop
    print_status $? "driftcop installed"
fi

# Install optional dependencies
echo ""
echo -e "${YELLOW}Installing optional dependencies...${NC}"

# Tree-sitter language parsers
pip install tree-sitter-python tree-sitter-javascript tree-sitter-go \
    tree-sitter-rust tree-sitter-java tree-sitter-c-sharp \
    tree-sitter-ruby tree-sitter-php 2>/dev/null || true

# Test installation
echo ""
echo -e "${YELLOW}Testing installation...${NC}"

if driftcop --version >/dev/null 2>&1; then
    VERSION=$(driftcop --version | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+')
    print_status 0 "driftcop v$VERSION installed successfully"
else
    print_status 1 "driftcop installation test failed"
    exit 1
fi

# Create config directory
echo ""
echo -e "${YELLOW}Setting up configuration...${NC}"

CONFIG_DIR="$HOME/.mcp-sec"
mkdir -p "$CONFIG_DIR"
print_status $? "Configuration directory created: $CONFIG_DIR"

# Create sample configuration
if [ ! -f "$CONFIG_DIR/config.toml" ]; then
    cat > "$CONFIG_DIR/config.toml" << EOF
# Drift Cop Configuration

# Maximum allowed risk score for CI/CD pipelines
max_risk_score = 5.0

# Known legitimate MCP servers
known_servers = [
    "mcp-server-filesystem",
    "mcp-server-github", 
    "mcp-server-postgres",
    "mcp-server-sqlite",
    "mcp-server-docker"
]

# Typosquatting similarity threshold (0.0-1.0)
typo_similarity_threshold = 0.92

# OpenAI API key for semantic analysis (optional)
# openai_api_key = "sk-..."

# Approval expiration time in hours
approval_expiration_hours = 72

# Risk score weights
[risk_weights]
critical = 10.0
high = 7.0
medium = 4.0
low = 1.0
info = 0.0
EOF
    print_status 0 "Sample configuration created: $CONFIG_DIR/config.toml"
else
    print_status 0 "Configuration already exists: $CONFIG_DIR/config.toml"
fi

# Create shell activation script
echo ""
echo -e "${YELLOW}Creating activation script...${NC}"

cat > activate_driftcop.sh << 'EOF'
#!/bin/bash
# Activation script for driftcop virtual environment

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/venv/bin/activate"
echo "driftcop environment activated"
echo "Run 'driftcop --help' to see available commands"
EOF

chmod +x activate_driftcop.sh
print_status $? "Activation script created: activate_driftcop.sh"

# Print summary
echo ""
echo -e "${GREEN}Setup complete!${NC}"
echo ""
echo "To use driftcop:"
echo "1. Activate the virtual environment:"
echo "   source activate_driftcop.sh"
echo ""
echo "2. Run driftcop commands:"
echo "   driftcop scan-server https://example.com/mcp-server"
echo "   driftcop scan-workspace /path/to/project"
echo "   driftcop scan-deps /path/to/project"
echo ""
echo "3. View all commands:"
echo "   driftcop --help"
echo ""
echo "Configuration file: $CONFIG_DIR/config.toml"
echo ""

# Show quick start examples
echo -e "${BLUE}Quick Start Examples:${NC}"
echo ""
echo "# Scan a remote MCP server"
echo "driftcop scan-server https://api.example.com/mcp/manifest.json"
echo ""
echo "# Scan local workspace for MCP security issues"
echo "driftcop scan-workspace ."
echo ""
echo "# Check dependencies for vulnerabilities"
echo "driftcop scan-deps ."
echo ""
echo "# Generate SARIF report for GitHub"
echo "driftcop scan-server https://example.com --format sarif -o report.sarif"
echo ""

# Deactivate virtual environment for clean exit
deactivate 2>/dev/null || true