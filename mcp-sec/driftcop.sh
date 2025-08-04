#!/bin/bash
# Wrapper script for driftcop CLI

# Add Python bin directory to PATH
export PATH="/Users/turingmindai/Library/Python/3.9/bin:$PATH"

# Suppress Python warnings
export PYTHONWARNINGS="ignore"

# Run driftcop with all arguments and filter out the specific warning
driftcop "$@" 2>&1 | grep -v "NotOpenSSLWarning" | grep -v "urllib3 v2 only supports OpenSSL"