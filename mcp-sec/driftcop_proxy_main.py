#!/usr/bin/env python3
"""
DriftCop Proxy - Main entry point
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from driftcop_proxy.cli import main

if __name__ == "__main__":
    main()