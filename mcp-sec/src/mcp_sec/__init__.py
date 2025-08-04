"""MCP Security Scanner - Shift-left security for Model Context Protocol servers."""

# Suppress urllib3 warnings at package import time
import warnings
warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL")

__version__ = "0.1.0"