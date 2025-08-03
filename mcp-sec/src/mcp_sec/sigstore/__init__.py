"""Sigstore integration for MCP security."""

from .dsse import create_dsse_envelope, verify_dsse_envelope, DSSEEnvelope
from .signer import SigstoreSigner, sign_manifest, verify_manifest

__all__ = [
    "create_dsse_envelope",
    "verify_dsse_envelope",
    "DSSEEnvelope",
    "SigstoreSigner",
    "sign_manifest",
    "verify_manifest"
]