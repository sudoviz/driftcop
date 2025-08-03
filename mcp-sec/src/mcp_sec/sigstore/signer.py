"""Sigstore signing and verification for MCP manifests."""

import base64
import hashlib
import json
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

from sigstore import sign, verify
from sigstore.oidc import Issuer
from sigstore.models import Bundle

from mcp_sec.crypto.canonicalize import canonicalize_json, create_canonical_tool_representation
from mcp_sec.models import MCPManifest
from .dsse import create_dsse_envelope, sign_dsse_envelope, DSSEEnvelope


class SigstoreSigner:
    """Handles Sigstore signing operations for MCP manifests."""
    
    def __init__(self, identity_token: Optional[str] = None):
        """
        Initialize Sigstore signer.
        
        Args:
            identity_token: Optional OIDC identity token. If not provided,
                          will attempt interactive authentication.
        """
        self.identity_token = identity_token
        self._signer = None
    
    def _get_signer(self):
        """Get or create the Sigstore signer."""
        if self._signer is None:
            if self.identity_token:
                self._signer = sign.Signer(
                    identity_token=self.identity_token,
                    issuer=Issuer.production()
                )
            else:
                # Interactive authentication
                self._signer = sign.Signer.production()
        return self._signer
    
    def sign_manifest(
        self,
        manifest: MCPManifest,
        manifest_path: str
    ) -> Tuple[str, DSSEEnvelope, Bundle]:
        """
        Sign an MCP manifest using Sigstore.
        
        Args:
            manifest: The manifest to sign
            manifest_path: Path or URL to the manifest
        
        Returns:
            Tuple of (digest, DSSE envelope, Sigstore bundle)
        """
        # Create canonical representation
        canonical_manifest = {
            "name": manifest.name,
            "version": manifest.version,
            "description": manifest.description,
            "author": manifest.author,
            "repository": manifest.repository,
            "permissions": sorted(manifest.permissions) if manifest.permissions else [],
            "tools": []
        }
        
        # Process tools with canonicalization
        tool_digests = {}
        for tool in manifest.tools:
            canonical_tool = create_canonical_tool_representation(tool.dict())
            tool_bytes = canonicalize_json(canonical_tool)
            tool_digest = base64.urlsafe_b64encode(
                hashlib.sha256(tool_bytes).digest()
            ).decode('ascii').rstrip('=')
            
            tool_digests[tool.name] = tool_digest
            canonical_manifest["tools"].append({
                "name": tool.name,
                "digest": tool_digest
            })
        
        # Create canonical bytes
        canonical_bytes = canonicalize_json(canonical_manifest)
        
        # Calculate digest
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(canonical_bytes).digest()
        ).decode('ascii').rstrip('=')
        
        # Create DSSE statement
        statement = create_dsse_envelope(
            manifest_path=manifest_path,
            digest=digest,
            algorithm="sha256",
            tool_digests=tool_digests
        )
        
        # Sign with Sigstore
        signer = self._get_signer()
        
        # Create a signing input file (Sigstore expects file input)
        statement_bytes = json.dumps(statement, sort_keys=True).encode('utf-8')
        
        with signer.sign(statement_bytes) as result:
            # Create DSSE envelope with Sigstore signature
            envelope = DSSEEnvelope(
                payload=base64.b64encode(statement_bytes).decode('ascii'),
                payload_type="application/vnd.in-toto+json",
                signatures=[{
                    "keyid": result.bundle.signing_certificate.subject_alternative_name,
                    "sig": base64.b64encode(result.signature).decode('ascii')
                }]
            )
            
            return digest, envelope, result.bundle
    
    @property
    def key_id(self) -> str:
        """Get the key ID for this signer."""
        signer = self._get_signer()
        # This is a simplified implementation
        return "sigstore-oidc"
    
    def sign(self, data: bytes) -> bytes:
        """Sign raw bytes (for DSSE envelope signing)."""
        signer = self._get_signer()
        with signer.sign(data) as result:
            return result.signature


def sign_manifest(
    manifest_path: Path,
    identity_token: Optional[str] = None
) -> Dict[str, Any]:
    """
    Sign an MCP manifest file using Sigstore.
    
    Args:
        manifest_path: Path to the manifest file
        identity_token: Optional OIDC token for non-interactive signing
    
    Returns:
        Signature bundle including digest, DSSE envelope, and Sigstore bundle
    """
    # Load manifest
    manifest_data = json.loads(manifest_path.read_text())
    manifest = MCPManifest(**manifest_data)
    
    # Sign
    signer = SigstoreSigner(identity_token)
    digest, envelope, bundle = signer.sign_manifest(
        manifest,
        str(manifest_path)
    )
    
    return {
        "digest": digest,
        "algorithm": "sha256",
        "envelope": envelope.to_dict(),
        "bundle": bundle.to_dict() if hasattr(bundle, 'to_dict') else str(bundle)
    }


def verify_manifest(
    manifest_path: Path,
    signature_bundle: Dict[str, Any],
    rekor_url: Optional[str] = None
) -> bool:
    """
    Verify a signed MCP manifest using Sigstore.
    
    Args:
        manifest_path: Path to the manifest file
        signature_bundle: The signature bundle from sign_manifest()
        rekor_url: Optional Rekor transparency log URL
    
    Returns:
        True if verification succeeds, False otherwise
    """
    try:
        # Load manifest and create canonical representation
        manifest_data = json.loads(manifest_path.read_text())
        manifest = MCPManifest(**manifest_data)
        
        # Recreate canonical representation
        canonical_manifest = {
            "name": manifest.name,
            "version": manifest.version,
            "description": manifest.description,
            "author": manifest.author,
            "repository": manifest.repository,
            "permissions": sorted(manifest.permissions) if manifest.permissions else [],
            "tools": []
        }
        
        # Process tools
        for tool in manifest.tools:
            canonical_tool = create_canonical_tool_representation(tool.dict())
            tool_bytes = canonicalize_json(canonical_tool)
            tool_digest = base64.urlsafe_b64encode(
                hashlib.sha256(tool_bytes).digest()
            ).decode('ascii').rstrip('=')
            
            canonical_manifest["tools"].append({
                "name": tool.name,
                "digest": tool_digest
            })
        
        # Create canonical bytes and digest
        canonical_bytes = canonicalize_json(canonical_manifest)
        expected_digest = base64.urlsafe_b64encode(
            hashlib.sha256(canonical_bytes).digest()
        ).decode('ascii').rstrip('=')
        
        # Verify digest matches
        if signature_bundle.get("digest") != expected_digest:
            return False
        
        # Verify DSSE envelope
        envelope = DSSEEnvelope.from_dict(signature_bundle["envelope"])
        
        # Decode and verify payload matches expected
        payload = json.loads(base64.b64decode(envelope.payload))
        subject_digest = None
        for subject in payload.get("subject", []):
            if "digest" in subject:
                subject_digest = subject["digest"].get("sha256")
                break
        
        if subject_digest != expected_digest:
            return False
        
        # TODO: Integrate with actual Sigstore verification
        # This would involve verifying the bundle against Rekor
        
        return True
        
    except Exception as e:
        print(f"Verification error: {e}")
        return False