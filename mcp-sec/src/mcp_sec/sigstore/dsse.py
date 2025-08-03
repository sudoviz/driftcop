"""DSSE (Dead Simple Signing Envelope) implementation for MCP security."""

import base64
import json
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from datetime import datetime

from securesystemslib import dsse


@dataclass
class DSSEEnvelope:
    """DSSE envelope for MCP manifest signatures."""
    payload: str  # Base64-encoded payload
    payload_type: str
    signatures: List[Dict[str, str]]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "_type": "https://in-toto.io/Statement/v0.1",
            "payload": self.payload,
            "payloadType": self.payload_type,
            "signatures": self.signatures
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DSSEEnvelope":
        """Create from dictionary representation."""
        return cls(
            payload=data["payload"],
            payload_type=data["payloadType"],
            signatures=data["signatures"]
        )


def create_dsse_envelope(
    manifest_path: str,
    digest: str,
    algorithm: str = "sha256",
    tool_digests: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Create a DSSE envelope for an MCP manifest.
    
    Args:
        manifest_path: Path or URL to the manifest
        digest: Base64url-encoded digest of canonical manifest
        algorithm: Hash algorithm used
        tool_digests: Optional mapping of tool names to their digests
    
    Returns:
        DSSE statement ready for signing
    """
    # Create in-toto statement
    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicateType": "https://mcp.security/Manifest/v1",
        "subject": [
            {
                "name": manifest_path,
                "digest": {
                    algorithm: digest
                }
            }
        ],
        "predicate": {
            "manifestVersion": "1.0",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "canonicalization": {
                "method": "mcp-canonical-v1",
                "unicodeNormalization": "NFC",
                "whitespaceHandling": "collapse",
                "markdownStripping": True
            }
        }
    }
    
    # Add tool digests if provided
    if tool_digests:
        statement["predicate"]["tools"] = [
            {
                "name": name,
                "digest": {algorithm: digest}
            }
            for name, digest in tool_digests.items()
        ]
    
    return statement


def sign_dsse_envelope(statement: Dict[str, Any], signer) -> DSSEEnvelope:
    """
    Sign a DSSE statement using the provided signer.
    
    Args:
        statement: The statement to sign
        signer: A signer object with sign() method
    
    Returns:
        Signed DSSE envelope
    """
    # Encode payload
    payload_bytes = json.dumps(statement, sort_keys=True).encode('utf-8')
    payload_b64 = base64.b64encode(payload_bytes).decode('ascii')
    
    # Create signature
    signature = signer.sign(payload_bytes)
    
    return DSSEEnvelope(
        payload=payload_b64,
        payload_type="application/vnd.in-toto+json",
        signatures=[{
            "keyid": signer.key_id,
            "sig": base64.b64encode(signature).decode('ascii')
        }]
    )


def verify_dsse_envelope(
    envelope: DSSEEnvelope,
    expected_digest: str,
    verifier
) -> bool:
    """
    Verify a DSSE envelope signature and content.
    
    Args:
        envelope: The DSSE envelope to verify
        expected_digest: Expected digest of the manifest
        verifier: A verifier object with verify() method
    
    Returns:
        True if valid, False otherwise
    """
    try:
        # Decode payload
        payload_bytes = base64.b64decode(envelope.payload)
        statement = json.loads(payload_bytes)
        
        # Verify statement type
        if statement.get("_type") != "https://in-toto.io/Statement/v0.1":
            return False
        
        # Verify subject digest matches
        subjects = statement.get("subject", [])
        if not subjects:
            return False
        
        subject_digest = None
        for alg, digest in subjects[0].get("digest", {}).items():
            if alg == "sha256":
                subject_digest = digest
                break
        
        if subject_digest != expected_digest:
            return False
        
        # Verify signature
        for sig_block in envelope.signatures:
            signature = base64.b64decode(sig_block["sig"])
            if verifier.verify(payload_bytes, signature):
                return True
        
        return False
        
    except Exception:
        return False


def create_rekor_entry(envelope: DSSEEnvelope, manifest_url: str) -> Dict[str, Any]:
    """
    Create a Rekor transparency log entry for the DSSE envelope.
    
    Args:
        envelope: Signed DSSE envelope
        manifest_url: Public URL of the manifest
    
    Returns:
        Rekor entry ready for submission
    """
    return {
        "apiVersion": "0.0.1",
        "kind": "dsse",
        "spec": {
            "proposedContent": {
                "envelope": envelope.to_dict(),
                "verifiers": [manifest_url]
            }
        }
    }