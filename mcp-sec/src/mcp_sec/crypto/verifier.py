"""Cryptographic signature verification for MCP manifests."""

import json
import base64
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ed25519
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend


class SignatureAlgorithm(str, Enum):
    """Supported signature algorithms."""
    RSA_SHA256 = "rsa-sha256"
    ED25519 = "ed25519"


@dataclass
class SignatureVerificationResult:
    """Result of signature verification."""
    valid: bool
    algorithm: Optional[SignatureAlgorithm] = None
    signer: Optional[str] = None
    error: Optional[str] = None
    certificate_info: Optional[Dict[str, Any]] = None


def verify_signature(
    manifest_data: Dict[str, Any],
    signature: str,
    public_key_pem: str,
    algorithm: SignatureAlgorithm = SignatureAlgorithm.RSA_SHA256
) -> SignatureVerificationResult:
    """
    Verify the digital signature of an MCP manifest.
    
    Args:
        manifest_data: The manifest dictionary
        signature: Base64-encoded signature
        public_key_pem: PEM-encoded public key or certificate
        algorithm: Signature algorithm used
    
    Returns:
        SignatureVerificationResult with verification status
    """
    try:
        # Canonicalize the manifest for signing
        canonical_json = json.dumps(manifest_data, sort_keys=True, separators=(',', ':'))
        message_bytes = canonical_json.encode('utf-8')
        
        # Decode the signature
        signature_bytes = base64.b64decode(signature)
        
        # Load the public key
        public_key, cert_info = _load_public_key(public_key_pem)
        
        # Verify based on algorithm
        if algorithm == SignatureAlgorithm.RSA_SHA256:
            _verify_rsa_signature(public_key, signature_bytes, message_bytes)
        elif algorithm == SignatureAlgorithm.ED25519:
            _verify_ed25519_signature(public_key, signature_bytes, message_bytes)
        else:
            return SignatureVerificationResult(
                valid=False,
                error=f"Unsupported algorithm: {algorithm}"
            )
        
        return SignatureVerificationResult(
            valid=True,
            algorithm=algorithm,
            signer=cert_info.get("subject") if cert_info else None,
            certificate_info=cert_info
        )
        
    except InvalidSignature:
        return SignatureVerificationResult(
            valid=False,
            algorithm=algorithm,
            error="Invalid signature"
        )
    except Exception as e:
        return SignatureVerificationResult(
            valid=False,
            algorithm=algorithm,
            error=f"Verification failed: {str(e)}"
        )


def _load_public_key(pem_data: str) -> Tuple[Any, Optional[Dict[str, Any]]]:
    """Load public key from PEM data (either raw key or certificate)."""
    pem_bytes = pem_data.encode('utf-8')
    
    # Try loading as certificate first
    try:
        cert = load_pem_x509_certificate(pem_bytes, default_backend())
        public_key = cert.public_key()
        
        # Extract certificate info
        cert_info = {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_valid_before": cert.not_valid_before_utc.isoformat(),
            "not_valid_after": cert.not_valid_after_utc.isoformat(),
            "serial_number": str(cert.serial_number)
        }
        
        return public_key, cert_info
        
    except Exception:
        # Try loading as raw public key
        try:
            public_key = serialization.load_pem_public_key(pem_bytes, default_backend())
            return public_key, None
        except Exception as e:
            raise ValueError(f"Failed to load public key: {str(e)}")


def _verify_rsa_signature(public_key: rsa.RSAPublicKey, signature: bytes, message: bytes) -> None:
    """Verify RSA signature."""
    public_key.verify(
        signature,
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )


def _verify_ed25519_signature(public_key: ed25519.Ed25519PublicKey, signature: bytes, message: bytes) -> None:
    """Verify Ed25519 signature."""
    public_key.verify(signature, message)


def generate_signature_metadata(
    manifest_hash: str,
    algorithm: SignatureAlgorithm,
    signer_id: str,
    timestamp: str
) -> Dict[str, Any]:
    """
    Generate metadata for a manifest signature.
    
    This metadata should be included alongside the signature
    to provide context and enable verification.
    """
    return {
        "version": "1.0",
        "manifest_hash": manifest_hash,
        "algorithm": algorithm.value,
        "signer": signer_id,
        "timestamp": timestamp,
        "format": "mcp-signature-v1"
    }


def verify_signed_manifest(signed_manifest: Dict[str, Any]) -> SignatureVerificationResult:
    """
    Verify a manifest with embedded signature.
    
    Expected format:
    {
        "manifest": { ... actual manifest data ... },
        "signature": {
            "signature": "base64-encoded-signature",
            "algorithm": "rsa-sha256",
            "public_key": "PEM-encoded-public-key",
            "metadata": { ... signature metadata ... }
        }
    }
    """
    try:
        manifest_data = signed_manifest.get("manifest")
        signature_data = signed_manifest.get("signature")
        
        if not manifest_data or not signature_data:
            return SignatureVerificationResult(
                valid=False,
                error="Missing manifest or signature data"
            )
        
        signature = signature_data.get("signature")
        algorithm = SignatureAlgorithm(signature_data.get("algorithm", "rsa-sha256"))
        public_key = signature_data.get("public_key")
        
        if not signature or not public_key:
            return SignatureVerificationResult(
                valid=False,
                error="Missing signature or public key"
            )
        
        return verify_signature(manifest_data, signature, public_key, algorithm)
        
    except Exception as e:
        return SignatureVerificationResult(
            valid=False,
            error=f"Failed to verify signed manifest: {str(e)}"
        )