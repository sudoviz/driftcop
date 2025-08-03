"""Unit tests for DSSE and Sigstore integration."""

import json
import pytest
from datetime import datetime, timezone
from mcp_sec.sigstore.dsse import create_dsse_envelope, verify_dsse_envelope
from mcp_sec.sigstore.signer import SigstoreSigner


class TestDSSE:
    """Test DSSE envelope creation and verification."""
    
    def test_create_dsse_envelope(self):
        """Test creating a DSSE envelope."""
        envelope = create_dsse_envelope(
            manifest_path="/path/to/manifest.json",
            digest="abcdef1234567890",
            algorithm="sha256",
            tool_digests={
                "tool1": "digest1",
                "tool2": "digest2"
            }
        )
        
        assert envelope["payloadType"] == "application/vnd.in-toto+json"
        assert "payload" in envelope
        assert "signatures" in envelope
        assert envelope["signatures"] == []  # No signatures yet
        
        # Decode and verify payload
        import base64
        payload_json = base64.b64decode(envelope["payload"]).decode()
        payload = json.loads(payload_json)
        
        assert payload["_type"] == "https://in-toto.io/Statement/v0.1"
        assert payload["predicateType"] == "https://mcp.security/ManifestAttestation/v1"
        assert len(payload["subject"]) == 1
        assert payload["subject"][0]["name"] == "/path/to/manifest.json"
        assert payload["subject"][0]["digest"]["sha256"] == "abcdef1234567890"
    
    def test_create_dsse_envelope_with_metadata(self):
        """Test DSSE envelope with additional metadata."""
        envelope = create_dsse_envelope(
            manifest_path="/path/to/manifest.json",
            digest="abcdef1234567890",
            metadata={
                "server_name": "test-server",
                "version": "1.0.0",
                "scanner_version": "0.1.0"
            }
        )
        
        import base64
        payload_json = base64.b64decode(envelope["payload"]).decode()
        payload = json.loads(payload_json)
        
        predicate = payload["predicate"]
        assert predicate["metadata"]["server_name"] == "test-server"
        assert predicate["metadata"]["version"] == "1.0.0"
        assert predicate["metadata"]["scanner_version"] == "0.1.0"
    
    def test_verify_dsse_envelope_structure(self):
        """Test verifying DSSE envelope structure."""
        valid_envelope = create_dsse_envelope(
            manifest_path="/test.json",
            digest="abc123"
        )
        
        # Add a dummy signature
        valid_envelope["signatures"] = [{
            "keyid": "test-key",
            "sig": "dummy-signature"
        }]
        
        errors = verify_dsse_envelope(valid_envelope)
        assert len(errors) == 0
        
        # Test invalid envelope
        invalid_envelope = {"invalid": "structure"}
        errors = verify_dsse_envelope(invalid_envelope)
        assert len(errors) > 0
        assert any("payloadType" in err for err in errors)
    
    def test_verify_dsse_envelope_payload(self):
        """Test verifying DSSE payload structure."""
        envelope = create_dsse_envelope(
            manifest_path="/test.json",
            digest="abc123"
        )
        
        # Corrupt the payload
        envelope["payload"] = "invalid-base64"
        
        errors = verify_dsse_envelope(envelope)
        assert len(errors) > 0
        assert any("decode" in err.lower() for err in errors)
    
    def test_dsse_timestamp(self):
        """Test DSSE timestamp handling."""
        before = datetime.now(timezone.utc)
        
        envelope = create_dsse_envelope(
            manifest_path="/test.json",
            digest="abc123"
        )
        
        after = datetime.now(timezone.utc)
        
        import base64
        payload_json = base64.b64decode(envelope["payload"]).decode()
        payload = json.loads(payload_json)
        
        timestamp_str = payload["predicate"]["timestamp"]
        timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        
        assert before <= timestamp <= after


class TestSigstoreSigner:
    """Test Sigstore signing functionality."""
    
    @pytest.fixture
    def signer(self):
        """Create a Sigstore signer instance."""
        return SigstoreSigner()
    
    @pytest.mark.skip(reason="Requires Sigstore environment setup")
    def test_sign_manifest(self, signer, tmp_path):
        """Test signing a manifest with Sigstore."""
        # This test requires proper Sigstore setup
        manifest_data = {
            "name": "test-server",
            "version": "1.0.0",
            "tools": []
        }
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(json.dumps(manifest_data))
        
        result = signer.sign_manifest(str(manifest_path))
        
        assert result is not None
        assert "envelope" in result
        assert "bundle" in result
        
        envelope = result["envelope"]
        assert len(envelope["signatures"]) > 0
        assert envelope["signatures"][0]["sig"] is not None
    
    @pytest.mark.skip(reason="Requires Sigstore environment setup")
    def test_verify_signature(self, signer):
        """Test verifying a Sigstore signature."""
        # This would test signature verification
        # Requires a valid signed envelope
        pass
    
    def test_signer_initialization(self, signer):
        """Test signer initialization."""
        assert signer is not None
        # Additional initialization tests would go here


class TestIntegration:
    """Test integration between components."""
    
    def test_manifest_to_dsse_flow(self, tmp_path):
        """Test the flow from manifest to DSSE envelope."""
        # Create manifest
        manifest_data = {
            "name": "integration-test",
            "version": "1.0.0",
            "description": "Integration test server",
            "tools": [
                {
                    "name": "test_tool",
                    "description": "Test tool",
                    "inputSchema": {"type": "object"}
                }
            ]
        }
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(json.dumps(manifest_data))
        
        # Compute digest
        from mcp_sec.crypto.hash import compute_manifest_digest, compute_tool_digest
        manifest_digest = compute_manifest_digest(manifest_data)
        
        tool_digests = {}
        for tool in manifest_data["tools"]:
            tool_digests[tool["name"]] = compute_tool_digest(tool)
        
        # Create DSSE envelope
        envelope = create_dsse_envelope(
            manifest_path=str(manifest_path),
            digest=manifest_digest,
            tool_digests=tool_digests,
            metadata={
                "server_name": manifest_data["name"],
                "version": manifest_data["version"]
            }
        )
        
        # Verify structure
        errors = verify_dsse_envelope(envelope)
        assert len(errors) == 0
        
        # Verify payload contains correct info
        import base64
        payload_json = base64.b64decode(envelope["payload"]).decode()
        payload = json.loads(payload_json)
        
        assert payload["subject"][0]["digest"]["sha256"] == manifest_digest
        assert payload["predicate"]["tool_digests"] == tool_digests
        assert payload["predicate"]["metadata"]["server_name"] == "integration-test"