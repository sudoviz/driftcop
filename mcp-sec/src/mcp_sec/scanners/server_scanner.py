"""Scanner for MCP server manifests and endpoints."""

import json
import uuid
from typing import Dict, Any, List
from urllib.parse import urlparse

import httpx
from jsonschema import validate, ValidationError

from mcp_sec.models import ScanResult, Finding, FindingType, Severity, MCPManifest
from mcp_sec.analyzers import typo_detector, semantic_analyzer
from mcp_sec.config import config
from mcp_sec.crypto import compute_manifest_digest
from mcp_sec.crypto.verifier import verify_signed_manifest
from mcp_sec.tracking import VersionTracker


# MCP Manifest JSON Schema
MCP_MANIFEST_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["name", "version", "description"],
    "properties": {
        "name": {"type": "string", "minLength": 1, "maxLength": 100},
        "version": {"type": "string", "pattern": r"^\d+\.\d+\.\d+$"},
        "description": {"type": "string", "maxLength": 500},
        "author": {"type": "string"},
        "repository": {"type": "string", "format": "uri"},
        "tools": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "description", "input_schema"],
                "properties": {
                    "name": {"type": "string", "pattern": "^[a-zA-Z0-9_-]+$"},
                    "description": {"type": "string"},
                    "input_schema": {"type": "object"},
                    "output_schema": {"type": "object"}
                }
            }
        },
        "permissions": {
            "type": "array",
            "items": {"type": "string", "enum": [
                "filesystem:read", "filesystem:write",
                "network:*", "network:http", "network:https",
                "process:spawn", "env:read", "env:write"
            ]}
        }
    }
}


def scan(url: str, verbose: bool = False, track_changes: bool = True) -> ScanResult:
    """Scan an MCP server for security issues."""
    findings: List[Finding] = []
    tracker = VersionTracker() if track_changes else None
    
    # Parse and validate URL
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")
    
    # Fetch manifest
    try:
        manifest_data = _fetch_manifest(url)
    except Exception as e:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            type=FindingType.SCHEMA_VIOLATION,
            severity=Severity.HIGH,
            title="Failed to fetch manifest",
            description=f"Could not fetch MCP manifest from {url}: {str(e)}",
            cwe_id="CWE-200"
        ))
        return ScanResult(server_url=url, findings=findings, total_risk_score=7.0)
    
    # Validate manifest schema
    schema_findings = _validate_schema(manifest_data, url)
    findings.extend(schema_findings)
    
    if schema_findings:
        # If schema is invalid, we can't parse it reliably
        return ScanResult(
            server_url=url,
            findings=findings,
            total_risk_score=_calculate_risk_score(findings)
        )
    
    # Parse manifest
    try:
        manifest = MCPManifest(**manifest_data)
    except Exception as e:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            type=FindingType.SCHEMA_VIOLATION,
            severity=Severity.HIGH,
            title="Invalid manifest structure",
            description=f"Failed to parse manifest: {str(e)}",
            cwe_id="CWE-20"
        ))
        return ScanResult(
            server_url=url,
            findings=findings,
            total_risk_score=_calculate_risk_score(findings)
        )
    
    # Check for typosquatting
    typo_findings = typo_detector.check_server_name(manifest.name)
    findings.extend(typo_findings)
    
    # Check for semantic drift
    for tool in manifest.tools:
        semantic_findings = semantic_analyzer.check_tool_semantic_drift(tool)
        findings.extend(semantic_findings)
    
    # Check permissions
    permission_findings = _check_permissions(manifest)
    findings.extend(permission_findings)
    
    # Check for signature if present
    if isinstance(manifest_data, dict) and "signature" in manifest_data:
        sig_findings = _verify_manifest_signature(manifest_data, url)
        findings.extend(sig_findings)
    
    # Check for version tracking and changes
    if tracker:
        change_findings = _check_version_changes(tracker, url, manifest)
        findings.extend(change_findings)
    
    # Calculate manifest hash
    manifest_hash = compute_manifest_digest(manifest)
    findings.append(Finding(
        id=str(uuid.uuid4()),
        type=FindingType.SCHEMA_VIOLATION,
        severity=Severity.INFO,
        title="Manifest fingerprint",
        description=f"Manifest hash: {manifest_hash[:16]}...",
        metadata={"hash": manifest_hash}
    ))
    
    # Calculate total risk score
    total_risk = _calculate_risk_score(findings)
    
    return ScanResult(
        server_url=url,
        findings=findings,
        total_risk_score=total_risk
    )


def _fetch_manifest(url: str) -> Dict[str, Any]:
    """Fetch MCP manifest from server."""
    manifest_url = f"{url.rstrip('/')}/manifest.json"
    
    with httpx.Client(timeout=10.0, follow_redirects=True) as client:
        response = client.get(manifest_url)
        response.raise_for_status()
        
        # Basic content type check
        content_type = response.headers.get("content-type", "")
        if not content_type.startswith("application/json"):
            raise ValueError(f"Expected JSON, got {content_type}")
        
        return response.json()


def _validate_schema(manifest_data: Dict[str, Any], url: str) -> List[Finding]:
    """Validate manifest against JSON schema."""
    findings = []
    
    try:
        validate(instance=manifest_data, schema=MCP_MANIFEST_SCHEMA)
    except ValidationError as e:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            type=FindingType.SCHEMA_VIOLATION,
            severity=Severity.HIGH,
            title="Manifest schema violation",
            description=f"Manifest does not conform to MCP schema: {e.message}",
            cwe_id="CWE-20",
            fix_suggestion=f"Update manifest at {url}/manifest.json to match the MCP schema specification"
        ))
    
    return findings


def _check_permissions(manifest: MCPManifest) -> List[Finding]:
    """Check for excessive permissions."""
    findings = []
    
    dangerous_perms = {
        "filesystem:write": "Can modify files on the system",
        "process:spawn": "Can execute arbitrary processes",
        "env:write": "Can modify environment variables",
        "network:*": "Unrestricted network access"
    }
    
    for perm in manifest.permissions:
        if perm in dangerous_perms:
            findings.append(Finding(
                id=str(uuid.uuid4()),
                type=FindingType.EXCESSIVE_PERMISSIONS,
                severity=Severity.MEDIUM,
                title=f"Potentially dangerous permission: {perm}",
                description=f"The server requests '{perm}' permission. {dangerous_perms[perm]}",
                cwe_id="CWE-250",
                fix_suggestion="Consider if this permission is truly necessary. Apply principle of least privilege."
            ))
    
    # Check if server has no declared permissions but has tools
    if manifest.tools and not manifest.permissions:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            type=FindingType.SCHEMA_VIOLATION,
            severity=Severity.LOW,
            title="No permissions declared",
            description="Server has tools but declares no permissions. This may indicate missing security declarations.",
            cwe_id="CWE-276",
            fix_suggestion="Explicitly declare required permissions in the manifest"
        ))
    
    return findings


def _calculate_risk_score(findings: List[Finding]) -> float:
    """Calculate total risk score from findings."""
    severity_scores = {
        Severity.CRITICAL: 10.0,
        Severity.HIGH: 7.0,
        Severity.MEDIUM: 4.0,
        Severity.LOW: 1.0,
        Severity.INFO: 0.0
    }
    
    total = 0.0
    for finding in findings:
        total += severity_scores.get(finding.severity, 0.0)
    
    # Cap at 10.0
    return min(total, 10.0)


def _verify_manifest_signature(manifest_data: Dict[str, Any], url: str) -> List[Finding]:
    """Verify the digital signature of a manifest."""
    findings = []
    
    result = verify_signed_manifest(manifest_data)
    
    if result.valid:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            type=FindingType.SCHEMA_VIOLATION,
            severity=Severity.INFO,
            title="Valid digital signature",
            description=f"Manifest signed by: {result.signer or 'Unknown'}",
            metadata={"algorithm": result.algorithm, "certificate": result.certificate_info}
        ))
    else:
        findings.append(Finding(
            id=str(uuid.uuid4()),
            type=FindingType.SCHEMA_VIOLATION,
            severity=Severity.HIGH,
            title="Invalid or missing digital signature",
            description=f"Signature verification failed: {result.error}",
            cwe_id="CWE-347",
            fix_suggestion="Ensure the manifest is properly signed with a valid certificate"
        ))
    
    return findings


def _check_version_changes(tracker: VersionTracker, url: str, manifest: MCPManifest) -> List[Finding]:
    """Check for version changes and generate findings."""
    findings = []
    
    # Track the manifest and get change notifications
    notifications = tracker.track_manifest(url, manifest)
    
    for notification in notifications:
        severity = Severity.HIGH if notification.requires_approval else Severity.MEDIUM
        
        if notification.change_type == "new_server":
            findings.append(Finding(
                id=str(uuid.uuid4()),
                type=FindingType.SCHEMA_VIOLATION,
                severity=Severity.INFO,
                title="New MCP server detected",
                description=f"First time seeing server '{manifest.name}' at {url}",
                metadata={"notification_id": notification.notification_id}
            ))
        
        elif notification.change_type == "tool_modified":
            findings.append(Finding(
                id=str(uuid.uuid4()),
                type=FindingType.SCHEMA_VIOLATION,
                severity=severity,
                title=f"Tool '{notification.details['tool_name']}' has changed",
                description="Tool definition has been modified since last scan",
                fix_suggestion="Review changes and re-approve if acceptable",
                metadata={
                    "notification_id": notification.notification_id,
                    "changes": notification.details.get("changes", [])
                }
            ))
        
        elif notification.change_type == "permissions_changed":
            findings.append(Finding(
                id=str(uuid.uuid4()),
                type=FindingType.EXCESSIVE_PERMISSIONS,
                severity=Severity.HIGH,
                title="Server permissions have changed",
                description=f"Added: {notification.details.get('added', [])}; Removed: {notification.details.get('removed', [])}",
                cwe_id="CWE-276",
                fix_suggestion="Review permission changes carefully before approving",
                metadata={"notification_id": notification.notification_id}
            ))
        
        elif notification.change_type == "tool_added":
            findings.append(Finding(
                id=str(uuid.uuid4()),
                type=FindingType.SCHEMA_VIOLATION,
                severity=severity,
                title=f"New tool added: '{notification.details['tool_name']}'",
                description=notification.details.get("description", "No description provided"),
                fix_suggestion="Review new tool capabilities before approving",
                metadata={"notification_id": notification.notification_id}
            ))
        
        elif notification.change_type == "tool_removed":
            findings.append(Finding(
                id=str(uuid.uuid4()),
                type=FindingType.SCHEMA_VIOLATION,
                severity=Severity.MEDIUM,
                title=f"Tool removed: '{notification.details['tool_name']}'",
                description="Tool has been removed from the server",
                metadata={"notification_id": notification.notification_id}
            ))
    
    return findings