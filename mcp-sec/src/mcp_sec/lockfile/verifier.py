"""Lock file verification utilities."""

import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any

from mcp_sec.models import MCPManifest
from mcp_sec.lockfile.manager import LockFileManager


class LockFileVerificationError(Exception):
    """Raised when lock file verification fails."""
    pass


def verify_against_lockfile(
    manifest_path: Path,
    lockfile_path: Path = None,
    strict: bool = True
) -> Tuple[bool, Dict[str, Any]]:
    """
    Verify a manifest against the lock file.
    
    Args:
        manifest_path: Path to the manifest to verify
        lockfile_path: Optional path to lock file (defaults to .mcpsec-lock.toml)
        strict: If True, fail on any mismatch. If False, return detailed report.
    
    Returns:
        Tuple of (success, details)
    """
    # Load lock file
    manager = LockFileManager(lockfile_path)
    
    # Load manifest
    try:
        manifest_data = json.loads(manifest_path.read_text())
        manifest = MCPManifest(**manifest_data)
    except Exception as e:
        return False, {
            "error": f"Failed to load manifest: {e}",
            "path": str(manifest_path)
        }
    
    # Get relative or absolute path for lookup
    lookup_path = str(manifest_path)
    
    # Check if manifest is in lock file
    entry = manager.get_entry(lookup_path)
    if not entry:
        if strict:
            return False, {
                "error": "Manifest not found in lock file",
                "path": lookup_path,
                "suggestion": "Run 'mcp-sec lock add' to add this manifest"
            }
        else:
            return True, {
                "warning": "Manifest not in lock file",
                "path": lookup_path
            }
    
    # Verify manifest
    if manager.verify_manifest(lookup_path, manifest):
        return True, {
            "status": "verified",
            "path": lookup_path,
            "digest": entry.digest,
            "version": entry.version
        }
    
    # Get detailed changes
    changes = manager.get_changes(lookup_path, manifest)
    
    if strict:
        return False, {
            "error": "Manifest does not match lock file",
            "path": lookup_path,
            "changes": changes
        }
    
    return False, changes


def verify_workspace(
    workspace_path: Path,
    lockfile_path: Path = None,
    pattern: str = "**/manifest.json"
) -> Dict[str, Any]:
    """
    Verify all manifests in a workspace against lock file.
    
    Args:
        workspace_path: Root directory to scan
        lockfile_path: Optional path to lock file
        pattern: Glob pattern for finding manifests
    
    Returns:
        Verification report
    """
    # Load lock file
    manager = LockFileManager(lockfile_path)
    
    results = {
        "verified": [],
        "failed": [],
        "not_locked": [],
        "errors": []
    }
    
    # Find all manifests
    for manifest_path in workspace_path.rglob(pattern):
        try:
            success, details = verify_against_lockfile(
                manifest_path,
                lockfile_path,
                strict=False
            )
            
            if success:
                results["verified"].append({
                    "path": str(manifest_path),
                    "digest": details.get("digest")
                })
            elif "warning" in details:
                results["not_locked"].append({
                    "path": str(manifest_path),
                    "warning": details["warning"]
                })
            else:
                results["failed"].append({
                    "path": str(manifest_path),
                    "changes": details.get("changes", {})
                })
                
        except Exception as e:
            results["errors"].append({
                "path": str(manifest_path),
                "error": str(e)
            })
    
    # Summary
    results["summary"] = {
        "total": len(results["verified"]) + len(results["failed"]) + 
                len(results["not_locked"]) + len(results["errors"]),
        "verified": len(results["verified"]),
        "failed": len(results["failed"]),
        "not_locked": len(results["not_locked"]),
        "errors": len(results["errors"])
    }
    
    return results


def verify_ci_digests(
    digest_map: Dict[str, str],
    workspace_path: Path
) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Verify manifests against a simple digest map (for CI).
    
    Args:
        digest_map: Dictionary of path -> expected digest
        workspace_path: Root directory containing manifests
    
    Returns:
        Tuple of (all_valid, failures)
    """
    failures = []
    
    # Create temporary lock file from digest map
    temp_manager = LockFileManager()
    temp_manager.import_from_ci(digest_map)
    
    for rel_path, expected_digest in digest_map.items():
        manifest_path = workspace_path / rel_path
        
        if not manifest_path.exists():
            failures.append({
                "path": rel_path,
                "error": "Manifest not found"
            })
            continue
        
        try:
            # Load and verify
            manifest_data = json.loads(manifest_path.read_text())
            manifest = MCPManifest(**manifest_data)
            
            if not temp_manager.verify_manifest(rel_path, manifest):
                entry = temp_manager.get_entry(rel_path)
                new_entry = temp_manager.add_manifest(rel_path, manifest)
                
                failures.append({
                    "path": rel_path,
                    "expected": expected_digest,
                    "actual": new_entry.digest,
                    "error": "Digest mismatch"
                })
                
        except Exception as e:
            failures.append({
                "path": rel_path,
                "error": f"Verification failed: {e}"
            })
    
    return len(failures) == 0, failures