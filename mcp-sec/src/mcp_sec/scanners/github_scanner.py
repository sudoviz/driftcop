"""Scanner for GitHub-hosted MCP repositories."""

import os
import tempfile
import shutil
from typing import Optional
from urllib.parse import urlparse
import subprocess
from pathlib import Path

from mcp_sec.models import ScanResult
from mcp_sec.scanners.workspace_scanner import scan


def scan_github_repo(
    repo_url: str,
    branch: Optional[str] = None,
    token: Optional[str] = None
) -> ScanResult:
    """
    Scan a GitHub repository for MCP security issues.
    
    Args:
        repo_url: GitHub repository URL (e.g., https://github.com/owner/repo)
        branch: Optional branch name to checkout (defaults to default branch)
        token: Optional GitHub token for private repositories
        
    Returns:
        ScanResult from scanning the repository
    """
    # Validate GitHub URL
    parsed = urlparse(repo_url)
    if parsed.netloc not in ['github.com', 'www.github.com']:
        raise ValueError(f"Not a valid GitHub URL: {repo_url}")
    
    # Extract owner and repo name
    path_parts = parsed.path.strip('/').split('/')
    if len(path_parts) < 2:
        raise ValueError(f"Invalid GitHub repository URL format: {repo_url}")
    
    owner, repo = path_parts[0], path_parts[1]
    
    # Remove .git suffix if present
    if repo.endswith('.git'):
        repo = repo[:-4]
    
    # Create temporary directory for cloning
    temp_dir = tempfile.mkdtemp(prefix=f"mcp-scan-{repo}-")
    
    try:
        # Clone the repository
        clone_url = f"https://github.com/{owner}/{repo}.git"
        
        # Add token to URL if provided (for private repos)
        if token:
            clone_url = f"https://{token}@github.com/{owner}/{repo}.git"
        
        clone_cmd = ["git", "clone", "--depth", "1"]
        
        # Add branch if specified
        if branch:
            clone_cmd.extend(["-b", branch])
        
        clone_cmd.extend([clone_url, temp_dir])
        
        # Run git clone
        result = subprocess.run(
            clone_cmd,
            capture_output=True,
            text=True,
            timeout=60  # 60 second timeout
        )
        
        if result.returncode != 0:
            error_msg = result.stderr or "Unknown error"
            # Don't expose token in error messages
            error_msg = error_msg.replace(token, "***") if token else error_msg
            raise RuntimeError(f"Failed to clone repository: {error_msg}")
        
        # Get the actual branch name if not specified
        if not branch:
            # Get the current branch name
            branch_result = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=temp_dir,
                capture_output=True,
                text=True
            )
            if branch_result.returncode == 0:
                branch = branch_result.stdout.strip()
            else:
                branch = "main"  # Default fallback
        
        # Scan the cloned repository
        scan_result = scan(Path(temp_dir))
        
        # Add metadata about the GitHub source
        scan_result.metadata = scan_result.metadata or {}
        scan_result.metadata.update({
            "source": "github",
            "repository": f"{owner}/{repo}",
            "branch": branch,
            "url": repo_url
        })
        
        # Convert local file paths to GitHub URLs in findings
        temp_dir_path = Path(temp_dir).resolve()
        for finding in scan_result.findings:
            if finding.file_path:
                try:
                    # Convert absolute path to relative path from repo root
                    file_path = Path(finding.file_path).resolve()
                    relative_path = file_path.relative_to(temp_dir_path)
                    
                    # Build GitHub URL
                    github_file_url = f"https://github.com/{owner}/{repo}/blob/{branch}/{relative_path}"
                    
                    # Add line number if available
                    if finding.line_number:
                        github_file_url += f"#L{finding.line_number}"
                    
                    # Store both the local path and GitHub URL
                    finding.metadata["github_url"] = github_file_url
                    finding.metadata["local_path"] = finding.file_path
                    # Replace the file_path with the relative path for cleaner display
                    finding.file_path = str(relative_path)
                    
                except ValueError:
                    # Path is not relative to temp_dir, keep as is
                    pass
        
        return scan_result
        
    finally:
        # Always cleanup temporary directory
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


def parse_github_url(url: str) -> tuple[str, str, Optional[str]]:
    """
    Parse a GitHub URL and extract owner, repo, and optional branch.
    
    Supports formats:
    - https://github.com/owner/repo
    - https://github.com/owner/repo.git
    - https://github.com/owner/repo/tree/branch
    - github.com/owner/repo
    
    Returns:
        Tuple of (owner, repo, branch)
    """
    # Ensure https:// prefix
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urlparse(url)
    
    # Validate GitHub domain
    if parsed.netloc not in ['github.com', 'www.github.com']:
        raise ValueError(f"Not a valid GitHub URL: {url}")
    
    # Parse path
    path_parts = [p for p in parsed.path.strip('/').split('/') if p]
    
    if len(path_parts) < 2:
        raise ValueError(f"Invalid GitHub repository URL format: {url}")
    
    owner = path_parts[0]
    repo = path_parts[1]
    
    # Remove .git suffix
    if repo.endswith('.git'):
        repo = repo[:-4]
    
    # Check for branch in URL (e.g., /tree/branch_name)
    branch = None
    if len(path_parts) >= 4 and path_parts[2] == 'tree':
        branch = path_parts[3]
    
    return owner, repo, branch