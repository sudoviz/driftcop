# Copyright (c) 2025 DriftCop Project
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""CLI interface for MCP Security Scanner."""

import sys
import warnings
from datetime import datetime
from pathlib import Path
from typing import Optional

# Suppress urllib3 NotOpenSSLWarning
warnings.filterwarnings("ignore", category=UserWarning, module="urllib3")

import typer
from rich.console import Console
from rich.table import Table

from mcp_sec import __version__
from mcp_sec.config import config
from mcp_sec.models import ScanResult, Severity
from mcp_sec.scanners import server_scanner, workspace_scanner, dependency_scanner
from mcp_sec.scanners.github_scanner import scan_github_repo
from mcp_sec.scanners import ClientDiscovery, ServerFinder, discover_and_scan_all
from mcp_sec.reporters import generate_report, ReportFormat
from mcp_sec.tracking import VersionTracker, ApprovalManager
from mcp_sec.lockfile import LockFileManager, verify_against_lockfile
from mcp_sec.sigstore import sign_manifest

app = typer.Typer(
    name="mcp-sec",
    help="Security scanner for Model Context Protocol (MCP) servers",
    rich_markup_mode="markdown"
)
console = Console()


def version_callback(value: bool) -> None:
    """Show version and exit."""
    if value:
        console.print(f"mcp-sec version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit",
        callback=version_callback,
        is_eager=True
    )
) -> None:
    """MCP Security Scanner - Shift-left security for MCP servers."""
    pass


@app.command()
def discover(
    client: Optional[str] = typer.Option(None, "--client", "-c", help="Specific client to discover (claude, cursor, vscode, windsurf)"),
    scan: bool = typer.Option(False, "--scan", "-s", help="Scan discovered servers for security issues"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed information")
) -> None:
    """Discover all MCP configurations on the system."""
    with console.status("Discovering MCP configurations..."):
        discovery = ClientDiscovery()
        configs = discovery.discover_configs()
        
        if not configs:
            console.print("[yellow]No MCP configurations found[/yellow]")
            return
        
        # Filter by client if specified
        if client:
            configs = [c for c in configs if c.client_name == client]
            if not configs:
                console.print(f"[yellow]No configurations found for client '{client}'[/yellow]")
                return
        
        # Display discovered configurations
        table = Table(title="Discovered MCP Configurations")
        table.add_column("Client", style="cyan")
        table.add_column("Config Path", style="green")
        table.add_column("Servers", style="yellow")
        
        for config in configs:
            server_names = ", ".join(config.servers.keys()) if config.servers else "None"
            table.add_row(
                config.client_name,
                str(config.config_path),
                server_names
            )
        
        console.print(table)
        
        # Show server details if verbose
        if verbose:
            finder = ServerFinder()
            servers = finder.find_all_servers()
            
            console.print(f"\n[bold]Total servers found: {len(servers)}[/bold]")
            
            for server_info in servers:
                console.print(f"\n[cyan]{server_info.server.name}[/cyan] ({server_info.client})")
                console.print(f"  Type: {server_info.server.type}")
                if server_info.server.command:
                    console.print(f"  Command: {server_info.server.command}")
                if server_info.server.url:
                    console.print(f"  URL: {server_info.server.url}")
        
        # Run security scan if requested
        if scan:
            console.print("\n[bold]Running security scan...[/bold]")
            servers, findings = discover_and_scan_all()
            
            if findings:
                console.print(f"\n[yellow]Found {len(findings)} security issues:[/yellow]")
                for finding in findings[:10]:  # Show first 10
                    severity_color = {
                        Severity.CRITICAL: "red",
                        Severity.HIGH: "orange1",
                        Severity.MEDIUM: "yellow",
                        Severity.LOW: "blue",
                        Severity.INFO: "green"
                    }.get(finding.severity, "white")
                    
                    console.print(f"[{severity_color}]{finding.severity.upper()}[/{severity_color}]: {finding.title}")
                    if verbose:
                        console.print(f"  {finding.description}")
                
                if len(findings) > 10:
                    console.print(f"\n... and {len(findings) - 10} more findings")
            else:
                console.print("[green]No security issues found[/green]")


@app.command()
def scan_all(
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    format: ReportFormat = typer.Option(ReportFormat.JSON, "--format", "-f", help="Report format"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output")
) -> None:
    """Scan all discovered MCP configurations for security issues."""
    with console.status("Discovering and scanning all MCP configurations..."):
        start_time = datetime.now()
        
        try:
            # Discover and scan
            servers, findings = discover_and_scan_all()
            
            if not servers:
                console.print("[yellow]No MCP servers found on system[/yellow]")
                return
            
            # Create scan result
            result = ScanResult(
                scanner_name="comprehensive",
                passed=len(findings) == 0,
                findings=findings,
                metadata={
                    "scan_duration_seconds": (datetime.now() - start_time).total_seconds(),
                    "scanned_at": start_time.isoformat(),
                    "servers_found": len(servers),
                    "clients_scanned": list(set(s.client for s in servers))
                }
            )
            
            _display_results(result)
            
            # Show server summary
            console.print(f"\n[bold]Servers discovered: {len(servers)}[/bold]")
            client_counts = {}
            for server in servers:
                client_counts[server.client] = client_counts.get(server.client, 0) + 1
            
            for client, count in client_counts.items():
                console.print(f"  {client}: {count} servers")
            
            if output:
                report = generate_report(result, format)
                output.write_text(report)
                console.print(f"\n[green]Report saved to: {output}[/green]")
            
            _exit_with_code(result)
            
        except Exception as e:
            console.print(f"[red]Error during discovery scan: {e}[/red]")
            raise typer.Exit(1)


@app.command()
def scan_server(
    url: str = typer.Argument(..., help="MCP server URL to scan"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    format: ReportFormat = typer.Option(ReportFormat.JSON, "--format", "-f", help="Report format"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output")
) -> None:
    """Scan an MCP server for security issues."""
    with console.status(f"Scanning server: {url}..."):
        start_time = datetime.now()
        
        try:
            result = server_scanner.scan(url, verbose=verbose)
            
            duration = (datetime.now() - start_time).total_seconds()
            result.metadata["scan_duration_seconds"] = duration
            result.metadata["scanned_at"] = start_time.isoformat()
            
            _display_results(result)
            
            if output:
                report = generate_report(result, format)
                output.write_text(report)
                console.print(f"\n[green]Report saved to: {output}[/green]")
            
            _exit_with_code(result)
            
        except Exception as e:
            console.print(f"[red]Error scanning server: {e}[/red]")
            raise typer.Exit(1)


@app.command()
def scan_workspace(
    path: Path = typer.Argument(Path.cwd(), help="Workspace path to scan"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    format: ReportFormat = typer.Option(ReportFormat.JSON, "--format", "-f", help="Report format"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output")
) -> None:
    """Scan a workspace for MCP security issues."""
    with console.status(f"Scanning workspace: {path}..."):
        start_time = datetime.now()
        
        try:
            result = workspace_scanner.scan(path, verbose=verbose)
            
            duration = (datetime.now() - start_time).total_seconds()
            result.metadata["scan_duration_seconds"] = duration
            result.metadata["scanned_at"] = start_time.isoformat()
            
            _display_results(result)
            
            if output:
                report = generate_report(result, format)
                output.write_text(report)
                console.print(f"\n[green]Report saved to: {output}[/green]")
            
            _exit_with_code(result)
            
        except Exception as e:
            console.print(f"[red]Error scanning workspace: {e}[/red]")
            raise typer.Exit(1)


@app.command()
def scan_deps(
    path: Path = typer.Argument(Path.cwd(), help="Project path with dependencies"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    format: ReportFormat = typer.Option(ReportFormat.JSON, "--format", "-f", help="Report format"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output")
) -> None:
    """Scan project dependencies for security issues."""
    with console.status(f"Scanning dependencies in: {path}..."):
        start_time = datetime.now()
        
        try:
            result = dependency_scanner.scan(path, verbose=verbose)
            
            duration = (datetime.now() - start_time).total_seconds()
            result.metadata["scan_duration_seconds"] = duration
            result.metadata["scanned_at"] = start_time.isoformat()
            
            _display_results(result)
            
            if output:
                report = generate_report(result, format)
                output.write_text(report)
                console.print(f"\n[green]Report saved to: {output}[/green]")
            
            _exit_with_code(result)
            
        except Exception as e:
            console.print(f"[red]Error scanning dependencies: {e}[/red]")
            raise typer.Exit(1)


@app.command()
def scan_github(
    repo_url: str = typer.Argument(..., help="GitHub repository URL (e.g., https://github.com/owner/repo)"),
    branch: Optional[str] = typer.Option(None, "--branch", "-b", help="Git branch to scan (defaults to default branch)"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="GitHub token for private repositories", envvar="GITHUB_TOKEN"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    format: ReportFormat = typer.Option(ReportFormat.JSON, "--format", "-f", help="Report format"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output")
) -> None:
    """Scan a GitHub repository for MCP security issues."""
    # Hide token in console output
    display_url = repo_url
    if branch:
        display_url += f" (branch: {branch})"
    
    with console.status(f"Scanning GitHub repository: {display_url}..."):
        start_time = datetime.now()
        
        try:
            # Import here to avoid circular imports
            from mcp_sec.scanners.github_scanner import scan_github_repo
            
            result = scan_github_repo(repo_url, branch=branch, token=token)
            
            duration = (datetime.now() - start_time).total_seconds()
            result.metadata["scan_duration_seconds"] = duration
            result.metadata["scanned_at"] = start_time.isoformat()
            
            _display_results(result)
            
            if output:
                report = generate_report(result, format)
                output.write_text(report)
                console.print(f"\n[green]Report saved to: {output}[/green]")
            
            _exit_with_code(result)
            
        except Exception as e:
            console.print(f"[red]Error scanning GitHub repository: {e}[/red]")
            raise typer.Exit(1)


@app.command()
def risk_report(
    scan_results: Path = typer.Argument(..., help="Path to scan results JSON"),
    format: ReportFormat = typer.Option(ReportFormat.MARKDOWN, "--format", help="Report format"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path")
) -> None:
    """Generate a risk report from scan results."""
    try:
        import json
        data = json.loads(scan_results.read_text())
        result = ScanResult(**data)
        
        report = generate_report(result, format)
        
        if output:
            output.write_text(report)
            console.print(f"[green]Report saved to: {output}[/green]")
        else:
            console.print(report)
            
    except Exception as e:
        console.print(f"[red]Error generating report: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def ci_hook(
    target: str = typer.Argument(..., help="Target to scan (server URL or workspace path)"),
    threshold: float = typer.Option(config.max_risk_score, "--threshold", help="Maximum risk score"),
    sarif_output: Optional[Path] = typer.Option(None, "--sarif", help="SARIF output path")
) -> None:
    """CI/CD integration hook."""
    start_time = datetime.now()
    
    # Determine scan type
    if target.startswith(("http://", "https://")):
        result = server_scanner.scan(target)
    else:
        result = workspace_scanner.scan(Path(target))
    
    result.metadata["scan_duration_seconds"] = (datetime.now() - start_time).total_seconds()
    result.metadata["scanned_at"] = start_time.isoformat()
    
    # Generate SARIF if requested
    if sarif_output:
        sarif_report = generate_report(result, ReportFormat.SARIF)
        sarif_output.write_text(sarif_report)
        console.print(f"[green]SARIF report saved to: {sarif_output}[/green]")
    
    # Check threshold
    # Get total risk score from metadata or calculate it
    total_risk_score = result.metadata.get("total_risk_score", 0.0)
    if total_risk_score == 0.0 and result.findings:
        # Calculate if not in metadata
        severity_scores = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 4.0,
            Severity.LOW: 1.0,
            Severity.INFO: 0.0
        }
        total_risk_score = sum(severity_scores.get(f.severity, 0.0) for f in result.findings)
        total_risk_score = min(total_risk_score, 10.0)
    
    if total_risk_score > threshold:
        console.print(f"[red]Risk score {total_risk_score:.2f} exceeds threshold {threshold}[/red]")
        _display_results(result)
        raise typer.Exit(1)
    else:
        console.print(f"[green]Risk score {total_risk_score:.2f} within threshold[/green]")
        raise typer.Exit(0)


def _display_results(result: ScanResult) -> None:
    """Display scan results in a table."""
    table = Table(title="Security Scan Results")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    
    table.add_row("[red]Critical[/red]", str(result.critical_count))
    table.add_row("[orange1]High[/orange1]", str(result.high_count))
    table.add_row("[yellow]Medium[/yellow]", str(result.medium_count))
    table.add_row("[blue]Low[/blue]", str(result.low_count))
    
    console.print("\n")
    console.print(table)
    
    # Get total risk score from metadata or calculate it
    total_risk_score = result.metadata.get("total_risk_score", 0.0)
    if total_risk_score == 0.0 and result.findings:
        # Calculate if not in metadata
        severity_scores = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 4.0,
            Severity.LOW: 1.0,
            Severity.INFO: 0.0
        }
        total_risk_score = sum(severity_scores.get(f.severity, 0.0) for f in result.findings)
        total_risk_score = min(total_risk_score, 10.0)
    
    console.print(f"\nTotal Risk Score: [bold]{total_risk_score:.2f}[/bold]")
    
    # Get scan duration from metadata if available
    scan_duration = result.metadata.get("scan_duration_seconds")
    if scan_duration:
        console.print(f"Scan Duration: {scan_duration:.2f}s")
    
    if result.findings:
        console.print("\n[bold]Top Findings:[/bold]")
        for finding in result.findings[:5]:
            severity_color = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "orange1", 
                Severity.MEDIUM: "yellow",
                Severity.LOW: "blue",
                Severity.INFO: "green"
            }.get(finding.severity, "white")
            
            console.print(f"\n[{severity_color}]{finding.severity.upper()}[/{severity_color}]: {finding.title}")
            console.print(f"  {finding.description}")
            
            # Show file location
            if finding.file_path:
                if finding.metadata.get("github_url"):
                    console.print(f"  [cyan]Location:[/cyan] {finding.metadata['github_url']}")
                else:
                    location = f"{finding.file_path}"
                    if finding.line_number:
                        location += f":{finding.line_number}"
                    console.print(f"  [cyan]Location:[/cyan] {location}")
            
            if hasattr(finding, 'recommendation') and finding.recommendation:
                console.print(f"  [green]Fix:[/green] {finding.recommendation}")


def _exit_with_code(result: ScanResult) -> None:
    """Exit with appropriate code based on findings."""
    if result.critical_count > 0:
        raise typer.Exit(2)
    elif result.high_count > 0:
        raise typer.Exit(1)
    else:
        raise typer.Exit(0)


@app.command()
def check_changes(
    server_url: Optional[str] = typer.Option(None, "--server", "-s", help="Check specific server"),
    approve: Optional[str] = typer.Option(None, "--approve", help="Approve a specific change by ID"),
    reject: Optional[str] = typer.Option(None, "--reject", help="Reject a specific change by ID"),
    reason: str = typer.Option("", "--reason", help="Reason for rejection")
) -> None:
    """Check for pending changes and manage approvals."""
    tracker = VersionTracker()
    approval_mgr = ApprovalManager()
    
    # Handle approval/rejection
    if approve:
        if approval_mgr.approve_request(approve, "cli-user"):
            console.print(f"[green]Approved change: {approve}[/green]")
        else:
            console.print(f"[red]Failed to approve: {approve}[/red]")
        return
    
    if reject:
        if approval_mgr.reject_request(reject, "cli-user", reason or "Rejected via CLI"):
            console.print(f"[red]Rejected change: {reject}[/red]")
        else:
            console.print(f"[red]Failed to reject: {reject}[/red]")
        return
    
    # Show pending changes
    notifications = tracker.get_pending_notifications()
    
    if not notifications:
        console.print("[green]No pending changes detected[/green]")
        return
    
    table = Table(title="Pending MCP Changes Requiring Approval")
    table.add_column("ID", style="cyan")
    table.add_column("Server", style="yellow")
    table.add_column("Type", style="magenta")
    table.add_column("Details")
    table.add_column("Risk", style="red")
    
    for notif in notifications:
        # Create approval request if needed
        if notif.requires_approval:
            request = approval_mgr.create_approval_request(notif)
            risk = request.risk_level
        else:
            risk = "low"
        
        table.add_row(
            notif.notification_id[:12],
            notif.server_name,
            notif.change_type.replace("_", " ").title(),
            str(notif.details)[:50] + "...",
            risk
        )
    
    console.print(table)
    console.print("\nTo approve: mcp-sec check-changes --approve <ID>")
    console.print("To reject: mcp-sec check-changes --reject <ID> --reason 'Reason'")


@app.command()
def verify_signature(
    manifest_file: Path = typer.Argument(..., help="Path to signed manifest JSON"),
    public_key: Optional[Path] = typer.Option(None, "--key", "-k", help="Public key file")
) -> None:
    """Verify the digital signature of a manifest."""
    try:
        import json
        from mcp_sec.crypto.verifier import verify_signed_manifest, verify_signature
        
        manifest_data = json.loads(manifest_file.read_text())
        
        if "signature" in manifest_data:
            # Self-contained signed manifest
            result = verify_signed_manifest(manifest_data)
        elif public_key:
            # Separate signature
            result = verify_signature(
                manifest_data.get("manifest", manifest_data),
                manifest_data.get("signature", ""),
                public_key.read_text()
            )
        else:
            console.print("[red]No signature found in manifest and no public key provided[/red]")
            raise typer.Exit(1)
        
        if result.valid:
            console.print(f"[green]✓ Valid signature[/green]")
            if result.signer:
                console.print(f"  Signed by: {result.signer}")
            if result.certificate_info:
                console.print(f"  Valid until: {result.certificate_info.get('not_valid_after')}")
        else:
            console.print(f"[red]✗ Invalid signature: {result.error}[/red]")
            raise typer.Exit(1)
            
    except Exception as e:
        console.print(f"[red]Error verifying signature: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def show_hash(
    manifest_file: Path = typer.Argument(..., help="Path to manifest JSON")
) -> None:
    """Calculate and display manifest/tool hashes."""
    try:
        import json
        from mcp_sec.crypto import compute_manifest_digest, compute_tool_digest
        from mcp_sec.models import MCPManifest
        
        data = json.loads(manifest_file.read_text())
        manifest = MCPManifest(**data)
        
        manifest_hash = compute_manifest_digest(manifest)
        console.print(f"[bold]Manifest Hash:[/bold] {manifest_hash}")
        
        if manifest.tools:
            console.print("\n[bold]Tool Hashes:[/bold]")
            for tool in manifest.tools:
                tool_hash = compute_tool_digest(tool)
                console.print(f"  {tool.name}: {tool_hash[:32]}...")
                
    except Exception as e:
        console.print(f"[red]Error calculating hash: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def lock(
    action: str = typer.Argument(..., help="Action: add, verify, update, remove, list"),
    manifest_path: Optional[Path] = typer.Argument(None, help="Path to manifest file"),
    lockfile: Path = typer.Option(Path(".mcpsec-lock.toml"), "--lockfile", "-l", help="Path to lock file"),
    sign: bool = typer.Option(False, "--sign", "-s", help="Sign with Sigstore when adding"),
    strict: bool = typer.Option(True, "--strict", help="Fail on any verification mismatch")
) -> None:
    """Manage MCP manifest lock file."""
    
    manager = LockFileManager(lockfile)
    
    if action == "add":
        if not manifest_path:
            console.print("[red]Manifest path required for 'add' action[/red]")
            raise typer.Exit(1)
            
        try:
            # Load manifest
            import json
            manifest_data = json.loads(manifest_path.read_text())
            from mcp_sec.models import MCPManifest
            manifest = MCPManifest(**manifest_data)
            
            # Sign if requested
            signature = None
            if sign:
                with console.status("Signing with Sigstore..."):
                    sig_bundle = sign_manifest(manifest_path)
                    signature = sig_bundle
                    console.print("[green]✓ Signed with Sigstore[/green]")
            
            # Add to lock file
            entry = manager.add_manifest(str(manifest_path), manifest, signature)
            manager.save()
            
            console.print(f"[green]Added {manifest_path} to lock file[/green]")
            console.print(f"  Digest: {entry.digest}")
            console.print(f"  Version: {entry.version}")
            console.print(f"  Tools: {len(entry.tools)}")
            
        except Exception as e:
            console.print(f"[red]Error adding manifest: {e}[/red]")
            raise typer.Exit(1)
    
    elif action == "verify":
        if manifest_path:
            # Verify single manifest
            success, details = verify_against_lockfile(manifest_path, lockfile, strict)
            
            if success:
                console.print(f"[green]✓ {manifest_path} verified[/green]")
                if "digest" in details:
                    console.print(f"  Digest: {details['digest']}")
            else:
                console.print(f"[red]✗ {manifest_path} verification failed[/red]")
                if "error" in details:
                    console.print(f"  Error: {details['error']}")
                if "changes" in details:
                    changes = details["changes"]
                    if changes.get("tool_changes"):
                        console.print("  Tool changes:")
                        for change in changes["tool_changes"]:
                            console.print(f"    - {change['type']}: {change['name']}")
                            
                raise typer.Exit(1)
        else:
            # Verify all entries
            console.print("Verifying all locked manifests...")
            all_valid = True
            
            for entry in manager.list_entries():
                manifest_path = Path(entry.path)
                if manifest_path.exists():
                    success, _ = verify_against_lockfile(manifest_path, lockfile, strict)
                    if success:
                        console.print(f"  [green]✓[/green] {entry.path}")
                    else:
                        console.print(f"  [red]✗[/red] {entry.path}")
                        all_valid = False
                else:
                    console.print(f"  [yellow]?[/yellow] {entry.path} (not found)")
                    all_valid = False
            
            if not all_valid:
                raise typer.Exit(1)
    
    elif action == "update":
        if not manifest_path:
            console.print("[red]Manifest path required for 'update' action[/red]")
            raise typer.Exit(1)
        
        # Update existing entry
        try:
            import json
            manifest_data = json.loads(manifest_path.read_text())
            from mcp_sec.models import MCPManifest
            manifest = MCPManifest(**manifest_data)
            
            # Check for changes
            changes = manager.get_changes(str(manifest_path), manifest)
            
            if changes["status"] == "unchanged":
                console.print(f"[yellow]No changes detected in {manifest_path}[/yellow]")
            else:
                # Update entry
                entry = manager.add_manifest(str(manifest_path), manifest)
                manager.save()
                
                console.print(f"[green]Updated {manifest_path} in lock file[/green]")
                console.print(f"  New digest: {entry.digest}")
                
                if changes.get("tool_changes"):
                    console.print("  Changes:")
                    for change in changes["tool_changes"]:
                        console.print(f"    - {change['type']}: {change['name']}")
                        
        except Exception as e:
            console.print(f"[red]Error updating manifest: {e}[/red]")
            raise typer.Exit(1)
    
    elif action == "remove":
        if not manifest_path:
            console.print("[red]Manifest path required for 'remove' action[/red]")
            raise typer.Exit(1)
            
        if manager.remove_entry(str(manifest_path)):
            manager.save()
            console.print(f"[green]Removed {manifest_path} from lock file[/green]")
        else:
            console.print(f"[red]{manifest_path} not found in lock file[/red]")
            raise typer.Exit(1)
    
    elif action == "list":
        entries = manager.list_entries()
        
        if not entries:
            console.print("[yellow]No entries in lock file[/yellow]")
        else:
            table = Table(title=f"Lock File: {lockfile}")
            table.add_column("Path", style="cyan")
            table.add_column("Version", style="green")
            table.add_column("Digest", style="yellow")
            table.add_column("Tools", justify="right")
            table.add_column("Signed", style="blue")
            
            for entry in entries:
                table.add_row(
                    entry.path,
                    entry.version or "-",
                    entry.digest[:16] + "...",
                    str(len(entry.tools)),
                    "✓" if entry.signature else "✗"
                )
            
            console.print(table)
    
    else:
        console.print(f"[red]Unknown action: {action}[/red]")
        console.print("Valid actions: add, verify, update, remove, list")
        raise typer.Exit(1)


@app.command()
def sign(
    manifest_path: Path = typer.Argument(..., help="Path to manifest to sign"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output signature file"),
    identity_token: Optional[str] = typer.Option(None, "--token", help="OIDC identity token")
) -> None:
    """Sign an MCP manifest with Sigstore."""
    try:
        with console.status("Signing with Sigstore..."):
            sig_bundle = sign_manifest(manifest_path, identity_token)
        
        console.print(f"[green]✓ Successfully signed {manifest_path}[/green]")
        console.print(f"  Digest: {sig_bundle['digest']}")
        console.print(f"  Algorithm: {sig_bundle['algorithm']}")
        
        if output:
            import json
            output.write_text(json.dumps(sig_bundle, indent=2))
            console.print(f"  Signature saved to: {output}")
        
        # Also update lock file if it exists
        lockfile = Path(".mcpsec-lock.toml")
        if lockfile.exists():
            manager = LockFileManager(lockfile)
            if manager.update_signature(str(manifest_path), sig_bundle):
                manager.save()
                console.print(f"  Updated signature in lock file")
                
    except Exception as e:
        console.print(f"[red]Signing failed: {e}[/red]")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()