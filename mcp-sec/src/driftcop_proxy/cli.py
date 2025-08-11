"""
CLI interface for DriftCop Proxy
"""

import sys
import asyncio
import logging
import signal
import multiprocessing as mp
from pathlib import Path
from typing import Optional, List
import json
import typer
from rich.console import Console
from rich.table import Table
from rich.logging import RichHandler
from rich.panel import Panel
from rich.syntax import Syntax

from .core import DriftCopProxy
from .config import load_config, ProxyConfig

app = typer.Typer(
    name="driftcop-proxy",
    help="DriftCop MCP Security Proxy",
    rich_markup_mode="markdown"
)
console = Console()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)
logger = logging.getLogger(__name__)


@app.command()
def start(
    command: List[str] = typer.Argument(..., help="MCP server command to proxy"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Configuration file"),
    profile: str = typer.Option("default", "--profile", "-p", help="Security profile to use"),
    mode: str = typer.Option("enforce", "--mode", "-m", help="Proxy mode: monitor, enforce, interactive"),
    workers: int = typer.Option(None, "--workers", "-w", help="Number of worker processes"),
    no_workers: bool = typer.Option(False, "--no-workers", help="Disable worker pool for debugging"),
    hot_reload: bool = typer.Option(True, "--hot-reload/--no-hot-reload", help="Enable hot reload for config changes"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    debug: bool = typer.Option(False, "--debug", "-d", help="Debug mode")
):
    """
    Start proxy for MCP server
    
    Example:
        driftcop-proxy start python -m mcp_server
        driftcop-proxy start --config proxy.yaml -- npm run server
    """
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    elif verbose:
        logging.getLogger().setLevel(logging.INFO)
    else:
        logging.getLogger().setLevel(logging.WARNING)
    
    console.print(f"[bold green]Starting DriftCop Proxy[/bold green]")
    console.print(f"Command: {' '.join(command)}")
    console.print(f"Profile: {profile}")
    console.print(f"Mode: {mode}")
    
    # Load configuration
    proxy_config = {}
    if config and config.exists():
        proxy_config = load_config(config)
        console.print(f"Loaded config from: {config}")
    
    # Override with CLI options
    proxy_config['profile'] = profile
    proxy_config['mode'] = mode
    if workers:
        proxy_config['worker_count'] = workers
        proxy_config['use_worker_pool'] = True
    if no_workers:
        proxy_config['use_worker_pool'] = False
        console.print("[yellow]Worker pool disabled[/yellow]")
    else:
        proxy_config['use_worker_pool'] = True
        worker_count = workers or proxy_config.get('worker_count', mp.cpu_count())
        console.print(f"Worker pool: {worker_count} processes")
    
    proxy_config['hot_reload'] = hot_reload
    if hot_reload:
        console.print("Hot reload: enabled")
    else:
        console.print("[yellow]Hot reload: disabled[/yellow]")
    
    # Create and run proxy
    proxy = DriftCopProxy(proxy_config)
    
    # Setup signal handlers
    def signal_handler(sig, frame):
        console.print("\n[yellow]Shutting down proxy...[/yellow]")
        asyncio.create_task(proxy.shutdown())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Run proxy
        asyncio.run(proxy.start(command))
    except KeyboardInterrupt:
        console.print("\n[yellow]Proxy interrupted[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@app.command()
def monitor(
    command: List[str] = typer.Argument(..., help="MCP server command to monitor"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file for logs"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output")
):
    """
    Monitor MCP traffic without enforcement
    
    Example:
        driftcop-proxy monitor python server.py
    """
    console.print("[bold blue]Starting in monitor mode[/bold blue]")
    
    config = {
        'mode': 'monitor',
        'interceptors': [
            {
                'type': 'logging',
                'config': {
                    'log_file': str(output) if output else None,
                    'verbose': verbose
                }
            }
        ]
    }
    
    proxy = DriftCopProxy(config)
    
    try:
        asyncio.run(proxy.start(command))
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring stopped[/yellow]")


@app.command()
def test(
    config: Path = typer.Argument(..., help="Configuration file to test"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output")
):
    """
    Test proxy configuration
    
    Example:
        driftcop-proxy test proxy.yaml
    """
    console.print(f"[bold]Testing configuration: {config}[/bold]")
    
    if not config.exists():
        console.print(f"[red]Configuration file not found: {config}[/red]")
        sys.exit(1)
    
    try:
        proxy_config = load_config(config)
        
        # Validate configuration
        from .config import validate_config
        errors = validate_config(proxy_config)
        
        if errors:
            console.print("[red]Configuration errors:[/red]")
            for error in errors:
                console.print(f"  • {error}")
            sys.exit(1)
        
        console.print("[green]✓ Configuration is valid[/green]")
        
        if verbose:
            console.print("\n[bold]Configuration:[/bold]")
            console.print(json.dumps(proxy_config, indent=2))
        
        # Test interceptor creation
        console.print("\n[bold]Testing interceptors:[/bold]")
        from ..driftcop_interceptors.factory import InterceptorFactory
        factory = InterceptorFactory()
        
        for interceptor_config in proxy_config.get('interceptors', []):
            try:
                interceptor = factory.create(interceptor_config)
                if interceptor:
                    console.print(f"  ✓ {interceptor_config['type']}")
                else:
                    console.print(f"  ✗ {interceptor_config['type']} - failed to create")
            except Exception as e:
                console.print(f"  ✗ {interceptor_config['type']} - {e}")
        
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        sys.exit(1)


@app.command()
def profile(
    list_profiles: bool = typer.Option(False, "--list", "-l", help="List available profiles"),
    show: Optional[str] = typer.Option(None, "--show", "-s", help="Show profile details"),
    create: Optional[str] = typer.Option(None, "--create", help="Create new profile"),
    base: Optional[str] = typer.Option(None, "--base", "-b", help="Base profile for new profile"),
    namespace: str = typer.Option("default", "--namespace", "-n", help="Profile namespace"),
    delete: Optional[str] = typer.Option(None, "--delete", "-d", help="Delete profile"),
    validate: Optional[str] = typer.Option(None, "--validate", "-v", help="Validate profile"),
    export: Optional[str] = typer.Option(None, "--export", "-e", help="Export profile"),
    import_file: Optional[Path] = typer.Option(None, "--import", "-i", help="Import profile from file")
):
    """
    Manage guard profiles with namespace support
    
    Examples:
        driftcop-proxy profile --list
        driftcop-proxy profile --list --namespace builtin
        driftcop-proxy profile --show strict-compliance
        driftcop-proxy profile --create myprofile --base development
        driftcop-proxy profile --validate myprofile.json
        driftcop-proxy profile --export myprofile --namespace custom
    """
    from .profiles import ProfileManager
    
    manager = ProfileManager()
    
    if list_profiles:
        profiles = manager.list_profiles(namespace if namespace != 'all' else None)
        
        if not profiles:
            console.print(f"[yellow]No profiles found in namespace: {namespace}[/yellow]")
            return
        
        table = Table(title="Guard Profiles")
        table.add_column("Namespace", style="magenta")
        table.add_column("Name", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("Description", style="white")
        table.add_column("Interceptors", style="yellow", justify="center")
        
        for profile in profiles:
            # Truncate description if too long
            desc = profile.get('description', '')
            if len(desc) > 50:
                desc = desc[:47] + '...'
            
            table.add_row(
                profile.get('namespace', 'default'),
                profile['name'],
                profile.get('version', '1.0.0'),
                desc,
                str(profile.get('interceptor_count', 0))
            )
        
        console.print(table)
        console.print(f"\n[dim]Total profiles: {len(profiles)}[/dim]")
    
    elif show:
        # Parse namespace/name format
        if '/' in show:
            ns, name = show.split('/', 1)
        else:
            ns = namespace
            name = show
        
        profile = manager.load_profile(name, ns)
        if profile:
            console.print(f"[bold]Profile: {ns}/{name}[/bold]\n")
            
            # Pretty print profile details
            from rich.panel import Panel
            from rich.syntax import Syntax
            
            profile_json = json.dumps(profile.to_dict(), indent=2)
            syntax = Syntax(profile_json, "json", theme="monokai", line_numbers=False)
            
            panel = Panel(
                syntax,
                title=f"{profile.name} v{profile.version}",
                subtitle=profile.description[:50] if len(profile.description) > 50 else profile.description
            )
            console.print(panel)
            
            # Validate profile
            errors = profile.validate()
            if errors:
                console.print("\n[red]Validation Errors:[/red]")
                for error in errors:
                    console.print(f"  • {error}")
            else:
                console.print("\n[green]✓ Profile is valid[/green]")
        else:
            console.print(f"[red]Profile not found: {ns}/{name}[/red]")
    
    elif create:
        # Create new profile
        description = typer.prompt("Profile description", default="Custom security profile")
        
        profile = manager.create_profile(
            name=create,
            namespace=namespace,
            base_profile=base,
            description=description
        )
        
        if profile:
            console.print(f"[green]✓ Created profile: {namespace}/{create}[/green]")
            if base:
                console.print(f"  Based on: {base}")
            console.print(f"  Description: {description}")
            console.print(f"\nEdit the profile at: {manager._get_profile_path(create, namespace)}")
        else:
            console.print(f"[red]Failed to create profile: {namespace}/{create}[/red]")
    
    elif delete:
        # Parse namespace/name format
        if '/' in delete:
            ns, name = delete.split('/', 1)
        else:
            ns = namespace
            name = delete
        
        if ns == 'builtin':
            console.print("[red]Cannot delete builtin profiles[/red]")
            return
        
        # Confirm deletion
        confirm = typer.confirm(f"Delete profile {ns}/{name}?")
        if confirm:
            if manager.delete_profile(name, ns):
                console.print(f"[green]✓ Deleted profile: {ns}/{name}[/green]")
            else:
                console.print(f"[red]Failed to delete profile: {ns}/{name}[/red]")
    
    elif validate:
        # Validate profile file
        validate_path = Path(validate)
        if not validate_path.exists():
            console.print(f"[red]File not found: {validate}[/red]")
            return
        
        try:
            with open(validate_path, 'r') as f:
                if validate_path.suffix in ('.yaml', '.yml'):
                    import yaml
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)
            
            from .profiles import GuardProfile
            profile = GuardProfile.from_dict(data)
            errors = profile.validate()
            
            if errors:
                console.print(f"[red]Validation failed for {validate}:[/red]")
                for error in errors:
                    console.print(f"  • {error}")
            else:
                console.print(f"[green]✓ Profile is valid: {validate}[/green]")
                
        except Exception as e:
            console.print(f"[red]Error validating profile: {e}[/red]")
    
    elif export:
        # Export profile
        if '/' in export:
            ns, name = export.split('/', 1)
        else:
            ns = namespace
            name = export
        
        output_path = Path(f"{name}.json")
        if manager.export_profile(name, ns, output_path):
            console.print(f"[green]✓ Exported profile to: {output_path}[/green]")
        else:
            console.print(f"[red]Failed to export profile: {ns}/{name}[/red]")
    
    elif import_file:
        # Import profile from file
        if not import_file.exists():
            console.print(f"[red]File not found: {import_file}[/red]")
            return
        
        profile = manager.import_profile(import_file, namespace)
        if profile:
            console.print(f"[green]✓ Imported profile: {namespace}/{profile.name}[/green]")
            console.print(f"  Version: {profile.version}")
            console.print(f"  Description: {profile.description}")
            console.print(f"  Interceptors: {len(profile.interceptors)}")
        else:
            console.print(f"[red]Failed to import profile from: {import_file}[/red]")
    
    else:
        # Show help if no options provided
        console.print("[yellow]No action specified. Use --help for usage information.[/yellow]")


@app.command()
def stats(
    session: Optional[str] = typer.Option(None, "--session", "-s", help="Session ID"),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table, json"),
    watch: bool = typer.Option(False, "--watch", "-w", help="Watch stats in real-time")
):
    """
    Show proxy statistics
    
    Example:
        driftcop-proxy stats
        driftcop-proxy stats --watch
        driftcop-proxy stats --session abc123 --format json
    """
    from .stats import get_stats, watch_stats
    
    if watch:
        watch_stats(console)
    else:
        stats = get_stats(session)
        
        if format == "json":
            console.print(json.dumps(stats, indent=2))
        else:
            table = Table(title="Proxy Statistics")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="yellow")
            
            for key, value in stats.items():
                if not isinstance(value, (dict, list)):
                    table.add_row(key, str(value))
            
            console.print(table)
            
            if 'sessions' in stats and stats['sessions']:
                console.print("\n[bold]Active Sessions:[/bold]")
                session_table = Table()
                session_table.add_column("Session ID", style="cyan")
                session_table.add_column("Client", style="white")
                session_table.add_column("Messages", style="green")
                session_table.add_column("Blocked", style="red")
                session_table.add_column("Risk", style="yellow")
                
                for session in stats['sessions']:
                    session_table.add_row(
                        session['session_id'][:8],
                        session['client'],
                        str(session['messages_processed']),
                        str(session['messages_blocked']),
                        f"{session['current_risk']:.2f}"
                    )
                
                console.print(session_table)


@app.command()
def approve(
    approval_id: str = typer.Argument(..., help="Approval request ID"),
    action: str = typer.Option(..., "--action", "-a", help="Action: approve, deny"),
    reason: Optional[str] = typer.Option(None, "--reason", "-r", help="Reason for decision")
):
    """
    Handle approval requests
    
    Example:
        driftcop-proxy approve abc123 --action approve
        driftcop-proxy approve abc123 --action deny --reason "Suspicious activity"
    """
    from ..driftcop_approval.manager import ApprovalManager
    
    manager = ApprovalManager()
    
    if action == "approve":
        if manager.approve(approval_id, reason):
            console.print(f"[green]Approved: {approval_id}[/green]")
        else:
            console.print(f"[red]Failed to approve: {approval_id}[/red]")
    elif action == "deny":
        if manager.deny(approval_id, reason or "Denied by administrator"):
            console.print(f"[red]Denied: {approval_id}[/red]")
        else:
            console.print(f"[red]Failed to deny: {approval_id}[/red]")
    else:
        console.print(f"[red]Invalid action: {action}[/red]")


@app.command()
def approvals(
    list_pending: bool = typer.Option(False, "--pending", "-p", help="List pending approvals"),
    list_all: bool = typer.Option(False, "--all", "-a", help="List all approvals"),
    show: Optional[str] = typer.Option(None, "--show", "-s", help="Show approval details")
):
    """
    Manage approval requests
    
    Example:
        driftcop-proxy approvals --pending
        driftcop-proxy approvals --show abc123
    """
    from ..driftcop_approval.manager import ApprovalManager
    
    manager = ApprovalManager()
    
    if list_pending or list_all:
        approvals = manager.list_approvals(pending_only=list_pending)
        
        if not approvals:
            console.print("[yellow]No approval requests found[/yellow]")
            return
        
        table = Table(title="Approval Requests")
        table.add_column("ID", style="cyan")
        table.add_column("Status", style="yellow")
        table.add_column("Method", style="white")
        table.add_column("Risk", style="red")
        table.add_column("Time", style="green")
        
        for approval in approvals:
            table.add_row(
                approval['id'][:8],
                approval['status'],
                approval.get('method', 'unknown'),
                f"{approval.get('risk_score', 0):.2f}",
                approval.get('timestamp', '')
            )
        
        console.print(table)
    
    elif show:
        approval = manager.get_approval(show)
        if approval:
            console.print(f"[bold]Approval Request: {show}[/bold]")
            console.print(json.dumps(approval, indent=2))
        else:
            console.print(f"[red]Approval not found: {show}[/red]")


@app.command()
def validate(
    manifest: Path = typer.Argument(..., help="Path to MCP manifest"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output")
):
    """
    Validate MCP manifest security
    
    Example:
        driftcop-proxy validate manifest.json
    """
    from ..mcp_sec.scanners.manifest import ManifestScanner
    
    console.print(f"[bold]Validating manifest: {manifest}[/bold]")
    
    if not manifest.exists():
        console.print(f"[red]Manifest not found: {manifest}[/red]")
        sys.exit(1)
    
    try:
        with open(manifest) as f:
            manifest_data = json.load(f)
        
        scanner = ManifestScanner()
        result = scanner.scan_manifest(manifest_data)
        
        if result.passed:
            console.print("[green]✓ Manifest passed security validation[/green]")
        else:
            console.print("[red]✗ Manifest failed security validation[/red]")
            
            if result.findings:
                console.print("\n[bold]Security Findings:[/bold]")
                for finding in result.findings:
                    severity_color = {
                        'CRITICAL': 'red',
                        'HIGH': 'orange1',
                        'MEDIUM': 'yellow',
                        'LOW': 'blue'
                    }.get(finding.severity.name, 'white')
                    
                    console.print(f"  [{severity_color}]{finding.severity.name}[/{severity_color}]: {finding.title}")
                    if verbose:
                        console.print(f"    {finding.description}")
        
        sys.exit(0 if result.passed else 1)
        
    except Exception as e:
        console.print(f"[red]Error validating manifest: {e}[/red]")
        sys.exit(1)


def main():
    """Main entry point"""
    app()


if __name__ == "__main__":
    main()