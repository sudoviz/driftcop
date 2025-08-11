"""
Hot reload capability for configuration and policies
Critical for production environments to update without downtime
"""

import asyncio
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, Callable, Set
from datetime import datetime
import hashlib
import logging

logger = logging.getLogger(__name__)


class ConfigWatcher:
    """
    Watches configuration files for changes and triggers reload
    Implements safe hot reload without disrupting active sessions
    """
    
    def __init__(
        self,
        config_paths: list[Path],
        reload_callback: Callable,
        check_interval: float = 1.0
    ):
        """
        Initialize config watcher
        
        Args:
            config_paths: List of configuration file paths to watch
            reload_callback: Async callback to trigger on config change
            check_interval: How often to check for changes (seconds)
        """
        self.config_paths = config_paths
        self.reload_callback = reload_callback
        self.check_interval = check_interval
        
        # Track file modification times and hashes
        self.file_states = {}
        self._initialize_file_states()
        
        # Watcher state
        self.watching = False
        self.watch_task: Optional[asyncio.Task] = None
        
        # Statistics
        self.reload_count = 0
        self.last_reload = None
        self.failed_reloads = 0
    
    def _initialize_file_states(self):
        """Initialize file state tracking"""
        for path in self.config_paths:
            if path.exists():
                self.file_states[path] = self._get_file_state(path)
            else:
                logger.warning(f"Config file not found: {path}")
                self.file_states[path] = None
    
    def _get_file_state(self, path: Path) -> Dict[str, Any]:
        """Get current state of a file"""
        try:
            stat = path.stat()
            content = path.read_bytes()
            return {
                'mtime': stat.st_mtime,
                'size': stat.st_size,
                'hash': hashlib.md5(content).hexdigest()
            }
        except Exception as e:
            logger.error(f"Error getting file state for {path}: {e}")
            return None
    
    async def start(self):
        """Start watching configuration files"""
        if self.watching:
            logger.warning("Config watcher already running")
            return
        
        self.watching = True
        self.watch_task = asyncio.create_task(self._watch_loop())
        logger.info(f"Started config watcher for {len(self.config_paths)} files")
    
    async def stop(self):
        """Stop watching configuration files"""
        self.watching = False
        if self.watch_task:
            self.watch_task.cancel()
            try:
                await self.watch_task
            except asyncio.CancelledError:
                pass
        logger.info("Stopped config watcher")
    
    async def _watch_loop(self):
        """Main watch loop"""
        while self.watching:
            try:
                # Check each config file
                changed_files = []
                
                for path in self.config_paths:
                    if await self._check_file_changed(path):
                        changed_files.append(path)
                
                # If any files changed, trigger reload
                if changed_files:
                    await self._handle_config_change(changed_files)
                
                # Wait before next check
                await asyncio.sleep(self.check_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in config watch loop: {e}")
                self.failed_reloads += 1
                await asyncio.sleep(self.check_interval * 2)  # Back off on error
    
    async def _check_file_changed(self, path: Path) -> bool:
        """Check if a file has changed"""
        if not path.exists():
            # File was deleted
            if self.file_states.get(path) is not None:
                logger.warning(f"Config file deleted: {path}")
                return True
            return False
        
        current_state = self._get_file_state(path)
        if current_state is None:
            return False
        
        previous_state = self.file_states.get(path)
        if previous_state is None:
            # New file appeared
            self.file_states[path] = current_state
            return True
        
        # Check if file changed (compare hash for accuracy)
        if current_state['hash'] != previous_state['hash']:
            self.file_states[path] = current_state
            return True
        
        return False
    
    async def _handle_config_change(self, changed_files: list[Path]):
        """Handle configuration change"""
        logger.info(f"Configuration changed: {[str(p) for p in changed_files]}")
        
        try:
            # Validate new configuration before reloading
            for path in changed_files:
                if not await self._validate_config(path):
                    logger.error(f"Invalid configuration in {path}, skipping reload")
                    self.failed_reloads += 1
                    return
            
            # Trigger reload callback
            await self.reload_callback(changed_files)
            
            # Update statistics
            self.reload_count += 1
            self.last_reload = datetime.now()
            
            logger.info(f"Configuration reloaded successfully (reload #{self.reload_count})")
            
        except Exception as e:
            logger.error(f"Failed to reload configuration: {e}")
            self.failed_reloads += 1
    
    async def _validate_config(self, path: Path) -> bool:
        """Validate configuration file"""
        try:
            content = path.read_text()
            
            # Parse based on file extension
            if path.suffix in ('.yaml', '.yml'):
                yaml.safe_load(content)
            elif path.suffix == '.json':
                json.loads(content)
            else:
                # Unknown format, skip validation
                pass
            
            return True
            
        except Exception as e:
            logger.error(f"Configuration validation failed for {path}: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get watcher statistics"""
        return {
            'watching': self.watching,
            'files_watched': len(self.config_paths),
            'reload_count': self.reload_count,
            'failed_reloads': self.failed_reloads,
            'last_reload': self.last_reload.isoformat() if self.last_reload else None
        }


class PolicyReloader:
    """
    Handles hot reload of security policies and interceptor configurations
    """
    
    def __init__(self, proxy):
        """
        Initialize policy reloader
        
        Args:
            proxy: DriftCop proxy instance
        """
        self.proxy = proxy
        self.policy_dir = Path.home() / '.driftcop' / 'policies'
        self.policy_dir.mkdir(parents=True, exist_ok=True)
        
        # Track loaded policies
        self.loaded_policies: Dict[str, Any] = {}
        self.policy_versions: Dict[str, int] = {}
    
    async def reload_policies(self, changed_files: list[Path]):
        """
        Reload security policies
        
        Args:
            changed_files: List of changed policy files
        """
        for path in changed_files:
            try:
                # Load new policy
                policy = self._load_policy(path)
                
                if not policy:
                    continue
                
                policy_name = policy.get('name', path.stem)
                
                # Check if this is a new version
                version = policy.get('version', 1)
                if policy_name in self.policy_versions:
                    if version <= self.policy_versions[policy_name]:
                        logger.warning(
                            f"Policy {policy_name} version {version} not newer than "
                            f"current version {self.policy_versions[policy_name]}"
                        )
                        continue
                
                # Apply policy to proxy
                await self._apply_policy(policy_name, policy)
                
                # Update tracking
                self.loaded_policies[policy_name] = policy
                self.policy_versions[policy_name] = version
                
                logger.info(f"Reloaded policy: {policy_name} v{version}")
                
            except Exception as e:
                logger.error(f"Failed to reload policy from {path}: {e}")
    
    def _load_policy(self, path: Path) -> Optional[Dict[str, Any]]:
        """Load policy from file"""
        try:
            content = path.read_text()
            
            if path.suffix in ('.yaml', '.yml'):
                return yaml.safe_load(content)
            elif path.suffix == '.json':
                return json.loads(content)
            else:
                logger.warning(f"Unknown policy format: {path}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to load policy from {path}: {e}")
            return None
    
    async def _apply_policy(self, name: str, policy: Dict[str, Any]):
        """Apply policy to proxy"""
        # Extract interceptor configuration
        interceptors_config = policy.get('interceptors', [])
        
        if not interceptors_config:
            logger.warning(f"Policy {name} has no interceptors")
            return
        
        # Create new interceptor chain
        from ..driftcop_interceptors.factory import InterceptorFactory
        factory = InterceptorFactory()
        
        new_interceptors = []
        for config in interceptors_config:
            interceptor = factory.create(config)
            if interceptor:
                new_interceptors.append(interceptor)
        
        if not new_interceptors:
            logger.warning(f"Policy {name} produced no valid interceptors")
            return
        
        # Update proxy's interceptor chain
        from ..driftcop_interceptors.chain import InterceptorChain
        new_chain = InterceptorChain(new_interceptors)
        
        # Safely swap the chain (atomic operation)
        old_chain = self.proxy.interceptor_chain
        self.proxy.interceptor_chain = new_chain
        
        logger.info(
            f"Applied policy {name} with {len(new_interceptors)} interceptors"
        )
        
        # Clean up old chain
        del old_chain
    
    async def reload_profiles(self, profile_name: str):
        """Reload security profiles"""
        from ..driftcop_proxy.config import get_profile_config
        
        try:
            # Load profile configuration
            profile_config = get_profile_config(profile_name)
            
            # Apply as policy
            await self._apply_policy(profile_name, profile_config)
            
            logger.info(f"Reloaded profile: {profile_name}")
            
        except Exception as e:
            logger.error(f"Failed to reload profile {profile_name}: {e}")


class HotReloadManager:
    """
    Main hot reload manager coordinating all reload operations
    """
    
    def __init__(self, proxy):
        """
        Initialize hot reload manager
        
        Args:
            proxy: DriftCop proxy instance
        """
        self.proxy = proxy
        self.policy_reloader = PolicyReloader(proxy)
        
        # Config paths to watch
        self.config_paths = [
            Path.home() / '.driftcop' / 'config.yaml',
            Path.home() / '.driftcop' / 'policies',
        ]
        
        # Add custom config path if specified
        if hasattr(proxy, 'config') and proxy.config.get('config_path'):
            self.config_paths.append(Path(proxy.config['config_path']))
        
        # Create watcher
        self.watcher = ConfigWatcher(
            self._get_all_config_files(),
            self._reload_callback
        )
        
        self.enabled = False
    
    def _get_all_config_files(self) -> list[Path]:
        """Get all configuration files to watch"""
        files = []
        
        for path in self.config_paths:
            if path.is_file():
                files.append(path)
            elif path.is_dir():
                # Watch all YAML and JSON files in directory
                files.extend(path.glob('*.yaml'))
                files.extend(path.glob('*.yml'))
                files.extend(path.glob('*.json'))
        
        return files
    
    async def _reload_callback(self, changed_files: list[Path]):
        """Handle configuration reload"""
        logger.info(f"Hot reload triggered for {len(changed_files)} files")
        
        # Separate config and policy files
        config_files = []
        policy_files = []
        
        for path in changed_files:
            if 'policies' in path.parts:
                policy_files.append(path)
            else:
                config_files.append(path)
        
        # Reload policies
        if policy_files:
            await self.policy_reloader.reload_policies(policy_files)
        
        # Reload main config
        if config_files:
            await self._reload_main_config(config_files)
    
    async def _reload_main_config(self, config_files: list[Path]):
        """Reload main configuration"""
        for path in config_files:
            try:
                # Load new configuration
                from ..driftcop_proxy.config import load_config
                new_config = load_config(path)
                
                # Update proxy configuration (safe updates only)
                self._update_proxy_config(new_config)
                
                logger.info(f"Reloaded main configuration from {path}")
                
            except Exception as e:
                logger.error(f"Failed to reload main config from {path}: {e}")
    
    def _update_proxy_config(self, new_config: Dict[str, Any]):
        """Safely update proxy configuration"""
        # Only update safe configuration options
        safe_options = [
            'mode',
            'enforcement_mode',
            'log_level',
            'approval_timeout',
            'metrics_enabled'
        ]
        
        for option in safe_options:
            if option in new_config:
                old_value = self.proxy.config.get(option)
                new_value = new_config[option]
                
                if old_value != new_value:
                    self.proxy.config[option] = new_value
                    logger.info(f"Updated {option}: {old_value} -> {new_value}")
    
    async def start(self):
        """Start hot reload manager"""
        if self.enabled:
            logger.warning("Hot reload already enabled")
            return
        
        self.enabled = True
        await self.watcher.start()
        logger.info("Hot reload enabled")
    
    async def stop(self):
        """Stop hot reload manager"""
        if not self.enabled:
            return
        
        self.enabled = False
        await self.watcher.stop()
        logger.info("Hot reload disabled")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get hot reload statistics"""
        return {
            'enabled': self.enabled,
            'watcher_stats': self.watcher.get_stats() if self.watcher else {},
            'loaded_policies': list(self.policy_reloader.loaded_policies.keys())
        }