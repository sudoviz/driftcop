"""
Configuration management for DriftCop Proxy
"""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


@dataclass
class ProxyConfig:
    """Proxy configuration"""
    mode: str = "enforce"  # monitor, enforce, interactive
    profile: str = "default"
    worker_count: Optional[int] = None
    queue_size: int = 10000
    use_shared_memory: bool = False
    shm_size: int = 100 * 1024 * 1024  # 100MB
    use_worker_pool: bool = True
    
    # Client configuration
    client_name: str = "unknown"
    env: Dict[str, str] = field(default_factory=dict)
    
    # Interceptor configuration
    interceptors: List[Dict[str, Any]] = field(default_factory=list)
    
    # Storage configuration
    storage_type: str = "lmdb"  # lmdb, sqlite, memory
    storage_path: Optional[Path] = None
    
    # Monitoring configuration
    metrics_enabled: bool = True
    metrics_port: int = 9090
    health_port: int = 8080
    
    # Approval configuration
    approval_timeout: int = 300  # seconds
    approval_path: Optional[Path] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'mode': self.mode,
            'profile': self.profile,
            'worker_count': self.worker_count,
            'queue_size': self.queue_size,
            'use_shared_memory': self.use_shared_memory,
            'shm_size': self.shm_size,
            'use_worker_pool': self.use_worker_pool,
            'client_name': self.client_name,
            'env': self.env,
            'interceptors': self.interceptors,
            'storage_type': self.storage_type,
            'storage_path': str(self.storage_path) if self.storage_path else None,
            'metrics_enabled': self.metrics_enabled,
            'metrics_port': self.metrics_port,
            'health_port': self.health_port,
            'approval_timeout': self.approval_timeout,
            'approval_path': str(self.approval_path) if self.approval_path else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProxyConfig':
        """Create from dictionary"""
        # Convert paths
        if 'storage_path' in data and data['storage_path']:
            data['storage_path'] = Path(data['storage_path'])
        if 'approval_path' in data and data['approval_path']:
            data['approval_path'] = Path(data['approval_path'])
        
        return cls(**data)


def load_config(path: Path) -> Dict[str, Any]:
    """
    Load configuration from file
    
    Args:
        path: Path to configuration file (JSON or YAML)
        
    Returns:
        Configuration dictionary
    """
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")
    
    with open(path) as f:
        if path.suffix in ('.yaml', '.yml'):
            return yaml.safe_load(f)
        else:
            return json.load(f)


def validate_config(config: Dict[str, Any]) -> List[str]:
    """
    Validate configuration
    
    Args:
        config: Configuration dictionary
        
    Returns:
        List of validation errors (empty if valid)
    """
    errors = []
    
    # Validate mode
    valid_modes = {'monitor', 'enforce', 'interactive'}
    if 'mode' in config and config['mode'] not in valid_modes:
        errors.append(f"Invalid mode: {config['mode']}. Must be one of {valid_modes}")
    
    # Validate interceptors
    if 'interceptors' in config:
        for i, interceptor in enumerate(config['interceptors']):
            if 'type' not in interceptor:
                errors.append(f"Interceptor {i} missing 'type' field")
    
    # Validate storage type
    valid_storage = {'lmdb', 'sqlite', 'memory'}
    if 'storage_type' in config and config['storage_type'] not in valid_storage:
        errors.append(f"Invalid storage_type: {config['storage_type']}. Must be one of {valid_storage}")
    
    # Validate ports
    if 'metrics_port' in config:
        port = config['metrics_port']
        if not isinstance(port, int) or port < 1 or port > 65535:
            errors.append(f"Invalid metrics_port: {port}")
    
    if 'health_port' in config:
        port = config['health_port']
        if not isinstance(port, int) or port < 1 or port > 65535:
            errors.append(f"Invalid health_port: {port}")
    
    return errors


def get_default_config() -> Dict[str, Any]:
    """Get default configuration"""
    return ProxyConfig().to_dict()


def get_profile_config(profile: str) -> Dict[str, Any]:
    """
    Get configuration for a specific profile
    
    Args:
        profile: Profile name (default, strict, development, production)
        
    Returns:
        Profile configuration
    """
    profiles = {
        'default': {
            'mode': 'enforce',
            'interceptors': [
                {
                    'type': 'security',
                    'config': {
                        'enable_tool_poisoning': True,
                        'enable_cross_origin': True,
                        'enable_toxic_flow': True,
                        'enable_semantic_drift': False,
                        'block_threshold': 8.0,
                        'review_threshold': 5.0
                    }
                },
                {
                    'type': 'rate_limit',
                    'config': {
                        'limits': {
                            'tools/call': {'max_calls': 10, 'window_seconds': 60},
                            'resources/write': {'max_calls': 5, 'window_seconds': 60}
                        }
                    }
                }
            ]
        },
        'strict': {
            'mode': 'enforce',
            'interceptors': [
                {
                    'type': 'security',
                    'config': {
                        'enable_tool_poisoning': True,
                        'enable_cross_origin': True,
                        'enable_toxic_flow': True,
                        'enable_semantic_drift': True,
                        'block_threshold': 5.0,
                        'review_threshold': 3.0
                    }
                },
                {
                    'type': 'sigstore',
                    'config': {
                        'verify_manifests': True,
                        'require_signatures': True
                    }
                },
                {
                    'type': 'rate_limit',
                    'config': {
                        'limits': {
                            'tools/call': {'max_calls': 5, 'window_seconds': 60},
                            'resources/write': {'max_calls': 2, 'window_seconds': 60},
                            'resources/delete': {'max_calls': 1, 'window_seconds': 300}
                        }
                    }
                },
                {
                    'type': 'approval',
                    'config': {
                        'require_approval': ['resources/delete', 'prompts/execute'],
                        'timeout': 300
                    }
                }
            ]
        },
        'development': {
            'mode': 'monitor',
            'interceptors': [
                {
                    'type': 'logging',
                    'config': {
                        'verbose': True,
                        'include_payloads': True
                    }
                },
                {
                    'type': 'security',
                    'config': {
                        'enable_tool_poisoning': True,
                        'enable_cross_origin': False,
                        'enable_toxic_flow': False,
                        'enable_semantic_drift': False,
                        'block_threshold': 10.0,
                        'review_threshold': 8.0
                    }
                }
            ]
        },
        'production': {
            'mode': 'enforce',
            'use_shared_memory': True,
            'use_worker_pool': True,
            'interceptors': [
                {
                    'type': 'security',
                    'config': {
                        'enable_tool_poisoning': True,
                        'enable_cross_origin': True,
                        'enable_toxic_flow': True,
                        'enable_semantic_drift': True,
                        'block_threshold': 6.0,
                        'review_threshold': 4.0
                    }
                },
                {
                    'type': 'sigstore',
                    'config': {
                        'verify_manifests': True,
                        'require_signatures': True,
                        'trusted_keys': ['prod-key.pub']
                    }
                },
                {
                    'type': 'rate_limit',
                    'config': {
                        'limits': {
                            'tools/call': {'max_calls': 20, 'window_seconds': 60},
                            'resources/write': {'max_calls': 10, 'window_seconds': 60},
                            'resources/delete': {'max_calls': 2, 'window_seconds': 300},
                            'prompts/execute': {'max_calls': 5, 'window_seconds': 60}
                        }
                    }
                },
                {
                    'type': 'approval',
                    'config': {
                        'require_approval': ['resources/delete'],
                        'timeout': 600
                    }
                },
                {
                    'type': 'audit',
                    'config': {
                        'log_all': True,
                        'include_payloads': False
                    }
                }
            ],
            'storage_type': 'lmdb',
            'metrics_enabled': True
        }
    }
    
    return profiles.get(profile, profiles['default'])


def merge_configs(*configs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge multiple configurations
    
    Args:
        *configs: Configuration dictionaries to merge
        
    Returns:
        Merged configuration
    """
    result = {}
    
    for config in configs:
        if config:
            # Deep merge
            for key, value in config.items():
                if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                    result[key] = merge_configs(result[key], value)
                elif key == 'interceptors' and key in result:
                    # Append interceptors
                    result[key] = result[key] + value
                else:
                    result[key] = value
    
    return result


def load_env_config() -> Dict[str, Any]:
    """Load configuration from environment variables"""
    config = {}
    
    # DRIFTCOP_MODE
    if 'DRIFTCOP_MODE' in os.environ:
        config['mode'] = os.environ['DRIFTCOP_MODE']
    
    # DRIFTCOP_PROFILE
    if 'DRIFTCOP_PROFILE' in os.environ:
        config['profile'] = os.environ['DRIFTCOP_PROFILE']
    
    # DRIFTCOP_WORKERS
    if 'DRIFTCOP_WORKERS' in os.environ:
        try:
            config['worker_count'] = int(os.environ['DRIFTCOP_WORKERS'])
        except ValueError:
            logger.warning(f"Invalid DRIFTCOP_WORKERS value: {os.environ['DRIFTCOP_WORKERS']}")
    
    # DRIFTCOP_CLIENT
    if 'DRIFTCOP_CLIENT' in os.environ:
        config['client_name'] = os.environ['DRIFTCOP_CLIENT']
    
    # DRIFTCOP_STORAGE_PATH
    if 'DRIFTCOP_STORAGE_PATH' in os.environ:
        config['storage_path'] = os.environ['DRIFTCOP_STORAGE_PATH']
    
    return config