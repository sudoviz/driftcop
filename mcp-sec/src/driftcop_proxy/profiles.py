"""
Guard Profile Manager for DriftCop
Implements namespace-based profile management for security policies
"""

import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List
import logging
from dataclasses import dataclass
from datetime import datetime
import shutil

logger = logging.getLogger(__name__)


@dataclass
class GuardProfile:
    """Represents a security guard profile"""
    name: str
    namespace: str
    version: str
    description: str
    interceptors: List[Dict[str, Any]]
    metadata: Dict[str, Any]
    base_profile: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'name': self.name,
            'namespace': self.namespace,
            'version': self.version,
            'description': self.description,
            'interceptors': self.interceptors,
            'metadata': self.metadata,
            'base_profile': self.base_profile
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any], namespace: str = 'default') -> 'GuardProfile':
        """Create from dictionary"""
        return cls(
            name=data.get('name', 'unnamed'),
            namespace=data.get('namespace', namespace),
            version=data.get('version', '1.0.0'),
            description=data.get('description', ''),
            interceptors=data.get('interceptors', []),
            metadata=data.get('metadata', {}),
            base_profile=data.get('base_profile')
        )
    
    def compose(self, other: 'GuardProfile') -> 'GuardProfile':
        """Compose with another profile"""
        # Merge interceptors
        combined_interceptors = self.interceptors.copy()
        
        # Add interceptors from other profile if not duplicates
        existing_types = {i.get('type') for i in self.interceptors}
        for interceptor in other.interceptors:
            if interceptor.get('type') not in existing_types:
                combined_interceptors.append(interceptor)
        
        # Create composed profile
        return GuardProfile(
            name=f"{self.name}+{other.name}",
            namespace=self.namespace,
            version=self.version,
            description=f"Composition of {self.name} and {other.name}",
            interceptors=combined_interceptors,
            metadata={
                **self.metadata,
                **other.metadata,
                'composed_from': [self.name, other.name],
                'composed_at': datetime.now().isoformat()
            }
        )
    
    def inherit(self, parent: 'GuardProfile') -> 'GuardProfile':
        """Inherit from parent profile with overrides"""
        # Start with parent's interceptors
        inherited_interceptors = parent.interceptors.copy()
        
        # Override with our interceptors
        our_types = {i.get('type'): i for i in self.interceptors}
        
        # Update or append interceptors
        result_interceptors = []
        for parent_interceptor in inherited_interceptors:
            interceptor_type = parent_interceptor.get('type')
            if interceptor_type in our_types:
                # Override parent's interceptor
                result_interceptors.append(our_types[interceptor_type])
                del our_types[interceptor_type]
            else:
                # Keep parent's interceptor
                result_interceptors.append(parent_interceptor)
        
        # Add remaining our interceptors
        result_interceptors.extend(our_types.values())
        
        # Create inherited profile
        return GuardProfile(
            name=self.name,
            namespace=self.namespace,
            version=self.version,
            description=self.description or parent.description,
            interceptors=result_interceptors,
            metadata={
                **parent.metadata,
                **self.metadata,
                'inherited_from': parent.name,
                'inheritance_time': datetime.now().isoformat()
            },
            base_profile=parent.name
        )
    
    def validate(self) -> List[str]:
        """Validate profile configuration"""
        errors = []
        
        # Check required fields
        if not self.name:
            errors.append("Profile must have a name")
        
        if not self.interceptors:
            errors.append("Profile must have at least one interceptor")
        
        # Validate each interceptor
        for i, interceptor in enumerate(self.interceptors):
            if 'type' not in interceptor:
                errors.append(f"Interceptor {i} missing 'type' field")
            
            # Check for valid interceptor types
            valid_types = [
                'filter', 'security', 'approval', 'rate_limit',
                'transform', 'logging', 'audit', 'sigstore',
                'python_function', 'chain'
            ]
            if interceptor.get('type') not in valid_types:
                errors.append(f"Interceptor {i} has invalid type: {interceptor.get('type')}")
        
        return errors


class ProfileManager:
    """Manages guard profiles with namespace support"""
    
    def __init__(self, base_dir: Optional[Path] = None):
        """
        Initialize profile manager
        
        Args:
            base_dir: Base directory for profiles (default: ~/.driftcop)
        """
        self.base_dir = base_dir or Path.home() / '.driftcop'
        self.profiles_dir = self.base_dir / 'guard-profiles'
        self.builtin_dir = Path(__file__).parent / 'profiles' / 'builtin'
        
        # Create directories
        self.profiles_dir.mkdir(parents=True, exist_ok=True)
        
        # Cache for loaded profiles
        self.profile_cache: Dict[str, GuardProfile] = {}
        
        logger.info(f"Profile manager initialized with base: {self.base_dir}")
    
    def _get_profile_path(self, name: str, namespace: str = 'default') -> Path:
        """Get path for a profile"""
        if namespace == 'builtin':
            return self.builtin_dir / f"{name}.json"
        else:
            namespace_dir = self.profiles_dir / namespace
            namespace_dir.mkdir(parents=True, exist_ok=True)
            return namespace_dir / f"{name}.json"
    
    def load_profile(self, name: str, namespace: str = 'default') -> Optional[GuardProfile]:
        """
        Load a guard profile
        
        Args:
            name: Profile name
            namespace: Profile namespace
            
        Returns:
            GuardProfile or None if not found
        """
        cache_key = f"{namespace}/{name}"
        
        # Check cache
        if cache_key in self.profile_cache:
            return self.profile_cache[cache_key]
        
        # Try to load from file
        profile_path = self._get_profile_path(name, namespace)
        
        if not profile_path.exists():
            # Try builtin if not found in user namespace
            if namespace != 'builtin':
                return self.load_profile(name, 'builtin')
            logger.warning(f"Profile not found: {namespace}/{name}")
            return None
        
        try:
            with open(profile_path, 'r') as f:
                if profile_path.suffix == '.yaml' or profile_path.suffix == '.yml':
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)
            
            profile = GuardProfile.from_dict(data, namespace)
            
            # Handle inheritance
            if profile.base_profile:
                # Load base profile
                base_parts = profile.base_profile.split('/')
                if len(base_parts) == 2:
                    base_namespace, base_name = base_parts
                else:
                    base_namespace = namespace
                    base_name = profile.base_profile
                
                base = self.load_profile(base_name, base_namespace)
                if base:
                    profile = profile.inherit(base)
            
            # Validate profile
            errors = profile.validate()
            if errors:
                logger.error(f"Profile validation errors for {namespace}/{name}: {errors}")
                return None
            
            # Cache the profile
            self.profile_cache[cache_key] = profile
            
            logger.info(f"Loaded profile: {namespace}/{name}")
            return profile
            
        except Exception as e:
            logger.error(f"Failed to load profile {namespace}/{name}: {e}")
            return None
    
    def save_profile(self, profile: GuardProfile) -> bool:
        """
        Save a guard profile
        
        Args:
            profile: Profile to save
            
        Returns:
            Success status
        """
        try:
            # Validate before saving
            errors = profile.validate()
            if errors:
                logger.error(f"Cannot save invalid profile: {errors}")
                return False
            
            profile_path = self._get_profile_path(profile.name, profile.namespace)
            
            # Create backup if exists
            if profile_path.exists():
                backup_path = profile_path.with_suffix('.json.bak')
                shutil.copy(profile_path, backup_path)
            
            # Save profile
            with open(profile_path, 'w') as f:
                json.dump(profile.to_dict(), f, indent=2)
            
            # Update cache
            cache_key = f"{profile.namespace}/{profile.name}"
            self.profile_cache[cache_key] = profile
            
            logger.info(f"Saved profile: {profile.namespace}/{profile.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save profile: {e}")
            return False
    
    def list_profiles(self, namespace: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List available profiles
        
        Args:
            namespace: Filter by namespace (None for all)
            
        Returns:
            List of profile summaries
        """
        profiles = []
        
        # List builtin profiles
        if namespace is None or namespace == 'builtin':
            if self.builtin_dir.exists():
                for profile_path in self.builtin_dir.glob('*.json'):
                    try:
                        with open(profile_path, 'r') as f:
                            data = json.load(f)
                        profiles.append({
                            'name': profile_path.stem,
                            'namespace': 'builtin',
                            'description': data.get('description', ''),
                            'version': data.get('version', '1.0.0'),
                            'interceptor_count': len(data.get('interceptors', []))
                        })
                    except Exception as e:
                        logger.error(f"Error reading profile {profile_path}: {e}")
        
        # List user profiles
        if namespace != 'builtin':
            search_namespaces = [namespace] if namespace else []
            
            if not search_namespaces:
                # List all namespaces
                for namespace_dir in self.profiles_dir.iterdir():
                    if namespace_dir.is_dir():
                        search_namespaces.append(namespace_dir.name)
            
            for ns in search_namespaces:
                namespace_dir = self.profiles_dir / ns
                if namespace_dir.exists():
                    for profile_path in namespace_dir.glob('*.json'):
                        try:
                            with open(profile_path, 'r') as f:
                                data = json.load(f)
                            profiles.append({
                                'name': profile_path.stem,
                                'namespace': ns,
                                'description': data.get('description', ''),
                                'version': data.get('version', '1.0.0'),
                                'interceptor_count': len(data.get('interceptors', []))
                            })
                        except Exception as e:
                            logger.error(f"Error reading profile {profile_path}: {e}")
        
        return profiles
    
    def delete_profile(self, name: str, namespace: str = 'default') -> bool:
        """
        Delete a profile
        
        Args:
            name: Profile name
            namespace: Profile namespace
            
        Returns:
            Success status
        """
        if namespace == 'builtin':
            logger.error("Cannot delete builtin profiles")
            return False
        
        try:
            profile_path = self._get_profile_path(name, namespace)
            
            if not profile_path.exists():
                logger.warning(f"Profile not found: {namespace}/{name}")
                return False
            
            # Create backup before deletion
            backup_path = profile_path.with_suffix('.json.deleted')
            shutil.move(profile_path, backup_path)
            
            # Remove from cache
            cache_key = f"{namespace}/{name}"
            self.profile_cache.pop(cache_key, None)
            
            logger.info(f"Deleted profile: {namespace}/{name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete profile: {e}")
            return False
    
    def create_profile(
        self,
        name: str,
        namespace: str = 'default',
        base_profile: Optional[str] = None,
        description: str = '',
        interceptors: Optional[List[Dict[str, Any]]] = None
    ) -> Optional[GuardProfile]:
        """
        Create a new profile
        
        Args:
            name: Profile name
            namespace: Profile namespace
            base_profile: Base profile to inherit from
            description: Profile description
            interceptors: List of interceptor configurations
            
        Returns:
            Created profile or None
        """
        # Check if already exists
        if self.load_profile(name, namespace):
            logger.error(f"Profile already exists: {namespace}/{name}")
            return None
        
        # Create profile
        profile = GuardProfile(
            name=name,
            namespace=namespace,
            version='1.0.0',
            description=description,
            interceptors=interceptors or [],
            metadata={
                'created_at': datetime.now().isoformat(),
                'created_by': 'driftcop'
            },
            base_profile=base_profile
        )
        
        # Handle inheritance if base specified
        if base_profile:
            base_parts = base_profile.split('/')
            if len(base_parts) == 2:
                base_namespace, base_name = base_parts
            else:
                base_namespace = 'builtin'
                base_name = base_profile
            
            base = self.load_profile(base_name, base_namespace)
            if base:
                profile = profile.inherit(base)
            else:
                logger.warning(f"Base profile not found: {base_profile}")
        
        # Save the profile
        if self.save_profile(profile):
            return profile
        
        return None
    
    def export_profile(self, name: str, namespace: str, output_path: Path) -> bool:
        """Export a profile to a file"""
        profile = self.load_profile(name, namespace)
        if not profile:
            return False
        
        try:
            with open(output_path, 'w') as f:
                if output_path.suffix in ('.yaml', '.yml'):
                    yaml.dump(profile.to_dict(), f, default_flow_style=False)
                else:
                    json.dump(profile.to_dict(), f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to export profile: {e}")
            return False
    
    def import_profile(self, input_path: Path, namespace: str = 'default') -> Optional[GuardProfile]:
        """Import a profile from a file"""
        try:
            with open(input_path, 'r') as f:
                if input_path.suffix in ('.yaml', '.yml'):
                    data = yaml.safe_load(f)
                else:
                    data = json.load(f)
            
            profile = GuardProfile.from_dict(data, namespace)
            
            if self.save_profile(profile):
                return profile
            
        except Exception as e:
            logger.error(f"Failed to import profile: {e}")
        
        return None