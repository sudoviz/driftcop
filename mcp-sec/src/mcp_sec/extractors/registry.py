"""Registry for language extractors."""

from typing import Dict, Optional, List, Type
from pathlib import Path

from .base import LanguageExtractor, ExtractedTool

# Import extractors that don't require tree-sitter
from .json_extractor import JSONExtractor
from .yaml_extractor import YAMLExtractor

# Conditionally import extractors that require tree-sitter
try:
    from .python_extractor import PythonExtractor
except ImportError:
    PythonExtractor = None

try:
    from .javascript_extractor import JavaScriptExtractor, TypeScriptExtractor
except ImportError:
    JavaScriptExtractor = None
    TypeScriptExtractor = None

try:
    from .go_extractor import GoExtractor
except ImportError:
    GoExtractor = None

try:
    from .rust_extractor import RustExtractor
except ImportError:
    RustExtractor = None

try:
    from .java_extractor import JavaExtractor
except ImportError:
    JavaExtractor = None

try:
    from .csharp_extractor import CSharpExtractor
except ImportError:
    CSharpExtractor = None

try:
    from .ruby_extractor import RubyExtractor
except ImportError:
    RubyExtractor = None

try:
    from .php_extractor import PHPExtractor
except ImportError:
    PHPExtractor = None


class ExtractorRegistry:
    """Registry for managing language-specific extractors."""
    
    def __init__(self):
        self._extractors: Dict[str, Type[LanguageExtractor]] = {}
        self._file_extensions: Dict[str, List[str]] = {}
        self._register_default_extractors()
    
    def _register_default_extractors(self):
        """Register all built-in extractors."""
        # Always available extractors
        self.register_extractor("json", JSONExtractor, [".json"])
        self.register_extractor("yaml", YAMLExtractor, [".yaml", ".yml"])
        
        # Register language-specific extractors if available
        if PythonExtractor is not None:
            self.register_extractor("python", PythonExtractor, [".py"])
        
        if JavaScriptExtractor is not None:
            self.register_extractor("javascript", JavaScriptExtractor, [".js", ".jsx", ".mjs"])
        
        if TypeScriptExtractor is not None:
            self.register_extractor("typescript", TypeScriptExtractor, [".ts", ".tsx"])
        
        if GoExtractor is not None:
            self.register_extractor("go", GoExtractor, [".go"])
        
        if RustExtractor is not None:
            self.register_extractor("rust", RustExtractor, [".rs"])
        
        if JavaExtractor is not None:
            self.register_extractor("java", JavaExtractor, [".java"])
        
        if CSharpExtractor is not None:
            self.register_extractor("csharp", CSharpExtractor, [".cs"])
        
        if RubyExtractor is not None:
            self.register_extractor("ruby", RubyExtractor, [".rb"])
        
        if PHPExtractor is not None:
            self.register_extractor("php", PHPExtractor, [".php"])
    
    def register_extractor(
        self, 
        language: str, 
        extractor_class: Type[LanguageExtractor],
        file_extensions: List[str]
    ):
        """Register a language extractor."""
        self._extractors[language] = extractor_class
        
        for ext in file_extensions:
            if ext not in self._file_extensions:
                self._file_extensions[ext] = []
            self._file_extensions[ext].append(language)
    
    def get_extractor_for_file(self, file_path: Path) -> Optional[LanguageExtractor]:
        """Get the appropriate extractor for a file."""
        ext = file_path.suffix.lower()
        
        if ext not in self._file_extensions:
            return None
        
        # Get the first matching language
        languages = self._file_extensions[ext]
        if not languages:
            return None
        
        language = languages[0]
        
        # Handle special cases
        if ext in [".ts", ".tsx"] and "typescript" in languages:
            language = "typescript"
        
        return self.get_extractor(language)
    
    def get_extractor(self, language: str) -> Optional[LanguageExtractor]:
        """Get an extractor by language name."""
        extractor_class = self._extractors.get(language)
        if extractor_class:
            return extractor_class()
        return None
    
    def extract_from_file(self, file_path: Path) -> List[ExtractedTool]:
        """Extract MCP tool definitions from a file."""
        extractor = self.get_extractor_for_file(file_path)
        if not extractor:
            return []
        
        return extractor.extract_tools(file_path)
    
    def extract_from_directory(
        self, 
        directory: Path, 
        recursive: bool = True,
        ignore_patterns: List[str] = None
    ) -> List[ExtractedTool]:
        """Extract MCP tool definitions from all files in a directory."""
        if ignore_patterns is None:
            ignore_patterns = [
                "node_modules", ".git", "__pycache__", 
                "venv", ".venv", "dist", "build", "target"
            ]
        
        all_tools = []
        
        # Get all supported file extensions
        supported_extensions = set(self._file_extensions.keys())
        
        # Walk directory
        for file_path in self._walk_directory(directory, recursive, ignore_patterns):
            if file_path.suffix.lower() in supported_extensions:
                try:
                    tools = self.extract_from_file(file_path)
                    all_tools.extend(tools)
                except Exception as e:
                    print(f"Error extracting from {file_path}: {e}")
        
        return all_tools
    
    def _walk_directory(
        self, 
        directory: Path, 
        recursive: bool,
        ignore_patterns: List[str]
    ) -> List[Path]:
        """Walk directory and yield file paths."""
        if not recursive:
            return list(directory.glob("*"))
        
        files = []
        for path in directory.rglob("*"):
            # Skip ignored directories
            if any(pattern in str(path) for pattern in ignore_patterns):
                continue
            
            if path.is_file():
                files.append(path)
        
        return files
    
    @property
    def supported_languages(self) -> List[str]:
        """Get list of supported languages."""
        return list(self._extractors.keys())
    
    @property
    def supported_extensions(self) -> List[str]:
        """Get list of supported file extensions."""
        return list(self._file_extensions.keys())


# Global registry instance
_registry = ExtractorRegistry()


def get_extractor(language: str) -> Optional[LanguageExtractor]:
    """Get an extractor for a specific language."""
    return _registry.get_extractor(language)


def extract_from_file(file_path: Path) -> List[ExtractedTool]:
    """Extract MCP tool definitions from a file."""
    return _registry.extract_from_file(file_path)


def extract_from_directory(
    directory: Path, 
    recursive: bool = True,
    ignore_patterns: List[str] = None
) -> List[ExtractedTool]:
    """Extract MCP tool definitions from a directory."""
    return _registry.extract_from_directory(directory, recursive, ignore_patterns)