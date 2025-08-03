"""Base classes for language extractors."""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from pathlib import Path

try:
    from tree_sitter import Parser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    Parser = None
    TREE_SITTER_AVAILABLE = False


class ExtractedTool:
    """Represents an extracted MCP tool definition."""
    
    def __init__(
        self,
        name: str,
        description: Optional[str] = None,
        input_schema: Optional[Dict[str, Any]] = None,
        output_schema: Optional[Dict[str, Any]] = None,
        line_number: int = 0,
        file_path: Optional[str] = None,
        language: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.name = name
        self.description = description
        self.input_schema = input_schema
        self.output_schema = output_schema
        self.line_number = line_number
        self.file_path = file_path
        self.language = language
        self.metadata = metadata or {}


class LanguageExtractor(ABC):
    """Base class for language-specific MCP tool extractors."""
    
    def __init__(self):
        if TREE_SITTER_AVAILABLE and self._uses_tree_sitter():
            self.parser = Parser()
            language = self._get_language()
            if language is not None:
                # New tree-sitter API uses property assignment
                try:
                    self.parser.language = language
                except AttributeError:
                    # Fallback for older tree-sitter versions
                    try:
                        self.parser.set_language(language)
                    except Exception:
                        self.parser = None
        else:
            self.parser = None
    
    def _uses_tree_sitter(self) -> bool:
        """Override to indicate if this extractor uses tree-sitter."""
        return True
    
    @abstractmethod
    def _get_language(self):
        """Get the Tree-sitter language object."""
        pass
    
    @abstractmethod
    def get_tool_query(self) -> str:
        """
        Get the Tree-sitter query for finding MCP tool definitions.
        
        The query should capture:
        - @name: Tool name
        - @description: Tool description
        - @input_schema: Input schema definition
        - @output_schema: Output schema definition (optional)
        - @meta: Additional metadata
        """
        pass
    
    @abstractmethod
    def parse_captured_nodes(self, captures: Dict[str, Any], source_code: bytes) -> ExtractedTool:
        """Parse captured nodes into an ExtractedTool object."""
        pass
    
    def extract_tools(self, file_path: Path) -> List[ExtractedTool]:
        """Extract all MCP tool definitions from a file."""
        if not self._uses_tree_sitter() or self.parser is None:
            # Subclass should override this for non-tree-sitter extraction
            return []
            
        try:
            source_code = file_path.read_bytes()
            tree = self.parser.parse(source_code)
            
            # Get the query
            query_text = self.get_tool_query()
            language = self._get_language()
            
            if language is None:
                return []
                
            # Create and execute query
            from tree_sitter import Query
            query = language.query(query_text)
            
            # Find all matches
            tools = []
            captures_dict = query.captures(tree.root_node)
            
            # The new API returns a dict with capture names as keys
            if isinstance(captures_dict, dict):
                # New API: dict of {capture_name: [nodes]}
                try:
                    tool = self.parse_captured_nodes(captures_dict, source_code)
                    tool.file_path = str(file_path)
                    tool.language = self._get_language_name()
                    if tool.name != "unknown":
                        tools.append(tool)
                except Exception:
                    pass
            else:
                # Old API compatibility: list of (node, name) tuples
                current_captures = {}
                
                for node, name in captures_dict:
                    # Remove @ prefix from capture name
                    name = name.lstrip('@')
                    
                    if name not in current_captures:
                        current_captures[name] = []
                    current_captures[name].append(node)
                    
                    # When we have a complete set, parse it
                    if name == "name" or name == "fn":  # Common trigger points
                        try:
                            tool = self.parse_captured_nodes(current_captures, source_code)
                            tool.file_path = str(file_path)
                            tool.language = self._get_language_name()
                            tools.append(tool)
                            current_captures = {}  # Reset for next tool
                        except Exception:
                            # Continue parsing other tools
                            pass
            
            return tools
            
        except Exception as e:
            print(f"Error extracting from {file_path}: {e}")
            return []
    
    def _get_language_name(self) -> str:
        """Get the name of this language."""
        return self.__class__.__name__.replace("Extractor", "").lower()
    
    def _get_node_text(self, node, source_code: bytes) -> str:
        """Get text content of a node."""
        if hasattr(node, 'text'):
            return node.text.decode('utf-8')
        return source_code[node.start_byte:node.end_byte].decode('utf-8')
    
    def _get_node_line(self, node) -> int:
        """Get line number of a node."""
        if hasattr(node, 'start_point'):
            return node.start_point[0] + 1
        return 0