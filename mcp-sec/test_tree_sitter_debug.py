#!/usr/bin/env python3
"""Debug tree-sitter initialization issues."""

import sys
import tree_sitter
import tree_sitter_python
import tree_sitter_javascript

print(f"Python version: {sys.version}")
print(f"tree-sitter module: {tree_sitter}")

# Check the language function
print("\nChecking tree_sitter_python.language():")
lang_func = tree_sitter_python.language()
print(f"Type: {type(lang_func)}")
print(f"Value: {lang_func}")

# Try the new API
print("\nTrying new tree-sitter API:")
try:
    # New API in tree-sitter 0.20+
    PY_LANGUAGE = tree_sitter.Language(tree_sitter_python)
    print("Success with new API!")
    
    parser = tree_sitter.Parser()
    parser.set_language(PY_LANGUAGE)
    
    # Test parsing
    tree = parser.parse(b"def hello(): pass")
    print(f"Parsed tree: {tree.root_node}")
    
except Exception as e:
    print(f"New API failed: {e}")

# Try the old API
print("\nTrying old tree-sitter API:")
try:
    # Old API
    PY_LANGUAGE = tree_sitter.Language(tree_sitter_python.language(), "python")
    print("Success with old API!")
except Exception as e:
    print(f"Old API failed: {e}")