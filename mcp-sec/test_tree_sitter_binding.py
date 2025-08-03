#!/usr/bin/env python3
"""Test tree-sitter language bindings."""

import tempfile
import os
from tree_sitter import Language, Parser

# Build a library from the installed parsers
print("Building tree-sitter language library...")

# Create a temporary directory for the library
with tempfile.TemporaryDirectory() as tmpdir:
    lib_path = os.path.join(tmpdir, "languages.so")
    
    # Try to find the language repos
    import tree_sitter_python
    import tree_sitter_javascript
    
    # Get the paths
    py_path = os.path.dirname(tree_sitter_python.__file__)
    js_path = os.path.dirname(tree_sitter_javascript.__file__)
    
    print(f"Python grammar path: {py_path}")
    print(f"JavaScript grammar path: {js_path}")
    
    # Check if the paths contain the necessary files
    print("\nChecking for grammar files...")
    for name, path in [("Python", py_path), ("JavaScript", js_path)]:
        grammar_js = os.path.join(path, "grammar.js")
        src_dir = os.path.join(path, "src")
        print(f"{name}:")
        print(f"  grammar.js exists: {os.path.exists(grammar_js)}")
        print(f"  src/ exists: {os.path.exists(src_dir)}")
        if os.path.exists(path):
            print(f"  Contents: {os.listdir(path)[:5]}")

# Alternative: Try using the bindings directly
print("\n\nTrying tree_sitter_python binding...")
import tree_sitter_python as tspython

# Check for binding
if hasattr(tspython, 'binding'):
    print("Found binding attribute!")
    print(f"Binding: {tspython.binding}")

# Try the language function with Parser
print("\nTrying direct parser initialization...")
parser = Parser()
try:
    # Maybe the language() returns something that can be used differently
    lang = tspython.language()
    print(f"Language object: {lang}")
    print(f"Language type: {type(lang)}")
    
    # Try to find how to use it
    print("\nChecking sys.modules for clues...")
    import sys
    for key in sys.modules:
        if 'tree_sitter' in key:
            print(f"  {key}")
            
except Exception as e:
    print(f"Error: {e}")

# Check tree-sitter-python package structure
print("\n\nExploring tree_sitter_python module...")
print(f"Module file: {tree_sitter_python.__file__}")
print(f"Module attributes: {[a for a in dir(tree_sitter_python) if not a.startswith('_')]}")