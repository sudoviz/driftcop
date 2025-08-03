#!/usr/bin/env python3
"""Find the correct tree-sitter API."""

import tree_sitter
from tree_sitter import Language, Parser
import tree_sitter_python
import tree_sitter_javascript

print("Testing different tree-sitter initialization methods...\n")

# Method 1: Direct language object
print("Method 1: Using language module directly")
try:
    PY_LANGUAGE = Language(tree_sitter_python.language)
    parser = Parser()
    parser.language = PY_LANGUAGE
    tree = parser.parse(b"def hello(): pass")
    print(f"✅ Success! Root node: {tree.root_node.type}")
except Exception as e:
    print(f"❌ Failed: {e}")

# Method 2: With language() function
print("\nMethod 2: Using language() function")
try:
    lang = tree_sitter_python.language()
    print(f"Language type: {type(lang)}")
    # Try to use it directly
    parser = Parser()
    parser.language = lang
    tree = parser.parse(b"def hello(): pass")
    print(f"✅ Success! Root node: {tree.root_node.type}")
except Exception as e:
    print(f"❌ Failed: {e}")

# Method 3: Check Parser.set_language
print("\nMethod 3: Using set_language method")
try:
    parser = Parser()
    parser.set_language(tree_sitter_python.language())
    tree = parser.parse(b"def hello(): pass")
    print(f"✅ Success! Root node: {tree.root_node.type}")
except Exception as e:
    print(f"❌ Failed: {e}")

# Method 4: Try with JavaScript
print("\nMethod 4: Testing JavaScript")
try:
    parser = Parser()
    parser.set_language(tree_sitter_javascript.language())
    tree = parser.parse(b"function hello() {}")
    print(f"✅ Success! Root node: {tree.root_node.type}")
except Exception as e:
    print(f"❌ Failed: {e}")

# Method 5: Check available attributes
print("\nChecking Parser attributes:")
parser = Parser()
print(f"Parser attributes: {[attr for attr in dir(parser) if not attr.startswith('_')]}")

print("\nChecking Language initialization:")
print(f"Language class: {Language}")
print(f"Language init signature: {Language.__init__.__doc__}")