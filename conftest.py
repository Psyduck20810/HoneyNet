"""
Honeypot Test Suite — conftest.py
Adds app/ to sys.path so all test files can import project modules directly.
Works with both pytest and python -m unittest discover.
"""
import sys
import os

# Ensure app/ directory is importable from any test file
APP_DIR = os.path.join(os.path.dirname(__file__), "app")
if APP_DIR not in sys.path:
    sys.path.insert(0, APP_DIR)
