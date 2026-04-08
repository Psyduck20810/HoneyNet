"""
tests/__init__.py
Adds app/ to sys.path so tests can import project modules regardless of
the working directory they are invoked from.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
