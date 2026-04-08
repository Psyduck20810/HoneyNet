"""
run_tests.py
============
Convenience script to run all honeypot unit tests from the project root.

Usage:
    python run_tests.py              # Run all tests
    python run_tests.py -v           # Verbose output
    python run_tests.py intelligence # Run only intelligence tests
    python run_tests.py anomaly      # Run only anomaly tests
    python run_tests.py logger       # Run only logger tests

Or with pytest (if installed):
    pytest tests/ -v
    pytest tests/ -v --tb=short
"""
import sys
import os
import unittest

# Make app/ importable
APP_DIR = os.path.join(os.path.dirname(__file__), "app")
sys.path.insert(0, APP_DIR)

SUITES = {
    "intelligence": "tests.test_intelligence",
    "anomaly":      "tests.test_anomaly",
    "logger":       "tests.test_logger",
}

def run(suite_names=None, verbosity=1):
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()

    targets = suite_names or list(SUITES.values())
    for name in targets:
        suite.addTests(loader.loadTestsFromName(name))

    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    verbose = "-v" in sys.argv or "--verbose" in sys.argv

    if args:
        # Map short name → module path
        targets = [SUITES.get(a, a) for a in args]
    else:
        targets = None  # all suites

    sys.exit(run(targets, verbosity=2 if verbose else 1))
