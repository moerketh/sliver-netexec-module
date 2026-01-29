"""
Pytest configuration for sliver_exec module tests.
"""
import pytest


def pytest_addoption(parser):
    """Add custom command-line options for pytest."""
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run integration tests against real targets (requires Sliver server and test target)",
    )


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers",
        "integration: mark test as integration test (requires --run-integration flag)",
    )


def pytest_collection_modifyitems(config, items):
    """Skip integration tests unless --run-integration is provided."""
    if config.getoption("--run-integration"):
        # --run-integration given in cli: do not skip integration tests
        return
    
    skip_integration = pytest.mark.skip(reason="need --run-integration option to run")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)
