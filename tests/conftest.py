"""
Pytest configuration for sliver_exec module tests.
"""
import pytest
import sys
import shutil
from pathlib import Path


def pytest_configure(config):
    """Configure pytest with custom markers and ensure protobuf files exist."""
    config.addinivalue_line(
        "markers",
        "integration: mark test as integration test (requires --run-integration flag)",
    )
    
    root_dir = Path(__file__).parent.parent
    src_dir = root_dir / "src" / "sliver_client"
    pb_dir = src_dir / "pb"
    
    # Ensure protobuf files exist in main src directory
    if not pb_dir.exists():
        parent_pb_dir = Path(__file__).parent.parent.parent / "src" / "sliver_client" / "pb"
        if parent_pb_dir.exists():
            pb_dir.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(parent_pb_dir, pb_dir, dirs_exist_ok=True)
    
    # Copy protobuf files to mutants directory for mutation testing
    mutants_dir = root_dir / "mutants"
    if mutants_dir.exists():
        # Copy entire sliver_client package structure to mutants
        mutants_sliver_dir = mutants_dir / "src" / "sliver_client"
        if src_dir.exists():
            mutants_sliver_dir.parent.mkdir(parents=True, exist_ok=True)
            # Copy the entire sliver_client directory
            if mutants_sliver_dir.exists():
                shutil.rmtree(mutants_sliver_dir)
            shutil.copytree(src_dir, mutants_sliver_dir, dirs_exist_ok=False)
        
        # Ensure mutants/src is in sys.path for mutant imports
        mutants_src_path = str(mutants_dir / "src")
        if mutants_src_path not in sys.path:
            sys.path.insert(0, mutants_src_path)


def pytest_addoption(parser):
    """Add custom command-line options for pytest."""
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run integration tests against real targets (requires Sliver server and test target)",
    )


def pytest_collection_modifyitems(config, items):
    """Skip integration tests unless --run-integration is provided."""
    if config.getoption("--run-integration"):
        return
    
    skip_integration = pytest.mark.skip(reason="need --run-integration option to run")
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)
