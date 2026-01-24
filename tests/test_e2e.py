"""
End-to-end tests for the sliver_exec module.
These tests verify integration with the actual netexec installation.
"""
import os
import shutil
import subprocess
import pytest


# If `netexec` is not installed or broken, skip these e2e tests.
# Check both PATH and separate venv location
netexec_paths = [shutil.which("netexec"), "/home/vscode/netexec-venv/bin/netexec"]
netexec_exe = None
for path in netexec_paths:
    if path and (shutil.which(path) or (path and os.path.exists(path))):
        netexec_exe = path
        break

if not netexec_exe:
    pytest.skip("netexec not installed - skipping e2e tests", allow_module_level=True)

try:
    result = subprocess.run([netexec_exe, '--help'], capture_output=True, text=True, timeout=2)
    if result.returncode != 0:
        pytest.skip("netexec is broken - skipping e2e tests", allow_module_level=True)
except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
    pytest.skip("netexec is broken - skipping e2e tests", allow_module_level=True)


class TestE2E:
    def test_e2e_module_available_in_netexec(self):
        """
        End-to-end test that verifies the sliver_exec module is properly installed
        and available in netexec's module list.
        """
        # Run netexec smb -L and capture output
        result = subprocess.run(
            [netexec_exe, 'smb', '-L'],
            capture_output=True,
            text=True,
            timeout=5
        )

        # Check that the command succeeded
        assert result.returncode == 0, f"netexec command failed: {result.stderr}"

        # Check that sliver_exec appears in the output
        assert 'sliver_exec' in result.stdout, "sliver_exec module not found in netexec module list"

        # Check that the description matches
        assert 'Generates unique Sliver beacon and executes on target' in result.stdout, \
               "sliver_exec module description not found in netexec output"

        # Check that sliver_exec is listed under HIGH PRIVILEGE MODULES
        high_privilege_index = result.stdout.find("HIGH PRIVILEGE MODULES")
        sliver_exec_index = result.stdout.find("sliver_exec")
        assert high_privilege_index != -1, "HIGH PRIVILEGE MODULES section not found"
        assert sliver_exec_index != -1, "sliver_exec not found in output"
        assert sliver_exec_index > high_privilege_index, \
               "sliver_exec should appear after HIGH PRIVILEGE MODULES section"

        # Check that sliver_exec appears in the PRIVILEGE_ESCALATION category under HIGH PRIVILEGE
        admin_index = result.stdout.find("PRIVILEGE_ESCALATION", high_privilege_index)
        assert admin_index != -1, "PRIVILEGE_ESCALATION category not found under HIGH PRIVILEGE"
        assert sliver_exec_index > admin_index, \
               "sliver_exec should appear in the ADMIN category under HIGH PRIVILEGE"

    def test_e2e_module_available_in_ssh(self):
        """
        End-to-end test that verifies the sliver_exec module is available for SSH protocol.
        """
        result = subprocess.run(
            [netexec_exe, 'ssh', '-L'],
            capture_output=True,
            text=True,
            timeout=5
        )

        assert result.returncode == 0, f"netexec ssh command failed: {result.stderr}"
        assert 'sliver_exec' in result.stdout, "sliver_exec module not found in SSH module list"
        assert 'Generates unique Sliver beacon and executes on target' in result.stdout, \
               "sliver_exec module description not found in SSH output"

    def test_e2e_module_available_in_winrm(self):
        """
        End-to-end test that verifies the sliver_exec module is available for WinRM protocol.
        """
        result = subprocess.run(
            [netexec_exe, 'winrm', '-L'],
            capture_output=True,
            text=True,
            timeout=5
        )

        assert result.returncode == 0, f"netexec winrm command failed: {result.stderr}"
        assert 'sliver_exec' in result.stdout, "sliver_exec module not found in WinRM module list"
        assert 'Generates unique Sliver beacon and executes on target' in result.stdout, \
               "sliver_exec module description not found in WinRM output"

    def test_e2e_module_available_in_mssql(self):
        """
        End-to-end test that verifies the sliver_exec module is available for MSSQL protocol.
        """
        result = subprocess.run(
            [netexec_exe, 'mssql', '-L'],
            capture_output=True,
            text=True,
            timeout=5
        )

        assert result.returncode == 0, f"netexec mssql command failed: {result.stderr}"
        assert 'sliver_exec' in result.stdout, "sliver_exec module not found in MSSQL module list"
        assert 'Generates unique Sliver beacon and executes on target' in result.stdout, \
               "sliver_exec module description not found in MSSQL output"

    def test_package_contains_required_files(self):
        """
        Test that the built wheel package contains both the sliver_exec module
        and the required Sliver protobuf bindings.
        """
        import zipfile
        import glob

        # Find the wheel file
        whl_files = glob.glob("dist/*.whl")
        assert len(whl_files) > 0, "No wheel file found in dist/"

        whl_path = whl_files[0]

        # Open the wheel and get file list
        with zipfile.ZipFile(whl_path, 'r') as whl:
            file_list = whl.namelist()

        # Check that sliver_exec.py is included
        assert any('nxc/modules/sliver_exec.py' in f for f in file_list), \
               "sliver_exec.py not found in wheel"

        # Check that Sliver protobuf bindings are included
        protobuf_files = [f for f in file_list if 'sliver_client/pb/' in f and f.endswith('.py')]
        assert len(protobuf_files) > 0, "No Sliver protobuf files found in wheel"

        # Check for specific expected protobuf modules
        expected_modules = ['clientpb', 'rpcpb', 'sliverpb', 'commonpb']
        for module in expected_modules:
            assert any(module in f for f in protobuf_files), \
                   f"Protobuf module {module} not found in wheel"