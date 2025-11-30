# tests/e2etests.py
"""
End-to-end tests for the sliver_exec module.
These tests verify integration with the actual netexec installation.
"""
import subprocess


class TestE2E:
    def test_e2e_module_available_in_netexec(self):
        """
        End-to-end test that verifies the sliver_exec module is properly installed
        and available in netexec's module list.
        """
        # Run netexec smb -L and capture output
        result = subprocess.run(
            ['netexec', 'smb', '-L'],
            capture_output=True,
            text=True,
            timeout=30
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
            ['netexec', 'ssh', '-L'],
            capture_output=True,
            text=True,
            timeout=30
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
            ['netexec', 'winrm', '-L'],
            capture_output=True,
            text=True,
            timeout=30
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
            ['netexec', 'mssql', '-L'],
            capture_output=True,
            text=True,
            timeout=30
        )

        assert result.returncode == 0, f"netexec mssql command failed: {result.stderr}"
        assert 'sliver_exec' in result.stdout, "sliver_exec module not found in MSSQL module list"
        assert 'Generates unique Sliver beacon and executes on target' in result.stdout, \
               "sliver_exec module description not found in MSSQL output"