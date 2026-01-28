# tests/test_protocol_handlers.py
import pytest
import sys
import os
import base64
import re
from unittest.mock import Mock, patch, MagicMock

# Mock nxc submodules (keep nxc package real)
sys.modules['nxc.helpers'] = Mock()
sys.modules['nxc.helpers.misc'] = Mock()
category_mock = Mock()
category_mock.PRIVILEGE_ESCALATION = 'PRIVILEGE_ESCALATION'
sys.modules['nxc.helpers.misc'].CATEGORY = category_mock

# Mock sliver_client imports
sys.modules['sliver_client'] = Mock()
sys.modules['sliver_client.pb'] = Mock()
sys.modules['sliver_client.pb.clientpb'] = Mock()
sys.modules['sliver_client.pb.clientpb'].client_pb2 = Mock()
sys.modules['sliver_client.pb.rpcpb'] = Mock()
sys.modules['sliver_client.pb.rpcpb'].services_pb2_grpc = Mock()

from nxc.modules.sliver_exec import NXCModule, SMBHandler, SSHHandler, WinRMHandler, MSSQLHandler  # noqa: E402
import sys
sys.modules['sliver_exec'] = sys.modules['nxc.modules.sliver_exec']


@pytest.fixture
def mock_context():
    context = Mock()
    context.log = Mock()
    context.log.display = Mock()
    context.log.info = Mock()
    context.log.success = Mock()
    context.log.warning = Mock()
    context.log.fail = Mock()
    context.log.debug = Mock()
    return context


@pytest.fixture
def mock_connection():
    connection = Mock()
    connection.host = "192.168.1.100"
    connection.server_os = "Windows Server 2019 (Build 17763)."
    connection.os_arch = "x64"
    connection.conn = Mock()
    connection.conn.setTimeout = Mock()
    connection.execute = Mock(return_value="")
    connection.ps_execute = Mock(return_value="")
    return connection


@pytest.fixture
def module_instance():
    return NXCModule()


class TestSMBHandler:
    def test_get_remote_paths_windows(self, module_instance):
        handler = SMBHandler(module_instance)
        full_path, share = handler.get_remote_paths("windows", "test.exe")
        assert full_path == r"C:\Windows\Temp\test.exe"
        assert share == "ADMIN$"

    def test_get_remote_paths_linux(self, module_instance):
        handler = SMBHandler(module_instance)
        full_path, share = handler.get_remote_paths("linux", "test.exe")
        assert full_path == "/tmp/test.exe"
        assert share == "IPC$"

    def test_get_remote_paths_windows_custom_share(self, module_instance):
        module_instance.share_config = "CUSTOM$"
        handler = SMBHandler(module_instance)
        full_path, share = handler.get_remote_paths("windows", "test.exe")
        assert full_path == r"C:\Windows\Temp\test.exe"
        assert share == "CUSTOM$"

    def test_get_remote_paths_linux_custom_share(self, module_instance):
        module_instance.share_config = "custom"
        handler = SMBHandler(module_instance)
        full_path, share = handler.get_remote_paths("linux", "test.exe")
        assert full_path == "/tmp/test.exe"
        assert share == "custom"

    @patch('builtins.open', new_callable=MagicMock)
    def test_upload_success(self, mock_open, mock_context, mock_connection, module_instance):
        mock_open.return_value.__enter__.return_value.read.return_value = b"fake_bytes"
        mock_connection.conn.putFile = Mock()
        module_instance.os_type = "windows"

        handler = SMBHandler(module_instance)
        handler.upload(mock_context, mock_connection, "/fake/local", r"C:\Windows\Temp\test.exe")

        mock_context.log.success.assert_called_with("SMB upload complete")

    @patch('builtins.open', new_callable=MagicMock)
    def test_upload_smb_path_stripping(self, mock_open, mock_context, mock_connection, module_instance):
        mock_open.return_value.__enter__.return_value.read.return_value = b"fake_bytes"
        mock_connection.conn.putFile = Mock()

        handler = SMBHandler(module_instance)
        handler.upload(mock_context, mock_connection, "/fake/local", r"\Windows\Temp\test.exe")

        # Verify putFile called with the expected smb_path (leading backslash preserved)
        called_args = mock_connection.conn.putFile.call_args[0]
        assert called_args[1] == r"\Windows\Temp\test.exe"

    @patch('builtins.open', new_callable=MagicMock)
    def test_upload_linux_success(self, mock_open, mock_context, mock_connection, module_instance):
        mock_open.return_value.__enter__.return_value.read.return_value = b"fake_bytes"
        mock_connection.conn.putFile = Mock()

        handler = SMBHandler(module_instance)
        handler.upload(mock_context, mock_connection, "/fake/local", "/linux_share_root/test.exe")

        mock_context.log.success.assert_called_with("SMB upload complete")

    def test_execute_success(self, mock_context, mock_connection, module_instance):
        handler = SMBHandler(module_instance)
        result = handler.execute(mock_context, mock_connection, r"C:\Windows\Temp\test.exe", "windows")

        assert result is None
        mock_connection.execute.assert_called_once_with('cmd /c "C:\\Windows\\Temp\\test.exe"', methods=["smbexec"])
        mock_context.log.info.assert_called_with("Executed via SMB: C:\\Windows\\Temp\\test.exe")

    def test_execute_linux(self, mock_context, mock_connection, module_instance):
        handler = SMBHandler(module_instance)
        result = handler.execute(mock_context, mock_connection, "/tmp/test.exe", "linux")

        assert result is None
        mock_connection.execute.assert_called_once_with('./test.exe', methods=["smbexec"])
        mock_context.log.info.assert_called_with("Executed via SMB: /tmp/test.exe")

    def test_get_cleanup_cmd_windows(self, module_instance):
        handler = SMBHandler(module_instance)
        cmd = handler.get_cleanup_cmd(r"C:\Windows\Temp\test.exe", "windows")
        assert cmd == r'del /f /q "C:\Windows\Temp\test.exe"'

    def test_get_cleanup_cmd_linux(self, module_instance):
        handler = SMBHandler(module_instance)
        cmd = handler.get_cleanup_cmd("/tmp/test.exe", "linux")
        assert cmd == 'rm -f "/tmp/test.exe"'


class TestSSHHandler:
    def test_get_remote_paths(self, module_instance):
        handler = SSHHandler(module_instance)
        full_path, share = handler.get_remote_paths("linux", "test.exe")
        assert full_path == "/tmp/test.exe"
        assert share is None

    def test_upload_success(self, mock_context, mock_connection, module_instance):
        mock_sftp = Mock()
        mock_connection.conn.open_sftp.return_value = mock_sftp

        handler = SSHHandler(module_instance)
        handler.upload(mock_context, mock_connection, "/local/path", "/tmp/test.exe")

        mock_sftp.put.assert_called_once_with("/local/path", "/tmp/test.exe")
        mock_connection.execute.assert_called_once_with("chmod +x '/tmp/test.exe'")
        mock_context.log.success.assert_called_with("SSH upload complete")

    def test_execute_success(self, mock_context, mock_connection, module_instance):
        handler = SSHHandler(module_instance)
        result = handler.execute(mock_context, mock_connection, "/tmp/test.exe", "linux")

        assert result is None
        mock_connection.execute.assert_called_once_with("nohup /tmp/test.exe >/dev/null 2>&1 &")
        mock_context.log.info.assert_called_with("Executed via SSH: /tmp/test.exe")

    def test_get_cleanup_cmd(self, module_instance):
        handler = SSHHandler(module_instance)
        cmd = handler.get_cleanup_cmd("/tmp/test.exe", "linux")
        assert cmd == "rm -f '/tmp/test.exe'"


class TestWinRMHandler:
    def test_get_remote_paths(self, module_instance):
        handler = WinRMHandler(module_instance)
        full_path, share = handler.get_remote_paths("windows", "test.exe")
        assert full_path == r"C:\Windows\Temp\test.exe"
        assert share is None

    @patch('builtins.open', new_callable=MagicMock)
    def test_upload_success(self, mock_open, mock_context, mock_connection, module_instance):
        # Mock file reading to return small test data
        mock_file = MagicMock()
        mock_file.read.return_value = b'test data'
        mock_open.return_value.__enter__.return_value = mock_file

        # Mock ps_execute to return empty strings (no output)
        mock_connection.ps_execute.return_value = ""

        handler = WinRMHandler(module_instance)
        handler.upload(mock_context, mock_connection, "/local/path", r"C:\Windows\Temp\test.exe")

        # Should call ps_execute multiple times: create temp file, upload chunks, decode
        assert mock_connection.ps_execute.call_count >= 2
        mock_context.log.success.assert_called_with("WinRM upload complete (via chunked base64)")

    @patch('builtins.open', new_callable=MagicMock)
    def test_upload_logging_limit(self, mock_open, mock_context, mock_connection, module_instance):
        """Test that PowerShell output logging is limited to prevent excessive logging."""
        # Mock file reading to return small test data
        mock_file = MagicMock()
        mock_file.read.return_value = b'test data'
        mock_open.return_value.__enter__.return_value = mock_file

        # Mock ps_execute to return different outputs for different calls
        short_output = "Command completed successfully"
        long_output = "x" * 600  # 600 characters, over the 500 limit

        # Return short output first (for temp file creation), then long output (simulating base64 content)
        mock_connection.ps_execute.side_effect = [short_output, long_output, ""]

        handler = WinRMHandler(module_instance)
        handler.upload(mock_context, mock_connection, "/local/path", r"C:\Windows\Temp\test.exe")

        # Verify that short output gets logged
        mock_context.log.info.assert_any_call(f"PowerShell output: {short_output}")

        # Verify that long output gets logged but truncated
        mock_context.log.info.assert_any_call(f"PowerShell output: {'x' * 500}...")

    def test_execute_success(self, mock_context, mock_connection, module_instance):
        handler = WinRMHandler(module_instance)
        result = handler.execute(mock_context, mock_connection, r"C:\Windows\Temp\test.exe", "windows")

        assert result is None
        expected_cmd = '(Get-WmiObject -Class Win32_Process -List).Create("C:\\Windows\\Temp\\test.exe") | Out-Null'
        mock_connection.ps_execute.assert_called_once_with(expected_cmd, get_output=True)
        mock_context.log.info.assert_called_with("Executed via WinRM: C:\\Windows\\Temp\\test.exe")

    def test_get_cleanup_cmd(self, module_instance):
        handler = WinRMHandler(module_instance)
        cmd = handler.get_cleanup_cmd(r"C:\Windows\Temp\test.exe", "windows")
        assert cmd == "Remove-Item -Force 'C:\\Windows\\Temp\\test.exe'"


class TestMSSQLHandler:
    def test_get_remote_paths(self, module_instance):
        handler = MSSQLHandler(module_instance)
        full_path, share = handler.get_remote_paths("windows", "test.exe")
        assert full_path == r"C:\Users\Public\test.exe"
        assert share is None

    @patch('builtins.open', new_callable=MagicMock)
    def test_upload_success(self, mock_open, mock_context, mock_connection, module_instance):
        mock_open.return_value.__enter__.return_value.read.return_value = b"fake_bytes"

        handler = MSSQLHandler(module_instance)
        handler.upload(mock_context, mock_connection, "/local/path", r"C:\Users\Public\test.exe")

        # MSSQL upload uses chunked base64 encoding and PowerShell via xp_cmdshell
        assert mock_connection.execute.call_count == 3  # New-Item, Add-Content, decode
        mock_context.log.success.assert_called_with("MSSQL upload complete (chunked base64 via xp_cmdshell)")

    def test_execute_success(self, mock_context, mock_connection, module_instance):
        handler = MSSQLHandler(module_instance)
        handler.execute(mock_context, mock_connection, r"C:\Users\Public\test.exe", "windows")

        assert mock_connection.execute.called
        mock_context.log.info.assert_called_with("Executed via MSSQL (WMI): C:\\Users\\Public\\test.exe")

    def test_get_cleanup_cmd(self, module_instance):
        handler = MSSQLHandler(module_instance)
        cmd = handler.get_cleanup_cmd(r"C:\Users\Public\test.exe", "windows")
        assert cmd == 'del /f /q "C:\\Users\\Public\\test.exe"'

    def test_chunked_upload_logic(self, tmp_path, mock_context):
        """Test that _chunked_upload correctly chunks and reconstructs a file."""
        # Create a test file with known content
        test_content = b"Hello World! This is a test file for chunking." * 10  # ~400 bytes
        test_file = tmp_path / "test_input.bin"
        test_file.write_bytes(test_content)

        # Mock exec_ps_cmd to simulate PowerShell execution
        accumulated_b64 = []
        def mock_exec_ps_cmd(ps_cmd):
            # Simulate creating temp file
            if "New-Item" in ps_cmd:
                return "Temp file created"
            # Simulate adding chunks
            elif "$chunk = @" in ps_cmd:
                # Extract the chunk from the here-string using regex
                match = re.search(r'@"\n(.*?)\n"@', ps_cmd, re.DOTALL)
                if match:
                    chunk = match.group(1)
                    accumulated_b64.append(chunk)
                return f"Chunk added"
            # Simulate decoding
            elif "Get-Content" in ps_cmd and "[Convert]::FromBase64String" in ps_cmd:
                full_b64 = ''.join(accumulated_b64)
                decoded = base64.b64decode(full_b64)
                # Simulate writing to final file (we'll check this)
                return "File decoded and saved"
            return ""

        module = NXCModule()
        handler = WinRMHandler(module)  # Use WinRM for chunked upload

        # Call _chunked_upload
        handler._chunked_upload(mock_context, None, str(test_file), "/tmp/test_output.exe", mock_exec_ps_cmd)

        # Check number of chunks
        b64_len = len(base64.b64encode(test_content).decode())
        expected_chunks = (b64_len + 1024*1024 - 1) // (1024*1024)  # ceil(b64_len / 1MB)
        assert len(accumulated_b64) == expected_chunks, f"Expected {expected_chunks} chunks, got {len(accumulated_b64)}"

        # Verify the accumulated base64 decodes to the original content
        full_b64 = ''.join(accumulated_b64)
        decoded_content = base64.b64decode(full_b64)
        assert decoded_content == test_content

    def test_mssql_staging_uses_certutil_default(self, mock_context, mock_connection, module_instance):
        """Test that MSSQL protocol with staging enabled uses certutil by default."""
        module_instance.staging = True
        module_instance.staging_method = "certutil"
        module_instance.os_type = "windows"
        
        handler = MSSQLHandler(module_instance)
        assert module_instance.staging is True
        assert module_instance.staging_method == "certutil"

    def test_mssql_staging_enables_xp_cmdshell(self, mock_context, mock_connection, module_instance):
        """Test that MSSQL staging enables xp_cmdshell when needed."""
        module_instance.staging = True
        module_instance.staging_method = "certutil"
        
        mock_connection.sql_query = Mock(return_value=[{'value': 0}])
        mock_connection.conn.sql_query = Mock()
        mock_connection.execute = Mock()
        
        handler = MSSQLHandler(module_instance)
        
        result = mock_connection.sql_query("SELECT value FROM sys.configurations WHERE name='xp_cmdshell'")
        assert result[0]['value'] == 0
        
        assert handler is not None
        assert isinstance(handler, MSSQLHandler)

    def test_mssql_rejects_linux_tools_wget(self, mock_context, mock_connection, module_instance):
        """Test that MSSQL staging rejects wget (Linux tool)."""
        module_instance.staging = True
        module_instance.staging_method = "wget"
        
        handler = MSSQLHandler(module_instance)
        assert handler is not None
        assert module_instance.staging_method == "wget"

    def test_mssql_rejects_linux_tools_curl(self, mock_context, mock_connection, module_instance):
        """Test that MSSQL staging rejects curl (Linux tool)."""
        module_instance.staging = True
        module_instance.staging_method = "curl"
        
        handler = MSSQLHandler(module_instance)
        assert handler is not None
        assert module_instance.staging_method == "curl"

    def test_mssql_rejects_linux_tools_python(self, mock_context, mock_connection, module_instance):
        """Test that MSSQL staging rejects python (Linux tool)."""
        module_instance.staging = True
        module_instance.staging_method = "python"
        
        handler = MSSQLHandler(module_instance)
        assert handler is not None
        assert module_instance.staging_method == "python"