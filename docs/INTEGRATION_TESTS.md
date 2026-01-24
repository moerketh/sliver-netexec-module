# Integration Tests Setup Guide

## Overview

Integration tests require live Windows/Linux targets with valid credentials. These tests are **skipped by default** and only run when:
1. Required environment variables are configured
2. The `--run-integration` flag is provided to pytest

**IMPORTANT**: Always use the `--run-integration` flag:
```bash
poetry run pytest tests/test_integration.py -v --run-integration
```

## Prerequisites

### 1. Sliver Server
- ✅ Sliver server installed at `/usr/local/bin/sliver-server`
- ✅ Sliver client config at `~/.sliver-client/configs/default.cfg`
- ✅ Sliver server running (started automatically by devcontainer)
- ✅ Proxychains configured to exclude localhost (allows module to connect to Sliver)

**Devcontainer Auto-Configuration:**
The devcontainer automatically:
- Installs Sliver server
- Starts Sliver daemon on port 31337
- Generates operator config with `--permissions all`
- Configures proxychains to exclude `127.0.0.0/255.0.0.0`

Check Sliver status:
```bash
sliver-status
# OR manually:
ps aux | grep sliver-server | grep -v grep
netstat -tlnp | grep 31337
```

### 2. NetExec Installation
- ✅ NetExec installed in separate venv at `~/netexec-venv/`
- ✅ Module symlinked: `~/netexec-venv/lib/python*/site-packages/nxc/modules/sliver_exec.py`

Verify module is available:
```bash
netexec smb -L | grep sliver_exec
```

### 3. Live Test Target
You need a Windows or Linux machine with:
- Network connectivity from this devcontainer
- Valid credentials (Administrator/root privileges)
- SMB/WinRM/SSH/MSSQL service enabled
- Firewall allows connections from your IP

### 4. Network Routing
Ensure the target can reach back to your Sliver listener:
- Sliver listener should be on a routable IP (not localhost)
- Target must be able to connect to `SLIVER_LISTENER_HOST:SLIVER_LISTENER_PORT`
- For staging tests: Target must reach `SLIVER_LISTENER_HOST:SLIVER_STAGER_PORT`

## Environment Variables

Set these variables before running integration tests:

```bash
# Target Configuration
export TARGET_HOST=192.168.1.100        # Target IP address
export TARGET_USER=Administrator        # Target username  
export TARGET_PASS='P@ssw0rd!'          # Target password

# Sliver Listener Configuration
# IMPORTANT: In devcontainer, use 0.0.0.0 to bind to all interfaces
export SLIVER_LISTENER_HOST=0.0.0.0     # Use 0.0.0.0 in devcontainer
export SLIVER_LISTENER_PORT=8888        # mTLS listener port (default: 8888)
export SLIVER_STAGER_PORT=8080          # HTTP staging port (default: 8080)
```

**Why 0.0.0.0 in devcontainer?**
The devcontainer runs in Docker with limited network interfaces. Using `0.0.0.0` allows Sliver to bind to all available interfaces, making it accessible to targets on the network. The actual routable IP depends on your Docker network configuration.

### Example: HTB Pwnbox Setup

```bash
# Get your VPN IP (usually tun0)
export SLIVER_LISTENER_HOST=$(ip addr show tun0 | grep "inet " | awk '{print $2}' | cut -d/ -f1)

# Set target (example: Windows target at 10.10.11.100)
export TARGET_HOST=10.10.11.100
export TARGET_USER=Administrator
export TARGET_PASS='Passw0rd!'

# Use default ports
export SLIVER_LISTENER_PORT=8888
export SLIVER_STAGER_PORT=8080
```

## Running Integration Tests

Once environment variables are set, **always include the `--run-integration` flag**:

```bash
# Run all integration tests
poetry run pytest tests/test_integration.py -v --run-integration

# Run specific test class
poetry run pytest tests/test_integration.py::TestIntegrationDirectUpload -v --run-integration

# Run specific test with output
poetry run pytest tests/test_integration.py::TestIntegrationDirectUpload::test_direct_upload_winrm_windows -v -s --run-integration
```

**Without `--run-integration`, all tests will be skipped.**

## Test Coverage

### TestIntegrationDirectUpload (1 test)
- `test_direct_upload_winrm_windows` - Direct implant upload via WinRM
  - Tests: Basic deployment, implant generation, beacon callback
  - Protocol: WinRM
  - Target: Windows

### TestIntegrationHTTPStaging (3 tests)
- `test_http_staging_powershell_windows` - HTTP staging with PowerShell download cradle
- `test_http_staging_certutil_windows` - HTTP staging with certutil
- `test_http_staging_bitsadmin_windows` - HTTP staging with bitsadmin
  - Tests: HTTP listener, download cradles, automatic cleanup
  - Protocol: WinRM
  - Target: Windows

### TestIntegrationEdgeCases (3 tests)
- `test_invalid_credentials` - Tests authentication failure handling
- `test_fileless_shellcode_staging_winrm` - Advanced shellcode injection
- `test_http_staging_linux_wget` - HTTP staging on Linux (SKIPPED - requires Linux target)

## Troubleshooting

### Tests are skipped
**Cause**: Missing environment variables or prerequisites

**Check**:
```bash
# Verify environment variables
env | grep -E "(TARGET|SLIVER)"

# Verify Sliver config
ls -la ~/.sliver-client/configs/default.cfg

# Verify NetExec module
netexec smb -L | grep sliver_exec
```

### Connection timeouts
**Cause**: Network routing or firewall issues

**Check**:
```bash
# Can you reach the target?
ping $TARGET_HOST

# Can target reach your listener?
# (Run this on the target to test)
Test-NetConnection -ComputerName $SLIVER_LISTENER_HOST -Port $SLIVER_LISTENER_PORT
```

### SSL/TLS errors
**Cause**: Sliver server not running or invalid operator config

**Fix**:
```bash
# Check Sliver status
sliver-status

# Restart Sliver server
sliver-stop
sliver-start

# Regenerate operator config
rm ~/.sliver-client/configs/default.cfg
sudo sliver-server operator --name $USER --lhost 127.0.0.1 --save /tmp/sliver.cfg --permissions all
sudo chown $USER:$USER /tmp/sliver.cfg
mv /tmp/sliver.cfg ~/.sliver-client/configs/default.cfg
chmod 600 ~/.sliver-client/configs/default.cfg
```

### "bind: cannot assign requested address"
**Cause**: SLIVER_LISTENER_HOST is set to an IP that doesn't exist on this machine

**Fix**:
```bash
# In devcontainer, use 0.0.0.0
export SLIVER_LISTENER_HOST=0.0.0.0

# Check available IPs
ip addr show | grep "inet "
```

### Proxychains blocking Sliver connection
**Cause**: Localhost not excluded in proxychains.conf

**Fix** (already done in devcontainer):
```bash
# Add to /etc/proxychains4.conf
localnet 127.0.0.0/255.0.0.0
```

### Module not found
**Cause**: sliver_exec module not installed in NetExec

**Fix**:
```bash
# Check symlink
ls -la ~/netexec-venv/lib/python*/site-packages/nxc/modules/sliver_exec.py

# Recreate symlink if needed
SITE_PACKAGES=$(~/netexec-venv/bin/python -c 'import site; print(site.getsitepackages()[0])')
ln -sf /workspaces/sliver-nxc-module/src/nxc/modules/sliver_exec.py $SITE_PACKAGES/nxc/modules/sliver_exec.py
```

## Expected Output

Successful integration test output should show:
```
tests/test_integration.py::TestIntegrationDirectUpload::test_direct_upload_winrm_windows PASSED
```

With NetExec output containing:
- "Generating unique Sliver beacon"
- "Beacon callback detected" or "Waiting for beacon"
- For staging tests: "Starting HTTP listener", "download cradle", "Payload size:"

## Current Status

✅ **Prerequisites Met:**
- Sliver server installed and running
- Sliver client config present
- NetExec installed with sliver_exec module
- Module package built and verified

❌ **Missing for Integration Tests:**
- Live target with credentials (requires user setup)
- Environment variables (TARGET_HOST, TARGET_USER, TARGET_PASS, SLIVER_LISTENER_HOST)

All **7 integration tests are SKIPPED** until environment variables are configured.

To enable integration tests, export the required environment variables listed above.
