# Installation Guide

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Install](#quick-install)
- [Manual HTB Pwnbox Installation](#manual-htb-pwnbox-installation)
- [Kali Linux Installation](#kali-linux-installation)

## Prerequisites

Install Sliver
```bash
curl https://sliver.sh/install | sudo bash
cp ~/.sliver-client/configs/${USER}_localhost.cfg ~/.sliver-client/configs/default.cfg
```

*Tip*: Add a bypass to proxychains to be able to reach the Sliver Server
```bash
echo "localnet 127.0.0.0/255.0.0.0" | sudo tee -a /etc/proxychains.conf
```

## Quick Install

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

## Manual HTB Pwnbox Installation

Copy-paste commands for quick setup on HTB Pwnbox:

```bash
# Note: HTB Pwnbox comes with NetExec 1.2.0 pre-installed at /opt/pipx/venvs/netexec/

# 1. Clone and build the module
git clone https://github.com/moerketh/sliver-netexec-module.git
cd sliver-netexec-module

# Disable Poetry keyring (prevents AT_SECURE errors with sudo)
export PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring

poetry install
poetry build

# 2. Install module into NetExec venv (direct python -m pip)
sudo /opt/pipx/venvs/netexec/bin/python -m pip install dist/sliver_nxc_module-*.whl

# 3. Verify installation
netexec smb -L | grep sliver_exec
```

## Kali Linux Installation

Copy-paste commands for Kali Linux:

```bash
# 1. Install NetExec (if not already installed)
sudo apt update
sudo apt install -y netexec

# Or via pipx for latest version:
# sudo apt install -y pipx
# pipx install git+https://github.com/Pennyw0rth/NetExec

# 2. Install poetry (if not already installed)
pipx install poetry 2>/dev/null || sudo apt install -y python3-poetry

# 3. Clone and build the module
cd /tmp
git clone https://github.com/moerketh/sliver-netexec-module.git
cd sliver-netexec-module
poetry install
poetry build

# 4. Install module (choose based on NetExec installation)
# If NetExec installed via apt:
sudo pip3 install dist/sliver_nxc_module-0.1.0-py3-none-any.whl --break-system-packages

# If NetExec installed via pipx (user installation):
pipx inject netexec dist/sliver_nxc_module-0.1.0-py3-none-any.whl

# 5. Verify installation
netexec smb -L | grep sliver_exec

# 6. Setup Sliver config
cp ~/.sliver-client/configs/${USER}_localhost.cfg ~/.sliver-client/configs/default.cfg
```
