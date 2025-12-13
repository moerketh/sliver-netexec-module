#!/bin/bash
set -e
git config --global --add safe.directory /workspaces/sliver-nxc-module

echo "Installing Poetry..."
curl -sSL https://install.python-poetry.org | python3 -

echo "Configuring Poetry..."
export PATH="$HOME/.local/bin:$PATH"
poetry config virtualenvs.in-project true

echo "Installing dependencies..."
poetry install

echo "Initializing git submodules..."
git submodule update --init --recursive

echo "Generating protobuf bindings..."
poetry run generate-protobuf

echo "Installing netexec (latest from git) in a separate virtualenv..."
# Create a separate venv for netexec to avoid slowing down project tests
NETEXEC_VENV="$HOME/netexec-venv"
python3 -m venv "$NETEXEC_VENV"
"$NETEXEC_VENV/bin/pip" install --upgrade pip
"$NETEXEC_VENV/bin/pip" install --upgrade impacket
"$NETEXEC_VENV/bin/pip" install --upgrade "git+https://github.com/Pennyw0rth/NetExec.git"

# Symlink our module into NetExec's modules directory
MODULES_DIR="$NETEXEC_VENV/lib/python3.12/site-packages/nxc/modules"
mkdir -p "$MODULES_DIR"
ln -sf "/workspaces/sliver-nxc-module/sliver_exec.py" "$MODULES_DIR/sliver_exec.py"

# Add to PATH for the session
export PATH="$NETEXEC_VENV/bin:$PATH"

echo "Development environment setup complete!"