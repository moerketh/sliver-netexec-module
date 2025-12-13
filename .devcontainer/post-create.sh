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

echo "Installing netexec (latest from git) into the project's virtualenv..."
# Install into the poetry-managed venv so `poetry run pytest` can find the `netexec` CLI.
# Also install impacket which netexec needs
poetry run pip install --upgrade impacket
poetry run pip install --upgrade "git+https://github.com/Pennyw0rth/NetExec.git"

echo "Development environment setup complete!"