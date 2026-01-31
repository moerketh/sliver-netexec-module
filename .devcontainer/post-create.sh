#!/bin/bash
set -e

git config --global --add safe.directory /workspaces/sliver-nxc-module

# Poetry config and dependency install
export PATH="$HOME/.local/bin:$PATH"
poetry config virtualenvs.in-project true
poetry install

git submodule update --init --recursive

# NetExec venv creation and pip installs
NETEXEC_VENV="$HOME/netexec-venv"
python3 -m venv "$NETEXEC_VENV"
"$NETEXEC_VENV/bin/pip" install --upgrade pip
"$NETEXEC_VENV/bin/pip" install --upgrade impacket
"$NETEXEC_VENV/bin/pip" install --upgrade "git+https://github.com/Pennyw0rth/NetExec.git"
"$NETEXEC_VENV/bin/pip" install --upgrade 'grpcio>=1.60.0' 'protobuf>=5.26.1,<7.0' 'grpcio-tools>=1.60.0'

# Symlinks for NetExec modules
SITE_PACKAGES="$($NETEXEC_VENV/bin/python -c 'import site,sys; get = getattr(site, "getsitepackages", None); p = get() if get else [sys.prefix + "/lib/python" + sys.version[:3] + "/site-packages"]; print(p[0])')"
MODULES_DIR="$SITE_PACKAGES/nxc/modules"
mkdir -p "$MODULES_DIR"
ln -sf "/workspaces/sliver-nxc-module/src/nxc/modules/sliver_exec.py" "$MODULES_DIR/sliver_exec.py"
ln -sf "/workspaces/sliver-nxc-module/src/sliver_client" "$SITE_PACKAGES/sliver_client"

export PATH="$NETEXEC_VENV/bin:$PATH"

# Sliver config copy (user-specific)
cp ~/.sliver-client/configs/vscode_localhost.cfg ~/.sliver-client/configs/default.cfg || true

# Aliases and PATH setup
cat >> "$HOME/.bashrc" <<'EOF'
# Sliver NetExec Development - Add netexec-venv to PATH
export PATH="$HOME/netexec-venv/bin:$PATH"
EOF
cat >> "$HOME/.profile" <<'EOF'
export PATH="$HOME/netexec-venv/bin:$PATH"
EOF
source "$HOME/.bashrc" 2>/dev/null || true

# oh-my-opencode install and config (user-specific)
bunx oh-my-opencode install --no-tui --claude=no --openai=no --gemini=no --copilot=no --skip-auth
bunx oh-my-opencode doctor
