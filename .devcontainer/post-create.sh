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

echo "Installing netexec (latest from git) in a separate virtualenv..."
# Create a separate venv for netexec to avoid slowing down project tests
NETEXEC_VENV="$HOME/netexec-venv"
python3 -m venv "$NETEXEC_VENV"
"$NETEXEC_VENV/bin/pip" install --upgrade pip
"$NETEXEC_VENV/bin/pip" install --upgrade impacket
"$NETEXEC_VENV/bin/pip" install --upgrade "git+https://github.com/Pennyw0rth/NetExec.git"

echo "Installing sliver_client dependencies in netexec-venv..."
"$NETEXEC_VENV/bin/pip" install --upgrade 'grpcio>=1.60.0' 'protobuf>=5.26.1,<7.0' 'grpcio-tools>=1.60.0'

# Symlink our module into NetExec's modules directory.
# Determine the venv's site-packages path in a robust way (works across Python patch versions).
SITE_PACKAGES="$($NETEXEC_VENV/bin/python -c 'import site,sys
get = getattr(site, "getsitepackages", None)
if get:
	p = get()
else:
    # Fallback for some virtualenv layouts
	p = [sys.prefix + "/lib/python" + sys.version[:3] + "/site-packages"]
print(p[0])')"

MODULES_DIR="$SITE_PACKAGES/nxc/modules"
mkdir -p "$MODULES_DIR"
ln -sf "/workspaces/sliver-nxc-module/src/nxc/modules/sliver_exec.py" "$MODULES_DIR/sliver_exec.py"
echo "Created symlink: $MODULES_DIR/sliver_exec.py -> /workspaces/sliver-nxc-module/src/nxc/modules/sliver_exec.py"

ln -sf "/workspaces/sliver-nxc-module/src/sliver_client" "$SITE_PACKAGES/sliver_client"
echo "Created symlink: $SITE_PACKAGES/sliver_client -> /workspaces/sliver-nxc-module/src/sliver_client"

export PATH="$NETEXEC_VENV/bin:$PATH"

echo "Installing proxychains-ng..."
sudo apt-get update || true
sudo apt-get install -y proxychains4 iputils-ping

echo "Configuring proxychains for sudo usage..."
sudo tee /etc/proxychains4.conf > /dev/null <<'EOF'
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 1080
EOF

echo "Configuring sudo to preserve LD_PRELOAD for proxychains..."
sudo tee /etc/sudoers.d/proxychains > /dev/null <<EOF
Defaults env_keep += "LD_PRELOAD"
Defaults secure_path="/home/vscode/netexec-venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EOF
sudo chmod 0440 /etc/sudoers.d/proxychains

echo "Installing Sliver server..."
if [ ! -f /usr/local/bin/sliver-server ]; then
    SLIVER_VERSION="v1.6.7"
    SLIVER_ARCH="linux"
    SLIVER_URL="https://github.com/BishopFox/sliver/releases/download/${SLIVER_VERSION}/sliver-server_${SLIVER_ARCH}"
    
    sudo curl -L -o /usr/local/bin/sliver-server "${SLIVER_URL}"
    sudo chmod +x /usr/local/bin/sliver-server
    echo "Sliver server installed: ${SLIVER_VERSION}"
else
    echo "Sliver server already installed: $(sliver-server version 2>/dev/null | head -1 || echo 'unknown version')"
fi

echo "Creating Sliver startup script..."
sudo tee /usr/local/bin/sliver-start > /dev/null <<'EOF'
#!/bin/bash
SLIVER_PID_FILE="/tmp/sliver-server.pid"

if [ -f "$SLIVER_PID_FILE" ]; then
    PID=$(cat "$SLIVER_PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "Sliver server is already running (PID: $PID)"
        exit 0
    fi
fi

echo "Starting Sliver server in background..."
nohup sudo /usr/local/bin/sliver-server daemon > /tmp/sliver-server.log 2>&1 &
echo $! > "$SLIVER_PID_FILE"
echo "Sliver server started (PID: $(cat $SLIVER_PID_FILE))"
echo "Logs: /tmp/sliver-server.log"
EOF

sudo tee /usr/local/bin/sliver-stop > /dev/null <<'EOF'
#!/bin/bash
SLIVER_PID_FILE="/tmp/sliver-server.pid"

if [ ! -f "$SLIVER_PID_FILE" ]; then
    echo "Sliver server is not running (no PID file)"
    exit 0
fi

PID=$(cat "$SLIVER_PID_FILE")
if ps -p "$PID" > /dev/null 2>&1; then
    echo "Stopping Sliver server (PID: $PID)..."
    sudo kill "$PID"
    rm -f "$SLIVER_PID_FILE"
    echo "Sliver server stopped"
else
    echo "Sliver server is not running (stale PID file)"
    rm -f "$SLIVER_PID_FILE"
fi
EOF

sudo tee /usr/local/bin/sliver-status > /dev/null <<'EOF'
#!/bin/bash
SLIVER_PID_FILE="/tmp/sliver-server.pid"

if [ ! -f "$SLIVER_PID_FILE" ]; then
    echo "Sliver server: stopped"
    exit 1
fi

PID=$(cat "$SLIVER_PID_FILE")
if ps -p "$PID" > /dev/null 2>&1; then
    echo "Sliver server: running (PID: $PID)"
    echo "Logs: /tmp/sliver-server.log"
    echo "Listening on: localhost:31337 (default)"
    exit 0
else
    echo "Sliver server: stopped (stale PID file)"
    rm -f "$SLIVER_PID_FILE"
    exit 1
fi
EOF

sudo chmod +x /usr/local/bin/sliver-start
sudo chmod +x /usr/local/bin/sliver-stop
sudo chmod +x /usr/local/bin/sliver-status

echo "Starting Sliver server..."
/usr/local/bin/sliver-start

echo "Waiting for Sliver to initialize..."
sleep 5

echo "Checking Sliver server status..."
/usr/local/bin/sliver-status

echo "Generating Sliver client config..."
SLIVER_CONFIG_DIR="$HOME/.sliver-client/configs"
mkdir -p "$SLIVER_CONFIG_DIR"

if [ ! -f "$SLIVER_CONFIG_DIR/default.cfg" ]; then
    echo "Creating Sliver operator config..."
    # Create config in temp location first (requires sudo)
    TEMP_CONFIG="/tmp/sliver_operator_$USER.cfg"
    if sudo sliver-server operator --name "$USER" --lhost 127.0.0.1 --save "$TEMP_CONFIG" 2>&1 | tee /tmp/sliver-operator-creation.log; then
        # Change ownership and move to user's config directory
        sudo chown "$USER:$USER" "$TEMP_CONFIG"
        mv "$TEMP_CONFIG" "$SLIVER_CONFIG_DIR/default.cfg"
        chmod 600 "$SLIVER_CONFIG_DIR/default.cfg"
        echo "Sliver client config created: $SLIVER_CONFIG_DIR/default.cfg"
    else
        echo "Error: Failed to create Sliver operator config"
        echo "See /tmp/sliver-operator-creation.log for details"
        echo "Manual command: sudo sliver-server operator --name $USER --lhost 127.0.0.1 --save ~/.sliver-client/configs/default.cfg"
    fi
else
    echo "Sliver client config already exists: $SLIVER_CONFIG_DIR/default.cfg"
fi

echo "Creating helper aliases and PATH setup..."
cat >> "$HOME/.bashrc" <<'EOF'

# Sliver NetExec Development - Add netexec-venv to PATH
export PATH="$HOME/netexec-venv/bin:$PATH"

# Sliver NetExec Development Aliases
alias nxc='proxychains -q netexec'
alias pnxc='sudo proxychains -q netexec'
EOF

# Also add to .profile for login shells
cat >> "$HOME/.profile" <<'EOF'

# Sliver NetExec Development - Add netexec-venv to PATH
export PATH="$HOME/netexec-venv/bin:$PATH"
EOF

source "$HOME/.bashrc" 2>/dev/null || true

# Update NPM
echo "Updating npm to the latest version..."
# Download and install nvm:
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
# in lieu of restarting the shell
\. "$HOME/.nvm/nvm.sh"
# Download and install Node.js:
nvm install 24
# Verify the Node.js version:
node -v # Should print "v24.13.0".
# Verify npm version:
npm -v # Should print "11.6.2".


# Install oh-my-opencode via npm
sudo apt install -y npm 
echo "Installing opencode..."
sudo npm install -g opencode-ai

echo "Installing Bun..."
sudo curl -fsSL https://bun.sh/install | bash
source /home/vscode/.bashrc

echo "Installing oh-my-opencode via bun..."
bunx oh-my-opencode install

echo ""
echo "=========================================="
echo "Development environment setup complete!"
echo "=========================================="
echo ""
echo "Sliver Server:"
echo "  - Binary: /usr/local/bin/sliver-server"
echo "  - Start:  sliver-start"
echo "  - Stop:   sliver-stop"
echo "  - Status: sliver-status"
echo "  - Logs:   tail -f /tmp/sliver-server.log"
echo "  - Config: ~/.sliver-client/configs/default.cfg"
echo ""
echo "Proxychains:"
echo "  - Config: /etc/proxychains4.conf"
echo "  - Default: socks5 127.0.0.1:1080"
echo "  - Sudo support: enabled"
echo ""
echo "Aliases:"
echo "  - nxc   : proxychains -q netexec"
echo "  - pnxc  : sudo proxychains -q netexec"
echo ""
echo "Quick Test:"
echo "  sudo proxychains -q netexec smb -L | grep sliver"
echo ""