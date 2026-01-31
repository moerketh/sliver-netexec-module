FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

# Set up timezone and locale
ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC

# Update package lists
RUN apt-get update

# Install Python and essential development tools
RUN apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    libssl-dev \
    libffi-dev \
    git \
    curl \
    wget \
    jq \
    vim \
    nano \
    sudo \
    ca-certificates \
    gnupg \
    lsb-release

# Install network and security tools
RUN apt-get install -y --no-install-recommends \
    proxychains4 \
    iputils-ping \
    net-tools \
    netcat-openbsd \
    openssh-client

# Proxychains config for sudo usage
RUN echo 'strict_chain\nproxy_dns\nremote_dns_subnet 224\ntcp_read_time_out 15000\ntcp_connect_time_out 8000\n\n[ProxyList]\nsocks5 127.0.0.1 1080' > /etc/proxychains4.conf && \
    echo 'Defaults env_keep += "LD_PRELOAD"\nDefaults secure_path="/home/vscode/netexec-venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"' > /etc/sudoers.d/proxychains && \
    chmod 0440 /etc/sudoers.d/proxychains

# Install Sliver server
RUN curl https://sliver.sh/install | bash || true

# Install Node.js LTS (for opencode)
RUN apt-get install -y --no-install-recommends \
    nodejs \
    npm

# Install nvm and set up Node.js 24 (for compatibility)
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash && \
    export NVM_DIR="$HOME/.nvm" && \
    [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh" && \
    nvm install 24

# Install opencode-ai globally via npm
RUN npm install -g opencode-ai@latest

# Ensure 'python' points to 'python3' for compatibility
RUN ln -s /usr/bin/python3 /usr/bin/python || true

# Clean up apt cache to reduce image size
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# Switch to vscode user for user-specific installations
USER vscode

# Install Poetry for Python dependency management (as vscode user)
RUN curl -sSL https://install.python-poetry.org | python3 - && \
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc

# Install Bun (needed for oh-my-opencode) as vscode user
RUN curl -fsSL https://bun.sh/install | bash && \
    echo 'export PATH="$HOME/.bun/bin:$PATH"' >> ~/.bashrc

# Ensure tools are in PATH
ENV PATH="/home/vscode/.local/bin:/home/vscode/.bun/bin:$PATH"

# Switch back to root (devcontainer will switch to vscode user automatically)
USER root
