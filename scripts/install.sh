#!/bin/bash
#
# sliver-nxc-module Installation Script
# ========================================
# This script installs Sliver NetExec module into NetExec
#

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
print_success() {
    echo -e "${GREEN}✔${NC} $1"
}

print_error() {
    echo -e "${RED}✖${NC} $1"
}

print_info() {
    echo -e "${YELLOW}ℹ${NC} $1"
}

print_header() {
    echo -e "${GREEN}==>${NC} $1${NC}"
}

# Dependency checks
check_dependencies() {
    print_header "Checking dependencies..."

    # Check Python version
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is required"
        exit 1
    fi

    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

    if [ "$PYTHON_MAJOR" -ne 3 ] || [ "$PYTHON_MINOR" -lt 10 ]; then
        print_error "Python 3.10+ is required (found: $PYTHON_VERSION)"
        exit 1
    fi

    print_success "Python $PYTHON_VERSION detected"

    # Check for pip
    if ! command -v pip3 &> /dev/null; then
        print_error "pip3 is required"
        exit 1
    fi

    print_success "pip3 is available"

    # Check for NetExec
    if command -v netexec &> /dev/null; then
        NXC_CMD="netexec"
    elif command -v nxc &> /dev/null; then
        NXC_CMD="nxc"
    else
        print_error "NetExec not found. Please install NetExec first."
        exit 1
    fi

    print_success "NetExec found: $NXC_CMD"

    # Check for poetry (needed for building)
    if command -v poetry &> /dev/null; then
        POETRY_CMD="poetry"
    else
        print_info "Poetry not found. Will try pip directly."
        POETRY_CMD=""
    fi

    if [ -n "$POETRY_CMD" ]; then
        print_success "Poetry is available"
    fi
}

# Detect NetExec installation location and method
detect_nxc_installation() {
    print_header "Detecting NetExec installation..."

    NXC_BINARY=$(which netexec 2>/dev/null || which nxc 2>/dev/null)
    
    if [ -z "$NXC_BINARY" ]; then
        print_error "NetExec not found. Please install NetExec first."
        exit 1
    fi

    NETEXEC_PYTHON=$(head -1 "$NXC_BINARY" | sed 's/#!//' | awk '{print $1}')
    
    if [ ! -x "$NETEXEC_PYTHON" ]; then
        print_error "Cannot determine Python interpreter used by NetExec"
        print_info "NetExec binary: $NXC_BINARY"
        print_info "Shebang: $(head -1 $NXC_BINARY)"
        exit 1
    fi

    print_info "NetExec uses Python: $NETEXEC_PYTHON"

    NXC_MODULES_DIR=$($NETEXEC_PYTHON -c "
import sys
import os
from importlib.util import find_spec

spec = find_spec('nxc')
if spec and spec.origin:
    print(os.path.join(os.path.dirname(spec.origin), 'modules'))
" 2>/dev/null)

    if [ -z "$NXC_MODULES_DIR" ]; then
        print_error "Could not find NetExec modules directory"
        exit 1
    fi

    print_info "NetExec modules at: $NXC_MODULES_DIR"

    if echo "$NXC_MODULES_DIR" | grep -q "pipx"; then
        INSTALL_METHOD="pipx"
        NXC_VENV=$(echo "$NXC_MODULES_DIR" | grep -oE "^.*/venvs/[^/]+")
        
        if [ -f "$NXC_VENV/bin/pip3" ]; then
            INSTALL_PIP="$NXC_VENV/bin/pip3"
        elif [ -f "$NXC_VENV/bin/pip" ]; then
            INSTALL_PIP="$NXC_VENV/bin/pip"
        else
            INSTALL_PIP="$NETEXEC_PYTHON -m pip"
        fi
        
        print_success "NetExec installed via pipx: $NXC_VENV"
        print_info "Using pip: $INSTALL_PIP"
    elif echo "$NXC_MODULES_DIR" | grep -q "\.local"; then
        INSTALL_METHOD="pip-user"
        INSTALL_PYTHON="$NETEXEC_PYTHON"
        INSTALL_PIP="$NETEXEC_PYTHON -m pip"
        print_success "NetExec installed via pip (user)"
    elif echo "$NXC_MODULES_DIR" | grep -qE "(venv|virtualenv)"; then
        INSTALL_METHOD="pip-venv"
        NXC_VENV=$(echo "$NXC_MODULES_DIR" | grep -oE "^.*/(venv|virtualenv|.*-venv|.*env)")
        
        if [ -f "$NXC_VENV/bin/pip3" ]; then
            INSTALL_PIP="$NXC_VENV/bin/pip3"
        elif [ -f "$NXC_VENV/bin/pip" ]; then
            INSTALL_PIP="$NXC_VENV/bin/pip"
        else
            INSTALL_PIP="$NETEXEC_PYTHON -m pip"
        fi
        
        print_success "NetExec installed in venv: $NXC_VENV"
        print_info "Using pip: $INSTALL_PIP"
    elif echo "$NXC_MODULES_DIR" | grep -q "/usr"; then
        INSTALL_METHOD="apt"
        INSTALL_PYTHON="$NETEXEC_PYTHON"
        INSTALL_PIP="$NETEXEC_PYTHON -m pip"
        print_success "NetExec installed via system package"
    else
        INSTALL_METHOD="pip"
        INSTALL_PYTHON="$NETEXEC_PYTHON"
        INSTALL_PIP="$NETEXEC_PYTHON -m pip"
        print_success "NetExec installed via pip"
    fi
}

# Build wheel
build_wheel() {
    print_header "Building wheel..."

    if [ -n "$POETRY_CMD" ]; then
        cd "$PROJECT_ROOT"
        $POETRY_CMD build
        print_success "Wheel built with Poetry"
    else
        print_error "Poetry is required to build wheel. Install with: pip install poetry"
        exit 1
    fi
}

# Install via pip
install_pip() {
    print_header "Installing via pip..."

    WHEEL_PATH=$(find "$PROJECT_ROOT/dist" -name "sliver_nxc_module-*.whl" | head -1)

    if [ ! -f "$WHEEL_PATH" ]; then
        print_error "Wheel not found. Run 'poetry build' first."
        exit 1
    fi

    print_info "Installing: $WHEEL_PATH"

    case "$INSTALL_METHOD" in
        pipx)
            if [ -n "$INSTALL_PIP" ]; then
                print_info "Installing into pipx venv using: $INSTALL_PIP"
                if [ -w "$NXC_VENV/lib" ]; then
                    $INSTALL_PIP install "$WHEEL_PATH"
                else
                    print_info "pipx venv requires sudo access"
                    sudo -H $INSTALL_PIP install "$WHEEL_PATH"
                fi
            else
                print_error "pipx venv pip not configured"
                exit 1
            fi
            ;;
        pip-venv)
            if [ -n "$INSTALL_PIP" ]; then
                print_info "Installing into NetExec venv using: $INSTALL_PIP"
                $INSTALL_PIP install "$WHEEL_PATH"
            else
                print_error "NetExec venv pip not configured"
                exit 1
            fi
            ;;
        apt)
            print_info "Installing with sudo for system Python"
            sudo -H $INSTALL_PIP install "$WHEEL_PATH" --break-system-packages
            ;;
        pip-user)
            print_info "Installing to user site-packages using: $INSTALL_PIP"
            $INSTALL_PIP install --user "$WHEEL_PATH"
            ;;
        *)
            print_info "Installing using: $INSTALL_PIP"
            $INSTALL_PIP install "$WHEEL_PATH"
            ;;
    esac
    
    print_success "Module installed via pip"
}

# Uninstall module
uninstall_module() {
    print_header "Uninstalling module..."

    if [ -n "$INSTALL_PIP" ]; then
        if [ "$INSTALL_METHOD" = "pipx" ] && [ ! -w "$NXC_VENV/lib" ]; then
            sudo -H $INSTALL_PIP uninstall -y sliver-nxc-module 2>/dev/null || true
        else
            $INSTALL_PIP uninstall -y sliver-nxc-module 2>/dev/null || true
        fi
        print_success "Module removed"
    else
        print_error "Could not determine pip to use for uninstall"
        exit 1
    fi
}

cleanup_existing() {
    print_header "Checking for existing installation..."
    
    local PIP_TO_USE="${INSTALL_PIP:-pip3}"
    
    if $PIP_TO_USE show sliver-nxc-module &> /dev/null; then
        print_info "Found existing installation, removing..."
        if [ "$INSTALL_METHOD" = "pipx" ] && [ ! -w "$NXC_VENV/lib" ]; then
            sudo -H $PIP_TO_USE uninstall -y sliver-nxc-module 2>/dev/null || true
        else
            $PIP_TO_USE uninstall -y sliver-nxc-module 2>/dev/null || true
        fi
    fi
    
    if command -v pipx &> /dev/null; then
        if pipx list 2>/dev/null | grep -q "sliver-nxc-module"; then
            print_info "Found existing pipx injection, removing..."
            pipx uninject netexec sliver-nxc-module 2>/dev/null || true
        fi
    fi
    
    print_success "Cleanup complete"
}

# Verify installation
verify_installation() {
    print_header "Verifying installation..."

    if [ ! -f "$NXC_MODULES_DIR/sliver_exec.py" ]; then
        print_error "Module file not found at: $NXC_MODULES_DIR/sliver_exec.py"
        print_info "Checking where it was installed..."
        find ~/.local -name "sliver_exec.py" 2>/dev/null || true
        find /usr/local -name "sliver_exec.py" 2>/dev/null || true
        exit 1
    fi

    print_success "Module file exists: $NXC_MODULES_DIR/sliver_exec.py"
    
    if $NXC_CMD smb -L 2>&1 | grep -q "sliver_exec"; then
        print_success "Module is visible in NetExec module list"
    else
        print_error "Module file exists but is NOT visible in 'netexec smb -L'"
        print_info "This may indicate a Python environment mismatch"
        exit 1
    fi
}

# Display Sliver config reminder
show_config_reminder() {
    print_header "Sliver Configuration"
    cat <<-'EOF'

The module requires a Sliver client configuration file at:
  ~/.sliver-client/configs/default.cfg

To set this up:
  cp ~/.sliver-client/configs/${USER}_localhost.cfg ~/.sliver-client/configs/default.cfg

EOF
}

# Display usage
usage() {
    printf "%b" "Usage: %s [OPTIONS]\n\n"
    printf "%b" "Options:\n"
    printf "%b" "  --build              Build wheel\n"
    printf "%b" "  --uninstall           Uninstall module\n"
    printf "%b" "  --install             Build and install module\n"
    printf "%b" "  --verify             Verify module is installed\n"
    printf "%b" "  --config-reminder     Show Sliver config setup instructions\n"
    printf "%b" "\nExamples:\n"
    printf "%b" "  %s --build\n" "$0"
    printf "%b" "  %s --install\n" "$0"
    printf "%b" "  %s --verify\n" "$0"
    printf "%b" "  %s --config-reminder\n" "$0"
}

# Main script
main() {
    cd "$PROJECT_ROOT"

    # Parse arguments
    case "${1:-}" in
        --build)
            check_dependencies
            detect_nxc_installation
            build_wheel
            ;;
        --install)
            check_dependencies
            detect_nxc_installation
            cleanup_existing
            build_wheel
            install_pip
            ;;
        --uninstall)
            check_dependencies
            detect_nxc_installation
            uninstall_module
            ;;
        --verify)
            check_dependencies
            detect_nxc_installation
            verify_installation
            ;;
        --config-reminder)
            show_config_reminder
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)

            check_dependencies
            detect_nxc_installation
            cleanup_existing
            build_wheel
            install_pip

            echo ""
            verify_installation
            echo ""
            print_info "Installation complete!"
            echo ""
            show_config_reminder
            ;;
    esac
}

main "$@"
