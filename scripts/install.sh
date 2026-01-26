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

    NXC_MODULES_DIR=$(python3 -c "
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

    # Detect installation method
    if echo "$NXC_BINARY" | grep -q "pipx"; then
        INSTALL_METHOD="pipx"
        print_success "NetExec installed via pipx"
    elif echo "$NXC_MODULES_DIR" | grep -q "\.local"; then
        INSTALL_METHOD="pip-user"
        print_success "NetExec installed via pip (user)"
    elif echo "$NXC_MODULES_DIR" | grep -qE "(venv|virtualenv)"; then
        INSTALL_METHOD="pip-venv"
        NXC_VENV=$(echo "$NXC_MODULES_DIR" | grep -oE "^.*/(venv|virtualenv|.*-venv|.*env)")
        NXC_PIP="$NXC_VENV/bin/pip"
        print_success "NetExec installed in venv: $NXC_VENV"
    elif echo "$NXC_MODULES_DIR" | grep -q "/usr"; then
        INSTALL_METHOD="apt"
        print_success "NetExec installed via system package"
    else
        INSTALL_METHOD="pip"
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

# Install via pipx
install_pipx() {
    print_header "Installing via pipx..."

    WHEEL_PATH=$(find "$PROJECT_ROOT/dist" -name "sliver_nxc_module-*.whl" | head -1)

    if [ ! -f "$WHEEL_PATH" ]; then
        print_error "Wheel not found. Run 'poetry build' first."
        exit 1
    fi

    print_info "Injecting: $WHEEL_PATH"

    pipx inject netexec "$WHEEL_PATH"
    print_success "Module installed via pipx"
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
        pip-venv)
            if [ -n "$NXC_PIP" ] && [ -f "$NXC_PIP" ]; then
                print_info "Installing into NetExec venv: $NXC_VENV"
                "$NXC_PIP" install "$WHEEL_PATH"
            else
                print_error "NetExec venv pip not found at: $NXC_PIP"
                exit 1
            fi
            ;;
        apt)
            sudo -H pip3 install "$WHEEL_PATH" --break-system-packages
            ;;
        pip-user)
            pip3 install --user "$WHEEL_PATH"
            ;;
        *)
            pip3 install "$WHEEL_PATH"
            ;;
    esac
    
    print_success "Module installed via pip"
}

# Uninstall module
uninstall_module() {
    print_header "Uninstalling module..."

    case "$INSTALL_METHOD" in
        pipx)
            pipx uninject netexec sliver-nxc-module 2>/dev/null || true
            print_success "Module removed via pipx"
            ;;
        pip-venv)
            if [ -n "$NXC_PIP" ] && [ -f "$NXC_PIP" ]; then
                "$NXC_PIP" uninstall -y sliver-nxc-module 2>/dev/null || true
            else
                pip3 uninstall -y sliver-nxc-module 2>/dev/null || true
            fi
            print_success "Module removed via pip"
            ;;
        apt)
            sudo -H pip3 uninstall -y sliver-nxc-module 2>/dev/null || true
            print_success "Module removed via pip"
            ;;
        pip-user)
            pip3 uninstall -y sliver-nxc-module 2>/dev/null || true
            print_success "Module removed via pip"
            ;;
        *)
            pip3 uninstall -y sliver-nxc-module 2>/dev/null || true
            print_success "Module removed via pip"
            ;;
    esac
}

cleanup_existing() {
    print_header "Checking for existing installation..."
    
    if [ "$INSTALL_METHOD" = "pip-venv" ] && [ -n "$NXC_PIP" ] && [ -f "$NXC_PIP" ]; then
        if "$NXC_PIP" show sliver-nxc-module &> /dev/null; then
            print_info "Found existing installation in venv, removing..."
            "$NXC_PIP" uninstall -y sliver-nxc-module 2>/dev/null || true
        fi
    elif pip3 show sliver-nxc-module &> /dev/null; then
        print_info "Found existing pip installation, removing..."
        pip3 uninstall -y sliver-nxc-module 2>/dev/null || true
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

    if $NXC_CMD -M sliver_exec 2>&1 | grep -q "sliver_exec"; then
        print_success "Module is available in NetExec"
    else
        print_error "Module not found in NetExec"
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
            case "$INSTALL_METHOD" in
                pipx)
                    install_pipx
                    ;;
                *)
                    install_pip
                    ;;
            esac
            ;;
        --uninstall)
            check_dependencies
            detect_nxc_installation
            uninstall_module
            ;;
        --verify)
            check_dependencies
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

            case "$INSTALL_METHOD" in
                pipx)
                    install_pipx
                    ;;
                *)
                    install_pip
                    ;;
            esac

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
