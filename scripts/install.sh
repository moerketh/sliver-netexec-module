#!/bin/bash
#
# sliver-nxc-module Installation Script
# ========================================
# This script installs Sliver NetExec module into NetExec
#

set -e

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

    PYTHON_VERSION=$(python3 --version | cut -d' ' -f1)
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)

    if [ "$PYTHON_MAJOR" -lt 3 ] || [ "$PYTHON_MAJOR" -gt 3 ] || [ "$PYTHON_MAJOR" -eq 3 -a "$(echo $PYTHON_VERSION | cut -d'.' -f2)" -lt 10 ]; then
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

# Detect NetExec installation method
detect_nxc_installation() {
    print_header "Detecting NetExec installation..."

    # Check pipx
    if command -v pipx &> /dev/null; then
        NXC_PIPX_PATH=$(pipx list | grep netexec)
        if [ -n "$NXC_PIPX_PATH" ]; then
            INSTALL_METHOD="pipx"
            print_success "NetExec installed via pipx"
            return
        fi
    fi

    # Check pip list
    if pip3 list 2>/dev/null | grep -q "netexec"; then
        INSTALL_METHOD="pip"
        print_success "NetExec installed via pip"
        return
    fi

    # Check system package
    if dpkg -l 2>/dev/null | grep -q "netexec"; then
        INSTALL_METHOD="apt"
        print_success "NetExec installed via apt"
        return
    fi

    print_error "Could not detect NetExec installation method"
    exit 1
}

# Build wheel
build_wheel() {
    print_header "Building wheel..."

    if [ -n "$POETRY_CMD" ]; then
        cd /workspaces/sliver-nxc-module
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

    WHEEL_PATH=$(find /workspaces/sliver-nxc-module/dist -name "sliver_nxc_module-*.whl" | head -1)

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

    WHEEL_PATH=$(find /workspaces/sliver-nxc-module/dist -name "sliver_nxc_module-*.whl" | head -1)

    if [ ! -f "$WHEEL_PATH" ]; then
        print_error "Wheel not found. Run 'poetry build' first."
        exit 1
    fi

    print_info "Installing: $WHEEL_PATH"

    # Check if we need sudo (for system pip)
    if [ "$INSTALL_METHOD" = "apt" ]; then
        SUDO="sudo -H"
    else
        SUDO=""
    fi

    $SUDO pip3 install "$WHEEL_PATH" --break-system-packages
    print_success "Module installed via pip"
}

# Uninstall module
uninstall_module() {
    print_header "Uninstalling module..."

    case "$INSTALL_METHOD" in
        pipx)
            pipx uninject netexec sliver-nxc-module
            print_success "Module removed via pipx"
            ;;
        pip|apt)
            $SUDO pip3 uninstall -y sliver-nxc-module
            print_success "Module removed via pip"
            ;;
        *)
            print_error "Cannot uninstall from $INSTALL_METHOD"
            exit 1
            ;;
    esac
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
    cd /workspaces/sliver-nxc-module

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
            build_wheel
            case "$INSTALL_METHOD" in
                pipx)
                    install_pipx
                    ;;
                pip|apt)
                    install_pip
                    ;;
                *)
                    print_error "Unsupported installation method: $INSTALL_METHOD"
                    exit 1
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
            # No arguments - do full install workflow

            check_dependencies
            detect_nxc_installation
            build_wheel

            case "$INSTALL_METHOD" in
                pipx)
                    install_pipx
                    ;;
                pip|apt)
                    install_pip
                    ;;
                *)
                    print_error "Unsupported installation method: $INSTALL_METHOD"
                    exit 1
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
