# Testing Guide

This document provides comprehensive testing information for the sliver-nxc-module.

## Test Categories

### 1. Unit Tests
**Location**: `tests/test_sliver_exec.py`, `tests/test_protocol_handlers.py`, `tests/test_protobuf.py`

**Purpose**: Test individual components and functions in isolation using mocks.

**Run**:
```bash
poetry run pytest tests/test_sliver_exec.py -v
poetry run pytest tests/test_protocol_handlers.py -v
```

**Coverage**:
- Option validation
- OS/architecture detection
- Implant generation logic
- Protocol handler methods (SMB, WinRM, SSH, MSSQL)
- HTTP staging workflow
- Beacon waiting and cleanup

**Expected**: ~100 tests, all should pass

---

### 2. End-to-End Tests
**Location**: `tests/test_e2e.py`

**Purpose**: Verify the module is correctly packaged and integrated with NetExec.

**Run**:
```bash
poetry run pytest tests/test_e2e.py -v
```

**Coverage**:
- Module discoverable in NetExec (`nxc smb -L`)
- Module available for all protocols (SMB, WinRM, SSH, MSSQL)
- Package contains all required files (module + protobuf bindings)

**Expected**: 5 tests, all should pass

---

### 3. Integration Tests
**Location**: `tests/test_integration.py`

**Purpose**: Test against real Windows/Linux targets with live Sliver server.

**Requirements**:
- Live target with valid credentials
- Sliver server running
- Environment variables configured
- **`--run-integration` flag**

**Run**:
```bash
# Set environment variables first
export TARGET_HOST=<target_ip>
export TARGET_USER=<username>
export TARGET_PASS=<password>
export SLIVER_LISTENER_HOST=0.0.0.0  # Use 0.0.0.0 in devcontainer

# Run tests with flag
poetry run pytest tests/test_integration.py -v --run-integration
```

**Coverage**:
- Direct implant upload via WinRM
- HTTP staging with PowerShell/certutil/bitsadmin
- Invalid credentials handling
- Fileless shellcode injection

**Expected**: 7 tests (6 active, 1 Linux test skipped)

See [INTEGRATION_TESTS.md](../INTEGRATION_TESTS.md) for detailed setup.

---

## Quick Test Commands

```bash
# All unit tests
poetry run pytest tests/ -v -k "not integration"

# All tests including e2e
poetry run pytest tests/test_sliver_exec.py tests/test_e2e.py -v

# Integration tests only (requires setup)
poetry run pytest tests/test_integration.py -v --run-integration

# Run everything (unit + e2e, skip integration)
poetry run pytest tests/ -v
```

---

## Test Environment

### Devcontainer
The devcontainer automatically configures:
- Sliver server (running on port 31337)
- NetExec with sliver_exec module
- Proxychains with localhost exclusion
- Operator config at `~/.sliver-client/configs/default.cfg`

### Manual Setup
If not using devcontainer:

1. **Install Sliver**:
   ```bash
   # Download and install sliver-server
   wget https://github.com/BishopFox/sliver/releases/download/v1.5.42/sliver-server_linux
   sudo mv sliver-server_linux /usr/local/bin/sliver-server
   sudo chmod +x /usr/local/bin/sliver-server
   ```

2. **Start Sliver**:
   ```bash
   sudo sliver-server daemon &
   ```

3. **Create operator config**:
   ```bash
   sudo sliver-server operator --name $USER --lhost 127.0.0.1 --save /tmp/sliver.cfg --permissions all
   sudo chown $USER:$USER /tmp/sliver.cfg
   mkdir -p ~/.sliver-client/configs
   mv /tmp/sliver.cfg ~/.sliver-client/configs/default.cfg
   chmod 600 ~/.sliver-client/configs/default.cfg
   ```

4. **Install NetExec module**:
   ```bash
   poetry build
   pipx inject netexec dist/sliver_nxc_module-*.whl
   ```

---

## CI/CD

GitHub Actions runs:
- Unit tests on every push
- E2E tests on every push
- Integration tests are skipped (no live targets in CI)

See `.github/workflows/test.yml` for CI configuration.
