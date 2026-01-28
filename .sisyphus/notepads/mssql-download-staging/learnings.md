# Learnings - MSSQL Download Staging

## Conventions & Patterns

### STAGING=direct Implementation Pattern
- Three distinct locations require synchronization in sliver_exec.py:
  1. **__init__()** (~line 726): Initialize `self.staging_direct = False` (new attribute)
  2. **_validate_required_options()** (~line 827): Add "direct" to valid STAGING values in condition check
  3. **_parse_module_options()** (~line 960): Handle the special case with explicit state setting
     - Set `self.staging = False` and `self.staging_direct = True` for direct opt-out
     - Maintains backward compatibility with existing STAGING=http/tcp/https behavior

### Key Implementation Details
- STAGING=direct explicitly disables staging and marks it as intentional (staging_direct flag)
- Differs from other "disabled" states because it's an explicit user choice for air-gapped targets
- Must be added to validation acceptance list before parsing logic can handle it
- Pattern matches existing protocol handlers but with reversed semantics (False instead of True)

### Testing Insights
- All 16 staging-related tests pass successfully
- Full test suite runs 94/96 tests passing (2 pre-existing failures unrelated to this task)
- Tests validate backward compatibility with old STAGING=True/False syntax
- No regressions introduced by STAGING=direct addition

## MSSQL HTTP Staging Execution Path

### Implementation Location
- Lines 1412-1461 in `_run_beacon_staged_http()` function
- Added `elif protocol == "mssql":` block between WinRM and generic handler

### Key Implementation Details
1. **Linux tool rejection**: wget, curl, python rejected with clear error (MSSQL is Windows-only)
2. **xp_cmdshell state management**: Same pattern as MSSQLHandler.upload()
   - Helper functions defined inline: `query_option_state()`, `set_option()`
   - Backup original states for 'show advanced options' and 'xp_cmdshell'
   - Enable both if needed, execute cradle, restore in finally block
3. **Execution via `connection.execute(cmd)`**: Simple xp_cmdshell command execution

### Pattern Reuse
- Copied xp_cmdshell management pattern from MSSQLHandler.upload() (lines 603-650)
- Uses `connection.conn.sql_query()` for sp_configure + RECONFIGURE
- Uses `connection.sql_query()` for SELECT queries
- Uses `connection.execute()` for command execution (same as upload handler)

### Testing Insights
- All 5 MSSQL handler tests pass
- All 16 staging tests pass
- No regressions introduced

## MSSQL Default HTTP Staging Implementation

### Implementation Location
- Lines 1197-1206 in `_run_beacon()` function (new block added)
- Inserted after protocol detection (line 1196) and before the try block

### Key Implementation Details
1. **Condition**: `protocol == "mssql" and not self.staging_direct`
   - Only triggers for MSSQL protocol
   - Skipped if user explicitly set STAGING=direct (air-gapped scenario)
   
2. **Auto-settings applied**:
   - `self.staging = True`: Enable HTTP staging mode
   - `self.stager_port = self.stager_port or 8080`: Default port if not specified
   - `self.staging_method = "certutil"`: Only if unset or still "powershell" default
   
3. **User override respected**:
   - If user sets DOWNLOAD_TOOL=bitsadmin, staging_method keeps that value
   - If user sets STAGING=direct, entire auto-staging block is skipped

### Testing Insights
- All 94/96 tests pass (same as before - 2 pre-existing on_login failures)
- Change follows existing WinRM staging decision pattern
- Routes correctly to `_run_beacon_staged_http()` for MSSQL

### Breaking Change Impact
- MSSQL now defaults to HTTP download staging instead of chunked upload
- Users who need chunked upload (air-gapped) can opt-out with STAGING=direct
- Log shows "Using HTTP download staging (certutil)" for visibility
