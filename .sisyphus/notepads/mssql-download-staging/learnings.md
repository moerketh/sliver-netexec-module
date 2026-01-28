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
