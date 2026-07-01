"""
PATTERN EXTRACTOR for LIBERTEA Helldivers 2 Cheat DLL
Extracts all IDA-style byte pattern signatures with metadata
from the unpacked .text section.
"""
import struct, re, json

BIN_PATH = r'C:\Users\emora\OneDrive\Desktop\2\.text_unpacked_mem.bin'
OUTPUT_JSON = r'C:\Users\emora\OneDrive\Desktop\2\patterns_extracted.json'

with open(BIN_PATH, 'rb') as f:
    data = f.read()

print(f"[*] Loaded {len(data):,} bytes from {BIN_PATH}")

# ---------------------------------------------------------------------------
# STEP 1: Find all IDA-style signature strings
# ---------------------------------------------------------------------------
pattern_re = re.compile(rb'(?:[0-9A-Fa-f]{2}|\?\?)(?: (?:[0-9A-Fa-f]{2}|\?\?)){5,}')
raw_matches = list(pattern_re.finditer(data))
print(f"[*] Found {len(raw_matches)} raw pattern string matches")

# ---------------------------------------------------------------------------
# STEP 2: Parse metadata around each pattern
# ---------------------------------------------------------------------------
# The structure seems to be (variable layout):
#   [module_name\0] [uint32 pattern_len?] [pattern_string\0] [name\0] [type_tag\0]
# But not all entries follow this exactly. We parse heuristically.

entries = []

for m in raw_matches:
    start = m.start()
    end = m.end()
    sig = m.group().decode('ascii', errors='replace')
    
    # Skip past trailing null bytes
    pos = end
    while pos < len(data) and data[pos] == 0:
        pos += 1
    
    # Read up to 8 null-terminated strings following the pattern
    post_data = data[pos:pos + 512]
    post_strs = []
    cur = b''
    for b in post_data:
        if b == 0:
            if len(cur) >= 1:
                try:
                    decoded = cur.decode('ascii', errors='replace')
                    if decoded.strip():
                        post_strs.append(decoded)
                except:
                    pass
                cur = b''
            if len(post_strs) >= 6:
                break
            # Count consecutive nulls but don't stop on each one
        else:
            cur += bytes([b])
    
    # Read strings before pattern (in reverse)
    pre_start = max(0, start - 512)
    pre_data = data[pre_start:start]
    pre_strs = []
    cur = b''
    for b in reversed(pre_data):
        if b == 0:
            if len(cur) >= 1:
                try:
                    decoded = cur[::-1].decode('ascii', errors='replace')
                    if decoded.strip():
                        pre_strs.insert(0, decoded)
                except:
                    pass
                cur = b''
            if len(pre_strs) >= 6:
                break
        else:
            cur += bytes([b])
    
    # Determine module, name, type_tag
    module = ""
    name = ""
    type_tag = ""
    
    # Module name: look for .dll in pre_strs (filter out format strings with %)
    for s in pre_strs:
        if s.endswith('.dll') and '%' not in s and not s.startswith('\\'):
            module = s
            break
    if not module:
        for s in post_strs:
            if s.endswith('.dll') and '%' not in s and not s.startswith('\\'):
                module = s
                break
    
    # Type tag: FN_X or PTR_X pattern
    for s in post_strs:
        if re.match(r'^(FN|PTR)_[A-Z0-9]+$', s):
            type_tag = s
            break
    if not type_tag:
        for s in pre_strs:
            if re.match(r'^(FN|PTR)_[A-Z0-9]+$', s):
                type_tag = s
                break
    
    # Name: first non-pattern, non-type, non-module string after pattern
    for s in post_strs:
        if '??' not in s and not re.match(r'^(FN|PTR)_[A-Z0-9]+$', s) and not s.endswith('.dll') and s not in ('wb',):
            name = s
            break
    if not name:
        for s in pre_strs:
            if '??' not in s and not re.match(r'^(FN|PTR)_[A-Z0-9]+$', s) and not s.endswith('.dll') and s not in ('wb', 'derived', 'xref', 'context', 'constant'):
                name = s
                break
    
    # Skip patterns that look like false positives (parts of other strings)
    if len(sig) < 8:
        continue
    
    # Clean up module name - filter out debug/log strings
    clean_module = module.strip() if module else 'game.dll'
    if 'AOB' in clean_module or 'not found' in clean_module or '%' in clean_module:
        clean_module = 'game.dll'
    
    entries.append({
        'offset': start,
        'signature': sig,
        'name': name.strip() if name else '',
        'module': clean_module,
        'type_tag': type_tag.strip() if type_tag else '',
        'sig_length_bytes': len(re.findall(r'[0-9A-Fa-f]{2}|\?\?', sig)),
    })

# ---------------------------------------------------------------------------
# STEP 3: Deduplicate
# ---------------------------------------------------------------------------
seen_sigs = set()
unique_entries = []
for e in entries:
    if e['signature'] not in seen_sigs:
        seen_sigs.add(e['signature'])
        unique_entries.append(e)

print(f"[*] Unique patterns after dedup: {len(unique_entries)}")

# ---------------------------------------------------------------------------
# STEP 4: Classify patterns by hook type
# ---------------------------------------------------------------------------
def classify_pattern(entry):
    """Classify hook type based on pattern name and signature."""
    name = entry['name'].lower()
    sig = entry['signature']
    
    # NOP patches (replace with 0x90 bytes)
    if name.startswith('nop'):
        return 'NOP_PATCH'
    
    # Conditional jump inversions
    if name.startswith('force unconditional jump'):
        return 'CONDITIONAL_INVERT'
    
    # Function returns (replace prologue with RET)
    if name.startswith('return') or 'return' in name:
        return 'FUNCTION_RETURN'
    
    # Function prologue match (used for detour hooking)
    if entry['type_tag'] in ('FN_C', 'FN_D', 'FN_F', 'FN_GT', 'FN_9', 'FN_A', 'FN_B'):
        return 'FUNCTION_PROLOGUE'
    
    # Pointer resolution (PTR_* tags)
    if entry['type_tag'].startswith('PTR_'):
        return 'POINTER_RESOLVE'
    
    # Memory write patches
    if name.startswith('nop') or 'write' in name:
        return 'MEMORY_WRITE'
    
    # Skip/NOP checks
    if 'skip' in name or 'bypass' in name or 'freeze' in name:
        return 'NOP_PATCH'
    
    # Default  
    return 'CODE_PATCH'

for e in unique_entries:
    e['hook_type'] = classify_pattern(e)

# ---------------------------------------------------------------------------
# STEP 5: Group by module
# ---------------------------------------------------------------------------
from collections import defaultdict
modules = defaultdict(list)
for e in unique_entries:
    modules[e['module']].append(e)

# ---------------------------------------------------------------------------
# STEP 6: Output
# ---------------------------------------------------------------------------
print("\n" + "=" * 78)
print("EXTRACTED PATTERNS BY MODULE")
print("=" * 78)

for mod_name in sorted(modules.keys(), key=lambda x: (x == 'game.dll', x)):
    pats = modules[mod_name]
    print(f"\n{'='*78}")
    print(f"  MODULE: {mod_name}  ({len(pats)} patterns)")
    print(f"{'='*78}")
    print(f"  {'#':<4} {'TYPE':<20} {'OFFSET':<10} {'HOOK':<18} {'SIGNATURE (truncated)'}")
    print(f"  {'-'*4} {'-'*20} {'-'*10} {'-'*18} {'-'*35}")
    
    for i, p in enumerate(pats[:50], 1):
        sig_short = p['signature'][:65]
        print(f"  {i:<4} {p['name'][:20]:<20} 0x{p['offset']:06X}  {p['hook_type']:<18} {sig_short}")

# ---------------------------------------------------------------------------
# STEP 7: Find special structures
# ---------------------------------------------------------------------------
print("\n" + "=" * 78)
print("ADDITIONAL FINDS")
print("=" * 78)

# Find syscall stubs (real ones)
syscall_offs = []
for i in range(len(data) - 1):
    if data[i] == 0x0F and data[i+1] == 0x05:
        # Check for real syscall: preceded by mov eax, SSN (B8 XX XX XX XX)
        if i >= 5 and data[i-5] == 0xB8:
            ssn = struct.unpack_from('<I', data, i-4)[0]
            syscall_offs.append((i, ssn))
        # Check for mov r10, rcx; mov eax, SSN (4C 8B D1; B8 XX XX XX XX)
        elif i >= 8 and data[i-8:i-5] == b'\x4C\x8B\xD1' and data[i-5] == 0xB8:
            ssn = struct.unpack_from('<I', data, i-4)[0]
            syscall_offs.append((i, ssn))

print(f"\nReal syscall stubs (with mov eax, SSN): {len(syscall_offs)}")
ssn_map = {
    0x18: 'NtAllocateVirtualMemory',
    0x19: 'NtFreeVirtualMemory',
    0x1A: 'NtQueryVirtualMemory',
    0x1B: 'NtReadVirtualMemory',
    0x1C: 'NtWriteVirtualMemory',
    0x2A: 'NtCreateFile',
    0x2D: 'NtProtectVirtualMemory',  # common
    0x32: 'NtWaitForSingleObject',   # 0x32
    0x36: 'NtQuerySystemInformation',
    0x37: 'NtQueryInformationProcess',
    0x3F: 'NtOpenProcess',
    0x4B: 'NtClose',
    0x50: 'NtQueryInformationThread',  # 0x50
    0x53: 'NtOpenThread',
    0x5A: 'NtSuspendProcess',
    0x5B: 'NtResumeProcess',
    0x62: 'NtCreateThreadEx',
    0x69: 'NtTerminateThread',
    0x70: 'NtQueueApcThread',
    0x7C: 'NtGetContextThread',
    0x9A: 'NtAlertThread',
    0xA0: 'NtSetContextThread',
    0xCC: 'NtSuspendThread',
    0xCD: 'NtResumeThread',
    0xD5: 'NtTerminateProcess',
    0xD8: 'NtQueryPerformanceCounter',
    0xE0: 'NtDelayExecution',
}

for off, ssn in syscall_offs:
    ssn_name = ssn_map.get(ssn, f'UNKNOWN_SSN_0x{ssn:X}')
    print(f"  SYSCALL 0x{ssn:02X} ({ssn_name}) at code offset 0x{off:06X}")

# Find ScPresent::Install context
sc_off = data.find(b'ScPresent::Install:')
if sc_off >= 0:
    print(f"\nScPresent::Install string at: 0x{sc_off:06X}")
    # Show surrounding strings
    start = max(0, sc_off - 64)
    end = min(len(data), sc_off + 256)
    ctx = data[start:end]
    strs = []
    for s in ctx.split(b'\x00'):
        s = s.strip()
        if len(s) >= 1 and all(32 <= b <= 126 for b in s):
            strs.append(s.decode('ascii', errors='replace'))
    for s in strs:
        print(f"    \"{s}\"")

# Find ntdll.dll reference for SSN resolution
ntdll_off = data.find(b'ntdll.dll')
if ntdll_off >= 0:
    print(f"\nntdll.dll string at: 0x{ntdll_off:06X}")
    # Look for code that references ntdll.dll (GetModuleHandle/load library)
    # Find LEA refs
    for i in range(len(data) - 7):
        if data[i] == 0x48 and data[i+1] == 0x8D:
            modrm = data[i+2]
            if modrm in (0x0D, 0x15, 0x05, 0x1D, 0x2D, 0x35, 0x3D):
                rel = struct.unpack_from('<i', data, i+3)[0]
                abs_addr = (i + 7) + rel
                if abs_addr == ntdll_off:
                    print(f"  LEA ref at 0x{i:06X}")

# Find string with function name patterns (for SSN resolution)
print("\nKey strings for SSN resolution:")
for term in [b'GetProcAddress', b'LoadLibrary', b'GetModuleHandle', b'LdrLoadDll',
             b'syscall', b'SSN', b'ssn', b'syscall stub', b'stub']:
    off = data.find(term)
    if off >= 0:
        end = min(len(data), off + 40)
        chunk = data[off:end]
        null_at = chunk.find(b'\x00')
        if null_at > 0:
            s = chunk[:null_at].decode('ascii', errors='replace')
        else:
            s = chunk.decode('ascii', errors='replace')
        print(f"  '{s}' at 0x{off:X}")

# Write JSON output
with open(OUTPUT_JSON, 'w') as f:
    json.dump(unique_entries, f, indent=2, default=str)

print(f"\n[*] JSON written to {OUTPUT_JSON}")
print(f"[*] Total unique patterns: {len(unique_entries)}")
print("[*] Done.")
