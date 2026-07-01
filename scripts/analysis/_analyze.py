import struct, re, json

with open(r'C:\Users\emora\OneDrive\Desktop\2\.text_unpacked_mem.bin', 'rb') as f:
    data = f.read()

# ======================================================
# 1. Find all .dll strings with context
# ======================================================
print("=" * 60)
print("SECTION 1: DLL MODULE NAMES IN .TEXT")
print("=" * 60)
dll_pattern = re.compile(rb'[a-zA-Z_][a-zA-Z0-9_]*\.dll')
seen_dlls = set()
for m in dll_pattern.finditer(data):
    name = m.group().decode()
    if name in seen_dlls:
        continue
    seen_dlls.add(name)
    off = m.start()
    start = max(0, off - 8)
    end = min(len(data), off + len(name) + 128)
    ctx = data[start:end]
    strs = []
    for s in ctx.split(b'\x00'):
        s = s.strip()
        if len(s) >= 1 and all(32 <= b <= 126 for b in s):
            strs.append(s.decode('ascii', errors='replace'))
    nearby_patterns = [s for s in strs if '??' in s]
    print(f"  0x{off:06X}: {name}")
    if nearby_patterns:
        print(f"    Nearby patterns: {nearby_patterns[:3]}")

# ======================================================
# 2. Find all IDA-style patterns with surrounding metadata
# ======================================================
print("\n" + "=" * 60)
print("SECTION 2: PATTERN SIGNATURES WITH METADATA")
print("=" * 60)

pattern_re = re.compile(rb'(?:[0-9A-Fa-f]{2}|\?\?)(?: (?:[0-9A-Fa-f]{2}|\?\?)){5,}')
matches = list(pattern_re.finditer(data))

entries = []
i = 0
while i < len(matches):
    m = matches[i]
    start = m.start()
    end = m.end()
    sig = m.group().decode('ascii', errors='replace')
    
    # Find null-terminated strings immediately after the pattern
    post_start = end
    # Skip null bytes after pattern
    while post_start < len(data) and data[post_start] == 0:
        post_start += 1
    
    # Read strings after pattern
    post_data = data[post_start:post_start + 256]
    post_strs = []
    for s in post_data.split(b'\x00'):
        s = s.strip()
        if len(s) >= 1 and all(32 <= b <= 126 for b in s):
            post_strs.append(s.decode('ascii', errors='replace'))
        if len(post_strs) >= 5:
            break
    
    # Look for strings before pattern
    pre_start = max(0, start - 128)
    pre_data = data[pre_start:start]
    pre_strs = []
    for s in pre_data.split(b'\x00'):
        s = s.strip()
        if len(s) >= 1 and all(32 <= b <= 126 for b in s):
            pre_strs.append(s.decode('ascii', errors='replace'))
    
    # Determine name: usually a non-pattern, non-type-tag string before/after
    name = ""
    module = ""
    type_tag = ""
    
    # Look for module name in pre strings
    for s in pre_strs:
        if s.endswith('.dll'):
            module = s
            break
    
    # Look for type tag (FN_X, PTR_X) in post strings
    for s in post_strs:
        if re.match(r'^(FN|PTR)_[A-Z0-9]+$', s):
            type_tag = s
            break
    
    # Look for name in post strings (exclude type tags and patterns)
    for s in post_strs:
        if '??' not in s and not re.match(r'^(FN|PTR)_[A-Z0-9]+$', s) and not s.endswith('.dll'):
            name = s
            break
    if not name:
        # Look in pre strings
        for s in reversed(pre_strs):
            if '??' not in s and not re.match(r'^(FN|PTR)_[A-Z0-9]+$', s) and not s.endswith('.dll'):
                name = s
                break
    
    entries.append({
        'index': i,
        'offset': start,
        'signature': sig,
        'name': name,
        'module': module,
        'type_tag': type_tag,
    })
    
    # Skip patterns that appear as part of other strings (e.g., the previous pattern's string showing up in post)
    # We need to advance i; the patterns are sequential, but some patterns appear in the post_strings of others
    # The actual unique patterns are every other one approximately
    i += 1

# Filter out duplicate patterns (which appear as strings within other pattern contexts)
seen_sigs = set()
unique_entries = []
for e in entries:
    if e['signature'] not in seen_sigs:
        seen_sigs.add(e['signature'])
        unique_entries.append(e)

print(f"Total unique patterns: {len(unique_entries)}")
print()

# Group by module
modules = {}
for e in unique_entries:
    mod = e['module'] if e['module'] else '(no module)'
    if mod not in modules:
        modules[mod] = []
    modules[mod].append(e)

for mod, pats in modules.items():
    print(f"\n--- Module: {mod} ({len(pats)} patterns) ---")
    for p in pats:
        print(f"  [{p['type_tag']:12s}] {p['name']:20s} | {p['signature'][:70]}")

# ======================================================
# 3. Find syscall stubs and their SSN resolution
# ======================================================
print("\n" + "=" * 60)
print("SECTION 3: SYSCALL STUBS")
print("=" * 60)

# Look for syscall instructions (0F 05) but filter out false positives
syscall_offs = []
for i in range(len(data) - 1):
    if data[i] == 0x0F and data[i+1] == 0x05:
        # Check if this is a real syscall (preceded by syscall setup)
        # Real syscalls have: mov eax, SSN; ...; syscall
        # False positives: part of other instructions like mov [rbp+X], 0x0000050F
        # Heuristic: check if the 2 bytes before are an operand
        if i >= 5:
            # A real syscall is typically preceded by mov r10, rcx; mov eax, SSN
            pre5 = data[i-5:i]
            # mov r10, rcx = 4C 8B D1 (3 bytes) + mov eax, imm32 = B8 XX XX XX XX (5 bytes)
            # Or just mov eax, imm32 = B8 XX XX XX XX (5 bytes)
            if data[i-5] == 0xB8 or (data[i-3] == 0xB8 and data[i-5] == 0x4C):
                syscall_offs.append(i)
                continue
            # Also check if preceded by mov eax from a memory location
            if data[i-7:i-5] == b'\x4C\x8B' or data[i-10:i-8] == b'\x4C\x8B':  # mov r10, ...
                syscall_offs.append(i)
                continue
        # Include if we're unsure
        syscall_offs.append(i)

print(f"Real syscall candidates: {len(syscall_offs)}")
for off in syscall_offs:
    start = max(0, off - 20)
    end = min(len(data), off + 5)
    ctx = data[start:end]
    hex_str = ' '.join(f'{b:02X}' for b in ctx)
    ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in ctx)
    print(f"  0x{off:06X}: {hex_str}")
    print(f"           {ascii_str}")
    print()

# ======================================================
# 4. Find VirtualProtect/NtProtectVirtualMemory references
# ======================================================
print("=" * 60)
print("SECTION 4: MEMORY PROTECTION API REFERENCES")
print("=" * 60)

vp_off = data.find(b'VirtualProtect\x00')
nt_off = data.find(b'NtProtectVirtualMemory\x00')
print(f"VirtualProtect at: 0x{vp_off:X}")
print(f"NtProtectVirtualMemory at: 0x{nt_off:X}")

# Find LEA instructions referencing these
for target_off, target_name in [(vp_off, 'VirtualProtect'), (nt_off, 'NtProtectVirtualMemory')]:
    print(f"\n  References to {target_name}:")
    count = 0
    for i in range(len(data) - 7):
        if data[i] == 0x48 and data[i+1] == 0x8D:
            modrm = data[i+2]
            if modrm in (0x0D, 0x15, 0x05, 0x1D, 0x2D, 0x35, 0x3D):
                rel = struct.unpack_from('<i', data, i+3)[0]
                abs_addr = (i + 7) + rel
                if abs_addr == target_off:
                    print(f"    LEA at 0x{i:06X}")
                    # Show surrounding code
                    ctx = data[max(0,i-16):i+16]
                    hex_str = ' '.join(f'{b:02X}' for b in ctx)
                    print(f"      {hex_str}")
                    count += 1
    if count == 0:
        print(f"    (no direct LEA refs found)")

# ======================================================
# 5. Find ScPresent::Install references
# ======================================================
print("\n" + "=" * 60)
print("SECTION 5: ScPresent::Install AND OVERLAY RENDERING")
print("=" * 60)

sc_off = data.find(b'ScPresent::Install')
if sc_off >= 0:
    print(f"ScPresent::Install string at: 0x{sc_off:X}")
    # Find LEA refs
    for i in range(len(data) - 7):
        if data[i] == 0x48 and data[i+1] == 0x8D:
            modrm = data[i+2]
            if modrm in (0x0D, 0x15, 0x05, 0x1D, 0x2D, 0x35, 0x3D):
                rel = struct.unpack_from('<i', data, i+3)[0]
                abs_addr = (i + 7) + rel
                if abs_addr == sc_off:
                    print(f"  LEA ref at 0x{i:06X}")
                    ctx = data[max(0,i-40):i+40]
                    hex_str = ' '.join(f'{b:02X}' for b in ctx)
                    print(f"    {hex_str}")

# Find SetWindowLongPtr / CallWindowProc references
for name in [b'SetWindowLongPtrW', b'SetWindowLongPtrA', b'CallWindowProcW', b'CallWindowProcA',
             b'SetWindowSubclass', b'DefWindowProcW', b'DefWindowProcA']:
    off = data.find(name + b'\x00')
    if off >= 0:
        print(f"  {name.decode()} string at: 0x{off:X}")

# Find present/hook related code strings
for name in [b'origWndProc', b'hwnd=', b'QueueSC', b'PostMessage', b'WM_', b'wndproc',
             b'DXGI', b'dxgi', b'swapchain', b'SwapChain', b'Present', b'ResizeBuffers']:
    off = data.find(name)
    if off >= 0:
        ctx_start = max(0, off - 8)
        ctx_end = min(len(data), off + len(name) + 8)
        ctx = data[ctx_start:ctx_end]
        strs = []
        for s in ctx.split(b'\x00'):
            s = s.strip()
            if len(s) >= 1 and all(32 <= b <= 126 for b in s):
                strs.append(s.decode('ascii', errors='replace'))
        print(f"  '{name.decode()}' at 0x{off:X}: {strs[:3]}")
