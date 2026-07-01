#!/usr/bin/env python3
"""
SUPPLEMENT: Binary-level analysis for patterns capstone missed
Appends syscall analysis and raw binary pattern scanning.
"""
import struct
from collections import Counter, defaultdict

BIN_PATH = r"C:\Users\emora\OneDrive\Desktop\2\.text_unpacked_mem.bin"
OUT_PATH = r"C:\Users\emora\OneDrive\Desktop\2\resweep_code.txt"

with open(BIN_PATH, "rb") as f:
    CODE = f.read()
SIZE = len(CODE)

lines = []

def w(s):
    lines.append(s)

def section(title):
    lines.append("")
    lines.append("=" * 80)
    lines.append(f"  {title}")
    lines.append("=" * 80)

# ================================================================
section("SUPPLEMENT S1: SYSCALL STUB COMPLETE ANALYSIS")
# ================================================================

# Find all 0F 05 sequences and analyze preceding bytes for SSN
lines.append("")
lines.append("S1.1 COMPLETE SYSCALL INSTRUCTION SITES")
lines.append("    Format: mov r10, rcx (4C 8B D1); mov eax, SSN (B8 XX XX XX XX); syscall (0F 05); ret (C3)")
lines.append("")

syscall_sites = []
# Search for the complete stub pattern
for i in range(SIZE - 14):
    # Pattern: 4C 8B D1 B8 XX XX XX XX 0F 05 C3
    if CODE[i:i+2] == b'\x4C\x8B' and CODE[i+2] == 0xD1:
        if CODE[i+3] == 0xB8:  # mov eax, imm32
            ssn = struct.unpack_from('<I', CODE, i+4)[0]
            if i+8 < SIZE and CODE[i+8:i+10] == b'\x0F\x05':
                syscall_sites.append((i, ssn, 'FULL_STUB'))
                continue
    # Also search for: mov eax, SSN; syscall (without mov r10 prefix)
    if CODE[i] == 0xB8 and i+6 < SIZE:
        ssn = struct.unpack_from('<I', CODE, i+1)[0]
        if CODE[i+5:i+7] == b'\x0F\x05':
            # Check if preceded by mov r10, rcx (or not)
            has_mov_r10 = (i >= 4 and CODE[i-4:i] == b'\x4C\x8B\xD1\x90') or \
                          (i >= 3 and CODE[i-3:i] == b'\x4C\x8B\xD1')
            syscall_sites.append((i, ssn, 'MOV_EAX_only'))
            continue

# Also find bare 0F 05 that weren't caught above
for i in range(SIZE - 1):
    if CODE[i] == 0x0F and CODE[i+1] == 0x05:
        already_found = any(abs(s[0] - i) <= 10 for s in syscall_sites)
        if not already_found:
            # Try to find SSN nearby
            ssn = None
            for j in range(max(0, i-8), i):
                if j+4 < SIZE and CODE[j] == 0xB8:
                    ssn = struct.unpack_from('<I', CODE, j+1)[0]
                    break
            syscall_sites.append((i, ssn, 'BARE_syscall'))

# Deduplicate
seen_rva = set()
unique_sites = []
for rva, ssn, stype in sorted(syscall_sites, key=lambda x: x[0]):
    if rva not in seen_rva:
        seen_rva.add(rva)
        unique_sites.append((rva, ssn, stype))

lines.append(f"    Total syscall sites found: {len(unique_sites)}")
lines.append("")

for rva, ssn, stype in unique_sites:
    lines.append(f"    RVA {hex(rva)}:")
    lines.append(f"      Type: {stype}")
    if ssn is not None:
        # Map common SSNs to function names
        ssn_names = {
            0x18: 'NtAllocateVirtualMemory',
            0x1B: 'NtReadVirtualMemory', 0x1C: 'NtWriteVirtualMemory',
            0x2D: 'NtProtectVirtualMemory',
            0x36: 'NtQuerySystemInformation', 0x37: 'NtQueryInformationProcess',
            0x62: 'NtCreateThreadEx', 0xE0: 'NtDelayExecution',
            0x19: 'NtFreeVirtualMemory', 0x1A: 'NtQueryVirtualMemory',
            0x1F: 'NtFlushInstructionCache', 0x22: 'NtCreateFile',
            0x2C: 'NtCreateSection', 0x2E: 'NtQuerySection',
            0x30: 'NtMapViewOfSection', 0x38: 'NtSetInformationProcess',
            0x50: 'NtQueryVolumeInformationFile',
        }
        name = ssn_names.get(ssn, 'UNKNOWN')
        lines.append(f"      SSN: 0x{ssn:X} ({ssn}) -> {name}")
    else:
        lines.append(f"      SSN: unknown (no mov eax found nearby)")
    
    # Show 30 bytes around the syscall
    start = max(0, rva - 16)
    end = min(SIZE, rva + 16)
    raw = CODE[start:end]
    hex_str = ' '.join(f'{b:02X}' for b in raw)
    # Mark the 0F 05
    idx = (rva - start) * 3
    hex_str_parts = list(hex_str)
    lines.append(f"      Bytes: {''.join(hex_str_parts)}")
    lines.append(f"             {' ' * (rva - start) * 3}^^-- 0F 05")

# ================================================================
section("SUPPLEMENT S2: PATTERN SCANNER BINARY ANALYSIS")
# ================================================================

lines.append("")
lines.append("S2.1 EXACT PATTERN SCANNING ALGORITHM (from byte-level analysis)")
lines.append("    Searching for the byte-comparison loop characteristic of pattern scanning...")
lines.append("")

# Look for: 80 3C XX ?? (cmp byte ptr [rsp/rbp + offset], imm) sequences in a loop
# Pattern scanner loops typically do:
#   movzx eax, byte [module_ptr + offset]
#   cmp al, byte [pattern_ptr + offset]  
#   je match / jne continue
# Wildcard: compare with 0x3F (?) or check against mask

# Search for movzx patterns in scanning code region
scan_region_start = 0x6000
scan_region_end = 0x12000

lines.append("    Binary patterns in scanner region (0x6000-0x12000):")
lines.append("")

# Pattern: 0F B6 (movzx eax/r8d/edx, byte [mem]) - byte load
movzx_count = 0
for i in range(scan_region_start, min(scan_region_end, SIZE)):
    if CODE[i] == 0x0F and CODE[i+1] in (0xB6, 0xB7):  # movzx to register
        movzx_count += 1
        if movzx_count <= 15:
            reg = {0xB6:'movzx byte', 0xB7:'movzx word'}[CODE[i+1]]
            lines.append(f"    {hex(i)}: {reg}")

lines.append(f"    ... total movzx instructions in scan region: {movzx_count}")

# Pattern: cmp byte ptr [reg], imm (80 3C XX XX) - byte compare
lines.append("")
lines.append("    Byte comparison patterns (cmp byte ptr [reg], imm):")
byte_cmp_count = 0
for i in range(scan_region_start, min(scan_region_end, SIZE-3)):
    if CODE[i] == 0x80 and CODE[i+1] == 0x3C:
        imm = CODE[i+3]
        byte_cmp_count += 1
        if byte_cmp_count <= 15:
            lines.append(f"    {hex(i)}: cmp byte ptr, 0x{imm:02X}")

lines.append(f"    ... total byte cmp in scan region: {byte_cmp_count}")

# ================================================================
section("SUPPLEMENT S3: STRING REFERENCE EXTRACTION (improved)")
# ================================================================

lines.append("")
lines.append("S3.1 ALL STRING REFERENCES (null-terminated ASCII, >= 4 chars)")
lines.append("    Extracting all printable ASCII strings from the binary...")
lines.append("")

strings = []
current = b''
current_start = 0
min_len = 4

for i in range(SIZE):
    b = CODE[i]
    if 0x20 <= b <= 0x7E:
        if not current:
            current_start = i
        current += bytes([b])
    else:
        if len(current) >= min_len:
            strings.append((current_start, current.decode('ascii')))
        current = b''

if current and len(current) >= min_len:
    strings.append((current_start, current.decode('ascii')))

lines.append(f"    Total printable strings (>=4 chars): {len(strings)}")

# Categorize strings
categories = defaultdict(list)
for rva, s in strings:
    s_lower = s.lower()
    if any(k in s_lower for k in ['http', 'https', 'winhttp', 'wininet', 'curl', 'content-type', 'user-agent', 'cookie', 'header']):
        categories['HTTP'].append((rva, s))
    if any(k in s_lower for k in ['imgui', 'dear im', 'widget', '##', 'checkbox', 'slider', 'combo', 'button', 'inputtext', 'beginchild']):
        categories['IMGUI'].append((rva, s))
    if any(k in s_lower for k in ['json', 'parse', 'serialize', 'missionid', 'captured', 'entity', 'amount']):
        categories['JSON'].append((rva, s))
    if any(k in s_lower for k in ['thread', 'mutex', 'critical', 'semaphore', 'event', 'apc', 'dispatch']):
        categories['THREADING'].append((rva, s))
    if any(k in s_lower for k in ['sleep', 'timer', 'queryperform', 'tick', 'clock', 'delay', 'cooldown']):
        categories['TIMING'].append((rva, s))
    if any(k in s_lower for k in ['createfile', 'readfile', 'writefile', 'fopen', 'fclose', 'mapview', 'filemapping', 'libertea_replay', 'ntdll.dll', 'game.dll']):
        categories['FILEIO'].append((rva, s))
    if any(k in s_lower for k in ['malloc', 'free', 'heap', 'virtualalloc', 'alloc', 'vector', 'new', 'delete']):
        categories['ALLOC'].append((rva, s))
    if any(k in s_lower for k in ['xor', 'encrypt', 'decrypt', 'cipher', 'obfuscate', 'hash', 'crc', 'md5', 'sha', 'aes', 'rc4', 'bcrypt']):
        categories['CRYPTO'].append((rva, s))
    if any(k in s_lower for k in ['hook', 'pattern', 'scan', 'nop', 'detour', 'trampoline', 'patch', 'stub', 'syscall']):
        categories['HOOKING'].append((rva, s))
    if any(k in s_lower for k in ['dllmain', 'dll_process', 'exception', 'vectored', 'handler', 'security_cookie', 'rtti', 'typeid', 'dynamic_cast']):
        categories['RUNTIME'].append((rva, s))
    if any(k in s_lower for k in ['sc ', 'super credit', 'farming', 'medal', 'replay', 'batch', 'goal']):
        categories['SC_FARMING'].append((rva, s))
    if any(k in s_lower for k in ['weapon', 'armor', 'xp', 'god mode', 'ragdoll', 'recoil', 'ammo', 'reload', 'grenade', 'stim', 'stratagem']):
        categories['CHEATS'].append((rva, s))

lines.append("")
for cat in sorted(categories.keys()):
    items = categories[cat]
    lines.append(f"    {cat}: {len(items)} strings")
    if len(items) <= 20:
        for rva, s in items:
            lines.append(f"      {hex(rva)}: \"{s}\"")
    else:
        for rva, s in items[:10]:
            lines.append(f"      {hex(rva)}: \"{s}\"")
        lines.append(f"      ... ({len(items)-10} more)")

# ================================================================
section("SUPPLEMENT S4: INSTRUCTION DISTRIBUTION AND RARE PATTERNS")
# ================================================================

lines.append("")
lines.append("S4.1 RARE/UNUSUAL INSTRUCTIONS")
# Manually scan for rare instruction prefixes
rare_patterns = {
    'CPUID (0F A2)': b'\x0F\xA2',
    'RDTSC (0F 31)': b'\x0F\x31',
    'RDTSCP (0F 01 F9)': b'\x0F\x01\xF9',
    'RDRAND': b'\x48\x0F\xC7',
    'XGETBV (0F 01 D0)': b'\x0F\x01\xD0',
    'XSAVE': b'\x0F\xAE',
    'LFENCE (0F AE E8)': b'\x0F\xAE\xE8',
    'MFENCE (0F AE F0)': b'\x0F\xAE\xF0',
    'SFENCE (0F AE F8)': b'\x0F\xAE\xF8',
    'CLFLUSH': b'\x0F\xAE\x38',
    'PREFETCH': b'\x0F\x18',
    'MOVNTI': b'\x0F\xC3',
    'MOVNTDQ': b'\x66\x0F\xE7',
    'VZEROUPPER': b'\xC5\xF8\x77',
    'VZEROALL': b'\xC5\xFC\x77',
    'PAUSE (F3 90)': b'\xF3\x90',
    'UD2 (0F 0B)': b'\x0F\x0B',
    'INT3 (CC)': b'\xCC',
    'HLT (F4)': b'\xF4',
    'CLI (FA)': b'\xFA',
    'STI (FB)': b'\xFB',
    'INVD': b'\x0F\x08',
    'WBINVD': b'\x0F\x09',
}

for name, pattern in rare_patterns.items():
    count = 0
    pos = 0
    while True:
        pos = CODE.find(pattern, pos)
        if pos == -1:
            break
        count += 1
        pos += 1
    if count > 0:
        lines.append(f"    {name}: {count} occurrences")

# ================================================================
section("SUPPLEMENT S5: PATTERN SCANNER FULL DISASSEMBLY")
# ================================================================

lines.append("")
lines.append("S5.1 RE-DISASSEMBLY OF KNOWN PATTERN SCANNER FUNCTION")
lines.append("    Using targeted disassembly with proper alignment...")

# Import capstone just for this section
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# Try to find the actual pattern scanner function start
# The scanner at ~0x6D70 seems to start earlier. Let's scan for the function prologue near 0x6C00-0x6E00
lines.append("")
lines.append("    Searching for scanner function entry in 0x6C00-0x6E00...")

for probe in range(0x6C00, 0x6E00, 1):
    b = CODE[probe:probe+4]
    # Check for typical prologues
    if b[:1] == b'\x55' or b[:2] == b'\x40\x55' or b[:2] == b'\x40\x53' or \
       b[:2] == b'\x40\x57' or (b[0]==0x48 and b[1]==0x89 and b[2] in (0x5C,0x6C,0x74,0x7C)):
        # Verify that the next few bytes decode reasonably
        try:
            insns = list(md.disasm(CODE[probe:probe+0x100], probe))
            if len(insns) >= 3:
                lines.append(f"      Found prologue at {hex(probe)}: {insns[0].mnemonic} {insns[0].op_str}")
        except:
            pass

# Try specific offsets known from previous analysis
scanner_ofs = [0x6CC0, 0x6CD0, 0x6CE0, 0x6D00, 0x6D20, 0x6D40, 0x6D60, 0x6D70, 0x6D90]
for ofs in scanner_ofs:
    lines.append(f"")
    lines.append(f"    === Disassembly at {hex(ofs)} (re-disassembled) ===")
    try:
        chunk = CODE[ofs:ofs+0x100]
        insns = list(md.disasm(chunk, ofs))
        for insn in insns[:40]:
            lines.append(f"    {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
    except Exception as e:
        lines.append(f"    [decode error: {e}]")

# ================================================================
section("SUPPLEMENT S6: IMPORT RESOLVER DEEP DIVE")
# ================================================================

lines.append("")
lines.append("S6.1 IMPORT STUB ANALYSIS (RVA 0x1020 - 0x10A0 region)")
lines.append("    Analyzing call/jmp stubs that reference import names...")
lines.append("")

# Known pattern: LEA RCX, [rip + string_offset]; JMP [rip + resolver_offset]
# At the stub addresses, look for this pattern
for addr in range(0x1020, 0x1100, 8):  # Step 8 - typical stub alignment
    bs = CODE[addr:addr+16]
    if len(bs) < 12:
        continue
    # Pattern 1: lea rcx, [rip + offset]; jmp [rip + offset]
    if bs[0:3] == b'\x48\x8D\x0D':  # lea rcx, [rip + disp32]
        disp = struct.unpack_from('<i', bs, 3)[0]
        target_string = addr + 7 + disp
        next_byte = bs[7] if len(bs) > 7 else 0
        if next_byte == 0xFF:  # jmp [rip + disp32] usually
            lines.append(f"    {hex(addr)}: LEA RCX, [{hex(target_string)}] -> JMP resolver (import stub)")
    # Pattern 2: jmp [rip + offset] only  
    elif bs[0:2] == b'\xFF\x25':  # jmp [rip + disp32]
        disp = struct.unpack_from('<i', bs, 2)[0]
        target = addr + 6 + disp
        lines.append(f"    {hex(addr)}: JMP [{hex(target)}] (import stub, no string ref)")

# ================================================================
section("SUPPLEMENT S7: IMGUI VERSION AND INITIALIZATION DEEP DIVE")
# ================================================================

lines.append("")
lines.append("S7.1 IMGUI IL VERSION MARKERS")
lines.append("    Searching for ImGui version strings in binary...")
lines.append("")

# ImGui version is often embedded as "ImGui 1.XX" or "Dear ImGui 1.XX"
for i in range(SIZE - 12):
    if CODE[i:i+5] == b'ImGui' or CODE[i:i+9] == b'Dear ImGui':
        end = CODE.find(b'\x00', i)
        s = CODE[i:min(end+1, i+100)].decode('ascii', errors='replace')
        lines.append(f"    {hex(i)}: \"{s}\"")

lines.append("")
lines.append("S7.2 IMGUI INITIALIZATION CODE RECONSTRUCTION")
lines.append("    Searching for the call sequence: CreateContext -> StyleColors -> Font...")

# Look for the initialization sequence near where ImGui strings are referenced
# Find style color references
style_strings = [b'StyleColorsDark', b'StyleColorsLight', b'StyleColorsClassic',
                 b'CreateContext', b'GetIO', b'NewFrame']
for ss in style_strings:
    if ss in CODE:
        pos = CODE.find(ss)
        lines.append(f"    '{ss.decode()}' at RVA {hex(pos)}")
        # Show code before the string reference
        try:
            ctx = CODE[max(0, pos-0x200):pos+0x100]
            insns = list(md.disasm(ctx, max(0, pos-0x200)))
            lines.append(f"    Code near this reference:")
            for insn in insns:
                if abs(insn.address - pos) < 0x180:
                    if any(x in insn.mnemonic.lower() for x in ('call', 'lea', 'jmp', 'mov')):
                        lines.append(f"      {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
        except:
            pass

# ================================================================
section("SUPPLEMENT S8: STRING HASH ALGORITHM DEEP DIVE")
# ================================================================

lines.append("")
lines.append("S8.1 CRC32 INSTRUCTION ANALYSIS")
lines.append("")

# Find all code sequences containing CRC32
for i in range(SIZE - 10):
    if CODE[i:i+4] == b'\xF2\x0F\x38\xF1' or CODE[i:i+4] == b'\xF2\x41\x0F\x38' or \
       CODE[i:i+4] == b'\xF2\x0F\x38\xF0':
        lines.append(f"    CRC32 instruction at {hex(i)}")
        try:
            ctx = CODE[max(0,i-0x30):i+0x20]
            insns = list(md.disasm(ctx, max(0,i-0x30)))
            lines.append(f"      Context:")
            for insn in insns[-8:]:
                lines.append(f"      {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
        except:
            pass

lines.append("")
lines.append("S8.2 HASH FUNCTION DETECTION BY CONSTANTS")
lines.append("    Scanning for well-known hash constants embedded in code...")

hash_magic = {
    0x1505: 'CRC-16',
    0xEDB88320: 'CRC-32 (IEEE 802.3)',
    0x04C11DB7: 'CRC-32 (PKZIP)',
    0x811C9DC5: 'FNV-1 32-bit offset basis',
    0x01000193: 'FNV-1 32-bit prime',
    0xCBF29CE484222325: 'FNV-1 64-bit offset basis',
    0x100000001B3: 'FNV-1 64-bit prime',
    0xC6A4A793: 'MurmurHash3 (c1)',
    0x5BD1E995: 'MurmurHash2 (m)',
    0x85EBCA6B: 'CityHash64 (k2)',
    0xC2B2AE35: 'CityHash64 (k1)',
    0x9AE16A3B2F90404F: 'xxHash64 (prime)',
    0x165667B19E3779F9: 'xxHash64 (prime2)',
    0x67452301: 'MD5/SHA1 (IV)',
    0xEFCDAB89: 'MD5 (IV)',
    0x98BADCFE: 'MD5 (IV)',
    0x10325476: 'MD5 (IV)',
}

# Check for 32-bit constants
for i in range(SIZE - 4):
    val = struct.unpack_from('<I', CODE, i)[0]
    if val in hash_magic:
        name = hash_magic[val]
        lines.append(f"    {hex(i)}: 0x{val:08X} -> {name}")
    # Also check common 64-bit patterns split across two dwords
    if i + 4 <= SIZE - 4:
        val64 = struct.unpack_from('<Q', CODE, i)[0]
        if val64 in hash_magic:
            name = hash_magic[val64]
            lines.append(f"    {hex(i)}: 0x{val64:016X} -> {name}")

# ================================================================
section("SUPPLEMENT S9: ENCRYPTION / OBFUSCATION DEEP DIVE")
# ================================================================

lines.append("")
lines.append("S9.1 XOR ENCRYPTION LOOP PATTERNS")
lines.append("    Searching for XOR-based encryption/decryption loops...")
lines.append("")

# Look for: movzx eax, byte [src]; xor eax, key; mov [dst], al; inc src; inc dst; loop
xor_loop_count = 0
for i in range(0, min(SIZE-20, 0x80000), 1):  # First 512KB for performance
    if CODE[i] in (0x0F, 0x48) and CODE[i+1] == 0xB6:  # movzx
        # Look forward for XOR with immediate
        for j in range(i+3, min(i+20, SIZE)):
            if CODE[j] == 0x34 or (CODE[j] == 0x80 and j+3 < SIZE and CODE[j+1] == 0xF0):
                # XOR AL, imm8 or XOR EAX, imm32
                xor_loop_count += 1
                if xor_loop_count <= 10:
                    lines.append(f"    Potential XOR decrypt loop at {hex(i)}")
                break

lines.append(f"    XOR decrypt loop candidates (first 512KB): {xor_loop_count}")

# ================================================================
section("SUPPLEMENT S10: CODE CAVE / SHELLCODE REGIONS")
# ================================================================

lines.append("")
lines.append("S10.1 CODE CAVES (large regions of executable padding)")
lines.append("")

# Find regions of consecutive identical bytes (potential caves)
cave_min = 64
current_byte = None
current_start = 0
caves = []

for i in range(SIZE):
    b = CODE[i]
    if b == current_byte:
        continue
    else:
        if current_byte is not None:
            length = i - current_start
            if length >= cave_min:
                caves.append((current_byte, current_start, i))
        current_byte = b
        current_start = i

if current_byte is not None and SIZE - current_start >= cave_min:
    caves.append((current_byte, current_start, SIZE))

lines.append(f"    Code cave regions (>= {cave_min} bytes identical):")
for bval, start, end in caves:
    sz = end - start
    label = {0x00: 'NUL', 0x90: 'NOP', 0xCC: 'INT3'}.get(bval, f'0x{bval:02X}')
    lines.append(f"    {hex(start)}-{hex(end)}: {sz:,} bytes of {label}")

# ================================================================
section("SUPPLEMENT S11: XREF CROSS-REFERENCE MAP")
# ================================================================

lines.append("")
lines.append("S11.1 CROSS-REFERENCE SUMMARY")
lines.append("    Mapping which code regions reference which data/strings...")
lines.append("")

# Find LEA instructions referencing RIP-relative addresses (potential string refs)
lea_count = 0
for i in range(SIZE - 7):
    # LEA reg, [rip + disp32]
    if CODE[i] in (0x48, 0x4C) and CODE[i+1] == 0x8D:  # REX.W + LEA
        modrm = CODE[i+2]
        if (modrm & 0xC7) == 0x05:  # mod=00, rm=101 (RIP-relative)
            disp = struct.unpack_from('<i', CODE, i+3)[0]
            target = i + 7 + disp
            if 0 <= target < SIZE:
                lea_count += 1

lines.append(f"    Total RIP-relative LEA instructions: {lea_count}")

# ================================================================
section("SUPPLEMENT S12: DATA TABLES AND STRUCTURES")
# ================================================================

lines.append("")
lines.append("S12.1 PATTERN TABLE STRUCTURE ANALYSIS")
lines.append("    Searching for the pattern signature table in data sections...")
lines.append("")

# Look for IDA-style pattern strings with ?? wildcards
# Pattern: sequences of hex bytes separated by spaces
pattern_like = []
for i in range(SIZE - 20):
    # Check if we have a sequence of 2-char hex+space patterns with ??
    bs = CODE[i:i+40]
    text = bs.decode('ascii', errors='replace')
    if text.count('??') >= 2 and len(text.strip()) > 10 and all(c in '0123456789ABCDEFabcdef ?*' for c in text.strip()):
        pattern_like.append((i, text.strip()))

lines.append(f"    IDA-style pattern strings found: {len(pattern_like)}")
for rva, pat in pattern_like[:30]:
    lines.append(f"    {hex(rva)}: \"{pat[:80]}\"")

# ================================================================
section("SUPPLEMENT S13: WINHTTP/LIBCURL BACKEND IDENTIFICATION")
# ================================================================

lines.append("")
lines.append("S13.1 HTTP BACKEND DETERMINATION")
lines.append("")

# Check which HTTP stack is primary
has_winhttp = b'winhttp.dll' in CODE
has_wininet = b'wininet.dll' in CODE
has_libcurl = b'libcurl.dll' in CODE
has_raw_socket = b'WSAStartup' in CODE or b'socket' in CODE.lower() or b'connect' in CODE

lines.append(f"    WinHTTP: {'YES' if has_winhttp else 'NO'}")
lines.append(f"    WinINet: {'YES' if has_wininet else 'NO'}")
lines.append(f"    libcurl: {'YES' if has_libcurl else 'NO'}")
lines.append(f"    Raw sockets (Winsock): {'YES' if has_raw_socket else 'NO'}")

# Count API resolution stubs for each backend
lines.append("")
lines.append("    HTTP API function references:")
http_funcs = [b'WinHttpOpen', b'WinHttpConnect', b'WinHttpOpenRequest',
              b'WinHttpSendRequest', b'WinHttpReceiveResponse', b'WinHttpReadData',
              b'WinHttpCloseHandle', b'WinHttpSetOption', b'WinHttpQueryHeaders',
              b'WinHttpQueryDataAvailable', b'WinHttpWriteData',
              b'curl_easy_init', b'curl_easy_setopt', b'curl_easy_perform',
              b'curl_easy_getinfo', b'curl_easy_cleanup', b'curl_slist_append',
              b'curl_slist_free_all']

for func in http_funcs:
    if func in CODE:
        c = CODE.count(func)
        lines.append(f"    \"{func.decode()}\": {c} references")

# ================================================================
# APPEND TO OUTPUT FILE
# ================================================================

print(f"[*] Writing {len(lines):,} supplemental lines")

with open(OUT_PATH, 'a', encoding='utf-8') as f:
    f.write('\n' + '\n'.join(lines))

print("[*] Supplement appended successfully!")
