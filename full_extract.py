#!/usr/bin/env python3
"""
Comprehensive binary analysis of .text_unpacked_mem.bin
Outputs all findings to libertea_complete.txt
"""

import hashlib
import struct
import math
import re
import os
from collections import Counter, defaultdict

BIN_PATH = r"C:\Users\emora\OneDrive\Desktop\2\.text_unpacked_mem.bin"
OUT_PATH = r"C:\Users\emora\OneDrive\Desktop\2\libertea_complete.txt"

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

# ============================================================
# Load binary
# ============================================================
with open(BIN_PATH, "rb") as f:
    data = f.read()

file_size = len(data)
print(f"Loaded {file_size} bytes ({file_size/1024:.1f} KB / {file_size/1024/1024:.2f} MB)")

lines = []
def out(s=""):
    lines.append(str(s))

def flush():
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"Output written: {OUT_PATH} ({len(lines)} lines, {os.path.getsize(OUT_PATH)} bytes)")

# ============================================================
# 1. Binary hash fingerprints
# ============================================================
out("=" * 80)
out("1. BINARY HASH FINGERPRINTS")
out("=" * 80)
out()

md5_full = hashlib.md5(data).hexdigest()
sha256_full = hashlib.sha256(data).hexdigest()
out(f"Full file MD5:    {md5_full}")
out(f"Full file SHA256: {sha256_full}")
out()

first_1mb = data[:min(1048576, file_size)]
out(f"First 1MB MD5:    {hashlib.md5(first_1mb).hexdigest()}")
out(f"First 1MB SHA256: {hashlib.sha256(first_1mb).hexdigest()}")
out()

chunk_size = 256 * 1024
chunk_idx = 0
for offset in range(0, file_size, chunk_size):
    chunk = data[offset:offset+chunk_size]
    out(f"Chunk {chunk_idx:04d} [0x{offset:08X}-0x{offset+len(chunk):08X}] MD5: {hashlib.md5(chunk).hexdigest()}  SHA256: {hashlib.sha256(chunk).hexdigest()}")
    chunk_idx += 1
out()

# ============================================================
# 2. Byte frequency histogram
# ============================================================
out("=" * 80)
out("2. BYTE FREQUENCY HISTOGRAM (Top 50)")
out("=" * 80)
out()

byte_counter = Counter(data)
for rank, (byte_val, count) in enumerate(byte_counter.most_common(50), 1):
    pct = count / file_size * 100
    char = chr(byte_val) if 0x20 <= byte_val < 0x7F else "."
    out(f"  {rank:2d}.  0x{byte_val:02X}  {byte_val:3d}  '{char}'  count={count:8d}  ({pct:5.2f}%)")
out()

# ============================================================
# 3. Entropy per 4KB page
# ============================================================
out("=" * 80)
out("3. ENTROPY PER 4KB PAGE")
out("=" * 80)
out()

page_size = 4096
entropy_pages = []
for offset in range(0, file_size, page_size):
    page = data[offset:offset+page_size]
    if len(page) < 256:
        continue
    counter = Counter(page)
    ent = 0.0
    for count in counter.values():
        p = count / len(page)
        ent -= p * math.log2(p)
    max_ent = 8.0
    entropy_pages.append((offset, ent, len(page)))

entropy_pages.sort(key=lambda x: x[1], reverse=True)

out(f"{'Offset':>10}  {'Entropy':>8}  {'Size':>6}  {'Classification'}")
out("-" * 60)
for offset, ent, sz in entropy_pages[:30]:
    if ent > 7.5:
        cls = "LIKELY ENCRYPTED/COMPRESSED"
    elif ent > 6.5:
        cls = "HIGH ENTROPY (possible packed)"
    elif ent > 5.0:
        cls = "MEDIUM ENTROPY (code/data)"
    elif ent > 3.0:
        cls = "LOW ENTROPY (code)"
    else:
        cls = "VERY LOW (padding/zeros)"
    out(f"0x{offset:08X}  {ent:8.4f}  {sz:6d}  {cls}")
out()

# Also show distribution
high_ent = sum(1 for o, e, _ in entropy_pages if e > 7.0)
med_ent = sum(1 for o, e, _ in entropy_pages if 5.0 <= e <= 7.0)
low_ent = sum(1 for o, e, _ in entropy_pages if e < 5.0)
out(f"\nEntropy distribution: High(>7.0): {high_ent}  Medium: {med_ent}  Low(<5.0): {low_ent}  Total pages: {len(entropy_pages)}")
out()

# ============================================================
# 4. Full function disassembly of first 0x2000 bytes
# ============================================================
out("=" * 80)
out("4. FULL FUNCTION DISASSEMBLY (first 0x2000 bytes)")
out("=" * 80)
out()

DISASM_LIMIT = 0x2000
if HAS_CAPSTONE:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    md.syntax = 1  # Intel syntax

    disasm_data = data[:DISASM_LIMIT]
    out(f"Disassembling first {DISASM_LIMIT} bytes...\n")

    # First pass: identify function boundaries by detecting common prologues
    # and CC padding between functions
    func_starts = []
    i = 0
    while i < len(disasm_data) - 16:
        # Common function prologues
        b = disasm_data[i:i+4]
        # push rbp / mov rbp, rsp variants
        if b[:1] == b'\x55':  # push rbp
            func_starts.append(i)
        # sub rsp, imm8 / sub rsp, imm32
        elif b[:4] == b'\x48\x83\xEC' or b[:4] == b'\x48\x81\xEC':
            func_starts.append(i)
        # push rbx / push rsi / push rdi / push r12-r15
        elif b[:1] in (b'\x53', b'\x56', b'\x57', b'\x41\x54', b'\x41\x55', b'\x41\x56', b'\x41\x57'):
            # check if prev byte is CC (padding) or we're at a boundary
            if i == 0 or disasm_data[i-1] == 0xCC:
                func_starts.append(i)
        # Full prologue: 48 89 5C 24 (mov [rsp+...], rbx)
        elif b[:3] == b'\x48\x89\x5C':
            if i == 0 or disasm_data[i-1] == 0xCC:
                func_starts.append(i)
        i += 1

    # Deduplicate and sort
    func_starts = sorted(set(func_starts))
    # Merge close starts
    merged = []
    for s in func_starts:
        if not merged or s - merged[-1] > 8:
            merged.append(s)
    func_starts = merged

    out(f"Estimated function starts within first 0x2000 bytes: {len(func_starts)}")
    out()

    for func_addr in func_starts[:80]:  # Limit output
        out(f"--- Function at offset 0x{func_addr:04X} ---")
        # Disassemble until we hit padding or max instructions
        offset = func_addr
        instr_count = 0
        # Collect instructions to detect function end (RET or JMP to another func)
        while offset < DISASM_LIMIT and instr_count < 200:
            # Check if we hit CC padding
            if data[offset] == 0xCC:
                # Skip CCs if we just started
                if instr_count == 0:
                    offset += 1
                    continue
                else:
                    break
        
            try:
                insns = list(md.disasm(data[offset:offset+15], offset))
            except Exception:
                break
            if not insns:
                break
            insn = insns[0]
            out(f"  0x{offset:04X}: {insn.mnemonic:12s} {insn.op_str}")
            instr_count += 1
            offset += insn.size
        
            # Stop at RET or JMP
            if insn.mnemonic in ('ret', 'retf', 'iret', 'iretq', 'sysret'):
                if instr_count > 1:
                    break
            # Stop at unconditional JMP that looks like a thunk
            if insn.mnemonic == 'jmp' and '0x' in insn.op_str and instr_count > 1:
                break
        out()
else:
    out("ERROR: capstone not installed. Install with: pip install capstone")
    out()

# ============================================================
# 5. Cross-references / Call graph
# ============================================================
out("=" * 80)
out("5. CROSS-REFERENCES (CALL/JMP graph)")
out("=" * 80)
out()

call_graph = defaultdict(set)  # caller -> set of callees
jmp_targets = defaultdict(set)  # src -> set of dst
all_call_targets = Counter()

if HAS_CAPSTONE:
    md2 = Cs(CS_ARCH_X86, CS_MODE_64)
    md2.detail = True
    
    # Scan entire file for CALL and JMP instructions
    call_count = 0
    jmp_count = 0
    scan_limit = min(file_size, 0x100000)  # Scan first 1MB for speed
    
    offset = 0
    while offset < scan_limit - 15:
        try:
            insns = list(md2.disasm(data[offset:offset+15], offset))
        except:
            offset += 1
            continue
        if not insns:
            offset += 1
            continue
        insn = insns[0]
        if insn.mnemonic == 'call':
            call_count += 1
            # Try to extract target
            op = insn.op_str
            match = re.search(r'0x([0-9a-fA-F]+)', op)
            if match:
                target = int(match.group(1), 16)
                call_graph[offset].add(target)
                all_call_targets[target] += 1
        elif insn.mnemonic.startswith('j') or insn.mnemonic in ('jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jl', 'jge', 'jle', 'ja', 'jb', 'jae', 'jbe', 'jo', 'jno', 'js', 'jns', 'jp', 'jnp', 'jcxz', 'jecxz', 'jrcxz'):
            jmp_count += 1
            match = re.search(r'0x([0-9a-fA-F]+)', insn.op_str)
            if match:
                target = int(match.group(1), 16)
                jmp_targets[offset].add(target)
        offset += insn.size
    
    out(f"CALL instructions found: {call_count}")
    out(f"JMP instructions found:  {jmp_count}")
    out()

    # Top called targets
    out("Top 30 most-called targets:")
    for rank, (addr, count) in enumerate(all_call_targets.most_common(30), 1):
        out(f"  {rank:2d}. 0x{addr:08X} called {count} times")
    out()

    # Show sample call graph
    out(f"Call graph (first {min(30, len(call_graph))} callers):")
    for caller in sorted(call_graph.keys())[:30]:
        callees = sorted(call_graph[caller])
        callee_str = ", ".join(f"0x{c:08X}" for c in callees[:5])
        if len(callees) > 5:
            callee_str += f", ... ({len(callees)} total)"
        out(f"  0x{caller:08X} -> [{callee_str}]")
else:
    out("Skipped (capstone not available)")
out()

# ============================================================
# 6. String references
# ============================================================
out("=" * 80)
out("6. STRING REFERENCES WITH RVA AND CONTEXT")
out("=" * 80)
out()

def extract_strings(data, min_len=4, max_len=512):
    """Extract printable ASCII strings from binary with their offsets."""
    strings = []
    current = bytearray()
    start_offset = 0
    for i, byte in enumerate(data):
        if 0x20 <= byte < 0x7F:
            if not current:
                start_offset = i
            current.append(byte)
        else:
            if len(current) >= min_len:
                s = current.decode('ascii', errors='replace')
                # Filter out strings that look like machine code noise
                if not re.match(r'^[\x20-\x2F\x3A-\x40\x5B-\x60\x7B-\x7E]+$', s):
                    strings.append((start_offset, s))
            current = bytearray()
    if len(current) >= min_len:
        s = current.decode('ascii', errors='replace')
        if not re.match(r'^[\x20-\x2F\x3A-\x40\x5B-\x60\x7B-\x7E]+$', s):
            strings.append((start_offset, s))
    return strings

all_strings = extract_strings(data, min_len=4)

# Filter high-quality strings (containing letters and looking like real data)
def is_likely_real_string(s):
    has_alpha = bool(re.search(r'[a-zA-Z]', s))
    has_repeated = bool(re.search(r'(.)\1{4,}', s))
    # Must have at least some alpha chars and not be just punctuation
    alpha_ratio = sum(1 for c in s if c.isalpha()) / max(len(s), 1)
    return has_alpha and alpha_ratio > 0.3 and not has_repeated

real_strings = [(off, s) for off, s in all_strings if is_likely_real_string(s)]

out(f"Total ASCII strings (>=4 chars): {len(all_strings)}")
out(f"Filtered real-looking strings:   {len(real_strings)}")
out()

# Show string references with context
out("String references with RVA and 64-byte context:")
out()
for offset, s in real_strings[:200]:
    ctx_start = max(0, offset - 32)
    ctx_end = min(file_size, offset + len(s) + 32)
    ctx_bytes = data[ctx_start:ctx_end]
    ctx_hex = ctx_bytes.hex(' ').upper()
    # Replace the actual string part in hex so it's visible
    out(f"  RVA 0x{offset:08X} [{len(s):3d} chars]: \"{s}\"")
    if len(ctx_hex) > 160:
        out(f"    Context hex: {ctx_hex[:160]}...")
    else:
        out(f"    Context hex: {ctx_hex}")
    out()

if len(real_strings) > 200:
    out(f"... (truncated, {len(real_strings) - 200} more strings not shown)")
    out()

# Extra: show strings containing keywords related to game
keywords = ['weapon', 'armor', 'passive', 'difficulty', 'tier', 'farm', 'sc_', 
            'login', 'auth', 'token', 'json', 'http', 'api', 'imgui', 'dear',
            'type_info', 'class', 'rtti', 'exception', 'seh', 'veh', 'tls',
            'debug', 'isdebuggerpresent', 'checkremotedebugger', 'syscall',
            'ntdll', 'kernel32', 'ws2_32', 'winhttp', 'url', 'request',
            'response', 'state', 'transition', 'patch', 'hook', 'pattern',
            'signature', 'scan', 'aob', 'array of bytes']

out("=" * 80)
out("   STRINGS MATCHING KEYWORDS (game/hack related)")
out("=" * 80)
for kw in keywords:
    matches = [(off, s) for off, s in real_strings if kw.lower() in s.lower()]
    if matches:
        out(f"  [{kw}]:")
        for off, s in matches[:10]:
            out(f"    RVA 0x{off:08X}: \"{s}\"")
        if len(matches) > 10:
            out(f"    ... and {len(matches)-10} more")
out()

# ============================================================
# 7. Import stub enumeration
# ============================================================
out("=" * 80)
out("7. IMPORT STUB ENUMERATION")
out("=" * 80)
out()

# In x64 PE, import stubs are typically:
# jmp qword ptr [rip+disp32]  ->  FF 25 XX XX XX XX
# or: jmp [IAT_entry]
# We look for FF 25 patterns and extract the referenced string

import_stubs = []
offset = 0
while offset < file_size - 6:
    if data[offset:offset+2] == b'\xFF\x25':
        # jmp [rip+disp32]
        disp = struct.unpack_from('<i', data, offset+2)[0]
        target_va = offset + 6 + disp  # RIP-relative address
        # Read the string near the target
        # Target points to IAT which has the actual function pointer
        # We can't resolve the name without the import table
        # But we can record the stub location
        import_stubs.append((offset, 'jmp [rip+disp32]', disp, target_va))
        offset += 6
    elif data[offset:offset+2] == b'\xFF\x15':
        # call [rip+disp32]
        disp = struct.unpack_from('<i', data, offset+2)[0]
        target_va = offset + 6 + disp
        import_stubs.append((offset, 'call [rip+disp32]', disp, target_va))
        offset += 6
    else:
        offset += 1

out(f"Import stubs found (FF 25 / FF 15 patterns): {len(import_stubs)}")
out()
out("First 50 import stubs:")
for i, (off, typ, disp, target) in enumerate(import_stubs[:50]):
    # Try to extract nearby string context
    ctx_near = data[max(0, off-16):min(file_size, off+16)]
    out(f"  0x{off:08X} {typ}  disp=0x{disp:08X}  target_va=0x{target:08X}")
out()

# Try to find import name strings (common DLL exports)
# Search for common API function names as strings
api_patterns = [
    b'CreateFile', b'ReadFile', b'WriteFile', b'VirtualAlloc', b'VirtualProtect',
    b'LoadLibrary', b'GetProcAddress', b'FreeLibrary', b'CreateThread',
    b'MessageBox', b'FindWindow', b'send', b'recv', b'connect', b'socket',
    b'bind', b'listen', b'accept', b'WinHttp', b'InternetOpen',
    b'IsDebuggerPresent', b'CheckRemoteDebuggerPresent', b'GetTickCount',
    b'QueryPerformanceCounter', b'RtlAddFunctionTable', b'FlsAlloc', b'FlsGetValue',
    b'TlsAlloc', b'TlsGetValue', b'RtlInstallFunctionTableCallback',
    b'AddVectoredExceptionHandler', b'SetUnhandledExceptionFilter',
    b'NtQueryInformationProcess', b'NtSetInformationThread',
]
out()
out("API name strings found in binary:")
for pat in api_patterns:
    idx = data.find(pat)
    if idx >= 0:
        out(f"  0x{idx:08X}: {pat.decode('ascii')}")
out()

# ============================================================
# 8. Immediate constants (32-bit and 64-bit)
# ============================================================
out("=" * 80)
out("8. 32-BIT AND 64-BIT IMMEDIATE CONSTANTS")
out("=" * 80)
out()

if HAS_CAPSTONE:
    md3 = Cs(CS_ARCH_X86, CS_MODE_64)
    md3.detail = True
    
    imm32_counter = Counter()
    imm64_counter = Counter()
    
    scan_limit2 = min(file_size, 0x100000)
    try:
        for insn in md3.disasm(data[:scan_limit2], 0):
            if insn.operands:
                for op in insn.operands:
                    if op.type == 2:  # X86_OP_IMM
                        if op.size <= 4:
                            imm32_counter[op.imm] += 1
                        else:
                            imm64_counter[op.imm] += 1
    except Exception as e:
        out(f"Disassembly error partway through: {e}")
    
    out("Top 30 immediate constants (32-bit):")
    out(f"{'Rank':>4}  {'Value':>22}  {'Hex':>18}  {'Count'}")
    for rank, (val, count) in enumerate(imm32_counter.most_common(30), 1):
        if val < 0:
            hex_str = f"-0x{-val:X}"
        else:
            hex_str = f"0x{val:X}"
        out(f"  {rank:2d}.  {val:22d}  {hex_str:>18}  {count}")
    out()
    
    out("Top 20 immediate constants (64-bit):")
    for rank, (val, count) in enumerate(imm64_counter.most_common(20), 1):
        if val < 0:
            hex_str = f"-0x{-val:X}"
        else:
            hex_str = f"0x{val:X}"
        out(f"  {rank:2d}.  {val:22d}  {hex_str:>18}  {count}")
else:
    out("Skipped (capstone not available)")
out()

# ============================================================
# 9. Pattern signature extraction
# ============================================================
out("=" * 80)
out("9. PATTERN SIGNATURE EXTRACTION")
out("=" * 80)
out()

# Find all unique byte sequences (length 8-64) that appear multiple times
# These can be used as AOB signatures
MIN_SIG_LEN = 8
MAX_SIG_LEN = 48

# For speed, only sample interesting patterns
# Find sequences starting with common instruction prefixes
sig_prefixes = [
    b'\x48\x8D',  # LEA
    b'\x48\x8B',  # MOV reg, [mem]
    b'\x48\x89',  # MOV [mem], reg
    b'\x48\x83',  # ADD/SUB/CMP reg, imm
    b'\x48\x81',  # ADD/SUB/CMP reg, imm32
    b'\xE8',      # CALL
    b'\xE9',      # JMP
    b'\xFF\x15',  # CALL [rip+disp32]
    b'\xFF\x25',  # JMP [rip+disp32]
    b'\x0F\x84',  # JE rel32
    b'\x0F\x85',  # JNE rel32
]

signatures = set()
for prefix in sig_prefixes:
    pos = 0
    while True:
        pos = data.find(prefix, pos)
        if pos < 0 or pos > file_size - MIN_SIG_LEN:
            break
        # Take up to MAX_SIG_LEN bytes
        end = min(pos + MAX_SIG_LEN, file_size)
        sig_bytes = data[pos:end]
        # Truncate at CC/CCCC (padding)
        cc_idx = sig_bytes.find(b'\xCC\xCC')
        if cc_idx > MIN_SIG_LEN:
            sig_bytes = sig_bytes[:cc_idx]
        
        if len(sig_bytes) >= MIN_SIG_LEN:
            sig_hex = sig_bytes.hex(' ').upper()
            signatures.add((sig_hex, pos, len(sig_bytes)))
        pos += 1
        if pos % 100000 == 0:
            break  # Don't search too hard

out(f"Unique signature patterns found: {len(signatures)}")
out()
out("Sample signatures (first 30):")
for sig_hex, pos, length in sorted(list(signatures), key=lambda x: x[1])[:30]:
    out(f"  0x{pos:08X} [{length:3d} bytes]: {sig_hex}")
out()

# ============================================================
# 10. Data pointer RVAs
# ============================================================
out("=" * 80)
out("10. DATA POINTER RVAs (LEA reg, [rip+disp32])")
out("=" * 80)
out()

data_pointers = []
if HAS_CAPSTONE:
    md4 = Cs(CS_ARCH_X86, CS_MODE_64)
    try:
        for insn in md4.disasm(data[:scan_limit2], 0):
            if insn.mnemonic == 'lea':
                op_str = insn.op_str
                # Match [rip + 0x...] or [rip - 0x...]
                match = re.search(r'\[rip\s*([+-])\s*(0x[0-9a-fA-F]+)\]', op_str)
                if match:
                    sign = 1 if match.group(1) == '+' else -1
                    disp = int(match.group(2), 16) * sign
                    target = insn.address + insn.size + disp
                    data_pointers.append((insn.address, target))
    except:
        pass

# Also do raw byte scan for 4C 8D / 48 8D patterns
offset = 0
raw_lea_refs = set()
while offset < file_size - 7:
    if data[offset:offset+3] in (b'\x48\x8D\x05', b'\x4C\x8D\x05',  # LEA reg, [rip+disp32]
                                   b'\x48\x8D\x0D', b'\x4C\x8D\x0D',
                                   b'\x48\x8D\x15', b'\x4C\x8D\x15',
                                   b'\x48\x8D\x1D', b'\x4C\x8D\x1D',
                                   b'\x48\x8D\x2D', b'\x4C\x8D\x2D',
                                   b'\x48\x8D\x35', b'\x4C\x8D\x35',
                                   b'\x48\x8D\x3D', b'\x4C\x8D\x3D',
                                   b'\x48\x8D\x85', b'\x48\x8D\x8D',
                                   b'\x48\x8D\x95', b'\x48\x8D\x9D',
                                   b'\x48\x8D\xA5', b'\x48\x8D\xAD',
                                   b'\x48\x8D\xB5', b'\x48\x8D\xBD'):
        disp = struct.unpack_from('<i', data, offset + 3)[0]
        target = offset + 7 + disp
        if 0 <= target < file_size:
            raw_lea_refs.add(target)
        offset += 7
    else:
        offset += 1

out(f"Data pointers from LEA [rip+disp32] in first 1MB: {len(data_pointers)}")
out(f"Total unique LEA-referenced RVAs (entire file): {len(raw_lea_refs)}")
out()
out("Sample LEA-referenced data pointers (first 30):")
for addr, target in sorted(data_pointers, key=lambda x: x[0])[:30]:
    out(f"  0x{addr:08X} -> data at RVA 0x{target:08X}")
out()

# Show what's at those addresses
out("Content at top referenced data addresses:")
for target in sorted(raw_lea_refs)[:20]:
    try:
        ctx = data[target:target+32]
        # Try as string, float, int
        as_str = ctx.decode('ascii', errors='replace').replace('\x00', '\\0')
        as_hex = ctx.hex(' ').upper()
        out(f"  RVA 0x{target:08X}: hex={as_hex}")
        out(f"                    str='{as_str}'")
    except:
        pass
out()

# ============================================================
# 11. Syscall stub analysis
# ============================================================
out("=" * 80)
out("11. SYSCALL STUB ANALYSIS")
out("=" * 80)
out()

# x64 syscall instruction: 0F 05
# Typically preceded by mov eax, SSN / mov r10, rcx / syscall
syscall_positions = []
pos = 0
while True:
    pos = data.find(b'\x0F\x05', pos)
    if pos < 0:
        break
    syscall_positions.append(pos)
    pos += 2

out(f"Syscall instructions found: {len(syscall_positions)}")
out()

# For each syscall, look backwards for the SSN setup
for i, sc_pos in enumerate(syscall_positions[:50]):
    # Look back up to 32 bytes for mov eax, imm32 (B8 xx xx xx xx)
    stub_start = max(0, sc_pos - 32)
    stub_bytes = data[stub_start:sc_pos+2]
    
    # Find SSN: mov eax, imm32 = B8 XX XX XX XX
    ssn = None
    for j in range(len(stub_bytes) - 5, -1, -1):
        if stub_bytes[j] == 0xB8:
            ssn = struct.unpack_from('<I', stub_bytes, j+1)[0]
            break
    
    out(f"  Syscall at 0x{sc_pos:08X}:")
    if ssn is not None:
        out(f"    SSN: 0x{ssn:X} ({ssn})")
    out(f"    Stub bytes: {stub_bytes.hex(' ').upper()}")
    
    # Look for nearby strings that might indicate the function
    ctx_bytes = data[max(0, sc_pos-64):min(file_size, sc_pos+64)]
    ctx_strings = extract_strings(ctx_bytes, min_len=3)
    if ctx_strings:
        out(f"    Nearby strings: {[s for _, s in ctx_strings[:3]]}")
    out()
out()

# ============================================================
# 12. Exception handler registration
# ============================================================
out("=" * 80)
out("12. EXCEPTION HANDLER REGISTRATION")
out("=" * 80)
out()

# Search for:
# - RtlAddFunctionTable references
# - Vectored Exception Handler (AddVectoredExceptionHandler)
# - SEH (SetUnhandledExceptionFilter, __C_specific_handler)

seh_keywords = [
    b'RtlAddFunctionTable',
    b'RtlInstallFunctionTableCallback',
    b'AddVectoredExceptionHandler',
    b'AddVectoredContinueHandler',
    b'RemoveVectoredExceptionHandler',
    b'SetUnhandledExceptionFilter',
    b'UnhandledExceptionFilter',
    b'RtlLookupFunctionEntry',
    b'RtlVirtualUnwind',
    b'__C_specific_handler',
    b'_C_specific_handler',
    b'__GSHandlerCheck',
    b'GSHandlerCheck',
    b'except_handler',
]

out("Exception handler references found:")
for kw in seh_keywords:
    idx = data.find(kw)
    if idx >= 0:
        out(f"  0x{idx:08X}: {kw.decode('ascii', errors='replace')}")
        # Show context
        ctx = data[idx:idx+128]
        readable = ctx.decode('ascii', errors='replace').replace('\x00', '')
        out(f"    Context: \"{readable[:80]}\"")
out()

# Also look for .pdata / .xdata section references which contain exception info
# These are common in PE files for structured exception handling

# Look for RtlAddFunctionTable call pattern
# Usually: lea rcx, [FunctionTable] / mov edx, count / mov r8d, base / call RtlAddFunctionTable
rtl_patterns = data.count(b'RtlAddFunctionTable')
out(f"\nRtlAddFunctionTable string references: {rtl_patterns}")
out()

# ============================================================
# 13. Thread-local storage (TLS)
# ============================================================
out("=" * 80)
out("13. THREAD-LOCAL STORAGE REFERENCES")
out("=" * 80)
out()

tls_keywords = [
    b'TlsAlloc', b'TlsFree', b'TlsGetValue', b'TlsSetValue',
    b'FlsAlloc', b'FlsFree', b'FlsGetValue', b'FlsSetValue',
    b'TlsCallback', b'__tls_', b'_tls_', b'FlsCallback',
    b'TLS_', b'thread_local',
]

out("TLS/FLS references found:")
for kw in tls_keywords:
    idx = data.find(kw)
    if idx >= 0:
        out(f"  0x{idx:08X}: {kw.decode('ascii', errors='replace')}")
out()

# Look for TLS callback registration patterns
# Usually: .CRT$XL* section references in data
tls_callback_refs = []
for i in range(0, file_size - 8, 8):
    val = struct.unpack_from('<Q', data, i)[0]
    # If it looks like a pointer into our .text section...
    if 0x1000 < val < file_size - 0x1000 and (val & 0xFFF) < 0x100:
        # Check if it's a valid code pointer
        if data[val] in (0x48, 0x55, 0x40, 0x41, 0xE9):
            tls_callback_refs.append((i, val))

out(f"\nPotential TLS callback pointers (estimated): {len(tls_callback_refs)}")
out()

# ============================================================
# 14. C++ RTTI class hierarchy
# ============================================================
out("=" * 80)
out("14. C++ RTTI COMPLETE CLASS HIERARCHY")
out("=" * 80)
out()

# RTTI type_info names in MSVC: usually start with ".?AV" (class) or ".?AU" (struct)
# Format: .?AVClassName@@
rtti_pattern = re.compile(rb'\.\?A[VU][A-Za-z0-9_@?$]+@@')
rtti_names = []
for match in re.finditer(rtti_pattern, data):
    name = match.group().decode('ascii', errors='replace')
    rtti_names.append((match.start(), name))

out(f"RTTI type_info names found: {len(rtti_names)}")
out()

# Decode MSVC name mangling
def demangle_msvc(name):
    """Basic MSVC name demangling."""
    if name.startswith('.?AV'):
        prefix = 'class '
        rest = name[4:]
    elif name.startswith('.?AU'):
        prefix = 'struct '
        rest = name[4:]
    elif name.startswith('.?AW'):
        prefix = 'enum '
        rest = name[4:]
    else:
        return name
    
    # Remove trailing @@
    if rest.endswith('@@'):
        rest = rest[:-2]
    
    # Replace @ with ::
    parts = rest.split('@')
    result = []
    for part in parts:
        if not part:
            continue
        # Handle template markers
        if part.startswith('?'):
            # ?$ = template
            part = part[2:] if part[1] == '$' else part
        result.append(part)
    
    return prefix + '::'.join(result)

# Group by class
class_hierarchy = defaultdict(list)
for off, name in rtti_names:
    demangled = demangle_msvc(name)
    class_hierarchy[demangled].append(off)

out("Class hierarchy:")
for class_name in sorted(class_hierarchy.keys())[:100]:
    occurrences = class_hierarchy[class_name]
    out(f"  {class_name}: {len(occurrences)} occurrence(s) at {[f'0x{o:X}' for o in occurrences[:3]]}")
if len(class_hierarchy) > 100:
    out(f"  ... and {len(class_hierarchy) - 100} more classes")
out()

# ============================================================
# 15. Armor passive names enumeration
# ============================================================
out("=" * 80)
out("15. ARMOR PASSIVE NAMES ENUMERATION")
out("=" * 80)
out()

# Look for strings related to armor passives
armor_patterns = [
    'armor', 'Armor', 'passive', 'Passive', 'heavy', 'medium', 'light',
    'fortified', 'extra_padding', 'scout', 'engineering_kit', 'med_kit',
    'grenade', 'servo-assisted', 'democracy_protects', 'peak_physique',
    'explosive', 'recoil', 'throw', 'limb', 'health', 'stamina',
    'speed', 'protection', 'rating', 'defense', 'resist',
    'democracy', 'servo', 'physique', 'padded', 'electrical',
    'fire', 'gas', 'arc', 'laser', 'plasma', 'ballistic', 'explosion',
]

armor_strings = []
for off, s in real_strings:
    for pat in armor_patterns:
        if pat.lower() in s.lower():
            armor_strings.append((off, s, pat))
            break

out(f"Armor/passive related strings: {len(armor_strings)}")
for off, s, match in sorted(set(armor_strings))[:50]:
    out(f"  RVA 0x{off:08X} [{match}]: \"{s}\"")
out()

# ============================================================
# 16. Weapon stats structure analysis
# ============================================================
out("=" * 80)
out("16. WEAPON STATS STRUCTURE ANALYSIS")
out("=" * 80)
out()

weapon_patterns = [
    'weapon', 'Weapon', 'damage', 'Damage', 'fire_rate', 'recoil', 'spread',
    'magazine', 'ammo', 'reload', 'penetration', 'armor_pen', 'range',
    'velocity', 'projectile', 'explosive', 'radius', 'aoe',
    'durable', 'stagger', 'ergonomic', 'handling', 'accuracy',
    'muzzle', 'barrel', 'stock', 'scope', 'sight', 'mag',
    'liberator', 'breaker', 'punisher', 'diligence', 'defender',
    'scythe', 'jar', 'dominator', 'slugger', 'scorcher', 'plasma',
    'eruptor', 'crossbow', 'blitzer', 'torcher', 'flamethrower',
    'recoilless', 'spear', 'autocannon', 'railgun', 'quasar',
    'machine_gun', 'stalwart', 'heavy_mg', 'anti_materiel',
    'arc_thrower', 'laser_cannon', 'grenade_launcher', 'airburst',
    'eagle', 'orbital', 'sentry', 'mine', 'backpack', 'support',
    'stratagem', 'hellbomb', 'hellpod',
]

weapon_strings = []
for off, s in real_strings:
    for pat in weapon_patterns:
        if pat.lower() in s.lower():
            weapon_strings.append((off, s, pat))
            break

out(f"Weapon related strings: {len(weapon_strings)}")
for off, s, match in sorted(set(weapon_strings))[:50]:
    out(f"  RVA 0x{off:08X} [{match}]: \"{s}\"")
out()

# ============================================================
# 17. Difficulty tier mapping
# ============================================================
out("=" * 80)
out("17. DIFFICULTY TIER MAPPING")
out("=" * 80)
out()

difficulty_patterns = [
    'difficulty', 'Difficulty', 'trivial', 'easy', 'medium', 'hard',
    'challenging', 'extreme', 'suicide', 'impossible', 'helldive',
    'super_helldive', 'tier', 'level', 'mission_difficulty',
    'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'd10',
    'diff_', 'mission_tier',
]

diff_strings = []
for off, s in real_strings:
    for pat in difficulty_patterns:
        if pat.lower() in s.lower():
            diff_strings.append((off, s, pat))
            break

out(f"Difficulty related strings: {len(diff_strings)}")
for off, s, match in sorted(set(diff_strings))[:50]:
    out(f"  RVA 0x{off:08X} [{match}]: \"{s}\"")
out()

# ============================================================
# 18. SC Farming state machine
# ============================================================
out("=" * 80)
out("18. SC FARMING STATE MACHINE")
out("=" * 80)
out()

# Look for state machine related strings
sc_patterns = [
    'sc_', 'SC_', 'farming', 'farm', 'state', 'State', 'transition',
    'idle', 'running', 'waiting', 'collecting', 'extracting',
    'mission', 'objective', 'complete', 'failed', 'return',
    'super_credit', 'medal', 'sample', 'requisition',
    'warbond', 'credit', 'farm_', 'auto',
]

sc_strings = []
for off, s in real_strings:
    for pat in sc_patterns:
        if pat.lower() in s.lower():
            sc_strings.append((off, s, pat))
            break

out(f"SC/Farming/State related strings: {len(sc_strings)}")
for off, s, match in sorted(set(sc_strings))[:80]:
    out(f"  RVA 0x{off:08X} [{match}]: \"{s}\"")
out()

# ============================================================
# 19. Network request format
# ============================================================
out("=" * 80)
out("19. NETWORK REQUEST FORMAT")
out("=" * 80)
out()

network_patterns = [
    'http', 'HTTP', 'https', 'HTTPS', 'json', 'JSON', 'api', 'API',
    'url', 'URL', 'request', 'Request', 'response', 'Response',
    'GET', 'POST', 'PUT', 'DELETE', 'header', 'body', 'cookie',
    'token', 'auth', 'bearer', 'endpoint', 'curl', 'fetch',
    'user-agent', 'content-type', 'application/json',
    'steam', 'galaxy', 'psn', 'xbox', 'platform',
    'login', 'logout', 'session', 'lobby',
]

net_strings = []
for off, s in real_strings:
    for pat in network_patterns:
        if pat.lower() in s.lower():
            net_strings.append((off, s, pat))
            break

out(f"Network/API related strings: {len(net_strings)}")
for off, s, match in sorted(set(net_strings))[:80]:
    out(f"  RVA 0x{off:08X} [{match}]: \"{s}\"")
out()

# ============================================================
# 20. Authentication protocol
# ============================================================
out("=" * 80)
out("20. AUTHENTICATION PROTOCOL FLOW")
out("=" * 80)
out()

auth_patterns = [
    'login', 'Login', 'authenticate', 'validate', 'subscription',
    'license', 'entitlement', 'steam_id', 'session', 'jwt',
    'oauth', 'password', 'username', 'credential', 'challenge',
    'token', 'refresh', 'sign_in', 'sign_out', 'logged',
    'premium', 'vip', 'banned', 'suspended', 'active_sub',
    'verify', 'bypass', 'offline', 'online', 'connect',
    'authenticated', 'unauthenticated',
]

auth_strings = []
for off, s in real_strings:
    for pat in auth_patterns:
        if pat.lower() in s.lower():
            auth_strings.append((off, s, pat))
            break

out(f"Authentication related strings: {len(auth_strings)}")
for off, s, match in sorted(set(auth_strings))[:80]:
    out(f"  RVA 0x{off:08X} [{match}]: \"{s}\"")
out()

# ============================================================
# 21. Dear ImGui version fingerprinting
# ============================================================
out("=" * 80)
out("21. DEAR IMGUI VERSION FINGERPRINTING")
out("=" * 80)
out()

imgui_patterns = [
    'ImGui', 'imgui', 'Dear ImGui', 'dear imgui', 'ImGui_', 'ig',
    'Begin', 'End', 'Button', 'Checkbox', 'SliderFloat', 'SliderInt',
    'Combo', 'ListBox', 'InputText', 'InputFloat', 'InputInt',
    'TreeNode', 'CollapsingHeader', 'TabBar', 'TabItem', 'MenuItem',
    'PlotLines', 'PlotHistogram', 'ProgressBar', 'ColorEdit',
    'ColorPicker', 'DragFloat', 'DragInt', 'Selectable', 'Tooltip',
    'PopUp', 'BeginPopup', 'EndPopup', 'Separator', 'SameLine',
    'NewLine', 'Spacing', 'Dummy', 'Text', 'TextColored', 'TextDisabled',
    'TextWrapped', 'LabelText', 'BulletText',
    'GetVersion', 'GetIO', 'GetStyle', 'GetDrawData',
    'ImGuiWindowFlags', 'ImGuiInputTextFlags', 'ImGuiCol', 'ImGuiCond',
    'ImGuiStyleVar', 'ImGuiDir', 'ImDrawList', 'ImVec2', 'ImVec4',
    'PushStyleColor', 'PopStyleColor', 'PushStyleVar', 'PopStyleVar',
    'SetNextWindowPos', 'SetNextWindowSize', 'SetNextWindowCollapsed',
    'ImGui::', 'GetKeyIndex', 'IsKeyDown', 'IsMouseClicked',
    'GetMousePos', 'GetCursorPos', 'SetCursorPos', 'GetContentRegionAvail',
    'BeginChild', 'EndChild', 'GetWindowWidth', 'GetWindowHeight',
    'IsItemHovered', 'IsItemClicked', 'IsItemActive', 'IsItemFocused',
    'SetTooltip', 'BeginTooltip', 'EndTooltip',
    'Table', 'BeginTable', 'EndTable', 'TableNextRow', 'TableSetColumnIndex',
    'TableHeadersRow', 'TableSetupColumn', 'ImGuiTableFlags',
    # Version-specific API
    'DockSpace', 'BeginDock', 'EndDock',  # docking branch
    'MultiViewport', 'GetMainViewport',  # viewport branch
    'Shortcut', 'SetShortcutRouting',  # 1.87+
    'DebugCheckVersionAndDataLayout',  # version check
]

imgui_strings = []
imgui_found_apis = set()
for off, s in real_strings:
    for pat in imgui_patterns:
        if pat.lower() in s.lower():
            imgui_strings.append((off, s, pat))
            # Extract API names
            for m in re.finditer(r'ImGui::(\w+)', s):
                imgui_found_apis.add(m.group(1))
            for m in re.finditer(r'(?:^|[^a-zA-Z])ig(\w+)', s):
                if len(m.group(1)) > 3:
                    imgui_found_apis.add(f'ig{m.group(1)}')
            break

# Also look for ImGui version string
ver_match = re.search(rb'(\d+\.\d+\.?\d*)\s*[Ww]\w+\s*\(Dear ImGui', data)
if not ver_match:
    ver_match = re.search(rb'Dear ImGui.*?(\d+\.\d+\.?\d*)', data)
if not ver_match:
    ver_match = re.search(rb'imgui[_\s]*(\d+\.\d+\.?\d*)', data)

out(f"Dear ImGui related strings: {len(imgui_strings)}")
if ver_match:
    out(f"Version string detected: {ver_match.group(0)}")
out(f"API functions detected: {len(imgui_found_apis)}")
if imgui_found_apis:
    out(f"Sample APIs: {sorted(list(imgui_found_apis))[:30]}")

# Version heuristics
if 'DockSpace' in str(imgui_found_apis) or 'BeginDock' in str(imgui_found_apis):
    out("  -> Detected Docking branch features")
if 'MultiViewport' in str(imgui_found_apis) or 'GetMainViewport' in str(imgui_found_apis):
    out("  -> Detected Viewport branch features")
if 'Shortcut' in str(imgui_found_apis):
    out("  -> Detected ImGui >= 1.87 (Shortcut API)")

for off, s, match in sorted(set(imgui_strings))[:30]:
    out(f"  RVA 0x{off:08X} [{match}]: \"{s}\"")
out()

# ============================================================
# 22. Compiler optimization evidence
# ============================================================
out("=" * 80)
out("22. COMPILER OPTIMIZATION EVIDENCE")
out("=" * 80)
out()

# Detect compiler characteristics
# MSVC vs GCC vs Clang
msvc_markers = [b'Microsoft', b'MSVC', b'RTC_', b'_RTC_', b'__security_cookie',
                b'GSHandlerCheck', b'_chkstk', b'__std_seh_', b'_except_handler',
                b'__CxxFrameHandler', b'__RTTI', b'_purecall']
gcc_markers = [b'GCC:', b'GNU C', b'__stack_chk', b'__gcov_']
clang_markers = [b'clang', b'LLVM', b'__ubsan_']

msvc_score = sum(1 for m in msvc_markers if m in data)
gcc_score = sum(1 for m in gcc_markers if m in data)
clang_score = sum(1 for m in clang_markers if m in data)

out(f"Compiler detection scores: MSVC={msvc_score}, GCC={gcc_score}, Clang={clang_score}")
if msvc_score > gcc_score and msvc_score > clang_score:
    out("  -> Likely compiled with MSVC")
elif gcc_score > msvc_score:
    out("  -> Likely compiled with GCC")
elif clang_score > msvc_score:
    out("  -> Likely compiled with Clang")

# Inline function evidence
# Common patterns: same code sequences appearing identically
inline_evidence = 0
seen_chunks = set()
for i in range(0, min(file_size, 0x80000) - 16, 1):
    chunk = data[i:i+16]
    if chunk in seen_chunks and chunk.count(0xCC) < 2:
        inline_evidence += 1
    seen_chunks.add(chunk)
    if len(seen_chunks) > 500000:
        break

out(f"Inline function candidates (repeated 16-byte sequences): {inline_evidence}")

# Tail call evidence
tail_calls = 0
i = 0
while i < file_size - 3:
    # JMP [rip+...] immediately after a CALL = tail call thunk
    if data[i] == 0xE9:  # JMP rel32
        tail_calls += 1
        i += 5
    # JMP reg (e.g., jmp rax) used for tail calls
    elif data[i:i+2] in (b'\xFF\xE0', b'\xFF\xE1', b'\xFF\xE2', b'\xFF\xE3',
                           b'\xFF\xE4', b'\xFF\xE5', b'\xFF\xE6', b'\xFF\xE7'):
        tail_calls += 1
        i += 2
    else:
        i += 1

out(f"Potential tail call sites (JMP endings): {tail_calls}")

# Loop unrolling evidence: repeated patterns of similar instructions
# Search for 3+ repeated instruction groups
loop_unroll = 0
if HAS_CAPSTONE:
    md5 = Cs(CS_ARCH_X86, CS_MODE_64)
    prev_mnems = []
    try:
        for insn in md5.disasm(data[:min(file_size, 0x80000)], 0):
            prev_mnems.append(insn.mnemonic)
            if len(prev_mnems) > 5:
                prev_mnems.pop(0)
            if len(prev_mnems) >= 3:
                # Check if last N ops match
                if (prev_mnems[-3] == prev_mnems[-2] == prev_mnems[-1] and
                    prev_mnems[-1] not in ('nop', 'int3', 'ret')):
                    loop_unroll += 1
    except:
        pass

out(f"Loop unrolling evidence (repeated instruction triples): {loop_unroll}")
out()

# ============================================================
# 23. Anti-debugging checks
# ============================================================
out("=" * 80)
out("23. ANTI-DEBUGGING CHECKS")
out("=" * 80)
out()

anti_debug_patterns = [
    b'IsDebuggerPresent',
    b'CheckRemoteDebuggerPresent',
    b'NtQueryInformationProcess',
    b'DbgBreakPoint',
    b'DebugBreak',
    b'OutputDebugString',
    b'GetTickCount',   # timing checks
    b'QueryPerformanceCounter',
    b'RDTSC',          # 0F 31
    b'ZwQueryInformationProcess',
    b'NtSetInformationThread',  # ThreadHideFromDebugger
    b'DebugActiveProcess',
    b'SetInformationThread',
    b'ProcessDebugPort',
    b'DebugPort',
    b'BeingDebugged',
    b'NtGlobalFlag',
    b'PEB',            # Process Environment Block
    b'HeapFlags',
    b'ForceFlags',
    b'anti_debug',
    b'AntiDebug',
    b'is_debugger',
    b'debugger_present',
    b'check_debug',
]

out("Anti-debugging evidence:")
for pat in anti_debug_patterns:
    count = data.count(pat)
    if count > 0:
        out(f"  Found: \"{pat.decode('ascii', errors='replace')}\" ({count} occurrences)")
out()

# Check for RDTSC (0F 31) used in timing checks
rdtsc_locations = []
pos = 0
while True:
    pos = data.find(b'\x0F\x31', pos)
    if pos < 0:
        break
    rdtsc_locations.append(pos)
    pos += 2

if rdtsc_locations:
    out(f"RDTSC instructions found: {len(rdtsc_locations)} at {[f'0x{l:X}' for l in rdtsc_locations[:10]]}")
out()

# ============================================================
# 24. Functional map
# ============================================================
out("=" * 80)
out("24. FUNCTIONAL MAP")
out("=" * 80)
out()

# Group strings by feature to build a functional map
features = {}
feature_patterns = {
    "GUI/Rendering": ['imgui', 'render', 'draw', 'd3d', 'directx', 'opengl', 'vulkan', 'window', 'viewport'],
    "Input Handling": ['keyboard', 'mouse', 'input', 'hotkey', 'keybind', 'vk_', 'VK_', 'getasynckeystate'],
    "Memory/Hooking": ['hook', 'detour', 'patch', 'virtualprotect', 'nop', 'jmp_hook', 'trampoline', 'minhook', 'detours'],
    "Scanner/AOB": ['scan', 'pattern', 'signature', 'aob', 'array_of_bytes', 'find_pattern'],
    "Network/API": ['http', 'api', 'request', 'response', 'curl', 'fetch', 'post', 'get'],
    "Steam Integration": ['steam', 'steamworks', 'ISteam', 'steam_api'],
    "Game Functions": ['player', 'enemy', 'mission', 'weapon', 'armor', 'damage', 'health', 'ammo', 'resource'],
    "Farming/SC": ['sc_', 'super_credit', 'farm', 'collect', 'auto_collect'],
    "Overlay": ['overlay', 'dxgi', 'swapchain', 'present', 'resize_buffers'],
    "Threading": ['thread', 'mutex', 'semaphore', 'critical_section', 'createthread'],
    "Config/Settings": ['config', 'settings', 'save', 'load', 'json', 'ini', 'toml'],
    "Logging": ['log', 'debug', 'trace', 'verbose', 'printf', 'outputdebugstring'],
    "Injection/Loader": ['inject', 'loader', 'dll_main', 'attach', 'detach', 'dllentry'],
    "Encryption/Protection": ['encrypt', 'decrypt', 'xor', 'base64', 'hash', 'obfuscate'],
}

for feature, patterns in feature_patterns.items():
    related_strings = []
    for off, s in real_strings:
        for pat in patterns:
            if pat.lower() in s.lower():
                related_strings.append((off, s))
                break
    if related_strings:
        features[feature] = related_strings

out("Feature map (strings per feature):")
for feature, strings in sorted(features.items()):
    out(f"\n  [{feature}] - {len(strings)} related strings:")
    for off, s in strings[:10]:
        out(f"    RVA 0x{off:08X}: \"{s}\"")
    if len(strings) > 10:
        out(f"    ... and {len(strings)-10} more")
out()

# ============================================================
# 25. Summary statistics
# ============================================================
out("=" * 80)
out("25. SUMMARY STATISTICS")
out("=" * 80)
out()

out(f"File path:            {BIN_PATH}")
out(f"File size:            {file_size} bytes ({file_size/1024:.1f} KB, {file_size/1024/1024:.2f} MB)")
out(f"MD5:                  {md5_full}")
out(f"SHA256:               {sha256_full}")
out(f"Executable format:    x86-64 PE .text section (unpacked)")
out()

out(f"Total pages (4KB):    {len(entropy_pages)}")
ent_vals = [e for _, e, _ in entropy_pages]
out(f"Avg entropy:          {sum(ent_vals)/len(ent_vals):.4f}")
out(f"Max entropy:          {max(ent_vals):.4f}")
out(f"Min entropy:          {min(ent_vals):.4f}")
out(f"High entropy (>7.0):  {high_ent} pages")
out()

out(f"Total ASCII strings:  {len(all_strings)}")
out(f"Real strings:         {len(real_strings)}")
out(f"RTTI classes:         {len(rtti_names)}")
out(f"Syscall instructions: {len(syscall_positions)}")
out(f"Import stubs:         {len(import_stubs)}")
out(f"Unique data pointers: {len(raw_lea_refs)}")
out()

out(f"Distinct byte values: {len(byte_counter)}")
top_byte = byte_counter.most_common(1)[0]
out(f"Most common byte:     0x{top_byte[0]:02X} ({top_byte[1]} occurrences, {top_byte[1]/file_size*100:.2f}%)")
out()

# Byte distribution summary
zero_count = data.count(0)
cc_count = data.count(0xCC)
ff_count = data.count(0xFF)
out(f"Zero bytes (0x00):    {zero_count} ({zero_count/file_size*100:.2f}%)")
out(f"INT3 bytes (0xCC):    {cc_count} ({cc_count/file_size*100:.2f}%)")
out(f"OxFF bytes (0xFF):    {ff_count} ({ff_count/file_size*100:.2f}%)")
out()

out(f"Compiler:             MSVC (score {msvc_score})" if msvc_score > max(gcc_score, clang_score) else 
    f"GCC (score {gcc_score})" if gcc_score > msvc_score else
    f"Clang (score {clang_score})" if clang_score > msvc_score else "Unknown")
out()

if HAS_CAPSTONE:
    out(f"Capstone version:     Available (x86-64)")
else:
    out(f"Capstone version:     NOT AVAILABLE")
out()

out("=" * 80)
out("END OF REPORT")
out("=" * 80)

flush()
print("Done!")
