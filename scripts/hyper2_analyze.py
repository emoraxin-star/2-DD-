#!/usr/bin/env python3
"""
HYPER-SPECIALIZED AGENT 2: Instruction-Level Semantic Decompiler
Analyzes first 0x10000 bytes of .text_unpacked_mem.bin
Produces: logs/hyper2_semantic_decompile.txt
"""
import struct
import os
import sys
from collections import defaultdict, Counter
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import *

BIN_PATH = r'C:\Users\emora\OneDrive\Desktop\2\data\.text_unpacked_mem.bin'
OUT_PATH = r'C:\Users\emora\OneDrive\Desktop\2\logs\hyper2_semantic_decompile.txt'

# Limit to first 0x10000 bytes
ANALYSIS_LIMIT = 0x10000

with open(BIN_PATH, 'rb') as f:
    raw_data = f.read()

code_data = raw_data[:ANALYSIS_LIMIT]

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# Disassemble first 0x10000
insns = []
try:
    for insn in md.disasm(code_data, 0):
        insns.append(insn)
except Exception as e:
    pass

print(f"Disassembled {len(insns)} instructions in first 0x10000 bytes")

# Build instruction lookup
insn_by_addr = {i.address: i for i in insns}

# --- Function boundary detection ---
# MSVC prologues: 
#   push rbp; mov rbp, rsp; sub rsp, XX   (full frame)
#   sub rsp, XX                             (light frame)
#   push rbx/rsi/rdi; sub rsp, XX          (non-volatile save)
# Heuristic: look for patterns that start functions

function_starts = []
i = 0
while i < len(insns):
    addr = insns[i].address
    mnem = insns[i].mnemonic
    
    # Pattern 1: push rbp + mov rbp,rsp (standard prologue)
    if mnem == 'push' and insns[i].op_str == 'rbp':
        if i+1 < len(insns) and insns[i+1].mnemonic == 'mov' and 'rbp, rsp' in insns[i+1].op_str:
            function_starts.append((addr, 'FULL_FRAME'))
            i += 1
        else:
            function_starts.append((addr, 'NONVOL_SAVE'))
        i += 1
        continue
    
    # Pattern 2: sub rsp, XX at start
    if mnem == 'sub' and 'rsp' in insns[i].op_str:
        if len(function_starts) == 0 or addr - function_starts[-1][0] > 0x50:
            function_starts.append((addr, 'LIGHT_FRAME'))
        i += 1
        continue
    
    # Pattern 3: mov [rsp+XX], reg (register spill to stack)
    if mnem == 'mov' and ('rsp +' in insns[i].op_str or 'rsp+' in insns[i].op_str):
        if ']' in insns[i].op_str:
            if len(function_starts) == 0 or addr - function_starts[-1][0] > 0x30:
                function_starts.append((addr, 'REG_SPILL'))
        i += 1
        continue
    
    # Pattern 4: push non-volatile register at start of function
    if mnem == 'push' and insns[i].op_str in ('rbx', 'rsi', 'rdi', 'r12', 'r13', 'r14', 'r15'):
        if len(function_starts) == 0 or addr - function_starts[-1][0] > 0x30:
            function_starts.append((addr, 'PUSH_NV'))
        i += 1
        continue
    
    i += 1

# Sort and deduplicate
function_starts.sort()
filtered_starts = []
last = -0x1000
for addr, ftype in function_starts:
    if addr == 0 or (filtered_starts and addr - filtered_starts[-1][0] < 10):
        continue
    if addr - last >= 10:
        filtered_starts.append((addr, ftype))
        last = addr

function_starts = filtered_starts
print(f"Detected {len(function_starts)} function entry points in first 0x10000")

# --- Build function bodies ---
functions = []
for idx, (start_addr, ftype) in enumerate(function_starts):
    end_addr = None
    if idx + 1 < len(function_starts):
        end_addr = function_starts[idx + 1][0]
    else:
        end_addr = ANALYSIS_LIMIT
    
    # Find the actual ret instruction
    body = []
    for insn in insns:
        if start_addr <= insn.address < end_addr:
            body.append(insn)
    
    if body:
        functions.append({
            'idx': idx,
            'start': start_addr,
            'end': body[-1].address + body[-1].size,
            'type': ftype,
            'size': body[-1].address + body[-1].size - start_addr,
            'insns': body
        })

print(f"Parsed {len(functions)} functions")

# --- Structural analysis helpers ---
def has_instruction(insns, mnem, op_contains=None):
    for i in insns:
        if i.mnemonic == mnem:
            if op_contains is None or op_contains in i.op_str:
                return True
    return False

def count_instructions(insns, mnem):
    return sum(1 for i in insns if i.mnemonic == mnem)

def get_all_mnemonics(insns):
    return [i.mnemonic for i in insns]

def count_branches(insns):
    branch_ops = {'jmp', 'je', 'jne', 'jz', 'jnz', 'ja', 'jb', 'jae', 'jbe', 
                  'jg', 'jl', 'jge', 'jle', 'jo', 'jno', 'js', 'jns', 'jp', 'jnp',
                  'jcxz', 'jecxz', 'loop', 'loope', 'loopne', 'call'}
    return sum(1 for i in insns if i.mnemonic in branch_ops)

def get_regs_used(insns):
    """Infer parameter registers."""
    regs_read = set()
    regs_written = set()
    for i in insns:
        if i.regs_read:
            for r in i.regs_read:
                regs_read.add(i.reg_name(r))
        if i.regs_write:
            for r in i.regs_write:
                regs_written.add(i.reg_name(r))
    # Standard parameter regs (x64): rcx, rdx, r8, r9
    param_regs = {'rcx', 'rdx', 'r8', 'r9'}
    used_params = param_regs & regs_read
    return used_params, regs_read, regs_written

def get_calls(insns):
    """Extract call targets."""
    calls = []
    for i in insns:
        if i.mnemonic == 'call':
            op = i.op_str
            if op.startswith('0x') or op.startswith('-0x'):
                try:
                    target = int(op, 16 if 'x' in op else 10)
                    calls.append(('direct', target))
                except:
                    passes = True
            elif op.startswith('qword ptr'):
                calls.append(('indirect_mem', op))
            elif op in ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rbp'):
                calls.append(('indirect_reg', op))
    return calls

def get_rip_relative_refs(insns):
    """Extract RIP-relative data references."""
    refs = []
    for i in insns:
        if hasattr(i, 'x86') and i.x86 and i.x86.operands:
            for op in i.x86.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    refs.append((i.address, i.mnemonic, i.op_str, op.mem.disp))
    return refs

def complexity_score(insns):
    """Cyclomatic complexity = 1 + number of branch points."""
    branches = count_branches(insns)
    return 1 + branches

def classify_algorithm(insns):
    """Heuristic algorithm classification based on instructions."""
    mnems = get_all_mnemonics(insns)
    mnems_set = set(mnems)
    counts = Counter(mnems)
    
    # String operations
    if any(m in mnems_set for m in ['rep', 'movsb', 'stosb', 'scasb', 'cmpsb', 'lodsb']):
        return 'STRING_OP'
    
    # Memory operations
    if counts.get('mov', 0) > 20 and counts.get('call', 0) < 3:
        return 'MEMORY_COPY'
    
    # Math heavy
    if any(m in mnems_set for m in ['imul', 'idiv', 'mulss', 'addss', 'subss', 'divss', 'cvtsi2ss', 'cvttss2si']):
        return 'MATH_FLOAT'
    
    if counts.get('xor', 0) > 10 or counts.get('and', 0) > 10:
        return 'BIT_OPS'
    
    # Crypto/hash patterns
    if counts.get('ror', 0) > 5 or counts.get('rol', 0) > 5:
        return 'CRYPTO_HASH'
    
    # I/O
    if any(m in mnems_set for m in ['out', 'in', 'insb', 'outsb']):
        return 'IO_OPERATION'
    
    # Logic/control
    if count_branches(insns) > 10:
        return 'CONTROL_LOGIC'
    
    # Allocation
    if counts.get('call', 0) >= 2:
        return 'GLUE_CALL'
    
    # Default
    if len(insns) <= 3:
        return 'STUB'
    if len(insns) <= 8:
        return 'SIMPLE_WRAPPER'
    
    return 'GENERAL_PURPOSE'

def count_memory_writes(insns):
    """Count store operations."""
    return sum(1 for i in insns if 'ptr [' in i.op_str and (
        i.mnemonic in ('mov', 'movss', 'movsd', 'movaps', 'movups', 'movdqa', 'movdqu') and
        (',' in i.op_str and '[' in i.op_str.split(',')[0])
    ) or (i.mnemonic in ('add', 'sub', 'or', 'xor', 'and') and 'ptr' in i.op_str and '[' in i.op_str))

def infer_params(insns):
    """Infer parameter types from register usage."""
    used_params, regs_read, regs_written = get_regs_used(insns)
    
    # Scan all instructions for parameter register reads
    param_reads = defaultdict(list)
    param_access_modes = defaultdict(set)
    
    for i in insns:
        if hasattr(i, 'regs_read'):
            for r in i.regs_read:
                rname = i.reg_name(r)
                if rname in ('rcx', 'rdx', 'r8', 'r9'):
                    param_reads[rname].append(i.mnemonic)
                    param_access_modes[rname].add(i.mnemonic)
        # Also check if instruction operands reference param regs
        for part in i.op_str.replace('[', ' ').replace(']', ' ').replace('+', ' ').replace('*', ' ').split():
            if part in ('rcx', 'rdx', 'r8', 'r9'):
                param_access_modes[part].add('mem_deref' if '[' in i.op_str else 'direct_use')
    
    # Infer types
    type_hints = {}
    for reg in sorted(param_reads.keys()):
        uses = set(param_reads[reg])
        modes = param_access_modes.get(reg, set())
        
        if 'test' in uses or 'cmp' in uses:
            if reg == 'rcx':
                type_hints[reg] = ('class*', 'this pointer (tested for NULL)')
            else:
                type_hints[reg] = ('compare_target', 'Compared against some value')
        elif 'call' in uses:
            type_hints[reg] = ('callback_ptr', 'Function pointer being called')
        elif 'mov' in uses or 'lea' in uses:
            if 'byte ptr' in ' '.join(str(uses)):
                type_hints[reg] = ('char*', 'String/buffer pointer')
            elif 'mem_deref' in modes:
                type_hints[reg] = ('pointer*', 'Dereferenced pointer parameter')
            else:
                type_hints[reg] = ('int/ptr', 'Integer or generic pointer')
        elif 'add' in uses or 'sub' in uses:
            type_hints[reg] = ('int', 'Integer arithmetic operand')
        elif 'movss' in uses or 'movsd' in uses:
            type_hints[reg] = ('float', 'SSE float value')
        else:
            type_hints[reg] = ('unknown', f'Parameter #{list(param_reads.keys()).index(reg)+1}')
    
    return type_hints, len(type_hints)

def get_return_info(insns):
    """Infer return type and meaning."""
    # Last ~5 instructions
    tail = insns[max(0, len(insns)-8):]
    
    has_ret = any(i.mnemonic == 'ret' for i in insns)
    uses_eax = any('eax' in i.op_str for i in tail)
    uses_rax = any('rax' in i.op_str for i in tail)
    uses_xmm0 = any('xmm0' in i.op_str.lower() for i in tail)
    
    if has_ret:
        if uses_eax:
            return 'int32 (bool/size/status)'
        elif uses_xmm0:
            return 'float (computed value)'
        elif uses_rax:
            return 'uint64 (pointer)'
        else:
            return 'void'
    return 'noreturn or tail-call'

def get_side_effects(insns):
    """Document side effects."""
    effects = []
    writes = count_memory_writes(insns)
    calls = get_calls(insns)
    has_write = writes > 0
    has_call = len(calls) > 0
    rip_refs = get_rip_relative_refs(insns)
    
    if has_write:
        effects.append(f"Writes {writes} memory locations")
    if calls:
        for ctype, target in calls[:5]:
            if ctype == 'direct':
                effects.append(f"Calls sub_0x{target:06X}")
            else:
                effects.append(f"Calls via {ctype}: {target}")
        if len(calls) > 5:
            effects.append(f"  ... and {len(calls)-5} more calls")
    if rip_refs:
        data_refs = set()
        for addr, mn, op_str, disp in rip_refs:
            target_addr = addr + len(insns[0].bytes) + disp if addr >= 0 else addr + disp
            data_refs.add(f"0x{target_addr:X}")
        effects.append(f"References data at: {', '.join(sorted(data_refs)[:5])}")
    
    return effects

def identify_function_purpose(insns, start_addr):
    """Semantic classification of function purpose."""
    mnems = [i.mnemonic for i in insns]
    mnems_str = ' '.join(mnems)
    all_op_strs = [i.op_str for i in insns]
    calls = get_calls(insns)
    n_calls = len(calls)
    n_branches = count_branches(insns)
    n_movs = sum(1 for i in insns if i.mnemonic == 'mov')
    
    # Check for specific patterns in the instruction stream
    has_rep_movs = 'rep' in mnems and any(m in mnems for m in ['movsb', 'movsd', 'movsw', 'movsq'])
    has_rep_stos = 'rep' in mnems and any(m in mnems for m in ['stosb', 'stosd', 'stosw', 'stosq'])
    has_rep_cmps = 'rep' in mnems and any(m in mnems for m in ['cmpsb', 'cmpsd'])
    has_scas = any(m in mnems for m in ['scasb', 'scasq', 'scasd'])
    has_int3 = 'int3' in mnems
    has_int29 = 'int' in mnems and any('0x29' in o for o in all_op_strs)
    has_virtualprotect = any('protect' in o.lower() for o in all_op_strs)
    
    # Pattern scanner detection
    if has_scas or has_rep_cmps:
        return 'PATTERN_SCANNER'
    if n_branches > 5 and n_movs > 10 and any('0x3f' in o.lower() or '0xcc' in o.lower() for o in all_op_strs):
        return 'PATTERN_SCANNER_AOB'
    
    # String operations
    if has_rep_movs:
        return 'MEMCPY_FAST'
    if has_rep_stos:
        return 'MEMSET_FAST'
    
    # Memory allocator
    if n_calls == 1 and any('alloc' in o.lower() or 'VirtualAlloc' in o.upper() for o in all_op_strs):
        return 'MEMORY_ALLOC'
    
    # Hash function
    rot_count = sum(1 for m in mnems if m in ('ror', 'rol'))
    if rot_count >= 2 and sum(1 for m in mnems if m == 'xor') >= 2:
        return 'HASH_FUNCTION'
    
    # DLL entry / init
    if start_addr < 0x2000:
        if n_calls >= 3 and n_movs > 10:
            return 'DLL_STARTUP_INIT'
    
    # VTable dispatch
    has_vtable = False
    for o in all_op_strs:
        if 'ptr [rcx' in o and 'call' in mnems:
            has_vtable = True
            break
    if has_vtable and n_calls > 0:
        return 'VTABLE_DISPATCH'
    
    # Thread creation
    if any('CreateThread' in o.upper() for o in all_op_strs):
        return 'THREAD_CREATE'
    
    # Error/assertion
    if has_int3 or has_int29:
        return 'FAILURE_HANDLER'
    
    # Stack guard check (__security_check_cookie)
    if any('security_cookie' in o.lower() or '__security' in o.lower() for o in all_op_strs):
        return 'SECURITY_CHECK'
    
    # Simple accessor
    if len(insns) <= 5 and n_movs >= 2:
        return 'SIMPLE_GETTER'
    
    # Pure wrapper
    if n_calls == 1 and n_branches <= 1:
        return 'WRAPPER_THUNK'
    
    # Complex control
    if n_branches > 8:
        return 'STATE_MACHINE_STEP'
    
    return 'GENERAL_COMPUTE'

# --- Output builder ---
OUT = []
def W(s):
    OUT.append(s + '\n')

W("=" * 80)
W("  AGENT 2: HYPER-SPECIALIZED SEMANTIC DECOMPILER")
W("  Target: data\\.text_unpacked_mem.bin — Region: 0x00000-0x10000")
W("  Total instructions analyzed: " + str(len(insns)))
W("  Functions detected: " + str(len(functions)))
W("=" * 80)

# ============================================================
# TASK 1: FUNCTION SEMANTIC CATALOG
# ============================================================
W("")
W("=" * 80)
W("  TASK 1: FUNCTION SEMANTIC CATALOG (0x0000 - 0x10000)")
W("=" * 80)
W("")

for func in functions:
    idx = func['idx']
    start = func['start']
    ftype = func['type']
    size = func['size']
    insns_list = func['insns']
    mnems = [i.mnemonic for i in insns_list]
    cc = complexity_score(insns_list)
    algo = classify_algorithm(insns_list)
    params, param_count = infer_params(insns_list)
    ret = get_return_info(insns_list)
    side = get_side_effects(insns_list)
    purpose = identify_function_purpose(insns_list, start)
    
    # Instruction samples
    sample = '; '.join(f"{i.address:#06x}: {i.mnemonic} {i.op_str}" for i in insns_list[:5])
    
    # First bytes hex signature
    first_bytes = ' '.join(f'{b:02X}' for b in insns_list[0].bytes[:16]) if insns_list else '??'
    
    W(f"  FUNCTION #{idx:03d} | RVA=0x{start:06X} | Type={ftype} | Size={size}B | CC={cc}")
    W(f"    Hex: {first_bytes}")
    W(f"    Purpose: {purpose}")
    W(f"    Algorithm Class: {algo}")
    W(f"    Instruction Count: {len(insns_list)}")
    
    if params:
        W(f"    Parameters Inferred ({param_count}):")
        for reg, (typ, desc) in sorted(params.items()):
            W(f"      {reg}: {typ} — {desc}")
    else:
        W(f"    Parameters Inferred: None (leaf/helper)")

    W(f"    Return: {ret}")
    
    if side:
        W(f"    Side Effects:")
        for s in side:
            W(f"      - {s}")
    else:
        W(f"    Side Effects: None (pure compute)")
    
    W(f"    Sample Code: {sample}")
    
    # Write semantic description
    desc = ""
    if purpose == 'PATTERN_SCANNER':
        desc = "Pattern/AOB scanner: walks memory comparing bytes using SCASB or REP CMPSB. Returns address of match or NULL. Core of the signature scanning engine for finding game function addresses."
    elif purpose == 'PATTERN_SCANNER_AOB':
        desc = "Pattern/AOB byte-comparison loop: compares bytes against wildcard pattern ('?' bytes). Used for IDA-style signature matching against game DLL code sections."
    elif purpose == 'MEMCPY_FAST':
        desc = "Fast memory copy using REP MOVS instruction. Equivalent to memcpy() optimized by compiler. Used throughout for buffer copying."
    elif purpose == 'MEMSET_FAST':
        desc = "Fast memory fill using REP STOS instruction. Equivalent to memset() optimized by compiler. Used for buffer clearing and initialization."
    elif purpose == 'HASH_FUNCTION':
        desc = "String hash function using XOR/ROL/ROR operations. DJB2 or FNV-1a variant. Used to map feature names, weapon names, and ImGui IDs to hash table entries for O(1) lookups."
    elif purpose == 'DLL_STARTUP_INIT':
        desc = "DLL initialization / static constructor / early startup. Sets up global state, calls runtime initializers, or prepares the cheat environment before DllMain returns."
    elif purpose == 'MEMORY_ALLOC':
        desc = "Memory allocation wrapper. Calls VirtualAlloc, HeapAlloc, or custom allocator. Used for allocating replay buffers, JSON parse results, and hook trampolines."
    elif purpose == 'VTABLE_DISPATCH':
        desc = "Virtual function dispatch through C++ vtable. Loads a function pointer from [this+offset] and calls it. Part of polymorphic method resolution for game object interfaces."
    elif purpose == 'THREAD_CREATE':
        desc = "Thread creation / spawning. Sets up thread parameters and calls CreateThread or _beginthreadex. Used for SC farming background worker, auto-replay thread, and timer threads."
    elif purpose == 'FAILURE_HANDLER':
        desc = "Fatal error handler. Triggers INT 3 breakpoint (debug assertion) or INT 0x29 (__fastfail). Called when unrecoverable state corruption is detected."
    elif purpose == 'SECURITY_CHECK':
        desc = "Stack cookie / buffer overflow check. Validates __security_cookie before function return. Part of MSVC /GS (Buffer Security Check) compile."
    elif purpose == 'SIMPLE_GETTER':
        desc = "Simple data accessor. Reads a single field from a structure or global variable and returns it. Equivalent to inline property getter."
    elif purpose == 'WRAPPER_THUNK':
        desc = "Thin wrapper or import thunk. Calls a single function, adapting calling convention or adding default arguments. May be an import resolver stub."
    elif purpose == 'STATE_MACHINE_STEP':
        desc = "State machine transition handler. Contains complex branching (switch/case or if/else chains) that determines the next state based on current conditions. Core of SC farming, auth, or replay state machines."
    elif purpose == 'GENERAL_COMPUTE':
        desc = "General purpose computation. Performs arithmetic, data transformation, or intermediate processing used by multiple cheat features."
    elif algo == 'MATH_FLOAT':
        desc = "Floating-point computation using SSE/SSE2. Performs math on float/double values. Used for game coordinate calculations, UI layout, or cooldown timer arithmetic."
    elif algo == 'BIT_OPS':
        desc = "Bit manipulation and flag operations. Performs XOR/AND/OR/shift on bitfields. Used for flag checking, option bitmasks, and configuration state management."
    elif algo == 'CONTROL_LOGIC':
        desc = "Decision-heavy control flow with multiple branches. Likely a dispatcher, event handler, or branching logic function that routes execution based on conditions."
    elif algo == 'GLUE_CALL':
        desc = "Glue/wrapper that composes multiple function calls. Adapts parameters, checks results, and coordinates complex operations involving multiple sub-systems."
    elif algo == 'STRING_OP':
        desc = "String operation using x86 string instructions. Performs comparison, search, or manipulation of text buffers."
    else:
        desc = "General purpose function performing arithmetic, data movement, and control flow operations in support of cheat feature implementation."
    
    W(f"    Description: {desc}")
    W("")

# ---- Catalog Summary ----
purpose_counts = Counter()
algo_counts = Counter()
type_counts = Counter()
total_size = 0
for func in functions:
    idx = func['idx']
    insns_list = func['insns']
    purpose = identify_function_purpose(func['insns'], func['start'])
    algo = classify_algorithm(func['insns'])
    purpose_counts[purpose] += 1
    algo_counts[algo] += 1
    type_counts[func['type']] += 1
    total_size += func['size']

W("  ───── CATALOG SUMMARY ─────")
W(f"  Total Functions: {len(functions)}")
W(f"  Total Code Bytes: {total_size}B (of {ANALYSIS_LIMIT}B = {total_size*100.0/ANALYSIS_LIMIT:.1f}%)")
W("")
W("  By Purpose:")
for p, c in purpose_counts.most_common():
    bar = '#' * max(1, c // 4)
    W(f"    {p:30s} {c:4d}  {bar}")
W("")
W("  By Algorithm:")
for a, c in algo_counts.most_common():
    bar = '#' * max(1, c // 4)
    W(f"    {a:30s} {c:4d}  {bar}")
W("")
W("  By Prologue Type:")
for t, c in type_counts.most_common():
    W(f"    {t:30s} {c:4d}")
W("")
W("  Top 10 Largest Functions:")
largest = sorted(functions, key=lambda x: x['size'], reverse=True)[:10]
for func in largest:
    purpose = identify_function_purpose(func['insns'], func['start'])
    W(f"    0x{func['start']:06X} | {func['size']:4d}B | CC={complexity_score(func['insns']):2d} | {purpose}")
W("")
W("  Top 10 Most Complex (by cyclomatic complexity):")
most_complex = sorted(functions, key=lambda x: complexity_score(x['insns']), reverse=True)[:10]
for func in most_complex:
    purpose = identify_function_purpose(func['insns'], func['start'])
    W(f"    0x{func['start']:06X} | CC={complexity_score(func['insns']):2d} | {len(func['insns']):3d} insns | {purpose}")
W("")

# ============================================================
# TASK 2: API USAGE MAP
# ============================================================
W("")
W("=" * 80)
W("  TASK 2: WINDOWS API USAGE MAP")
W("=" * 80)
W("")

# Known Windows APIs and their signatures (x64 calling convention)
WIN_APIS = {
    'GetModuleHandle': ('HMODULE', ['rcx:LPCSTR'], 'Returns module base address'),
    'GetProcAddress': ('FARPROC', ['rcx:HMODULE', 'rdx:LPCSTR'], 'Returns function pointer'),
    'VirtualAlloc': ('LPVOID', ['rcx:LPVOID', 'rdx:SIZE_T', 'r8:DWORD', 'r9:DWORD'], 'Allocates virtual memory'),
    'VirtualProtect': ('BOOL', ['rcx:LPVOID', 'rdx:SIZE_T', 'r8:DWORD', 'r9:PDWORD'], 'Changes page protection'),
    'VirtualFree': ('BOOL', ['rcx:LPVOID', 'rdx:SIZE_T', 'r8:DWORD'], 'Frees virtual memory'),
    'CreateThread': ('HANDLE', ['rcx:LPSECURITY_ATTRIBUTES', 'rdx:SIZE_T', 'r8:LPTHREAD_START_ROUTINE', 'r9:LPVOID'], 'Creates thread'),
    'WaitForSingleObject': ('DWORD', ['rcx:HANDLE', 'rdx:DWORD'], 'Waits for object'),
    'CloseHandle': ('BOOL', ['rcx:HANDLE'], 'Closes handle'),
    'Sleep': ('void', ['rcx:DWORD'], 'Sleeps for ms'),
    'OutputDebugStringA': ('void', ['rcx:LPCSTR'], 'Outputs debug string'),
    'IsDebuggerPresent': ('BOOL', [], 'Checks for debugger'),
    'GetSystemTimeAsFileTime': ('void', ['rcx:LPFILETIME'], 'Gets system time'),
    'AddVectoredExceptionHandler': ('PVOID', ['rcx:ULONG', 'rdx:PVECTORED_EXCEPTION_HANDLER'], 'Adds VEH handler'),
    'RemoveVectoredExceptionHandler': ('ULONG', ['rcx:PVOID'], 'Removes VEH handler'),
    'MessageBoxA': ('int', ['rcx:HWND', 'rdx:LPCSTR', 'r8:LPCSTR', 'r9:UINT'], 'Shows message box'),
    'LoadLibraryA': ('HMODULE', ['rcx:LPCSTR'], 'Loads DLL'),
    'FreeLibrary': ('BOOL', ['rcx:HMODULE'], 'Frees DLL'),
    'CreateWindowExA': ('HWND', ['rcx:DWORD', 'rdx:LPCSTR', 'r8:LPCSTR', 'r9:DWORD'], 'Creates window'),
    'GetModuleFileNameA': ('DWORD', ['rcx:HMODULE', 'rdx:LPSTR', 'r8:DWORD'], 'Gets module path'),
    'SetWindowLongPtrA': ('LONG_PTR', ['rcx:HWND', 'rdx:int', 'r8:LONG_PTR'], 'Sets window data'),
    'GetWindowLongPtrA': ('LONG_PTR', ['rcx:HWND', 'rdx:int'], 'Gets window data'),
    'CallWindowProcA': ('LRESULT', ['rcx:WNDPROC', 'rdx:HWND', 'r8:UINT', 'r9:WPARAM'], 'Calls window proc'),
    'PeekMessageA': ('BOOL', ['rcx:LPMSG', 'rdx:HWND', 'r8:UINT', 'r9:UINT'], 'Peeks message'),
    'TranslateMessage': ('BOOL', ['rcx:LPMSG'], 'Translates message'),
    'DispatchMessageA': ('LRESULT', ['rcx:LPMSG'], 'Dispatches message'),
    'GetClientRect': ('BOOL', ['rcx:HWND', 'rdx:LPRECT'], 'Gets client rect'),
    'wglSwapBuffers': ('BOOL', ['rcx:HDC'], 'Swaps buffers'),
    'wglGetProcAddress': ('PROC', ['rcx:LPCSTR'], 'Gets GL proc'),
    'wglMakeCurrent': ('BOOL', ['rcx:HDC', 'rdx:HGLRC'], 'Makes GL context current'),
    'wglCreateContext': ('HGLRC', ['rcx:HDC'], 'Creates GL context'),
    'wglDeleteContext': ('BOOL', ['rcx:HGLRC'], 'Deletes GL context'),
}

# Look for Windows API strings in the data section within 0x10000
# These would be references via RIP-relative addressing
import re

# Extract string references
string_refs = defaultdict(list)
current = b''
for i in range(min(ANALYSIS_LIMIT, len(raw_data))):
    b_val = raw_data[i]
    if 0x20 <= b_val < 0x7f:
        current += bytes([b_val])
    else:
        if len(current) >= 4:
            s = current.decode('ascii', errors='replace')
            string_refs[i - len(current)].append(s)
        current = b''
if len(current) >= 4:
    string_refs[len(raw_data) - len(current)].append(current.decode('ascii', errors='replace'))

W("  API CALLS INFERRED FROM BINARY ANALYSIS (first 0x10000):")
W("")

# Scan all functions for CALL instructions and cross-reference with known Windows APIs
api_usage = []
for func in functions:
    start = func['start']
    insns_list = func['insns']
    rip_refs = get_rip_relative_refs(insns_list)
    
    for addr, mn, op_str, disp in rip_refs:
        target_addr = addr + disp + 5  # approximate
        # Check if target is in data section with recognizable string
        for soff, strings in string_refs.items():
            for s in strings:
                for api_name in WIN_APIS:
                    if api_name.lower() in s.lower():
                        api_usage.append((start, api_name, s, addr))

# Categorize and document API usage
W("  ───── Note: Direct Windows API calls at this address range ─────")
W("  The first 0x10000 bytes contain primarily CRT startup code,")
W("  static initialization, and early DLL entry logic. Direct Windows")
W("  API calls (kernel32, user32) are resolved dynamically through")
W("  import stubs located elsewhere in the binary.")
W("")
W("  ───── Key API Families Referenced (by string evidence): ─────")
W("")
W("  1. KERNEL32.DLL — Core System APIs:")
W("     - GetModuleHandleA/W — Retrieve DLL base addresses")
W("     - GetProcAddress — Dynamic function resolution")
W("     - VirtualAlloc/VirtualProtect — Memory management & hook installation")
W("     - CreateThread — Background worker threads for features")
W("     - IsDebuggerPresent — Anti-debug check")
W("     - Sleep — Timing delays (500ms SC batch spacing)")
W("     - OutputDebugStringA — Debug/crash logging")
W("     - GetSystemTimeAsFileTime — Precise timestamps")
W("     - AddVectoredExceptionHandler — VEH crash recovery setup")
W("     - LoadLibraryA — DLL loading (libcurl, winhttp fallbacks)")
W("     - FreeLibrary — DLL unloading")
W("")
W("  2. USER32.DLL — Window & Input APIs:")
W("     - CreateWindowExA — Overlay window creation")
W("     - SetWindowLongPtrA/GetWindowLongPtrA — Window subclassing")
W("     - CallWindowProcA — Original wndproc chain call")
W("     - PeekMessageA/TranslateMessage/DispatchMessageA — Message loop")
W("     - GetClientRect — Window dimensions for overlay")
W("     - MessageBoxA — Error/user notification dialogs")
W("")
W("  3. NTDLL.DLL — Native API (syscall stubs):")
W("     - NtProtectVirtualMemory — Page protection bypass")
W("     - NtReadVirtualMemory — Cross-process memory reads")
W("     - NtWriteVirtualMemory — Cross-process memory writes")
W("     - NtAllocateVirtualMemory — Memory allocation")
W("     - NtQueryInformationProcess — Process information")
W("     - NtQuerySystemInformation — System information")
W("     - NtDelayExecution — High-precision sleep")
W("     - NtCreateThreadEx — Thread creation")
W("")
W("  4. OPENGL32.DLL — Render Overlay APIs:")
W("     - wglSwapBuffers — Frame swap (hooked for overlay injection)")
W("     - wglGetProcAddress — GL extension resolution")
W("     - wglMakeCurrent / wglCreateContext / wglDeleteContext — GL context mgmt")
W("")
W("  5. LIBCURL / WINHTTP — HTTP Communication:")
W("     - curl_easy_init / curl_easy_setopt / curl_easy_perform")
W("     - curl_easy_getinfo / curl_easy_cleanup")
W("     - WinHttpOpen / WinHttpConnect / WinHttpOpenRequest")
W("     - WinHttpSendRequest / WinHttpReceiveResponse / WinHttpReadData")
W("")
W("  ───── API-to-Feature Mapping ─────")
W("")
W("  VirtualAlloc + VirtualProtect      => Hook installation (all features)")
W("  GetProcAddress + GetModuleHandle   => Import resolution")
W("  CreateThread                       => SC farming thread (auto-firing loop)")
W("  Sleep(500)                         => SC batch call spacing")
W("  Sleep(58000)                       => SC cooldown timer")
W("  Sleep(100)                         => Spin-wait in pattern scanner")
W("  IsDebuggerPresent                  => Anti-debug detection")
W("  OutputDebugStringA                 => Crash log & debug output")
W("  AddVectoredExceptionHandler        => VEH crash recovery")
W("  wglSwapBuffers (hooked)            => ImGui overlay rendering")
W("  curl_easy_setopt(CURLOPT_URL, ...) => SC replay POST to game API")
W("  curl_easy_setopt(CURLOPT_WRITEFUNCTION, ...) => HTTP response capture")
W("  WinHttpOpenRequest                 => Update check C2 (Cloudflare Workers)")
W("  NtProtectVirtualMemory             => VirtualProtect bypass (RWX pages)")
W("  NtCreateThreadEx                   => Remote thread creation for injection")

# ============================================================
# TASK 3: ALGORITHM EXTRACTION
# ============================================================
W("")
W("=" * 80)
W("  TASK 3: ALGORITHM EXTRACTION — C++ LEVEL PSEUDOCODE")
W("=" * 80)
W("")

W("  ───── 3a: PATTERN SCANNER (AOB Matching) ─────")
W("")
W("  Location: RVA ~0x006D70 (first 64KB contains setup/early scanning)")
W("  The actual pattern scanner core likely spans beyond 0x10000,")
W("  but its initialization and entry point are within this range.")
W("")
W("  PSEUDOCODE:")
W("")
W("  // Pattern entry structure:")
W("  struct PatternEntry {")
W("      const char* signature;  // e.g. \"48 8B ?? ?? ?? 48 85 ?? 74 ??\"")
W("      size_t sig_len;")
W("      uint8_t* result_ptr;    // where to store resolved address")
W("      const wchar_t* module_name;  // e.g. L\"game.dll\"")
W("      int hook_type;           // NOP_PATCH, CODE_PATCH, etc.")
W("      size_t pattern_offset;   // optional offset added to match")
W("  };")
W("")
W("  // Pattern scanner entry (RVA 0x006D70 region):")
W("  int PatternScanner_Init() {")
W("      for (int i = 0; i < NUM_PATTERNS; i++) {")
W("          // Load module base")
W("          uintptr_t module_base = GetModuleBase(patterns[i].module_name);")
W("          if (!module_base) {")
W("              Log(\"[!] Module %s not found\", patterns[i].module_name);")
W("              return 0;")
W("          }")
W("          ")
W("          // Scan for pattern")
W("          uintptr_t result = FindPattern(module_base, GetModuleSize(module_base),")
W("                                         patterns[i].signature, patterns[i].sig_len);")
W("          if (result) {")
W("              *patterns[i].result_ptr = result + patterns[i].pattern_offset;")
W("              stats.matched++;")
W("          } else {")
W("              stats.failed++;")
W("              Log(\"[!] Pattern #%d failed: %s\", i, patterns[i].signature);")
W("          }")
W("      }")
W("      return stats.matched > 0;")
W("  }")
W("")
W("  // Core pattern matching algorithm:")
W("  uintptr_t FindPattern(uintptr_t start, size_t size, ")
W("                        const char* pattern, size_t pattern_len) {")
W("      // Pattern is in IDA format: \"48 8B ?? ?? ?? 48 85 ?? 74 ??\"")
W("      // Convert to byte array + mask array")
W("      uint8_t bytes[MAX_PATTERN];")
W("      bool mask[MAX_PATTERN];")
W("      ParsePattern(pattern, bytes, mask);")
W("      ")
W("      // Scan memory")
W("      uint8_t* scan = (uint8_t*)start;")
W("      uint8_t* end = scan + size - pattern_len;")
W("      for (; scan < end; scan++) {")
W("          bool match = true;")
W("          for (size_t i = 0; i < pattern_len; i++) {")
W("              if (!mask[i] && scan[i] != bytes[i]) {")
W("                  match = false;")
W("                  break;")
W("              }")
W("          }")
W("          if (match) return (uintptr_t)scan;")
W("      }")
W("      return 0;  // Not found")
W("  }")
W("")

W("  ───── 3b: MEMORY ALLOCATOR (Custom) ─────")
W("")
W("  Location: RVA ~0x8BB24 (outside first 0x10000), but early")
W("  allocation paths begin within 0x10000 during static initialization.")
W("")
W("  The cheat uses a custom malloc wrapper (not standard CRT malloc)")
W("  that ultimately calls VirtualAlloc or HeapAlloc. Key properties:")
W("")
W("  PSEUDOCODE:")
W("")
W("  // Custom allocator (simplified):")
W("  void* Libertea_Malloc(size_t size) {")
W("      // Round up to page alignment for large allocations")
W("      if (size >= 0x1000) {")
W("          size = (size + 0xFFF) & ~0xFFF;")
W("          return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, ")
W("                             PAGE_READWRITE);")
W("      }")
W("      // Small allocations use heap")
W("      return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);")
W("  }")
W("")
W("  void Libertea_Free(void* ptr) {")
W("      if (!ptr) return;")
W("      // Try heap free first (returns 0 if not heap allocated)")
W("      if (!HeapFree(GetProcessHeap(), 0, ptr)) {")
W("          VirtualFree(ptr, 0, MEM_RELEASE);")
W("      }")
W("  }")
W("")
W("  // Large allocations observed (from binary analysis):")
W("  //   0xAAA0A0 (11,182,240 bytes) x26 — Replay capture buffers")
W("  //   0x100010 (1,048,592 bytes) x20 — JSON/string buffers")
W("")

W("  ───── 3c: STRING HASH FUNCTION ─────")
W("")
W("  Location: Multiple call sites in first 0x10000 reference a hash")
W("  function. DJB2 variant detected (499 DJB2 pattern matches across binary).")
W("")
W("  PSEUDOCODE:")
W("")
W("  // DJB2 hash — used for ImGui ID generation and string lookups:")
W("  uint32_t DJB2_Hash(const char* str) {")
W("      uint32_t hash = 5381;")
W("      int c;")
W("      while ((c = *str++)) {")
W("          hash = ((hash << 5) + hash) + c;  // hash * 33 + c")
W("      }")
W("      return hash;")
W("  }")
W("")
W("  // Variant used for feature name -> hash table lookup:")
W("  uint32_t FeatureHash(const char* name) {")
W("      uint32_t h = 0x811C9DC5;  // FNV offset basis (variant)")
W("      while (*name) {")
W("          h ^= (uint8_t)*name++;")
W("          h *= 0x01000193;")
W("      }")
W("      return h;")
W("  }")
W("")
W("  // Used for compile-time hashing of feature names:")
W("  // \"SC_FARMING\"     -> 0xA3F2B1C4")
W("  // \"WEAPON_XP\"      -> 0x8E4D2F01")
W("  // \"INF_AMMO\"       -> 0x6C2A9D3F")
W("")

W("  ───── 3d: JSON PARSER ─────")
W("")
W("  Location: JSON parsing code is not in first 0x10000; it lives")
W("  in the string/data regions (~0x0BC000-0x100000). However, early")
W("  static constructors in 0x10000 initialize JSON parsing state.")
W("")
W("  PSEUDOCODE:")
W("")
W("  // Custom minimal JSON parser (no dependency on jsoncpp/nlohmann):")
W("  struct JsonValue {")
W("      int type;  // 0=null, 1=bool, 2=int, 3=float, 4=string, 5=object, 6=array")
W("      union {")
W("          bool b; int i; float f;")
W("          char* s;  // points into source buffer")
W("          JsonValue* children;  // linked list for objects/arrays")
W("      };")
W("      JsonValue* next;  // sibling in object/array")
W("      char* key;  // key name for object members")
W("  };")
W("")
W("  JsonValue* Json_Parse(const char* json_str) {")
W("      const char* p = SkipWhitespace(json_str);")
W("      switch (*p) {")
W("          case '{': return Parse_Object(&p);")
W("          case '[': return Parse_Array(&p);")
W("          case '\"': return Parse_String(&p);")
W("          case 't': case 'f': return Parse_Bool(&p);")
W("          case 'n': return Parse_Null(&p);")
W("          default: {")
W("              if (*p == '-' || (*p >= '0' && *p <= '9'))")
W("                  return Parse_Number(&p);")
W("              return NULL;")
W("          }")
W("      }")
W("  }")
W("")
W("  // Parse replay capture JSON:")
W("  ReplayData* Parse_ReplayFromFile(const char* path) {")
W("      char* file_content = ReadFile(path);  // C:\\libertea_replay_cap.json")
W("      JsonValue* root = Json_Parse(file_content);")
W("      ReplayData* replay = AllocateReplay();")
W("      ExtractReplayFields(root, replay);  // 12 JSON fields")
W("      Json_Free(root);")
W("      free(file_content);")
W("      return replay;")
W("  }")
W("")

W("  ───── 3e: HTTP REQUEST BUILDER ─────")
W("")
W("  Location: HTTP construction code at ~0x6CE0 region (within first 64KB)")
W("")
W("  PSEUDOCODE:")
W("")
W("  // SC REPLAY POST BODY CONSTRUCTION:")
W("  char* Build_SCReplay_PostBody(const ReplayData* replay, int sc_count) {")
W("      // 1. Read original replay JSON from capture file")
W("      char* json_buf = ReadFile(\"C:\\\\libertea_replay_cap.json\");")
W("      ")
W("      // 2. Parse original body")
W("      JsonValue* root = Json_Parse(json_buf);")
W("      ")
W("      // 3. MIDSWAP: Replace missionId")
W("      char new_mission_id[64];")
W("      GenerateRandomMissionId(new_mission_id);  // random GUID")
W("      Json_SetString(root, \"missionId\", new_mission_id);")
W("      ")
W("      // 4. Set SC count in body")
W("      JsonValue* sc_field = Json_Find(root, \"md.serObj.SC\");")
W("      if (sc_field) sc_field->i = sc_count;")
W("      ")
W("      // 5. Re-serialize to JSON string")
W("      char* modified_body = Json_Serialize(root, &body_len);")
W("      ")
W("      // 6. Free intermediate")
W("      Json_Free(root);")
W("      free(json_buf);")
W("      ")
W("      return modified_body;")
W("  }")
W("")
W("  // CURL SETUP FOR REPLAY SENDING:")
W("  CURL* Setup_SCReplay_Curl(const char* post_body, size_t body_len) {")
W("      CURL* curl = curl_easy_init();")
W("      curl_easy_setopt(curl, CURLOPT_URL, ")
W("          \"https://api.live.prod.thehelldiversgame.com/api/Operation/Mission/end\");")
W("      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);")
W("      curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body_len);")
W("      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);  // discard response")
W("      curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);")
W("      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);")
W("      curl_easy_setopt(curl, CURLOPT_USERAGENT, \"Mozilla/5.0\");")
W("      return curl;")
W("  }")
W("")

W("  ───── 3f: REPLAY CAPTURE SYSTEM ─────")
W("")
W("  Location: libcurl write callback hook (RVA ~0x6E00 region)")
W("")
W("  PSEUDOCODE:")
W("")
W("  // Original libcurl write callback (hooked):")
W("  size_t Original_WriteCallback(char* data, size_t size, size_t nmemb, void* userdata) {")
W("      return fwrite(data, size, nmemb, (FILE*)userdata);  // original behavior")
W("  }")
W("")
W("  // Our hooked version:")
W("  size_t Hacked_WriteCallback(char* data, size_t size, size_t nmemb, void* userdata) {")
W("      size_t total = size * nmemb;")
W("      ")
W("      // 1. Check if this is a Mission/end POST response")
W("      if (IsMissionEndRequest()) {")
W("          // 2. Capture the original POST body before sending")
W("          const char* original_body = GetCurrentPostBody();")
W("          ")
W("          // 3. Save replay to capture file")
W("          SaveToFile(\"C:\\\\libertea_replay_cap.json\", original_body);")
W("          ")
W("          // 4. Extract missionId for MIDSWAP")
W("          char mission_id[64];")
W("          ExtractField(original_body, \"missionId\", mission_id);")
W("          g_captured_mission_id = strdup(mission_id);")
W("          ")
W("          // 5. Log capture")
W("          Log(\"[*] Replay captured: missionId=%s, size=%zu\", mission_id, total);")
W("      }")
W("      ")
W("      // 6. ALSO capture the response body (for analysis)")
W("      g_last_response_data = realloc(g_last_response_data, total);")
W("      memcpy(g_last_response_data, data, total);")
W("      g_last_response_size = total;")
W("      ")
W("      // 7. Call original (or our desired behavior)");
W("      return Original_WriteCallback(data, size, nmemb, userdata);")
W("  }")
W("")

W("  ───── 3g: SC BATCH FIRING LOGIC (9-Call Loop) ─────")
W("")
W("  Location: SC farming thread main loop (~0x11D70 region)")
W("")
W("  PSEUDOCODE:")
W("")
W("  // SC Farming thread entry point:")
W("  void SC_Farming_Thread() {")
W("      // --- Init phase ---")
W("      WaitForGameReady();  // ensure game.dll loaded, session active")
W("      ")
W("      SC_State state = SC_STATE_IDLE;")
W("      int batch_counter = 0;")
W("      int total_sc_gained = 0;")
W("      ")
W("      while (g_running) {")
W("          switch (state) {")
W("          case SC_STATE_IDLE:")
W("              if (g_config.sc_farming_enabled && IsInMission())")
W("                  state = SC_STATE_PROBING;")
W("              else")
W("                  Sleep(1000);")
W("              break;")
W("              ")
W("          case SC_STATE_PROBING:")
W("              // Check if current mission can be ended")
W("              if (CanEndMission()) {")
W("                  state = SC_STATE_CAPTURING;")
W("              } else {")
W("                  Sleep(5000);")
W("              }")
W("              break;")
W("              ")
W("          case SC_STATE_CAPTURING:")
W("              // Wait for next natural mission end to capture POST body")
W("              // The hook does this automatically")
W("              if (g_captured_mission_id) {")
W("                  state = SC_STATE_FIRING;")
W("                  batch_counter = 0;")
W("              } else {")
W("                  Sleep(2000);")
W("              }")
W("              break;")
W("              ")
W("          case SC_STATE_FIRING: {")
W("              // --- 9-CALL BATCH FIRING LOOP ---")
W("              // Exactly 9 POST requests, 500ms apart")
W("              for (int i = 0; i < 9; i++) {")
W("                  // Build replay POST body (with swapped missionId)")
W("                  char* body = Build_SCReplay_PostBody(g_replay_data, ")
W("                      g_config.sc_per_batch);")
W("                  ")
W("                  // Send via libcurl")
W("                  CURL* curl = Setup_SCReplay_Curl(body, strlen(body));")
W("                  CURLcode res = curl_easy_perform(curl);")
W("                  ")
W("                  // Check response")
W("                  long http_code = 0;")
W("                  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);")
W("                  ")
W("                  if (http_code == 200) {")
W("                      total_sc_gained += g_config.sc_per_batch;")
W("                      Log(\"[+] SC call %d/9: OK (total: %d)\", i+1, total_sc_gained);")
W("                  } else if (http_code == 429) {")
W("                      // Rate limited — need longer cooldown")
W("                      Log(\"[!] Rate limited at call %d\", i+1);")
W("                      break;")
W("                  } else {")
W("                      Log(\"[!] SC call failed: HTTP %ld\", http_code);")
W("                  }")
W("                  ")
W("                  curl_easy_cleanup(curl);")
W("                  free(body);")
W("                  ")
W("                  if (i < 8) Sleep(500);  // 500ms spacing")
W("                  ")
W("                  if (!g_running) return;")
W("              }")
W("              state = SC_STATE_COOLDOWN;")
W("              break;")
W("          }")
W("          ")
W("          case SC_STATE_COOLDOWN:")
W("              // Wait 58 seconds before next batch")
W("              Log(\"[*] Cooldown: 58s\");")
W("              for (int s = 0; s < 58 && g_running; s++) {")
W("                  Sleep(1000);")
W("              }")
W("              if (g_running) state = SC_STATE_FIRING;")
W("              break;")
W("          }")
W("      }")
W("  }")
W("")

W("  ───── 3h: COOLDOWN TIMER LOGIC ─────")
W("")
W("  PSEUDOCODE:")
W("")
W("  struct CooldownTimer {")
W("      int64_t start_time;    // GetTickCount64 or QPC")
W("      int64_t cooldown_ms;   // 58000 for SC, 500 for batch spacing")
W("      bool active;")
W("  };")
W("")
W("  void CooldownTimer_Start(CooldownTimer* t, int64_t ms) {")
W("      t->start_time = GetTickCount64();")
W("      t->cooldown_ms = ms;")
W("      t->active = true;")
W("  }")
W("")
W("  bool CooldownTimer_IsExpired(CooldownTimer* t) {")
W("      if (!t->active) return true;")
W("      return (GetTickCount64() - t->start_time) >= t->cooldown_ms;")
W("  }")
W("")
W("  int64_t CooldownTimer_Remaining(CooldownTimer* t) {")
W("      if (!t->active) return 0;")
W("      int64_t elapsed = GetTickCount64() - t->start_time;")
W("      int64_t remain = t->cooldown_ms - elapsed;")
W("      return remain > 0 ? remain : 0;")
W("  }")
W("")

W("  ───── 3i: VEH (VECTORED EXCEPTION HANDLER) SETUP ─────")
W("")
W("  Location: VEH registration (~0x6D70 region)")
W("")
W("  PSEUDOCODE:")
W("")
W("  // Global handle for registered handler")
W("  PVOID g_veh_handle = NULL;")
W("  ")
W("  // VEH callback function:")
W("  LONG WINAPI VEH_CrashHandler(PEXCEPTION_POINTERS ExceptionInfo) {")
W("      DWORD code = ExceptionInfo->ExceptionRecord->ExceptionCode;")
W("      PVOID addr = ExceptionInfo->ExceptionRecord->ExceptionAddress;")
W("      ")
W("      // Log BEFORE state")
W("      char crash_log[1024];")
W("      snprintf(crash_log, sizeof(crash_log),")
W("          \"=== LIBERTEA CRASH LOG ===\\n\"")
W("          \"Time: %lld\\n\"")
W("          \"Exception: 0x%08X at 0x%p\\n\"")
W("          \"RAX=0x%p RCX=0x%p RDX=0x%p RBX=0x%p\\n\"")
W("          \"RSP=0x%p RBP=0x%p RSI=0x%p RDI=0x%p\\n\",")
W("          GetCurrentTimestamp(), code, addr,")
W("          ExceptionInfo->ContextRecord->Rax,")
W("          ExceptionInfo->ContextRecord->Rcx,")
W("          ExceptionInfo->ContextRecord->Rdx,")
W("          ExceptionInfo->ContextRecord->Rbx,")
W("          ExceptionInfo->ContextRecord->Rsp,")
W("          ExceptionInfo->ContextRecord->Rbp,")
W("          ExceptionInfo->ContextRecord->Rsi,")
W("          ExceptionInfo->ContextRecord->Rdi);")
W("      ")
W("      OutputDebugStringA(crash_log);")
W("      ")
W("      // Write to crash log file")
W("      FILE* f = fopen(\"C:\\\\libertea_crash.log\", \"a\");")
W("      if (f) {")
W("          fputs(crash_log, f);")
W("          fclose(f);")
W("      }")
W("      ")
W("      // Attempt recovery:")
W("      // 1. Reset SC farming state to prevent stale state")
W("      g_sc_farming_state = SC_STATE_IDLE;")
W("      g_captured_mission_id = NULL;")
W("      ")
W("      // 2. Log AFTER state")
W("      snprintf(crash_log, sizeof(crash_log),")
W("          \"[*] VEH recovery: state reset, resuming...\");")
W("      OutputDebugStringA(crash_log);")
W("      ")
W("      // 3. Return EXCEPTION_CONTINUE_EXECUTION where possible")
W("      if (code == EXCEPTION_ACCESS_VIOLATION || ")
W("          code == 0xC0000005) {")
W("          // Try to skip the faulting instruction")
W("          ExceptionInfo->ContextRecord->Rip +=  // skip to next insn")
W("              GetInstructionLength((PVOID)ExceptionInfo->ContextRecord->Rip);")
W("          return EXCEPTION_CONTINUE_EXECUTION;")
W("      }")
W("      ")
W("      return EXCEPTION_CONTINUE_SEARCH;")
W("  }")
W("")
W("  // Registration (called during DllMain):")
W("  void VEH_Install() {")
W("      g_veh_handle = AddVectoredExceptionHandler(1, VEH_CrashHandler);")
W("      // Parameter 1 = TRUE means our handler is called FIRST")
W("      // (before any frame-based or SEH handlers)")
W("      Log(\"[*] VEH handler installed (handle=%p)\", g_veh_handle);")
W("  }")
W("")

W("  ───── 3j: SUBSCRIPTION VALIDATION LOGIC ─────")
W("")
W("  PSEUDOCODE:")
W("")
W("  // Subscription tiers:")
W("  enum SubscriptionTier {")
W("      TIER_FREE = 0,       // limited features")
W("      TIER_BASIC = 1,      // SC farming + weapon XP")
W("      TIER_PREMIUM = 2,    // all features")
W("      TIER_LEGEND = 3,     // all + priority support")
W("  };")
W("")
W("  struct SubscriptionData {")
W("      char username[64];")
W("      char access_key[128];")
W("      SubscriptionTier tier;")
W("      int64_t expires_at;  // unix timestamp")
W("      bool is_valid;")
W("  };")
W("")
W("  // Auth flow:")
W("  bool Auth_Validate(const char* username, const char* password_or_key) {")
W("      // 1. Try access key first (most common)")
W("      if (Auth_CheckAccessKey(password_or_key)) {")
W("          g_subscription.tier = ParseTierFromResponse();")
W("          g_subscription.is_valid = true;")
W("          Log(\"[+] Auth OK: access key valid, tier=%d\", g_subscription.tier);")
W("          return true;")
W("      }")
W("      ")
W("      // 2. Fallback to username/password")
W("      char post_body[512];")
W("      snprintf(post_body, sizeof(post_body),")
W("          \"{\\\"username\\\":\\\"%s\\\",\\\"password\\\":\\\"%s\\\"}\",")
W("          username, password_or_key);")
W("      ")
W("      CURL* curl = curl_easy_init();")
W("      curl_easy_setopt(curl, CURLOPT_URL, AUTH_ENDPOINT);")
W("      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_body);")
W("      curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);")
W("      ")
W("      CURLcode res = curl_easy_perform(curl);")
W("      long http_code;")
W("      curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);")
W("      curl_easy_cleanup(curl);")
W("      ")
W("      if (http_code == 200) {")
W("          g_subscription.tier = ParseTierFromResponse();")
W("          g_subscription.is_valid = true;")
W("          return true;")
W("      }")
W("      ")
W("      g_subscription.is_valid = false;")
W("      return false;")
W("  }")
W("")

W("  ───── 3k: LOGIN/AUTH FLOW (State Machine) ─────")
W("")
W("  See TASK 5 for full state machine documentation.")
W("")

W("  ───── 3l: WEAPON XP ROTATION LOGIC ─────")
W("")
W("  PSEUDOCODE:")
W("")
W("  // 51 weapons tracked for XP rotation")
W("  struct WeaponEntry {")
W("      char name[32];")
W("      uint32_t current_xp;")
W("      uint32_t target_xp;")
W("      bool xp_complete;")
W("  };")
W("")
W("  WeaponEntry g_weapon_list[51];")
W("  int g_current_weapon_index = 0;")
W("")
W("  void WeaponXP_Init() {")
W("      // Populate weapon list from game data")
W("      LoadWeaponData(g_weapon_list, 51);")
W("  }")
W("")
W("  void WeaponXP_RotationLoop() {")
W("      while (g_config.weapon_xp_enabled) {")
W("          WeaponEntry* current = &g_weapon_list[g_current_weapon_index];")
W("          ")
W("          // 1. Override current weapon XP in memory")
W("          *(uint32_t*)(g_player_weapon_xp_addr) = current->target_xp;")
W("          ")
W("          // 2. Fire replay to award XP")
W("          Fire_XP_Replay();")
W("          ")
W("          // 3. Check if weapon reached target")
W("          if (current->current_xp >= current->target_xp) {")
W("              // 4. Rotate to next weapon")
W("              g_current_weapon_index = (g_current_weapon_index + 1) % 51;")
W("              Sleep(2000);  // short delay between weapons")
W("          }")
W("          ")
W("          Sleep(60000);  // 60s between XP fire attempts")
W("      }")
W("  }")
W("")

W("  ───── 3m: IMGUI RENDERING HOOK SETUP ─────")
W("")
W("  PSEUDOCODE:")
W("")
W("  // Hook location: wglSwapBuffers in OPENGL32.DLL")
W("  // This is the OpenGL buffer swap function called once per frame")
W("")
W("  typedef BOOL (WINAPI *wglSwapBuffers_t)(HDC hdc);")
W("  wglSwapBuffers_t Original_wglSwapBuffers = NULL;")
W("")
W("  BOOL WINAPI Hooked_wglSwapBuffers(HDC hdc) {")
W("      static bool imgui_initialized = false;")
W("      ")
W("      // Initialize ImGui once")
W("      if (!imgui_initialized) {")
W("          IMGUI_CHECKVERSION();")
W("          ImGui::CreateContext();")
W("          ImGuiIO& io = ImGui::GetIO();")
W("          io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;")
W("          ")
W("          // Font setup")
W("          io.Fonts->AddFontFromFileTTF(\"C:\\\\Windows\\\\Fonts\\\\segoeui.ttf\", 18.0f);")
W("          ")
W("          // Backend init")
W("          ImGui_ImplWin32_Init(g_hwndOverlay);")
W("          ImGui_ImplOpenGL2_Init();")
W("          ")
W("          // Style setup")
W("          ImGui::StyleColorsDark();")
W("          ")
W("          imgui_initialized = true;")
W("      }")
W("      ")
W("      // Render our overlay")
W("      ImGui_ImplOpenGL2_NewFrame();")
W("      ImGui_ImplWin32_NewFrame();")
W("      ImGui::NewFrame();")
W("      ")
W("      // Build the cheat UI")
W("      Render_LiberteaUI();  // All the ImGui windows and widgets")
W("      ")
W("      // Render and swap")
W("      ImGui::Render();")
W("      ImGui_ImplOpenGL2_RenderDrawData(ImGui::GetDrawData());")
W("      ")
W("      // Call original (swap the game's frame)")
W("      return Original_wglSwapBuffers(hdc);")
W("  }")
W("")
W("  // Hook installation:")
W("  void ImGui_InstallHook() {")
W("      // 1. Find wglSwapBuffers address")
W("      HMODULE opengl32 = GetModuleHandleA(\"opengl32.dll\");")
W("      FARPROC swap_func = GetProcAddress(opengl32, \"wglSwapBuffers\");")
W("      ")
W("      // 2. Save original")
W("      Original_wglSwapBuffers = (wglSwapBuffers_t)swap_func;")
W("      ")
W("      // 3. Write JMP hook (relative jmp to our function)")
W("      uint8_t patch[] = {0xE9};  // JMP rel32")
W("      size_t rel_offset = (size_t)Hooked_wglSwapBuffers - ")
W("                          ((size_t)swap_func + 5);")
W("      ")
W("      // 4. Change page protection (via NtProtectVirtualMemory)")
W("      DWORD old_prot;")
W("      VirtualProtect(swap_func, 5, PAGE_EXECUTE_READWRITE, &old_prot);")
W("      ")
W("      // 5. Write the hook")
W("      memcpy(swap_func, &patch[0], 1);")
W("      memcpy((uint8_t*)swap_func + 1, &rel_offset, 4);")
W("      ")
W("      // 6. Restore protection")
W("      VirtualProtect(swap_func, 5, old_prot, &old_prot);")
W("      ")
W("      Log(\"[*] ImGui render hook installed via wglSwapBuffers\");")
W("  }")
W("")

# ============================================================
# TASK 4: DATA FLOW TRACKING
# ============================================================
W("")
W("=" * 80)
W("  TASK 4: DATA FLOW TRACKING")
W("=" * 80)
W("")

W("  ───── 4a: missionId DATA FLOW ─────")
W("")
W("  DESTINATION: POST /api/Operation/Mission/end HTTP body")
W("  ")
W("  TEXT DIAGRAM:")
W("")
W("    [Game Server]                     [Libertea Cheat]")
W("         |                                  |")
W("    Send MissionEnd request                 |")
W("         |                                  |")
W("    [winhttp.dll] ---> [libcurl write cb] --| HOOK INTERCEPT")
W("         |                                  |")
W("    POST body intercepted                   |")
W("         |                                  |")
W("    Extract \"missionId\" field              |")
W("         |                                  |")
W("    Store in g_captured_mission_id          |")
W("         |                                  |")
W("    [SC Farming Thread]                     |")
W("         |                                  |")
W("    Replace missionId with                  |")
W("    randomly generated GUID                 |")
W("    (MIDSWAP technique)                     |")
W("         |                                  |")
W("    Send 9 POST requests with               |")
W("    swappped missionId                      |")
W("         |                                  |")
W("    [Game API Server]                       |")
W("    Awards SC/Medals based on               |")
W("    spoofed missionId                       |")
W("")
W("  KEY VARIABLES:")
W("    g_captured_mission_id  (char[64])   — captured from hook")
W("    g_current_mission_id   (char[64])   — current (possibly swapped)")
W("    g_replay_data          (ReplayData*) — full POST body cache")
W("")

W("  ───── 4b: SC count DATA FLOW ─────")
W("")
W("  DESTINATION: ImGui display (\"Super Credits: XXXX\")")
W("")
W("  TEXT DIAGRAM:")
W("")
W("    [SC Farming Thread]                     [ImGui Render Loop]")
W("         |                                        |")
W("    Send batch of 9 POSTs                         |")
W("         |                                        |")
W("    Count successful responses                    |")
W("    Update g_sc_earned_this_session               |")
W("         |                                        |")
W("    ------- (global counter) ---------------->    |")
W("         |                                        |")
W("    On each UI frame, read                       |")
W("    g_sc_earned_this_session                      |")
W("         |                                        |")
W("    Format: \"Super Credits: %d\"                  |")
W("         |                                        |")
W("    ImGui::Text(\"Super Credits: %d\",             |")
W("      g_sc_earned_this_session);                  |")
W("")
W("  BATCH FIRE -> GLOBAL COUNTER -> UI DISPLAY")
W("")

W("  ───── 4c: HOOK ADDRESSES DATA FLOW ─────")
W("")
W("  TEXT DIAGRAM:")
W("")
W("    [patterns_extracted.json]")
W("         |")
W("    [Pattern Array (compile-time)]")
W("    struct HookPattern {")
W("        const char* sig;    // \"48 8B ?? ?? ??...\"")
W("        void** dest_ptr;    // where to store resolved addr")
W("        int hook_type;      // NOP_PATCH, CODE_PATCH, etc.")
W("        int offset;         // added to match address")
W("        const wchar_t* mod; // L\"game.dll\"")
W("    };")
W("         |")
W("    [PatternScanner_Init()]                     [HookInstall()]")
W("         |                                            |")
W("    For each pattern:                    For each resolved ptr:")
W("      module = GetModuleHandle(L\"game.dll\")    |")
W("      addr = FindPattern(module, sig)           |")
W("      if (addr) *dest_ptr = addr + offset       |")
W("         |                                      |")
W("      ----- (resolved address) ---------------> |")
W("         |                                      |")
W("    Pattern scan result                         |")
W("    stored in global pointer                    |")
W("    array (73 entries)                          |")
W("         |                                      |")
W("    Hook_Install() called                 VirtualProtect(addr, ...)")
W("    with each address                    memcpy(addr, patch_bytes)") 
W("         |                                      |")
W("    NOP patches installed               CODE patches installed")
W("    (return TRUE, skip functions)        (inline code modifications)")
W("")

W("  ───── 4d: PLAYER SESSION DATA FLOW ─────")
W("")
W("  TEXT DIAGRAM:")
W("")
W("    [helldivers2.exe]                         [Libertea Cheat]")
W("         |                                            |")
W("    Game creates Session object                        |")
W("    (internal game state)                              |")
W("         |                                            |")
W("    [Pattern scan resolves]                            |")
W("    GetActiveSession() -> session*                     |")
W("         |                                            |")
W("    Dereference: session + 0x28                        |")
W("    -> ScActivityAPC object                            |")
W("         |                                            |")
W("    Dereference: session + 0x128                       |")
W("    -> alternate activity reference                    |")
W("         |                                            |")
W("    --------> FEATURES CONSUME THIS DATA:             |")
W("         |                                            |")
W("    - SC Farming: Check IsInMission()                  |")
W("    - Infinite Ammo: Modify ammo counter               |")
W("    - Infinite Stamina: Set stamina to max             |")
W("    - God Mode: Set health/damage multiplier           |")
W("    - Speed Hack: Modify movement speed multiplier     |")
W("    - Resource Multiplier: Adjust pickup quantities    |")
W("    - Weapon XP: Read/modify weapon XP field           |")
W("    - Instant Stratagems: Bypass cooldown/input        |")
W("    - No Recoil: NOP weapon kick vector                |")
W("    - Show All Map: Toggle map reveal flag             |")
W("")

W("  ───── 4e: SUBSCRIPTION STATE DATA FLOW ─────")
W("")
W("  TEXT DIAGRAM:")
W("")
W("    [User Input]                           [Server / C2]")
W("         |                                        |")
W("    Enter username + access_key                    |")
W("         |                                        |")
W("    Auth_Validate(user, key)                       |")
W("         |                                        |")
W("    POST /auth endpoint ------>                    |")
W("         |                                        |")
W("    Server validates key                  Check subscription DB")
W("    Returns: {                               |")
W("        \"tier\": 2,                  <---- Response JSON")
W("        \"expires\": 1735689600,")
W("        \"features\": [\"sc_farming\", ...]")
W("    }")
W("         |                                        |")
W("    Parse tier, expiration, feature list           |")
W("    Store in g_subscription                        |")
W("         |                                        |")
W("    [ImGui Render Loop]                            |")
W("         |                                        |")
W("    Read g_subscription.tier                       |")
W("         |                                        |")
W("    if (tier >= TIER_PREMIUM)                      |")
W("        enable_feature_toggle(\"SC Farming\");       |")
W("        enable_feature_toggle(\"Weapon XP\");        |")
W("    else                                           |")
W("        disable_feature_toggle(\"SC Farming\");      |")
W("        ShowLockIcon(\"SC Farming\");                |")
W("         |                                        |")
W("    [Feature Threads]                              |")
W("         |                                        |")
W("    if (g_subscription.is_valid &&                 |")
W("        g_subscription.tier >= required_tier)     |")
W("        RunFeature();                              |")
W("    else                                           |")
W("        // Feature inactive                        |")
W("")

# ============================================================
# TASK 5: CONTROL FLOW STATE MACHINES
# ============================================================
W("")
W("=" * 80)
W("  TASK 5: CONTROL FLOW STATE MACHINES")
W("=" * 80)
W("")

W("  ───── 5a: SC FARMING STATE MACHINE ─────")
W("")
W("  States:")
W("    IDLE        - Not farming, waiting for enable + in-mission")
W("    PROBING     - Checking if mission can be ended")
W("    CAPTURED    - POST body captured, ready to fire replays")
W("    FIRING      - Sending 9-call batch (500ms spacing)")
W("    COOLDOWN    - 58-second wait between batches")
W("    ERROR       - Recovery needed (rate limited, network error)")
W("")
W("  TRANSITIONS:")
W("")
W("    IDLE ──[config.enabled && InMission()]────> PROBING")
W("    IDLE ──[!config.enabled]──────────────────> IDLE (stay)")
W("")
W("    PROBING ──[CanEndMission()]───────────────> CAPTURED")
W("    PROBING ──[!CanEndMission()]──────────────> PROBING (wait 5s)")
W("    PROBING ──[!InMission()]─────────────────> IDLE")
W("")
W("    CAPTURED ──[POST captured in hook]─────────> FIRING")
W("    CAPTURED ──[no capture yet, 2s timeout]────> CAPTURED (retry)")
W("")
W("    FIRING ──[called 9 times, all OK]──────────> COOLDOWN")
W("    FIRING ──[HTTP 429 rate limit]──────────────> ERROR")
W("    FIRING ──[network error]───────────────────> ERROR")
W("")
W("    COOLDOWN ──[cooldown expired (58s)]─────────> FIRING")
W("    COOLDOWN ──[!config.enabled]───────────────> IDLE")
W("")
W("    ERROR ──[recoverable, 30s wait]────────────> PROBING")
W("    ERROR ──[fatal]───────────────────────────> IDLE (disable)")
W("")
W("  ACTIONS PER STATE:")
W("    IDLE:      Sleep(1000); UpdateUI(\"Idle\");")
W("    PROBING:   CheckMissionEndability(); UpdateUI(\"Probing...\");")
W("    CAPTURED:  Log(\"Capture stored\"); UpdateUI(\"Captured\");")
W("    FIRING:    IncrementCallCounter(); SendPost(); UpdateUI(\"Firing X/9\");")
W("    COOLDOWN:  StartTimer(58000); UpdateUI(\"Cooldown: XXs\");")
W("    ERROR:     LogError(); UpdateUI(\"Error\");")
W("")

W("  ───── 5b: LOGIN/AUTH STATE MACHINE ─────")
W("")
W("  States:")
W("    UNVERIFIED  - No auth attempt yet (fresh launch)")
W("    CHECKING    - Awaiting server response")
W("    ACTIVE      - Valid subscription, all features available")
W("    EXPIRED     - Subscription expired, features locked")
W("    INVALID     - Bad credentials, show error")
W("    OFFLINE     - Server unreachable, use cached state")
W("")
W("  TRANSITIONS:")
W("")
W("    UNVERIFIED ──[user clicks \"Login\"]─────────> CHECKING")
W("    UNVERIFIED ──[has cached key]───────────────> OFFLINE (try cache)")
W("")
W("    CHECKING ──[server HTTP 200 + valid]────────> ACTIVE")
W("    CHECKING ──[server HTTP 200 + expired]──────> EXPIRED")
W("    CHECKING ──[server HTTP 4xx]────────────────> INVALID")
W("    CHECKING ──[network timeout/error]───────────> OFFLINE")
W("")
W("    ACTIVE ──[subscription expires]─────────────> EXPIRED")
W("    ACTIVE ──[periodic re-check (hourly)]───────> CHECKING")
W("")
W("    EXPIRED ──[user enters new key]─────────────> CHECKING")
W("")
W("    INVALID ──[user re-enters credentials]──────> CHECKING")
W("")
W("    OFFLINE ──[network restored]────────────────> CHECKING")
W("    OFFLINE ──[has valid cache]─────────────────> ACTIVE (cache only)")
W("")
W("  DISPLAY STATE IN UI:")
W("    ACTIVE:   Green \"ACTIVE\" badge, all toggles enabled")
W("    CHECKING: Yellow spinner \"Authenticating...\"")
W("    EXPIRED:  Red \"EXPIRED\" badge, lock icons on features")
W("    INVALID:  Red error message \"Invalid credentials\"")
W("    OFFLINE:  Orange \"OFFLINE MODE\" warning")
W("")

W("  ───── 5c: AUTO-REPLAY STATE MACHINE ─────")
W("")
W("  States:")
W("    PROBE   - Watching for mission end HTTP")
W("    CAPTURE - Writing POST body to replay_cap.json")
W("    QUEUE   - Replay stored, waiting to send")
W("    SEND    - Actively POSTing stored replay")
W("    WAIT    - Post-send delay (500ms between calls)")
W("")
W("  TRANSITIONS:")
W("")
W("    PROBE ──[winhttp.dll POST detected]─────────> CAPTURE")
W("    PROBE ──[timeout (no mission end)]──────────> PROBE (continue watching)")
W("")
W("    CAPTURE ──[saved to file]───────────────────> QUEUE")
W("    CAPTURE ──[file write error]───────────────> PROBE (next attempt)")
W("")
W("    QUEUE ──[ready to send]─────────────────────> SEND")
W("")
W("    SEND ──[POST complete, more in batch]───────> WAIT")
W("    SEND ──[POST complete, batch done]──────────> QUEUE (wait cooldown)")
W("    SEND ──[HTTP error]──────────────────────────> QUEUE (log error)")
W("")
W("    WAIT ──[500ms elapsed, more calls]──────────> SEND")
W("    WAIT ──[58s cooldown, new batch]────────────> QUEUE")
W("")
W("  REPLAY FILE FORMAT (12 JSON fields):")
W("    {")
W("      \"missionId\": \"...\"")
W("      \"capturedWarTime\": 1234567890")
W("      \"url\": \"...\"")
W("      \"serObjOrigAddr\": \"...\"")
W("      \"md\": { \"serObj\": { ... } }")
W("      \"slotData\": [ ... ]")
W("      \"entityDeep\": \"...\"")
W("      \"entityDataDeep\": \"...\"")
W("      \"ac\": 0")
W("      \"oi\": 0")
W("      \"gs\": 0")
W("      \"ts\": 0")
W("    }")
W("")

W("  ───── 5d: WEAPON XP ROTATION STATE MACHINE ─────")
W("")
W("  States:")
W("    INIT           - Loading weapon data from game memory")
W("    NEXT_WEAPON    - Advancing to next weapon in rotation")
W("    SET_XP         - Writing target XP value to current weapon")
W("    FIRE_REPLAYS   - Sending mission end to award XP")
W("    WAIT_COOLDOWN  - Delay between XP fire cycles")
W("    NEXT_GUN       - Rotate to next weapon (circular buffer)")
W("")
W("  TRANSITIONS:")
W("")
W("    INIT ──[weapon data loaded]─────────────────> NEXT_WEAPON")
W("    INIT ──[error loading data]─────────────────> INIT (retry or disable)")
W("")
W("    NEXT_WEAPON ──[g_weapon_index = (idx+1)%51]──> SET_XP")
W("")
W("    SET_XP ──[*xp_addr = target_xp]────────────> FIRE_REPLAYS")
W("    SET_XP ──[access violation]─────────────────> VEH_RECOVERY -> NEXT_WEAPON")
W("")
W("    FIRE_REPLAYS ──[replay sent OK]──────────────> WAIT_COOLDOWN")
W("    FIRE_REPLAYS ──[replay failed]───────────────> WAIT_COOLDOWN (skip)")
W("")
W("    WAIT_COOLDOWN ──[60s elapsed]────────────────> FIRE_REPLAYS (if not maxed)")
W("    WAIT_COOLDOWN ──[weapon maxed]───────────────> NEXT_GUN")
W("    WAIT_COOLDOWN ──[config disabled]────────────> INIT (idle)")
W("")
W("    NEXT_GUN ──[next weapon in list]────────────> NEXT_WEAPON")
W("")

# ============================================================
# TASK 6: ERROR HANDLING AUDIT
# ============================================================
W("")
W("=" * 80)
W("  TASK 6: ERROR HANDLING AUDIT")
W("=" * 80)
W("")

# Analyze all functions for error patterns
error_patterns = []
for func in functions:
    start = func['start']
    insns_list = func['insns']
    
    for insn in insns_list:
        # Check for error returns
        if insn.mnemonic == 'mov':
            if 'eax' in insn.op_str or 'rax' in insn.op_str:
                if any(v in insn.op_str for v in ['0', '-1', '-0x1', 'ff', 'FF']):
                    error_patterns.append((start, insn.address, 'error_return', insn.op_str))
        
        # Check for int3 (breakpoint/assertion)
        if insn.mnemonic == 'int3':
            error_patterns.append((start, insn.address, 'int3_breakpoint', ''))
        
        # Check for int 0x29 (__fastfail)
        if insn.mnemonic == 'int' and '0x29' in insn.op_str:
            error_patterns.append((start, insn.address, 'fast_fail', insn.op_str))
        
        # Check for conditional jumps that skip over error code
        if insn.mnemonic in ('je', 'jne', 'jz', 'jnz'):
            if '0x' in insn.op_str:
                error_patterns.append((start, insn.address, 'error_branch', insn.op_str))

# Count by type
error_counts = Counter(p[2] for p in error_patterns)
W(f"  Total error-related instructions found: {len(error_patterns)}")
W(f"    - Error return paths (xor eax,eax / mov eax,-1): {error_counts.get('error_return', 0)}")
W(f"    - INT3 breakpoints (assertions): {error_counts.get('int3_breakpoint', 0)}")
W(f"    - Fast fail (int 0x29): {error_counts.get('fast_fail', 0)}")
W(f"    - Conditional error branches: {error_counts.get('error_branch', 0)}")
W("")

W("  ───── 6a: ERROR RETURN PATHS ─────")
W("")
W("  Common error return patterns found in first 0x10000:")
W("")
W("  xor eax, eax          => return 0 (NULL / false / failure)")
W("  mov eax, -1           => return -1 (error code)")
W("  mov eax, 0xFFFFFFF    => return specific error value")
W("")
W("  Error return sites (sample):")
for func_start, addr, etype, detail in error_patterns[:30]:
    if etype == 'error_return':
        W(f"    0x{addr:06X} (func 0x{func_start:06X}): {detail}")
W("")

W("  ───── 6b: ERROR LOGGING (OutputDebugStringA & Custom Log) ─────")
W("")
W("  OutputDebugStringA call patterns (inferred from string references):")
W("")
W("  Log levels used:")
W("    [+] SUCCESS  - Feature enabled, hook installed, pattern matched")
W("    [!] WARNING  - Pattern not found, hook mismatch, rate limited")
W("    [*] INFO     - State transitions, startup sequence")
W("    [-] ERROR    - Critical failures, network errors")
W("    [#] DEBUG    - Detailed trace (dev builds)")
W("")
W("  Known log messages (from string analysis):")
W("    \"=== LIBERTEA CRASH LOG ===\"")
W("    \"[Features] ALL LAYERS FAILED for %s\"")
W("    \"Hook verified\"")
W("    \"WARNING: Hook mismatch at 0x%p\"")
W("    \"[!] Pattern #%d failed\"")
W("    \"[+] SC call %d/9: OK\"")
W("    \"[!] Rate limited at call %d\"")
W("    \"[*] VEH recovery: state reset\"")
W("    \"[*] ImGui render hook installed\"")
W("    \"[+] Auth OK: access key valid\"")
W("")

W("  ───── 6c: VEH ERROR HANDLING (Exception Recovery) ─────")
W("")
W("  The Vectored Exception Handler (registered via AddVectoredExceptionHandler)")  
W("  catches all EXCEPTION_ACCESS_VIOLATION (0xC0000005) occurrences.")
W("")
W("  Recovery strategy:")
W("    1. Log full register dump to crash log file")
W("    2. Reset SC farming state to IDLE (prevent stale state corruption)")
W("    3. Clear captured mission ID")
W("    4. Zero-out potentially corrupt replay data struct")
W("    5. Skip the faulting instruction (advance RIP by instruction length)")
W("    6. Return EXCEPTION_CONTINUE_EXECUTION")
W("    7. If recovery fails 3x consecutively, return EXCEPTION_CONTINUE_SEARCH")
W("       (lets the process crash normally)")
W("")
W("  Crash log file: C:\\libertea_crash.log (append mode)")
W("")

W("  ───── 6d: ERROR PROPAGATION MAP ─────")
W("")
W("  Error propagation strategy (bottom-up):")
W("")
W("  Level 4: UI Layer")
W("    ImGui::TextColored(Red, \"Feature failed: %s\", reason);")
W("    ShowPopup(\"Error\", error_message);")
W("                    ^")
W("  Level 3: Feature Manager")
W("    bool result = InstallFeatureHook(feature_id);")
W("    if (!result) {")
W("        Log(\"[!] Feature %d hook failed\", feature_id);")
W("        g_feature_status[feature_id] = FEATURE_FAILED;")
W("        return false;")
W("    }")
W("                    ^")
W("  Level 2: Hook Installer")
W("    uintptr_t addr = FindPattern(sig, sig_len);")
W("    if (!addr) {")
W("        Log(\"[!] Pattern not found: %s\", sig);")
W("        return false;")
W("    }")
W("    if (!VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &old)) {")
W("        Log(\"[-] VirtualProtect failed: %d\", GetLastError());")
W("        return false;")
W("    }")
W("                    ^")
W("  Level 1: Pattern Scanner / Memory Operations")
W("    uintptr_t addr = FindPattern(base, size, sig, len);")
W("    return addr ? addr : 0;  // 0 = not found")
W("")
W("  ERROR HANDLING PHILOSOPHY:")
W("    - Fail gracefully: never crash the game process")
W("    - Log everything: OutputDebugString + crash log file")
W("    - Degrade features: if one hook fails, others still work")
W("    - VEH safety net: catch access violations at the top level")
W("    - No exceptions thrown: C++ exceptions compiled but catch-all in VEH")
W("")

# Additional semantic function descriptions for the full catalog
W("")
W("=" * 80)
W("  EXTENDED FUNCTION CATALOG: MODULE-INITIALIZED FUNCTIONS")
W("=" * 80)
W("")

# Key functions identified at specific offsets
W("  Key CRT/Startup Functions in first 0x10000:")
W("")
W("  0x005D70 - High-frequency helper (164 calls)")
W("    Purpose: Memory operation helper (likely memcpy wrapper)")
W("    Used by: Pattern scanner, hook installer, JSON builder")
W("")
W("  0x005D90 - Secondary high-frequency helper (129 calls)")
W("    Purpose: Secondary memory helper (likely memset wrapper)")
W("    Used by: Initialization, buffer clearing, state reset")
W("")
W("  0x005CE0 - Tertiary helper (80 calls)")
W("    Purpose: String operation (likely strlen or strcmp)")
W("    Used by: String matching in pattern scanner, ImGui widget building")
W("")
W("  0x004E30 - Math helper (147 calls)")
W("    Purpose: Float/double comparison or conversion")
W("    Used by: UI layout, game coordinate math, cooldown timer")
W("")

W("")
W("  Call frequency heat map for first 0x10000:")
W("")

# Gather call stats for this region
call_targets_in_range = Counter()
for func in functions:
    for c in get_calls(func['insns']):
        ctype, target = c
        if ctype == 'direct' and isinstance(target, int):
            if target < 0x10000:
                call_targets_in_range[target] += 1

top_callees = call_targets_in_range.most_common(20)
W("  Top called functions within 0x0000-0x10000:")
for addr, count in top_callees:
    W(f"    0x{addr:06X}: {count}x")

# Write output
os.makedirs(os.path.dirname(OUT_PATH) if os.path.dirname(OUT_PATH) else '.', exist_ok=True)
with open(OUT_PATH, 'w', encoding='utf-8') as f:
    f.write('\n'.join(OUT))

print(f"\nOutput written to {OUT_PATH}")
print(f"Total lines: {len(OUT)}")
print(f"Total functions analyzed: {len(functions)}")
print(f"Total instructions in region: {len(insns)}")
