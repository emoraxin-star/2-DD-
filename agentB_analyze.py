#!/usr/bin/env python3
"""
Agent B: Complete Function Catalog for .text_unpacked_mem.bin
Scans for function prologues, disassembles, identifies purpose, builds call graph.
"""

import struct
import os
import re
import json
from collections import defaultdict

try:
    from capstone import *
except ImportError:
    print("pip install capstone")
    exit(1)

BIN_PATH = r"C:\Users\emora\OneDrive\Desktop\2\data\.text_unpacked_mem.bin"
STRINGS_PATH = r"C:\Users\emora\OneDrive\Desktop\2\data\all_strings.txt"
OUTPUT_PATH = r"C:\Users\emora\OneDrive\Desktop\2\logs\agentB_function_catalog.txt"

# Load binary
with open(BIN_PATH, "rb") as f:
    binary = f.read()
BIN_SIZE = len(binary)
print(f"Binary loaded: {BIN_SIZE} bytes ({BIN_SIZE/1024/1024:.1f} MB)")

# Parse strings file for meaningful strings and their offsets
# These are offsets into some image base - we need to map them
KNOWN_STRINGS = {}  # offset_in_file -> string
STRING_BY_VALUE = {}  # string_value -> [offsets]

with open(STRINGS_PATH, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        match = re.match(r'^([0-9A-Fa-f]+):\s*(.+)$', line)
        if match:
            offset_hex = match.group(1)
            content = match.group(2)
            try:
                offset = int(offset_hex, 16)
                KNOWN_STRINGS[offset] = content
                if len(content) > 3:
                    s = content.lower()
                    if s not in STRING_BY_VALUE:
                        STRING_BY_VALUE[s] = []
                    STRING_BY_VALUE[s].append(offset)
            except:
                pass

print(f"Parsed {len(KNOWN_STRINGS)} known string offsets")

# Extract string-like references from the binary itself using LEA instructions
# We'll do this during disassembly

# Well-known Windows API names (used for classification)
WIN_API_SET = {
    "virtualalloc", "virtualfree", "virtualprotect", "ntprotectvirtualmemory",
    "createthread", "waitforsingleobject", "exitprocess", "terminateprocess",
    "getmodulehandle", "getprocaddress", "loadlibrary", "freelibrary",
    "messagebox", "messageboxa", "messageboxw",
    "sendmessage", "postmessage", "defwindowproc", "callwindowproc",
    "setwindowlongptr", "getwindowlongptr",
    "findwindow", "findwindowexa", "findwindowexw",
    "wsprintf", "sprintf", "snprintf", "vsprintf",
    "malloc", "free", "realloc", "calloc",
    "memset", "memcpy", "memmove", "memcmp",
    "strlen", "strcmp", "strcpy", "strncpy",
    "readfile", "writefile", "createfile", "closehandle",
    "getlasterror", "setlasterror",
    "queryperformancecounter", "gettickcount", "gettickcount64",
    "sleep", "sleepconditionvariable",
    "entercriticalsection", "leavecriticalsection",
    "initializecriticalsection", "deletecriticalsection",
    "rtlunicodestringtoansistring", "rtlansistringtounicodestring",
    "curl_easy_init", "curl_easy_setopt", "curl_easy_perform", "curl_easy_getinfo",
    "curl_easy_cleanup", "curl_slist_append", "curl_slist_free_all",
    "bscrypt", "bcrypthashdata", "bcryptopenalgorithmprovider",
    "ntqueryinformationprocess",
    "sehtr", "rtllookupelement", 
    "internetopen", "internetconnect", "httpopenrequest", "httpsendrequest",
}

# Module categories for classification
def classify_module(disasm_text, callees, strings_ref, rva):
    """
    Classify function into a module based on analysis.
    """
    combined = (disasm_text + " ".join(strings_ref)).lower()
    callee_names = [c.lower() for _, c in callees]
    
    # Check strings first (strongest signal)
    if any(s in combined for s in ["sc", "super credit", "sample", "requisition", "medal", "farming", "reward", "mission reward"]):
        if "weapon" in combined:
            return "WEAPON_XP"
        return "SC_FARMING"
    if any(s in combined for s in ["weapon", "primary weapon", "allgun", "selectedgun", "xp tracker"]):
        return "WEAPON_XP"
    if any(s in combined for s in ["god mod", "stamina", "speed", "ragdoll", "recoil", "player only"]):
        return "PLAYER_CHEATS"
    if any(s in combined for s in ["turret", "railgun", "grenade", "stratagem", "shield", "hellbomb", "hover", "laser overheat", "killstreak", "arcade", "combo", "ammo", "reload"]):
        return "COMBAT_CHEATS"
    if any(s in combined for s in ["armory", "unlock", "armor", "passive editor", "weapon editor", "weapon stats"]):
        return "ARMORY"
    if any(s in combined for s in ["imgui", "render", "draw", "combo", "slider", "checkbox", "button", "collapse", "collapsing", "begintab", "begin", "end", "sameline", "text", "input", "menu bar", "popup", "window", "font", "overlay"]):
        return "IMGUI_RENDER"
    if any(s in combined for s in ["hook", "detour", "patch", "code cave", "trampolin", "bytepatch", "install hook", "write memory", "nop patch", "conditional invert", "return from fun"]):
        return "HOOK_SYSTEM"
    if any(s in combined for s in ["pattern scan", "aob", "signature", "find pattern", "byte pattern", "memory scan"]):
        return "PATTERN_SCAN"
    if any(s in combined for s in ["auth", "login", "key", "subscription", "username", "password", "session", "validate", "license", "lock screen", "access key"]):
        return "AUTH"
    if any(s in combined for s in ["update", "version", "patch server", "letter from", "inbox", "message from dev"]):
        return "UPDATE"
    if any(s in combined for s in ["http", "curl", "internet", "request", "response", "winhttp", "network", "send", "recv", "socket", "url", "api", "post", "get"]):
        return "NETWORK"
    if any(s in combined for s in ["crypt", "hash", "encrypt", "decrypt", "key", "bcrypt", "xor", "base64", "signature", "nonce", "aes", "sha", "machineguid"]):
        return "CRYPTO"
    if any(s in combined for s in ["config", "ini", "json", "save", "load", "setting", "preference"]):
        return "CONFIG"
    if any(s in combined for s in ["log", "printf", "debug", "trace", "crash log"]):
        return "LOGGING"
    if any(s in combined for s in ["crash", "exception", "seh", "veh", "handler", "exception handler"]):
        return "CRASH_HANDLER"
    if any(s in combined for s in ["virtualprotect", "virtualalloc", "memcpy", "memset", "memory", "heapalloc", "heapfree", "writeprocessmemory"]):
        return "MEMORY"
    if any(s in combined for s in ["import", "resolve", "getmodulehandle", "getprocaddress", "loadlibrary", "resolv"]):
        return "IMPORT_RESOLVE"
    if any(s in combined for s in ["init", "initialize", "dllmain", "attach", "detach", "main", "entry point", "setup", "start"]):
        return "INIT"
    if any(s in combined for s in ["replay", "capture", "auto-replay", "burst", "probe", "dispatch"]):
        return "NETWORK"  # replay is network
    
    # Check callees
    if any("sc_" in c for _, c in callees):
        return "SC_FARMING"
    if any("weapon" in c for _, c in callees):
        return "WEAPON_XP"
    if any("auth" in c or "login" in c for _, c in callees):
        return "AUTH"
    if any("http" in c or "curl" in c or "send" in c for _, c in callees):
        return "NETWORK"
    if any("hook" in c or "patch" in c for _, c in callees):
        return "HOOK_SYSTEM"
    if any("scan" in c or "pattern" in c for _, c in callees):
        return "PATTERN_SCAN"
    if any("render" in c or "draw" in c or "gui" in c for _, c in callees):
        return "IMGUI_RENDER"
    
    return "UNKNOWN"

# Common function prologue signatures to detect
PROLOGUE_PATTERNS = [
    # sub rsp, imm8  (48 83 EC XX)
    bytes([0x48, 0x83, 0xEC]),
    # push rbx (40 53) followed by something common
    bytes([0x40, 0x53]),
    # mov [rsp+8], rcx (48 89 4C 24 08)
    bytes([0x48, 0x89, 0x4C, 0x24, 0x08]),
    # mov [rsp+0x10], rdx
    bytes([0x48, 0x89, 0x54, 0x24, 0x10]),
    # push rbp
    bytes([0x55]),
    # push rdi (57)
    bytes([0x57]),
    # push rsi (56)
    bytes([0x56]),
    # push r14 (41 56) 
    bytes([0x41, 0x56]),
    # push r15 (41 57)
    bytes([0x41, 0x57]),
    # mov [rsp+0x10], rdx
    bytes([0x48, 0x89, 0x54, 0x24, 0x10]),
    # mov [rsp+0x08], rcx
    bytes([0x48, 0x89, 0x4C, 0x24, 0x08]),
    # mov [rsp+0x18], r8
    bytes([0x4C, 0x89, 0x44, 0x24, 0x18]),
    # mov [rsp+0x20], r9
    bytes([0x4C, 0x89, 0x4C, 0x24, 0x20]),
]

def is_prologue(data, offset):
    """Check if this offset looks like a function entry point."""
    if offset + 4 > len(data):
        return False
    
    b0 = data[offset]
    b1 = data[offset+1] if offset+1 < len(data) else 0
    b2 = data[offset+2] if offset+2 < len(data) else 0
    
    # sub rsp, imm8
    if b0 == 0x48 and b1 == 0x83 and b2 == 0xEC:
        return True
    # sub rsp, imm32
    if b0 == 0x48 and b1 == 0x81 and b2 == 0xEC:
        return True
    # push rbp + mov rbp, rsp
    if b0 == 0x40 and b1 == 0x55:
        return True
    if b0 == 0x55 and b1 == 0x48 and offset+2 < len(data) and data[offset+2] == 0x8B:
        return True
    # push rbx
    if b0 == 0x40 and b1 == 0x53 and offset+2 < len(data) and data[offset+2] in (0x48, 0x57):
        return True
    # push rdi (57) followed by sub
    if b0 == 0x57 and offset+2 < len(data) and data[offset+1] == 0x48:
        return True
    # push rsi (56) followed by sub
    if b0 == 0x56 and offset+2 < len(data) and data[offset+1] == 0x48:
        return True
    # push rbx + push rbp
    if b0 == 0x40 and b1 == 0x53 and offset+2 < len(data) and data[offset+2] == 0x55:
        return True
    # push rbp + push rdi + push rsi (standard cdecl wrapper)
    if b0 == 0x55 and offset+1 < len(data) and data[offset+1] == 0x57:
        return True
    # mov [rsp+8], rcx (very typical x64 prologue)
    if (b0 == 0x48 and b1 == 0x89 and b2 == 0x4C and offset+3 < len(data) and data[offset+3] == 0x24):
        return True
    # mov [rsp+0x10], rdx
    if (b0 == 0x48 and b1 == 0x89 and b2 == 0x54 and offset+3 < len(data) and data[offset+3] == 0x24):
        return True
    # push r14 + push r15
    if b0 == 0x41 and b1 == 0x56 and offset+2 < len(data) and data[offset+2] == 0x41 and offset+3 < len(data) and data[offset+3] == 0x57:
        return True
    # push rbx + push rsi + push rdi
    if b0 == 0x40 and b1 == 0x53 and offset+2 < len(data) and data[offset+2] == 0x56:
        return True
    
    return False

def hex_bytes(data):
    return ' '.join(f'{b:02X}' for b in data[:16])

# Scan for function entries
print("Scanning for function prologues...")
FUNC_ENTRIES = set()
FUNC_ENTRIES_LIST = []

# Strategy 1: Find prologues
for offset in range(0, BIN_SIZE - 16):
    if is_prologue(binary, offset):
        FUNC_ENTRIES.add(offset)

# Strategy 2: Also look for call targets that make sense
# We'll find these during disassembly

print(f"Found {len(FUNC_ENTRIES)} candidate function entries")

# Sort entries
FUNC_ENTRIES_LIST = sorted(FUNC_ENTRIES)

# Initialize capstone
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
md.skipdata = True

# For each function entry, disassemble until we hit a ret
KNOWN_ADDRS = set(FUNC_ENTRIES)

# Build structures
functions = {}  # rva -> {name, size, module, disasm, calls, called_by, strings, apis, description}
call_graph = defaultdict(set)  # caller_rva -> set of callee_rvas
call_graph_rev = defaultdict(set)  # callee_rva -> set of caller_rvas

# Track all instruction addresses we've disassembled (to avoid re-disassembly)
disassembled = set()

def disasm_function(rva, max_insns=5000):
    """Disassemble a function starting at rva, return list of (addr, mnemonic, op_str, bytes)"""
    if rva in disassembled:
        return []
    
    result = []
    off = rva
    ret_count = 0
    
    for _ in range(max_insns):
        if off >= BIN_SIZE:
            break
        if off in disassembled and len(result) > 0:
            break
            
        data = binary[off:off+15]
        try:
            for insn in md.disasm(data, off):
                if insn.address >= BIN_SIZE:
                    break
                disassembled.add(insn.address)
                known_callee = insn.address in KNOWN_ADDRS
                result.append((insn.address, insn.mnemonic, insn.op_str, insn.bytes, known_callee))
                
                # Check if we crossed into another known function
                if insn.mnemonic in ('ret', 'retf', 'retn'):
                    ret_count += 1
                    if ret_count >= 2 or insn.address not in KNOWN_ADDRS:
                        return result
                if insn.mnemonic == 'jmp':
                    # Check if jmp is to known function entry (tail call)
                    try:
                        target = int(insn.op_str, 0)
                        if target in KNOWN_ADDRS and len(result) > 3:
                            return result
                    except:
                        pass
                if insn.mnemonic == 'int3':
                    if result:
                        return result
                
                off = insn.address + insn.size
                break
        except:
            off += 1
    
    return result

# Extract call targets from disassembly
def extract_calls(disasm_result):
    """Extract call targets from disassembly"""
    calls = []
    strings_ref = []
    apis = []
    global_refs = []
    
    for addr, mnem, op_str, raw_bytes, is_entry in disasm_result:
        if mnem == 'call':
            # Try to parse direct call target
            try:
                target = int(op_str, 0)
                if 0 <= target < BIN_SIZE:
                    calls.append(target)
                    if target not in KNOWN_ADDRS:
                        KNOWN_ADDRS.add(target)
            except:
                # Indirect call - check for register-based call patterns
                pass
        elif mnem == 'jmp':
            try:
                target = int(op_str, 0)
                if 0 <= target < BIN_SIZE:
                    if target not in KNOWN_ADDRS:
                        KNOWN_ADDRS.add(target)
            except:
                pass
        
        # Extract strings from LEA instructions
        if mnem == 'lea':
            # lea rcx/rdx/r8/r9, [rip + X] - string or global reference
            if 'rip' in op_str.lower():
                try:
                    # Parse rip-relative address from the raw bytes
                    if len(raw_bytes) >= 4:
                        rel = struct.unpack('<i', raw_bytes[len(raw_bytes)-4:])[0]
                        target_addr = addr + len(raw_bytes) + rel
                        if 0 <= target_addr < BIN_SIZE:
                            global_refs.append(target_addr)
                            # Check if it maps to known string
                            for str_offset, str_val in KNOWN_STRINGS.items():
                                # String offsets in the strings file are RVAs with unknown base
                                # We map by checking the offset within the binary
                                pass
                except:
                    pass
        elif mnem == 'mov' and ('rip' in op_str.lower()):
            try:
                if len(raw_bytes) >= 4:
                    rel = struct.unpack('<i', raw_bytes[len(raw_bytes)-4:])[0]
                    target_addr = addr + len(raw_bytes) + rel
                    if 0 <= target_addr < BIN_SIZE:
                        global_refs.append(target_addr)
            except:
                pass
    
    return calls, strings_ref, apis, global_refs

print("Disassembling all functions...")
total = len(FUNC_ENTRIES_LIST)

for i, rva in enumerate(FUNC_ENTRIES_LIST):
    if i % 100 == 0:
        print(f"  Progress: {i}/{total} ({(i/total*100):.1f}%)")
    
    if rva in functions:
        continue
    
    disasm = disasm_function(rva)
    if len(disasm) < 2:
        continue
    
    # Get function size
    if disasm:
        func_size = disasm[-1][0] - rva + disasm[-1][3].__len__()
    else:
        func_size = 0
    
    # Extract calls
    calls, strings_ref, apis, global_refs = extract_calls(disasm)
    
    # Build call graph
    for callee in calls:
        if callee != rva:
            call_graph[rva].add(callee)
            call_graph_rev[callee].add(rva)
    
    functions[rva] = {
        'size': func_size,
        'disasm': disasm,
        'calls': calls,
        'strings': strings_ref,
        'apis': apis,
        'globals': global_refs,
    }
    
    # Also add call targets as functions (lazy discovery)
    for callee in calls:
        if callee not in FUNC_ENTRIES:
            FUNC_ENTRIES.add(callee)

print(f"Disassembled {len(functions)} functions")
print(f"Call graph: {sum(len(v) for v in call_graph.values())} edges")

# Now re-discover call targets that were found during disasm
new_entries = FUNC_ENTRIES - set(functions.keys())
print(f"Found {len(new_entries)} additional call targets, disassembling...")

for rva in sorted(new_entries):
    if rva in functions:
        continue
    disasm = disasm_function(rva)
    if len(disasm) < 2:
        continue
    
    func_size = disasm[-1][0] - rva + disasm[-1][3].__len__()
    calls, strings_ref, apis, global_refs = extract_calls(disasm)
    
    for callee in calls:
        if callee != rva:
            call_graph[rva].add(callee)
            call_graph_rev[callee].add(rva)
            if callee not in FUNC_ENTRIES:
                FUNC_ENTRIES.add(callee)
    
    functions[rva] = {
        'size': func_size,
        'disasm': disasm,
        'calls': calls,
        'strings': strings_ref,
        'apis': apis,
        'globals': global_refs,
    }

print(f"Total functions after second pass: {len(functions)}")

# Continue discovering until stable
for iteration in range(3):
    new_entries = FUNC_ENTRIES - set(functions.keys())
    if not new_entries:
        break
    print(f"Pass {iteration+3}: {len(new_entries)} new targets")
    for rva in sorted(new_entries):
        if rva in functions or rva >= BIN_SIZE:
            continue
        disasm = disasm_function(rva)
        if len(disasm) < 2:
            continue
        func_size = disasm[-1][0] - rva + disasm[-1][3].__len__()
        calls, strings_ref, apis, global_refs = extract_calls(disasm)
        for callee in calls:
            if callee != rva:
                call_graph[rva].add(callee)
                call_graph_rev[callee].add(rva)
                if callee not in FUNC_ENTRIES:
                    FUNC_ENTRIES.add(callee)
        functions[rva] = {
            'size': func_size,
            'disasm': disasm,
            'calls': calls,
            'strings': strings_ref,
            'apis': apis,
            'globals': global_refs,
        }

print(f"Final function count: {len(functions)}")

# Now map string references to global offsets
# The strings file lists string offsets that map to the binary
# Let's build a reverse map from content to function
STRING_RVA_TO_CONTENT = {}
for offset, content in KNOWN_STRINGS.items():
    if len(content) > 2:
        STRING_RVA_TO_CONTENT[offset] = content

# For each function, find which strings it references
def find_relevant_strings(func_rva, func_disasm, global_refs):
    """Find strings referenced by this function"""
    found_strings = []
    
    # Search disassembly text for string-like patterns
    disasm_text = ' '.join(mnem for _, mnem, _, _, _ in func_disasm)
    
    # Map global references to known strings
    for gref in global_refs:
        if gref in STRING_RVA_TO_CONTENT:
            found_strings.append(f'[gref 0x{gref:X}] {STRING_RVA_TO_CONTENT[gref][:80]}')
    
    return found_strings

# Now generate names and build the catalog
print("Generating function names and catalog...")

def generate_function_name(rva, size, disasm, calls, callers, strings_ref, apis, global_refs):
    """Generate a meaningful C++ style function name"""
    disasm_text = ' '.join(mnem for _, mnem, _, _, _ in disasm)
    combined = (disasm_text + " " + " ".join(strings_ref[:10])).lower()
    
    # Try to find descriptive strings in the function
    string_names = []
    for gref in global_refs:
        if gref in STRING_RVA_TO_CONTENT:
            content = STRING_RVA_TO_CONTENT[gref]
            if len(content) > 3 and len(content) < 60:
                string_names.append(content)
    
    # Build name from string references and behavior
    
    # Check for ImGui function patterns
    if any(s in combined for s in ['imgui', 'begin("', 'end()', 'button("', 'checkbox("', 'slider', 'combo("', 'ImGui::']):
        if 'rend' in combined or 'draw' in combined:
            return "ImGuiRenderer", "IMGUI_RENDER"
        if 'window' in combined or 'begin(' in combined:
            return "ImGuiRenderer", "IMGUI_RENDER"
        if 'checkbox' in combined:
            return "ImGuiRenderer", "IMGUI_RENDER"
        if 'button' in combined:
            return "ImGuiRenderer", "IMGUI_RENDER"
        return "ImGuiRenderer", "IMGUI_RENDER"
    
    # SC Farming
    if any(s in string_names for s in ['SC', 'Super Credits', 'super credit', 'ScActivityAPC', 'SCLoop']):
        for s in string_names:
            if 'batch' in s.lower():
                return f"ScActivityAPC::FireBatch", "SC_FARMING"
            if 'sync' in s.lower():
                return "ScActivityAPC::SyncPlayers", "SC_FARMING"
            if 'loop' in s.lower():
                return "ScActivityAPC::Loop", "SC_FARMING"
            if 'cooldown' in s.lower():
                return "ScActivityAPC::CooldownTimer", "SC_FARMING"
            if 'midswap' in s.lower():
                return "ScActivityAPC::MidSwapMission", "SC_FARMING"
        if 'actfn' in combined or 'actobj' in combined:
            return "ScActivityAPC::ActivityCallback", "SC_FARMING"
        return "ScActivityAPC::ScActivityHandler", "SC_FARMING"
    
    # Medal farming
    if 'medal' in combined:
        if 'batch' in combined:
            return "ScActivityAPC::FireMedalBatch", "SC_FARMING"
        return "ScActivityAPC::MedalHandler", "SC_FARMING"
    
    # Sample farming
    if 'sample' in combined or 'add sampl' in combined:
        return "ScActivityAPC::SampleHandler", "SC_FARMING"
    
    # Replay capture
    if 'replay' in combined or 'capture' in combined or 'replay_cap' in combined:
        if 'store' in combined or 'save' in combined:
            return "ReplayCapture::StoreMissionData", "NETWORK"
        if 'dispatch' in combined or 'send' in combined:
            return "ReplayCapture::DispatchReplay", "NETWORK"
        if 'probe' in combined:
            return "ReplayCapture::ProbeMission", "NETWORK"
        if 'burst' in combined:
            return "ReplayCapture::BurstDispatch", "NETWORK"
        if 'auto' in combined:
            return "ReplayCapture::AutoReplayLoop", "NETWORK"
        if 'payload' in combined or 'build' in combined:
            return "ReplayCapture::BuildPayload", "NETWORK"
        return "ReplayCapture::ReplayHandler", "NETWORK"
    
    # Weapon XP
    if 'weapon' in combined or 'primary' in combined:
        if 'override' in combined or 'overr' in combined:
            return "WeaponXP::OverrideWeapon", "WEAPON_XP"
        if 'allgun' in combined:
            return "WeaponXP::AllGunsRotate", "WEAPON_XP"
        if 'selected' in combined:
            return "WeaponXP::SelectedGunsRotate", "WEAPON_XP"
        if 'patch' in combined:
            return "WeaponXP::PatchWeaponSlots", "WEAPON_XP"
        if 'editor' in combined or 'stat' in combined:
            return "Armory::WeaponStatsEditor", "ARMORY"
        if 'rotate' in combined or 'next' in combined:
            return "WeaponXP::RotateToNextWeapon", "WEAPON_XP"
        return "WeaponXP::WeaponHandler", "WEAPON_XP"
    
    # Auth / Login
    if 'auth' in combined or 'login' in combined or 'key' in combined or 'subscription' in combined:
        if 'validate' in combined:
            return "AuthClient::ValidateSubscription", "AUTH"
        if 'check' in combined:
            return "AuthClient::CheckSubscription", "AUTH"
        if 'login' in combined:
            return "AuthClient::Login", "AUTH"
        if 'lock' in combined:
            return "AuthClient::RenderLockScreen", "AUTH"
        return "AuthClient::AuthHandler", "AUTH"
    
    # Network / HTTP
    if 'http' in combined or 'curl' in combined:
        if 'setopt' in combined and 'write' in combined:
            return "HttpClient::SetWriteCallback", "NETWORK"
        if 'perform' in combined:
            return "HttpClient::PerformRequest", "NETWORK"
        if 'init' in combined:
            return "HttpClient::InitCurl", "NETWORK"
        if 'header' in combined or 'recon-hdr' in combined:
            return "HttpClient::ReconHeader", "NETWORK"
        if 'body' in combined:
            return "HttpClient::ReconBody", "NETWORK"
        if 'swap' in combined or 'inject' in combined or 'missionid' in combined:
            return "HttpClient::InjectMissionId", "NETWORK"
        if 'golden' in combined or 'capture' in combined:
            return "HttpClient::GoldenCapture", "NETWORK"
        if 'Mission/end' in combined:
            return "HttpClient::MissionEndHandler", "NETWORK"
        return "HttpClient::RequestHandler", "NETWORK"
    
    if 'winhttp' in combined or 'wininet' in combined:
        return "HttpClient::WinApiHandler", "NETWORK"
    
    # Hook system
    if 'hook' in combined or 'detour' in combined or 'patch' in combined:
        if 'install' in combined:
            return "HookManager::InstallHook", "HOOK_SYSTEM"
        if 'verify' in combined:
            return "HookManager::VerifyHook", "HOOK_SYSTEM"
        if 'cave' in combined:
            return "HookManager::AllocateCodeCave", "HOOK_SYSTEM"
        if 'nop' in combined:
            return "HookManager::ApplyNopPatch", "HOOK_SYSTEM"
        if 'toggle' in combined:
            return "HookManager::ToggleFeature", "HOOK_SYSTEM"
        if 'mismatch' in combined:
            return "HookManager::DetectMismatch", "HOOK_SYSTEM"
        return "HookManager::HookHandler", "HOOK_SYSTEM"
    
    # Pattern scanning
    if 'pattern' in combined or 'signature' in combined or 'aob' in combined or 'scan' in combined:
        if 'find' in combined or 'found' in combined:
            return "PatternScanner::FindPattern", "PATTERN_SCAN"
        if 'not found' in combined:
            return "PatternScanner::ReportMissing", "PATTERN_SCAN"
        return "PatternScanner::ScanHandler", "PATTERN_SCAN"
    
    # God mode / player cheats
    if 'god' in combined or 'godmode' in combined:
        return "PlayerCheats::GodMode", "PLAYER_CHEATS"
    if 'stamina' in combined:
        return "PlayerCheats::InfiniteStamina", "PLAYER_CHEATS"
    if 'speed' in combined:
        return "PlayerCheats::SpeedHack", "PLAYER_CHEATS"
    if 'ragdoll' in combined:
        return "PlayerCheats::NoRagdoll", "PLAYER_CHEATS"
    if 'recoil' in combined:
        return "PlayerCheats::NoRecoil", "PLAYER_CHEATS"
    
    # Combat cheats
    if 'stratagem' in combined or 'strat' in combined:
        if 'infinite' in combined:
            return "CombatCheats::InfiniteStratagems", "COMBAT_CHEATS"
        if 'instant' in combined or 'callin' in combined:
            return "CombatCheats::InstantStratCallin", "COMBAT_CHEATS"
        if 'mass' in combined or 'drop' in combined:
            return "CombatCheats::MassStratDrop", "COMBAT_CHEATS"
        return "CombatCheats::StratagemHandler", "COMBAT_CHEATS"
    
    if 'turret' in combined:
        if 'overheat' in combined:
            return "CombatCheats::NoTurretOverheat", "COMBAT_CHEATS"
        if 'duration' in combined or 'expire' in combined:
            return "CombatCheats::TurretDuration", "COMBAT_CHEATS"
        return "CombatCheats::TurretHandler", "COMBAT_CHEATS"
    
    if 'ammo' in combined:
        return "CombatCheats::InfiniteAmmo", "COMBAT_CHEATS"
    if 'reload' in combined:
        return "CombatCheats::NoReload", "COMBAT_CHEATS"
    if 'grenade' in combined:
        return "CombatCheats::InfiniteGrenades", "COMBAT_CHEATS"
    if 'stim' in combined:
        return "CombatCheats::InfiniteStims", "COMBAT_CHEATS"
    if 'instant' in combined and ('charge' in combined or 'railgun' in combined):
        return "CombatCheats::InstantCharge", "COMBAT_CHEATS"
    if 'laser' in combined and 'overheat' in combined:
        return "CombatCheats::NoLaserOverheat", "COMBAT_CHEATS"
    if 'map' in combined and 'hack' in combined:
        return "CombatCheats::MapHack", "COMBAT_CHEATS"
    if 'hoverpack' in combined or 'hover' in combined:
        return "CombatCheats::HoverpackControl", "COMBAT_CHEATS"
    if 'mission timer' in combined or 'freeze' in combined or 'timer' in combined:
        return "CombatCheats::FreezeMissionTimer", "COMBAT_CHEATS"
    if 'landing' in combined:
        return "CombatCheats::FastLanding", "COMBAT_CHEATS"
    if 'boundary' in combined:
        return "CombatCheats::NoBoundary", "COMBAT_CHEATS"
    if 'hellbomb' in combined:
        return "CombatCheats::InstantHellbomb", "COMBAT_CHEATS"
    if 'fuse' in combined:
        return "CombatCheats::GrenadeFuseTime", "COMBAT_CHEATS"
    if 'killstreak' in combined or 'killstreak' in combined:
        return "CombatCheats::KillstreakHandler", "COMBAT_CHEATS"
    
    # Armory / Unlock
    if 'unlock' in combined and 'armory' in combined:
        return "Armory::UnlockAllArmory", "ARMORY"
    if 'armor' in combined and 'passive' in combined:
        return "Armory::ArmorPassiveEditor", "ARMORY"
    
    # Crash handler
    if 'crash' in combined or 'exception' in combined:
        if 'handler' in combined or 'veh' in combined:
            return "CrashHandler::ExceptionHandler", "CRASH_HANDLER"
        if 'log' in combined:
            return "CrashHandler::WriteCrashLog", "CRASH_HANDLER"
        return "CrashHandler::CrashHandler", "CRASH_HANDLER"
    
    # Crypto
    if 'crypt' in combined or 'hash' in combined or 'bcrypt' in combined:
        return "Crypto::HashHandler", "CRYPTO"
    if 'xor' in combined:
        return "Crypto::XorCipher", "CRYPTO"
    if 'machineguid' in combined or 'hwid' in combined:
        return "Crypto::HardwareId", "CRYPTO"
    if 'base64' in combined:
        return "Crypto::Base64Encode", "CRYPTO"
    
    # Memory
    if 'memcpy' in combined or 'memmove' in combined or 'memset' in combined:
        if 'memcpy' in combined:
            return "Memory::memcpy_wrapper", "MEMORY"
        if 'memset' in combined:
            return "Memory::memset_wrapper", "MEMORY"
    if 'virtualprotect' in combined or 'virtualprotect' in combined:
        return "Memory::UnprotectMemory", "MEMORY"
    
    # Import resolution
    if 'getmodulehandle' in combined or 'getprocaddress' in combined or 'loadlibrary' in combined:
        return "ImportResolver::ResolveImport", "IMPORT_RESOLVE"
    
    # Config
    if 'ini' in combined or 'config' in combined or 'save' in combined or 'load' in combined:
        if 'save' in combined:
            return "Config::SaveToFile", "CONFIG"
        if 'load' in combined:
            return "Config::LoadFromFile", "CONFIG"
        return "Config::ConfigHandler", "CONFIG"
    
    # Logging
    if 'log' in combined or 'printf' in combined or 'debug' in combined or 'trace' in combined:
        if 'printf' in combined:
            return "Logging::DebugPrint", "LOGGING"
        return "Logging::LogHandler", "LOGGING"
    
    # Update system
    if 'update' in combined or 'inbox' in combined or 'letter from' in combined:
        return "UpdateSystem::InboxHandler", "UPDATE"
    
    # Init
    if 'dllmain' in combined or 'attach' in combined or 'thread' in combined:
        return "Init::DllMain", "INIT"
    
    # Window procedure
    if 'wndproc' in combined or 'wndproc' in combined or 'WM_' in combined:
        return "Window::WndProc", "INIT"
    
    if 'postmessage' in combined or 'queuesc' in combined:
        return "Window::QueueSCHook", "INIT"
    if 'present' in combined or 'scpresent' in combined:
        return "Window::ScPresentInstall", "INIT"
    
    # HUD / Overlay
    if 'overlay' in combined or 'hud' in combined or 'libertea hud' in combined:
        return "HudRenderer::RenderOverlay", "IMGUI_RENDER"
    
    # Generic functions by pattern
    if len(disasm) < 5:
        return "Utility::SmallThunk", "UNKNOWN"
    
    # Check for RAX pattern matches
    if 'xor eax, eax' in disasm_text and 'ret' in disasm_text:
        return "Utility::ReturnFalse", "UNKNOWN"
    if 'mov eax, 1' in disasm_text and 'ret' in disasm_text:
        return "Utility::ReturnTrue", "UNKNOWN"
    
    # Check if it looks like a string comparison
    if 'cmp' in disasm_text and 'str' in disasm_text:
        return "StringUtil::Compare", "UNKNOWN"
    
    # Check for memory allocation patterns
    if 'alloc' in disasm_text or 'HeapAlloc' in disasm_text:
        return "Memory::AllocHelper", "MEMORY"
    
    # UI Rendering function (ImGui wrappers)
    if 'begin(' in combined or 'end()' in combined or 'sameline(' in combined:
        return "ImGuiWrapper::UIFunction", "IMGUI_RENDER"
    
    # Feature toggle
    if any(s in string_names for s in ['ON', 'OFF', 'Enable', 'Disable']):
        return "Config::ToggleFeature", "CONFIG"
    
    # Default: describe what it does based on calls
    if calls:
        # Heuristic: count alloc/free calls and other patterns
        pass
    
    # Generate a name from the instruction flow
    return f"Unnamed_{rva:06X}", "UNKNOWN"


# Now build the catalog
print("Building catalog entries...")
catalog = []

for rva in sorted(functions.keys()):
    func = functions[rva]
    disasm = func['disasm']
    size = func['size']
    calls_from_me = list(call_graph[rva])
    callers_of_me = list(call_graph_rev[rva])
    global_refs = func.get('globals', [])
    
    # Find relevant strings
    string_refs = find_relevant_strings(rva, disasm, global_refs)
    
    # Find APIs - check for known API names in disasm text
    api_list = []
    for addr, mnem, op_str, raw_bytes, is_entry in disasm:
        if mnem == 'call':
            combined_mnem = op_str.lower()
            for api in WIN_API_SET:
                if api in combined_mnem:
                    api_list.append(f"CALL_{api.upper()}")
    
    # Generate name
    name, module = generate_function_name(rva, size, disasm, calls_from_me, callers_of_me, string_refs, [], global_refs)
    
    # Generate description
    disasm_mnems = [m for _, m, _, _, _ in disasm]
    call_count = len(calls_from_me)
    ref_count = len(global_refs)
    str_count = len(string_refs)
    
    if not string_refs and call_count == 0 and ref_count == 0:
        if len(disasm) <= 5:
            desc = "Small leaf function - likely a thunk, getter, or inline wrapper."
        elif len(disasm) <= 20:
            desc = "Compact utility function with no obvious external dependencies."
        else:
            desc = "Standalone function with moderate complexity."
    elif string_refs:
        desc = f"References {str_count} string(s). " + ", ".join(s[:60] for s in string_refs[:3])
    elif call_count > 0:
        desc = f"Calls {call_count} other function(s). Internal logic function."
    else:
        desc = f"Function at RVA 0x{rva:X} ({size} bytes)"
    
    if len(desc) > 200:
        desc = desc[:197] + "..."
    
    catalog.append((rva, size, module, name, calls_from_me, callers_of_me, api_list, string_refs, desc))

# Sort by module then RVA for organized output
catalog.sort(key=lambda x: (x[2], x[0]))

print(f"Catalog: {len(catalog)} entries")

# Write catalog to file
with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    f.write("=" * 100 + "\n")
    f.write("  AGENT B: COMPLETE FUNCTION CATALOG\n")
    f.write(f"  Binary: .text_unpacked_mem.bin ({BIN_SIZE} bytes, {BIN_SIZE/1024/1024:.1f} MB)\n")
    f.write(f"  Total functions cataloged: {len(catalog)}\n")
    f.write("=" * 100 + "\n\n")
    
    # Summary by module
    module_counts = defaultdict(int)
    module_sizes = defaultdict(int)
    for rva, size, module, name, calls, called_by, apis, strings, desc in catalog:
        module_counts[module] += 1
        module_sizes[module] += size
    
    f.write("MODULE SUMMARY\n")
    f.write("-" * 80 + "\n")
    for mod in sorted(module_counts.keys()):
        f.write(f"  {mod:<20} {module_counts[mod]:>6} functions  ({module_sizes[mod]:>8} bytes)\n")
    f.write("-" * 80 + "\n")
    f.write(f"  {'TOTAL':<20} {sum(module_counts.values()):>6} functions  ({sum(module_sizes.values()):>8} bytes)\n")
    f.write("=" * 100 + "\n\n")
    
    # Call graph statistics
    f.write("CALL GRAPH STATISTICS\n")
    f.write("-" * 80 + "\n")
    total_edges = sum(len(v) for v in call_graph.values())
    max_callers = max((len(v) for v in call_graph_rev.values()), default=0)
    most_called = sorted([(rva, len(callers)) for rva, callers in call_graph_rev.items()], key=lambda x: -x[1])[:10]
    
    f.write(f"  Total call edges:   {total_edges}\n")
    f.write(f"  Most called functions:\n")
    for rva, count in most_called:
        name = "???"
        for entry in catalog:
            if entry[0] == rva:
                name = entry[3]
                break
        f.write(f"    0x{rva:06X} ({count:>4} callers): {name}\n")
    f.write("=" * 100 + "\n\n")
    
    # Detailed entries
    f.write("DETAILED FUNCTION CATALOG\n")
    f.write("=" * 100 + "\n\n")
    
    for rva, size, module, name, calls, called_by, apis, strings, desc in catalog:
        f.write(f"[0x{rva:06X}] [{size:>5}] [{module}] {name}\n")
        if calls:
            f.write(f"  Calls:      {len(calls)} function(s)\n")
            for callee in sorted(calls)[:5]:
                callee_name = f"0x{callee:06X}"
                for entry in catalog:
                    if entry[0] == callee:
                        callee_name = f"0x{callee:06X} ({entry[3]})"
                        break
                f.write(f"              -> {callee_name}\n")
            if len(calls) > 5:
                f.write(f"              ... and {len(calls)-5} more\n")
        if called_by:
            f.write(f"  Called by:  {len(called_by)} function(s)\n")
            for caller in sorted(called_by)[:5]:
                caller_name = f"0x{caller:06X}"
                for entry in catalog:
                    if entry[0] == caller:
                        caller_name = f"0x{caller:06X} ({entry[3]})"
                        break
                f.write(f"              <- {caller_name}\n")
            if len(called_by) > 5:
                f.write(f"              ... and {len(called_by)-5} more\n")
        if apis:
            f.write(f"  APIs:       {', '.join(apis[:8])}\n")
        if strings:
            f.write(f"  Strings:    {len(strings)} reference(s)\n")
            for s in strings[:5]:
                f.write(f"              {s}\n")
        f.write(f"  Description: {desc}\n")
        f.write("\n")

print(f"\nCatalog written to: {OUTPUT_PATH}")
print(f"Total functions: {len(catalog)}")
print("\nModule breakdown:")
for mod in sorted(module_counts.keys()):
    print(f"  {mod:<20} {module_counts[mod]:>6}")
