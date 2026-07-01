#!/usr/bin/env python3
"""
Agent B v2: Robust Function Catalog for .text_unpacked_mem.bin
Scans for functions, disassembles, identifies purpose via embedded strings + behaviour.
"""

import struct, os, re, json
from collections import defaultdict, Counter

try:
    from capstone import *
except ImportError:
    print("pip install capstone")
    exit(1)

BIN_PATH = r"C:\Users\emora\OneDrive\Desktop\2\data\.text_unpacked_mem.bin"
OUTPUT_PATH = r"C:\Users\emora\OneDrive\Desktop\2\logs\agentB_function_catalog.txt"

with open(BIN_PATH, "rb") as f:
    binary = bytearray(f.read())
BIN_SIZE = len(binary)
print(f"Binary: {BIN_SIZE} bytes ({BIN_SIZE/1024/1024:.1f} MB)")

# ---- PHASE 1: Extract embedded ASCII strings from binary ----
print("Extracting embedded strings from binary...")
EMBEDDED_STRINGS = {}  # offset -> string
for i in range(BIN_SIZE):
    if i + 4 > BIN_SIZE:
        break
    if binary[i] == 0:
        continue
    # Try to find null-terminated ASCII (printable)
    end = i
    while end < BIN_SIZE and 32 <= binary[end] < 127:
        end += 1
    if end < BIN_SIZE and binary[end] == 0:
        slen = end - i
        if slen >= 3:
            s = binary[i:end].decode('ascii', errors='replace')
            EMBEDDED_STRINGS[i] = s.lower()
            i = end  # skip past terminator

print(f"  Found {len(EMBEDDED_STRINGS)} embedded ASCII strings in binary")

# Build a set of significant strings for feature detection
SIG_STRINGS = set()
for off, s in EMBEDDED_STRINGS.items():
    if len(s) >= 3 and s not in ('\x00\x00\x00',):
        SIG_STRINGS.add(s)

# ---- PHASE 2: Detect function prologues ----
print("Scanning for function prologues...")

def is_real_prologue(data, offset):
    """Return True if this is a legit function prologue."""
    if offset + 8 > len(data):
        return False
    b = data[offset:offset+8]
    
    # sub rsp, imm8 (48 83 EC XX) - most common
    if b[0] == 0x48 and b[1] == 0x83 and b[2] == 0xEC and b[3] >= 0x08:
        return True
    # sub rsp, imm32 (48 81 EC XX XX XX XX)
    if b[0] == 0x48 and b[1] == 0x81 and b[2] == 0xEC:
        return True
    # push rbp; mov rbp, rsp (55 48 8B EC or 40 55 48 8B EC)
    if b[0] == 0x55 and b[1] == 0x48 and b[2] in (0x8B, 0x89, 0x83):
        return True
    if b[0] == 0x40 and b[1] == 0x55 and b[2] == 0x48 and b[3] in (0x8B, 0x89, 0x83):
        return True
    # mov [rsp+8], rcx (48 89 4C 24 08)
    if b[0] == 0x48 and b[1] == 0x89 and b[2] in (0x4C, 0x54, 0x5C, 0x6C, 0x7C) and b[3] == 0x24:
        if len(b) > 4 and b[4] in (0x08, 0x10, 0x18, 0x20):
            return True
    # push rbx (40 53) followed by sub rsp, imm8 or mov [rsp+8], rcx
    if b[0] == 0x40 and b[1] == 0x53:
        if offset + 10 <= len(data) and data[offset+2] in (0x48, 0x55, 0x56, 0x57):
            return True
    # push rbx + push rbp + push rsi + push rdi (40 53 55 56 57)
    if b[0] == 0x40 and b[1] == 0x53 and b[2] == 0x55 and b[3] == 0x56 and b[4] == 0x57:
        return True
    # push rdi (57) then sub rsp, imm8
    if b[0] == 0x40 and b[1] == 0x57 and b[2] == 0x48:
        return True
    # push r14 + push r15 (41 56 41 57) then sub
    if b[0] == 0x41 and b[1] == 0x56 and b[2] == 0x41 and b[3] == 0x57:
        return True
    # Standard x64: push rbx; push rsi; push rdi; sub rsp, imm8
    if b[0] == 0x40 and b[1] == 0x53 and b[2] == 0x56:
        return True
    
    return False

FUNC_ENTRIES = set()
FAILED = 0
for offset in range(BIN_SIZE - 16):
    if is_real_prologue(binary, offset):
        # Quick smoke test: can first instruction decode?
        try:
            cs = Cs(CS_ARCH_X86, CS_MODE_64)
            cs.detail = True
            gen = cs.disasm(binary[offset:offset+15], offset)
            first = next(gen, None)
            if first and first.size <= 15:
                FUNC_ENTRIES.add(offset)
            else:
                FAILED += 1
        except:
            FAILED += 1

print(f"  Found {len(FUNC_ENTRIES)} prologue candidates ({FAILED} filtered)")

# ---- PHASE 3: Disassemble in a structured way ----
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

disassembled = set()
functions = {}  # rva -> {size, insns, calls, refs, strings, locals}

print("Disassembling functions (pass 1)...")
FUNC_LIST = sorted(FUNC_ENTRIES)
total = len(FUNC_LIST)

def disasm(rva, max_insns=3000):
    """Disassemble one function, return list of capstone instructions."""
    if rva in disassembled:
        return []
    result = []
    off = rva
    for _ in range(max_insns):
        if off >= BIN_SIZE:
            break
        if off in disassembled and off != rva:
            break
        try:
            data = binary[off:off+15]
            for insn in md.disasm(data, off):
                disassembled.add(insn.address)
                result.append(insn)
                if insn.mnemonic in ('ret', 'retf', 'retn'):
                    if insn.address not in FUNC_ENTRIES:
                        return result
                if insn.mnemonic == 'jmp':
                    try:
                        tgt = int(insn.op_str, 0)
                        if tgt in FUNC_ENTRIES and len(result) > 3:
                            return result
                    except:
                        pass
                if insn.mnemonic in ('int3', 'int', 'ud2'):
                    return result
                off = insn.address + insn.size
                break
            else:
                off += 1
        except:
            off += 1
    return result

for i, rva in enumerate(FUNC_LIST):
    if i % 200 == 0:
        print(f"  {i}/{total} ({(i/total*100):.0f}%)")
    insns = disasm(rva)
    if not insns or len(insns) < 2:
        continue
    fn_size = insns[-1].address - rva + insns[-1].size
    
    # Extract call targets
    calls = []
    refs = []
    for insn in insns:
        if insn.mnemonic == 'call':
            try:
                tgt = int(insn.op_str, 0)
                if 0 <= tgt < BIN_SIZE:
                    calls.append(tgt)
                    FUNC_ENTRIES.add(tgt)
            except:
                pass
        elif insn.mnemonic == 'lea':
            op = insn.op_str.lower()
            if 'rip' in op:
                riprel = insn.address + insn.size + struct.unpack('<i', bytes(insn.bytes[-4:]))[0]
                if 0 <= riprel < BIN_SIZE:
                    refs.append(riprel)
    
    functions[rva] = {'size': fn_size, 'insns': insns, 'calls': calls, 'refs': refs}

# Now discover functions found as call targets
NEW = FUNC_ENTRIES - set(functions.keys())
print(f"Pass 2: disassembling {len(NEW)} newly discovered targets...")
for rva in sorted(NEW):
    insns = disasm(rva)
    if not insns or len(insns) < 2:
        continue
    fn_size = insns[-1].address - rva + insns[-1].size
    calls = []
    refs = []
    for insn in insns:
        if insn.mnemonic == 'call':
            try:
                tgt = int(insn.op_str, 0)
                if 0 <= tgt < BIN_SIZE:
                    calls.append(tgt)
                    FUNC_ENTRIES.add(tgt)
            except:
                pass
        elif insn.mnemonic == 'lea':
            op = insn.op_str.lower()
            if 'rip' in op:
                riprel = insn.address + insn.size + struct.unpack('<i', bytes(insn.bytes[-4:]))[0]
                if 0 <= riprel < BIN_SIZE:
                    refs.append(riprel)
    functions[rva] = {'size': fn_size, 'insns': insns, 'calls': calls, 'refs': refs}

# Pass 3
NEW2 = FUNC_ENTRIES - set(functions.keys())
if NEW2:
    print(f"Pass 3: {len(NEW2)} remaining...")
    for rva in sorted(NEW2):
        insns = disasm(rva)
        if not insns or len(insns) < 2:
            continue
        fn_size = insns[-1].address - rva + insns[-1].size
        calls = []; refs = []
        for insn in insns:
            if insn.mnemonic == 'call':
                try:
                    tgt = int(insn.op_str, 0)
                    if 0 <= tgt < BIN_SIZE: calls.append(tgt)
                except: pass
            elif insn.mnemonic == 'lea' and 'rip' in insn.op_str.lower():
                riprel = insn.address + insn.size + struct.unpack('<i', bytes(insn.bytes[-4:]))[0]
                if 0 <= riprel < BIN_SIZE: refs.append(riprel)
        functions[rva] = {'size': fn_size, 'insns': insns, 'calls': calls, 'refs': refs}

print(f"Total disassembled functions: {len(functions)}")

# ---- PHASE 4: Build call graph ----
call_graph = defaultdict(set)  # caller -> set of callees
call_graph_rev = defaultdict(set)  # callee -> set of callers

for rva, fn in functions.items():
    for callee in fn['calls']:
        call_graph[rva].add(callee)
        call_graph_rev[callee].add(rva)

print(f"Call graph edges: {sum(len(v) for v in call_graph.values())}")

# ---- PHASE 5: Extract strings per function ----
print("Extracting function-level string references...")
for rva, fn in functions.items():
    strings = []
    for ref in fn['refs']:
        if ref in EMBEDDED_STRINGS:
            strings.append(EMBEDDED_STRINGS[ref])
    fn['strings'] = strings
    # Also scan disasm text for immediate constants that might be string-like
    mnems = ' '.join(i.mnemonic for i in fn['insns'])
    fn['mnems'] = mnems

# ---- PHASE 6: Classify and name ----
print("Classifying functions...")

def classify_and_name(rva, fn):
    strings = fn.get('strings', [])
    str_text = ' '.join(strings)
    mnems = fn.get('mnems', '')
    calls = fn.get('calls', [])
    size = fn['size']
    refs_count = len(fn.get('refs', []))
    callers = call_graph_rev.get(rva, set())
    
    # Build a richer profile
    has_curl = any('curl' in s for s in strings)
    has_http = any(s in str_text for s in ['http', 'api.', 'request', 'response', 'curl']) or has_curl
    has_replay = any(s in str_text for s in ['replay', 'capture', 'burst', 'probe', 'dispatch', 'replay_cap'])
    has_sc = any(s in str_text for s in ['sc', 'super credit', 'scactivity', 'scloop', 'super_credit', 'req.slip'])
    has_farming = any(s in str_text for s in ['farming', 'reward', 'multiplier', 'mission reward', 'sample', 'medal', 'requisition', 'xp multiply'])
    has_weapon = any(s in str_text for s in ['weapon', 'primary weapon', 'allgun', 'selectedgun', 'xp track'])
    has_auth = any(s in str_text for s in ['auth', 'login', 'password', 'username', 'key', 'subscription', 'validate', 'session', 'license', 'lock screen', 'access key'])
    has_update = any(s in str_text for s in ['inbox', 'letter from', 'message from', 'updates'])
    has_hook = any(s in str_text for s in ['hook', 'detour', 'cave', 'trampoline', 'bytepatch', '64h00k', 'nop patch'])
    has_pattern = any(s in str_text for s in ['pattern', 'signature', 'aob', '48 83 ec', 'scan', 'byte pattern'])
    has_crash = any(s in str_text for s in ['crash', 'exception', 'seh', 'veh', 'exception handler'])
    has_imgui = any(s in str_text for s in ['imgui', 'dear imgui', 'begin', 'end()', 'button', 'checkbox', 'slider', 'combo', 'pop', 'window', 'font'])
    has_crypto = any(s in str_text for s in ['crypt', 'hash', 'encrypt', 'decrypt', 'xor', 'bcrypt', 'base64', 'sha', 'aes', 'signature', 'nonce'])
    has_config = any(s in str_text for s in ['config', 'ini', 'json', 'save', 'load', 'setting'])
    has_memory = any(s in str_text for s in ['virtualprotect', 'virtualalloc', 'heapalloc', 'memcpy', 'writeprocess'])
    has_init = any(s in str_text for s in ['dllmain', 'attach', 'detach', 'initialize', 'thread'])
    has_log = any(s in str_text for s in ['log', 'printf', 'debug', 'trace', '%s', '%d', '%p', '%x'])
    has_cheat = any(s in str_text for s in ['god mod', 'stamina', 'ragdoll', 'recoil', 'turret', 'stratagem', 'hover', 'ammo', 'grenade', 'stim', 'laser', 'railgun', 'killstreak', 'inf ', 'nop ', 'freeze'])
    
    # Check if it looks like a wrapper/forwarder (small function doing single call + ret)
    is_wrapper = len(fn['insns']) <= 5 and len(calls) == 1 and 'jmp' in mnems
    
    # ---- Classification Logic ----
    
    # 1. Check for unique string markers first
    if 'libertea' in str_text or 'l i b e r t e a' in str_text:
        if 'hud' in str_text or 'overlay' in str_text:
            return "IMGUI_RENDER", "HudRenderer::RenderMainUI"
        if 'crash' in str_text or 'log' in str_text:
            return "CRASH_HANDLER", "CrashHandler::WriteLiberteaLog"
        return "INIT", "LiberteaApp::MainInit"
    
    if 'scpresent' in str_text or 'sc_present' in str_text:
        return "INIT", "Window::ScPresentInstall"
    if 'wndproc' in str_text and 'wm_sc_dispatch' in str_text:
        return "INIT", "Window::ScDispatchWndProc"
    if 'queuesc' in str_text:
        return "SC_FARMING", "ScActivityAPC::QueueSCCallback"
    
    # 2. SC Farming specific
    if 'scactivityapc' in str_text:
        return "SC_FARMING", "ScActivityAPC::ActivityCallback"
    if 'scloop' in str_text and 'actobj' in str_text:
        return "SC_FARMING", "ScActivityAPC::ScLoop"
    if '[sc]' in str_text and 'midswap' in str_text:
        return "SC_FARMING", "ScActivityAPC::MissionIdSwap"
    if '[sc]' in str_text and ('batch' in str_text or 'firing' in str_text):
        if 'medal' in str_text:
            return "SC_FARMING", "ScActivityAPC::FireMedalBatch"
        return "SC_FARMING", "ScActivityAPC::FireSCBatch"
    if '[sc]' in str_text and 'sync' in str_text:
        return "SC_FARMING", "ScActivityAPC::SyncPlayers"
    if '[sc]' in str_text and 'cooldown' in str_text:
        return "SC_FARMING", "ScActivityAPC::CooldownTimer"
    if '[sc]' in str_text and 'goal' in str_text:
        return "SC_FARMING", "ScActivityAPC::GoalTracker"
    if '[sc]' in str_text and 'ready' in str_text:
        return "SC_FARMING", "ScActivityAPC::Init"
    if 'sc tracker' in str_text:
        return "SC_FARMING", "ScActivityAPC::RenderSCTracker"
    if 'sc loop' in str_text:
        return "SC_FARMING", "ScActivityAPC::RenderSCLoop"
    if 'super credits' in str_text or 'super_credit' in str_text:
        return "SC_FARMING", "ScActivityAPC::SCOptionsRenderer"
    if 'add samples' in str_text:
        return "SC_FARMING", "ScActivityAPC::SampleOptionsRenderer"
    if 'mission reward' in str_text and 'multiplier' in str_text:
        return "SC_FARMING", "ScActivityAPC::RewardMultiplierRenderer"
    
    # 3. Replay
    if 'replay' in str_text and 'capture' in str_text and 'store' in str_text:
        return "NETWORK", "ReplayCapture::StoreMissionData"
    if 'replay' in str_text and 'dispatch' in str_text:
        return "NETWORK", "ReplayCapture::DispatchReplay"
    if 'buildpayload' in str_text or 'build_payload' in str_text:
        return "NETWORK", "ReplayCapture::BuildPayload"
    if 'golden-capt' in str_text or 'golden capture' in str_text:
        return "NETWORK", "ReplayCapture::GoldenCapture"
    if ('probe' in str_text and 'capture' in str_text) or '[probe]' in str_text.lower():
        return "NETWORK", "ReplayCapture::ProbeThread"
    if 'auto-replay' in str_text or 'auto replay' in str_text:
        return "NETWORK", "ReplayCapture::AutoReplayLoop"
    if 'burst' in str_text and 'replay' in str_text:
        return "NETWORK", "ReplayCapture::BurstDispatch"
    if 'burst loop' in str_text:
        return "NETWORK", "ReplayCapture::BurstLoopRenderer"
    if 'replay' in str_text and 'queued' in str_text:
        return "NETWORK", "ReplayCapture::QueueReplay"
    if 'replay sent' in str_text:
        return "NETWORK", "ReplayCapture::OnReplaySent"
    if 'replay' in str_text and 'log' in str_text:
        return "NETWORK", "ReplayCapture::MissionLogRenderer"
    
    # 4. HTTP / Network
    if 'http]' in str_text.lower() and 'swap' in str_text.lower():
        return "NETWORK", "HttpClient::MissionIdSwapInjector"
    if 'http]' in str_text.lower() and 'inject' in str_text.lower():
        return "NETWORK", "HttpClient::RequestBodyInjector"
    if 'http]' in str_text.lower() and ('setopt' in str_text.lower() or 'writefunction' in str_text.lower()):
        return "NETWORK", "HttpClient::SetWriteCallback"
    if 'http]' in str_text.lower() and 'body' in str_text.lower():
        return "NETWORK", "HttpClient::ReconBody"
    if 'http]' in str_text.lower() and 'header' in str_text.lower():
        return "NETWORK", "HttpClient::ReconHeader"
    if 'http]' in str_text.lower() and 'perform' in str_text.lower():
        return "NETWORK", "HttpClient::PerformRequest"
    if 'http]' in str_text.lower() and 'found' in str_text and 'curl' in str_text.lower():
        return "NETWORK", "HttpClient::FindLibcurl"
    if 'http]' in str_text.lower() and 'resolved' in str_text.lower():
        return "NETWORK", "HttpClient::ResolveCurlExports"
    if 'http]' in str_text.lower():
        return "NETWORK", "HttpClient::HttpHelper"
    if 'mission/end' in str_text:
        return "NETWORK", "HttpClient::MissionEndPost"
    if 'recon-' in str_text.lower():
        return "NETWORK", "HttpClient::ReconLogger"
    if has_http:
        return "NETWORK", "HttpClient::NetworkUtil"
    
    # 5. Weapon XP
    if 'weapon' in str_text and ('override' in str_text or 'weaponovr' in str_text.lower()):
        return "WEAPON_XP", "WeaponXP::OverridePrimaryWeapon"
    if 'weapon' in str_text and 'allgun' in str_text.lower():
        return "WEAPON_XP", "WeaponXP::AllGunsRenderer"
    if 'weapon' in str_text and 'selectedgun' in str_text.lower():
        return "WEAPON_XP", "WeaponXP::SelectedGunsRenderer"
    if 'weapon' in str_text and 'patch' in str_text:
        return "WEAPON_XP", "WeaponXP::PatchWeaponSlot"
    if 'weapon' in str_text and 'editor' in str_text:
        return "ARMORY", "Armory::WeaponStatsEditor"
    if 'weapon' in str_text and 'stat' in str_text:
        return "ARMORY", "Armory::WeaponStatsCapture"
    if 'xp tracker' in str_text:
        return "WEAPON_XP", "WeaponXP::XPTrackerRenderer"
    if 'weapon' in str_text:
        return "WEAPON_XP", "WeaponXP::WeaponHandler"
    
    # 6. Auth
    if 'auth' in str_text and 'failed' in str_text:
        return "AUTH", "AuthClient::AuthFailedHandler"
    if 'lock_screen' in str_text or 'lock screen' in str_text:
        return "AUTH", "AuthClient::RenderLockScreen"
    if 'enter your access key' in str_text:
        return "AUTH", "AuthClient::RenderKeyInput"
    if 'login with your account' in str_text:
        return "AUTH", "AuthClient::RenderLoginForm"
    if 'subscription active' in str_text:
        return "AUTH", "AuthClient::RenderSubscriptionInfo"
    if 'lifetime access' in str_text:
        return "AUTH", "AuthClient::CheckLifetimeAccess"
    if 'checking...' in str_text or 'validat' in str_text and 'key' in str_text:
        return "AUTH", "AuthClient::ValidateKey"
    if 'network error' in str_text and ('check connection' in str_text or 'try again' in str_text):
        return "AUTH", "AuthClient::NetworkErrorHandler"
    if 'hwid' in str_text:
        return "AUTH", "AuthClient::HardwareIDCollector"
    if has_auth:
        return "AUTH", "AuthClient::AuthHelper"
    
    # 7. Hook System
    if 'hook installed' in str_text or 'hook verified' in str_text:
        return "HOOK_SYSTEM", "HookManager::InstallHook"
    if 'hook mismatch' in str_text or 'mismatch' in str_text:
        return "HOOK_SYSTEM", "HookManager::DetectMismatch"
    if 'code cave' in str_text and 'alloc' in str_text:
        return "HOOK_SYSTEM", "HookManager::AllocateCodeCave"
    if 'call-site' in str_text:
        return "HOOK_SYSTEM", "HookManager::AnalyzeCallSite"
    if 'function prologue mismatch' in str_text:
        return "HOOK_SYSTEM", "HookManager::ValidatePrologue"
    if 'aob not found' in str_text:
        return "HOOK_SYSTEM", "HookManager::ReportMissingAOB"
    if '[features]' in str_text and ('found' in str_text or 'not found' in str_text):
        return "HOOK_SYSTEM", "HookManager::FeatureScanResult"
    if '[features]' in str_text and 'toggle' in str_text:
        return "HOOK_SYSTEM", "HookManager::ToggleFeature"
    if '[features]' in str_text and 'protect' in str_text:
        return "HOOK_SYSTEM", "HookManager::MemoryProtectWrapper"
    if 'handler install failed' in str_text:
        return "HOOK_SYSTEM", "HookManager::HandlerFailure"
    if has_hook:
        return "HOOK_SYSTEM", "HookManager::HookUtil"
    
    # 8. Pattern Scanner
    if 'pattern' in str_text and 'found' in str_text:
        return "PATTERN_SCAN", "PatternScanner::ReportFound"
    if 'pattern' in str_text and 'not found' in str_text:
        return "PATTERN_SCAN", "PatternScanner::ReportMissing"
    if 'sig' in str_text and 'capture' in str_text:
        return "PATTERN_SCAN", "PatternScanner::SignatureCapture"
    if has_pattern:
        return "PATTERN_SCAN", "PatternScanner::ScanHelper"
    
    # 9. Combat / Player Cheats
    if 'god mode' in str_text or 'godmode' in str_text:
        return "PLAYER_CHEATS", "PlayerCheats::GodMode"
    if 'inf stamina' in str_text:
        return "PLAYER_CHEATS", "PlayerCheats::InfiniteStamina"
    if 'speed' in str_text and 'cave' in str_text:
        return "PLAYER_CHEATS", "PlayerCheats::SpeedHack"
    if 'no ragdoll' in str_text:
        return "PLAYER_CHEATS", "PlayerCheats::NoRagdoll"
    if 'no recoil' in str_text:
        return "PLAYER_CHEATS", "PlayerCheats::NoRecoil"
    if 'inf ammo' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::InfiniteAmmo"
    if 'no reload' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::NoReload"
    if 'inf grenades' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::InfiniteGrenades"
    if 'inf stims' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::InfiniteStims"
    if 'instant charge' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::InstantCharge"
    if 'no laser overheat' in str_text or 'no laser overheat' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::NoLaserOverheat"
    if 'map hack' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::MapHack"
    if 'hoverpack control' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::HoverpackControl"
    if 'instant strat' in str_text or 'inf strategems' in str_text or 'infinite strat' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::InfiniteStratagems"
    if 'instant shuttle' in str_text or 'instant complete' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::InstantShuttle"
    if 'freeze mission timer' in str_text or 'freezes all countdown' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::FreezeMissionTimer"
    if 'mass strat drop' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::MassStratDrop"
    if 'takeoff force' in str_text or 'hover pack' in str_text or 'jump pack' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::HoverPackEditor"
    if 'grenade' in str_text and 'fuse' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::GrenadeFuseTime"
    if 'no boundary' in str_text or 'bypass boundary' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::NoBoundary"
    if 'instant hellbomb' in str_text or 'hellbomb arm timer' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::InstantHellbomb"
    if 'skip launch code' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::SkipLaunchCode"
    if 'reduce aggro' in str_text or 'aggro function' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::ReduceAggro"
    if 'zero perception' in str_text or 'perception multiply' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::ZeroPerception"
    if 'instant arrows' in str_text or 'arrow sequence' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::InstantArrows"
    if 'instant coordinates' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::InstantCoordinates"
    if 'instant pipes' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::InstantPipes"
    if 'instant arcade round' in str_text or 'arcade combo' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::ArcadeCheats"
    if 'correct combo' in str_text or 'combo mismatch' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::CorrectCombo"
    if 'killstreak' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::KillstreakBonus"
    if 'instant railgun' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::InstantRailgun"
    if 'longer hover' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::LongerHover"
    if 'fast landing' in str_text or 'landing speed' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::FastLanding"
    if 'shield cooldown' in str_text or 'shield relay' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::ShieldCooldown"
    if 'stratagem' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::StratagemHandler"
    if 'turret' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::TurretHandler"
    if 'eraser' in str_text and 'editor' in str_text:
        return "COMBAT_CHEATS", "CombatCheats::EradicationEditor"
    if has_cheat:
        return "COMBAT_CHEATS", "CombatCheats::CheatUtil"
    
    # 10. Armory
    if 'unlock all armory' in str_text:
        return "ARMORY", "Armory::UnlockAllArmory"
    if 'armor passive' in str_text:
        return "ARMORY", "Armory::ArmorPassiveEditor"
    if 'weapon stats editor' in str_text:
        return "ARMORY", "Armory::WeaponStatsEditor"
    if 'armor base' in str_text or 'tactician' in str_text or 'perk' in str_text:
        return "ARMORY", "Armory::ArmorPerksRenderer"
    
    # 11. ImGui
    if has_imgui and ('render' in str_text or 'overlay' in str_text or 'hud' in str_text):
        return "IMGUI_RENDER", "ImGuiRenderer::RenderFrame"
    if has_imgui:
        return "IMGUI_RENDER", "ImGuiRenderer::ImGuiWrapper"
    
    # 12. Crypto
    if 'machineguid' in str_text or 'hwid' in str_text:
        return "CRYPTO", "Crypto::GetHardwareId"
    if 'bcrypthashdata' in str_text or 'bcrypt' in str_text:
        return "CRYPTO", "Crypto::HashData"
    if 'base64' in str_text:
        return "CRYPTO", "Crypto::Base64Codec"
    if (('encrypt' in str_text or 'decrypt' in str_text) and ('key' in str_text or 'iv' in str_text)):
        return "CRYPTO", "Crypto::AESCipher"
    if 'xor' in mnems and 'loop' in mnems and len(fn['insns']) < 50:
        # Small function that does XOR looping - possible XOR cipher
        pass  # Don't assume - let it fall through
    if has_crypto:
        return "CRYPTO", "Crypto::CryptoHelper"
    
    # 13. Crash Handler
    if 'crash log' in str_text or 'crash' in str_text and 'exception' in str_text:
        return "CRASH_HANDLER", "CrashHandler::WriteCrashLog"
    if 'crashes absorbed' in str_text:
        return "CRASH_HANDLER", "CrashHandler::CrashCounterRenderer"
    if has_crash:
        return "CRASH_HANDLER", "CrashHandler::Handler"
    
    # 14. Update
    if 'updates' in str_text and ('letter from' in str_text or 'delete' in str_text):
        return "UPDATE", "UpdateSystem::InboxRenderer"
    if has_update:
        return "UPDATE", "UpdateSystem::CheckForUpdates"
    
    # 15. Config
    if 'imgui.ini' in str_text:
        return "CONFIG", "Config::ImGuiConfigLoader"
    if has_config:
        return "CONFIG", "Config::ConfigHelper"
    
    # 16. Memory
    if 'virtualprotect' in str_text or 'ntprotectvirtualmemory' in str_text:
        return "MEMORY", "Memory::ProtectMemory"
    if 'syscall stub' in str_text or 'syscall#' in str_text.lower():
        return "MEMORY", "Memory::SyscallStubBuilder"
    if 'protection layer' in str_text:
        return "MEMORY", "Memory::ProtectionLayers"
    if 'all layers failed' in str_text:
        return "MEMORY", "Memory::AllLayersFailed"
    if has_memory:
        return "MEMORY", "Memory::MemoryHelper"
    
    # 17. Log
    if has_log and ('%s' in str_text or '%d' in str_text) and '[' in str_text:
        return "LOGGING", "Logging::DebugPrintf"
    if has_log:
        return "LOGGING", "Logging::LogWriter"
    
    # 18. Init
    if '[init]' in str_text or 'dllmain' in str_text:
        return "INIT", "Init::DllMain"
    if 'helldivers 2' in str_text and ('loaded' in str_text or 'not loaded' in str_text):
        return "INIT", "Init::WaitForGameModule"
    if 'getmoduleinformation failed' in str_text:
        return "INIT", "Init::ModuleInfoFailure"
    if 'all paths failed' in str_text:
        return "INIT", "Init::ModulePathFailure"
    if 'dumped' in str_text and 'mb' in str_text.lower():
        return "INIT", "Init::DumpModule"
    if 'ntdll.dll' in str_text and 'handle' in str_text:
        return "INIT", "Init::GetNtdllHandle"
    if has_init:
        return "INIT", "Init::InitHelper"
    
    # 19. Fallback heuristics based on analysis
    # Check instruction composition
    call_count = len(calls)
    
    if is_wrapper:
        return "UNKNOWN", f"Wrapper_0x{rva:06X}"
    
    # Check mnemonics for known patterns
    if 'divss' in mnems or 'mulss' in mnems or 'sqrtss' in mnems:
        # Float math - could be game logic, physics, or cheat calculation
        if 'cmp' in mnems and 'jmp' in mnems:
            return "COMBAT_CHEATS", f"CombatCheats::FloatCalc_0x{rva:06X}"
    
    if 'movaps' in mnems or 'movups' in mnems or 'xorpd' in mnems:
        # SSE/AVX math
        return "UNKNOWN", f"SseMath_0x{rva:06X}"
    
    if call_count == 0 and len(fn['insns']) <= 10:
        return "UNKNOWN", f"Leaf_0x{rva:06X}"
    
    if call_count == 0 and len(fn['insns']) <= 30:
        return "UNKNOWN", f"SmallUtil_0x{rva:06X}"
    
    if call_count == 0:
        return "UNKNOWN", f"Standalone_0x{rva:06X}"
    
    if call_count <= 3 and len(fn['insns']) <= 20:
        return "UNKNOWN", f"Coordinator_0x{rva:06X}"
    
    # Distribution analysis - if multiple callers, could be shared utility
    callers_count = len(callers)
    if callers_count >= 10 and refs_count >= 2:
        return "MEMORY", f"SharedMemoryUtil_0x{rva:06X}"
    if callers_count >= 5:
        return "UNKNOWN", f"SharedHelper_0x{rva:06X}"
    
    return "UNKNOWN", f"Func_0x{rva:06X}"


# ---- Apply classification ----
for rva, fn in functions.items():
    module, name = classify_and_name(rva, fn)
    fn['module'] = module
    fn['name'] = name

# ---- Build output ----
print("Writing catalog...")

module_counts = Counter()
module_sizes = Counter()
for fn in functions.values():
    module_counts[fn['module']] += 1
    module_sizes[fn['module']] += fn['size']

# Sort functions by module then name
sorted_funcs = sorted(functions.items(), key=lambda x: (x[1]['module'], x[1]['name'], x[0]))

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    f.write("=" * 110 + "\n")
    f.write("  AGENT B: COMPLETE FUNCTION CATALOG\n")
    f.write(f"  Binary: .text_unpacked_mem.bin ({BIN_SIZE} bytes, {BIN_SIZE/1024/1024:.1f} MB)\n")
    f.write(f"  Total functions cataloged: {len(functions)}\n")
    f.write("=" * 110 + "\n\n")
    
    f.write("MODULE SUMMARY\n" + "-" * 90 + "\n")
    for mod in sorted(module_counts.keys()):
        f.write(f"  {mod:<22} {module_counts[mod]:>6} functions  ({module_sizes[mod]:>10} bytes, {module_sizes[mod]/1024:>8.1f} KB)\n")
    f.write("-" * 90 + "\n")
    f.write(f"  {'TOTAL':<22} {sum(module_counts.values()):>6} functions  ({sum(module_sizes.values()):>10} bytes, {sum(module_sizes.values())/1024:>8.1f} KB)\n")
    f.write("=" * 110 + "\n\n")
    
    # Call graph stats
    f.write("CALL GRAPH STATISTICS\n" + "-" * 90 + "\n")
    total_edges = sum(len(v) for v in call_graph.values())
    f.write(f"  Total call edges: {total_edges}\n")
    f.write(f"  Most called functions:\n")
    most_called = sorted(call_graph_rev.items(), key=lambda x: -len(x[1]))[:15]
    for rva, callers in most_called:
        name = functions[rva]['name'] if rva in functions else f"0x{rva:06X}"
        f.write(f"    [0x{rva:06X}] {len(callers):>4} callers -> {name}\n")
    
    f.write(f"\n  Largest functions:\n")
    biggest = sorted(functions.items(), key=lambda x: -x[1]['size'])[:15]
    for rva, fn in biggest:
        f.write(f"    [0x{rva:06X}] {fn['size']:>6} bytes -> [{fn['module']}] {fn['name']}\n")
    f.write("=" * 110 + "\n\n")
    
    # Detailed catalog
    f.write("DETAILED FUNCTION CATALOG\n" + "=" * 110 + "\n\n")
    
    for rva, fn in sorted_funcs:
        name = fn['name']
        module = fn['module']
        size = fn['size']
        calls = fn['calls']
        strings = fn.get('strings', [])
        callers = sorted(call_graph_rev.get(rva, set()))
        
        f.write(f"[0x{rva:06X}] [{size:>6}] [{module}] {name}\n")
        
        if calls:
            f.write(f"  Calls ({len(calls)}):\n")
            for callee in sorted(calls)[:5]:
                cn = functions[callee]['name'] if callee in functions else f"0x{callee:06X}"
                f.write(f"    -> [0x{callee:06X}] {cn}\n")
            if len(calls) > 5:
                f.write(f"    ... +{len(calls)-5} more\n")
        
        if callers:
            f.write(f"  Called by ({len(callers)}):\n")
            for caller in sorted(callers)[:5]:
                cn = functions[caller]['name'] if caller in functions else f"0x{caller:06X}"
                f.write(f"    <- [0x{caller:06X}] {cn}\n")
            if len(callers) > 5:
                f.write(f"    ... +{len(callers)-5} more\n")
        
        if strings:
            uniq = list(dict.fromkeys(strings))[:8]
            f.write(f"  Strings: {', '.join(repr(s[:50]) for s in uniq)}\n")
        
        # Quick opcode summary for unknown functions
        if module == 'UNKNOWN':
            mnems = fn.get('mnems', '')
            f.write(f"  Mnems: {mnems[:120]}\n")
        else:
            # Description based on strings and classification
            desc_parts = []
            if strings:
                key_strings = [s[:60] for s in strings[:3] if len(s) > 5]
                if key_strings:
                    desc_parts.append("Key strings: " + ", ".join(key_strings))
            if calls and module not in ('UNKNOWN',):
                called_names = set(functions[c]['name'] for c in calls if c in functions)
                if called_names:
                    desc_parts.append("Calls: " + ", ".join(list(called_names)[:4]))
            if desc_parts:
                f.write(f"  Desc: {' | '.join(desc_parts)}\n")
        
        f.write("\n")

print(f"\nDone! Wrote to {OUTPUT_PATH}")
print(f"\nModule breakdown:")
for mod, cnt in module_counts.most_common():
    print(f"  {mod:<22} {cnt:>6}")
print(f"\n  {'TOTAL':<22} {sum(module_counts.values()):>6}")
