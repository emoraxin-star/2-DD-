#!/usr/bin/env python3
"""
Agent B v3: With call-graph propagation, better string extraction, and richer heuristics.
"""

import struct, os, re, json
from collections import defaultdict, Counter, deque

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

# ==== Phase 1: Extract embedded strings ====
print("Extracting embedded strings...")
EMBEDDED_STRINGS = {}
for i in range(BIN_SIZE - 4):
    if binary[i] == 0: continue
    end = i
    while end < BIN_SIZE and 32 <= binary[end] < 127:
        end += 1
    if end < BIN_SIZE and binary[end] == 0 and end - i >= 3:
        s = binary[i:end].decode('ascii', errors='replace')
        EMBEDDED_STRINGS[i] = s
        i = end
print(f"  {len(EMBEDDED_STRINGS)} embedded ASCII strings")

# ==== Phase 2: Detect function prologues ====
print("Scanning for function prologues...")

def is_prologue(data, off):
    if off + 8 > len(data): return False
    b = data[off:off+8]
    # sub rsp, imm8
    if b[0] == 0x48 and b[1] == 0x83 and b[2] == 0xEC and b[3] >= 0x08:
        return True
    # sub rsp, imm32
    if b[0] == 0x48 and b[1] == 0x81 and b[2] == 0xEC:
        return True
    # push rbp; mov rbp, rsp
    if b[0] == 0x55 and b[1] == 0x48 and b[2] in (0x8B, 0x89):
        return True
    # mov [rsp+8], rcx
    if b[0] == 0x48 and b[1] == 0x89 and b[2] in (0x4C, 0x54, 0x5C, 0x6C, 0x7C) and b[3] == 0x24:
        if len(b) > 4 and b[4] in (0x08, 0x10, 0x18, 0x20):
            return True
    # push rbx (40 53) followed by typical
    if b[0] == 0x40 and b[1] == 0x53 and b[2] in (0x48, 0x55, 0x56, 0x57):
        return True
    # push rbx; push rbp; push rsi; push rdi
    if b[0] == 0x40 and b[1] == 0x53 and b[2] == 0x55 and b[3] == 0x56 and b[4] == 0x57:
        return True
    # push rdi then sub rsp
    if b[0] == 0x40 and b[1] == 0x57 and b[2] == 0x48:
        return True
    # push r14; push r15
    if b[0] == 0x41 and b[1] == 0x56 and b[2] == 0x41 and b[3] == 0x57:
        return True
    # push rbx; push rsi
    if b[0] == 0x40 and b[1] == 0x53 and b[2] == 0x56:
        return True
    # push rbp (just push rbp, then sub rsp or mov)
    if b[0] == 0x55 and b[1] == 0x48 and b[2] == 0x83 and b[3] == 0xEC:
        return True
    return False

FUNC_ENTRIES = set()
for off in range(BIN_SIZE - 16):
    if is_prologue(binary, off):
        FUNC_ENTRIES.add(off)
print(f"  {len(FUNC_ENTRIES)} prologue candidates")

# ==== Phase 3: Disassemble ====
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
disassembled = set()
functions = {}

def disasm(rva, max_insns=3000):
    if rva in disassembled: return []
    result = []
    off = rva
    for _ in range(max_insns):
        if off >= BIN_SIZE: break
        if off in disassembled and off != rva: break
        try:
            for insn in md.disasm(binary[off:off+15], off):
                disassembled.add(insn.address)
                result.append(insn)
                if insn.mnemonic in ('ret', 'retf', 'retn'):
                    if insn.address not in FUNC_ENTRIES:
                        return result
                if insn.mnemonic == 'jmp':
                    try:
                        if int(insn.op_str, 0) in FUNC_ENTRIES and len(result) > 3:
                            return result
                    except: pass
                if insn.mnemonic in ('int3', 'int', 'ud2'):
                    return result
                off = insn.address + insn.size
                break
            else:
                off += 1
        except:
            off += 1
    return result

FUNC_LIST = sorted(FUNC_ENTRIES)
print(f"Disassembling (pass 1: {len(FUNC_LIST)} candidates)...")
for i, rva in enumerate(FUNC_LIST):
    if i % 300 == 0: print(f"  {i}/{len(FUNC_LIST)}")
    insns = disasm(rva)
    if not insns or len(insns) < 2: continue
    size = insns[-1].address - rva + insns[-1].size
    calls = []; refs = []
    for insn in insns:
        if insn.mnemonic == 'call':
            try:
                t = int(insn.op_str, 0)
                if 0 <= t < BIN_SIZE: calls.append(t); FUNC_ENTRIES.add(t)
            except: pass
        elif insn.mnemonic == 'lea' and 'rip' in insn.op_str.lower():
            riprel = insn.address + insn.size + struct.unpack('<i', bytes(insn.bytes[-4:]))[0]
            if 0 <= riprel < BIN_SIZE: refs.append(riprel)
    functions[rva] = {'size': size, 'insns': insns, 'calls': calls, 'refs': refs}

# Discover new targets
for p in range(2, 5):
    new = FUNC_ENTRIES - set(functions.keys())
    if not new: break
    print(f"Pass {p}: {len(new)} new targets...")
    for i, rva in enumerate(sorted(new)):
        if i % 400 == 0: print(f"  {i}/{len(new)}")
        insns = disasm(rva)
        if not insns or len(insns) < 2: continue
        size = insns[-1].address - rva + insns[-1].size
        calls = []; refs = []
        for insn in insns:
            if insn.mnemonic == 'call':
                try:
                    t = int(insn.op_str, 0)
                    if 0 <= t < BIN_SIZE: calls.append(t); FUNC_ENTRIES.add(t)
                except: pass
            elif insn.mnemonic == 'lea' and 'rip' in insn.op_str.lower():
                riprel = insn.address + insn.size + struct.unpack('<i', bytes(insn.bytes[-4:]))[0]
                if 0 <= riprel < BIN_SIZE: refs.append(riprel)
        functions[rva] = {'size': size, 'insns': insns, 'calls': calls, 'refs': refs}

print(f"Total functions: {len(functions)}")

# ==== Phase 4: Build call graph ====
call_graph = defaultdict(set)
call_graph_rev = defaultdict(set)
for rva, fn in functions.items():
    for c in fn['calls']:
        call_graph[rva].add(c)
        call_graph_rev[c].add(rva)

print(f"Call edges: {sum(len(v) for v in call_graph.values())}")

# ==== Phase 5: Extract strings and features per function ====
print("Extracting per-function features...")
for rva, fn in functions.items():
    strings = []
    for ref in fn['refs']:
        if ref in EMBEDDED_STRINGS:
            strings.append(EMBEDDED_STRINGS[ref])
    fn['strings'] = list(dict.fromkeys(strings))  # unique, order preserved
    
    # Instruction analysis
    mnems = []
    has_xmm = has_stack_frame = has_loop = has_call = has_ret = False
    push_count = sub_count = 0
    for insn in fn['insns']:
        mnems.append(insn.mnemonic)
        if insn.mnemonic.startswith('push'): push_count += 1
        if insn.mnemonic == 'sub': sub_count += 1
        if 'xmm' in insn.op_str or insn.mnemonic.startswith('mov') and 'xmm' in insn.op_str:
            has_xmm = True
        if insn.mnemonic in ('loop', 'loopne', 'loope'):
            has_loop = True
        if insn.mnemonic == 'call':
            has_call = True
        if insn.mnemonic in ('ret', 'retn'):
            has_ret = True
    
    fn['mnem_counter'] = Counter(mnems)
    fn['has_xmm'] = has_xmm
    fn['has_call'] = has_call
    fn['push_count'] = push_count
    fn['sub_count'] = sub_count
    fn['insn_count'] = len(fn['insns'])
    fn['call_count'] = len(fn['calls'])
    fn['ref_count'] = len(fn['refs'])

# ==== Phase 6: Primary classification (string-based) ====
print("Phase 6: Primary string-based classification...")

STRONG_SIGNALS = {}
for rva, fn in functions.items():
    strings = fn['strings']
    st = ' '.join(strings)
    
    if any(s in st for s in ['scactivityapc', 'sc] ', 'super credits', 'super_credit', 'sc tracker', 'sc loop']):
        STRONG_SIGNALS[rva] = ('SC_FARMING', 100)
    elif any(s in st for s in ['replay', 'capture', 'burst', 'probe', 'dispatch', 'replay_cap', 'golden-capt']):
        STRONG_SIGNALS[rva] = ('NETWORK', 90)
    elif any(s in st for s in ['http]', 'curl', 'winhttp', 'mission/end']):
        STRONG_SIGNALS[rva] = ('NETWORK', 85)
    elif any(s in st for s in ['weapon', 'allgun', 'selectedgun', 'primary weapon', 'xp tracker']):
        STRONG_SIGNALS[rva] = ('WEAPON_XP', 100)
    elif any(s in st for s in ['auth', 'login', 'password', 'username', 'subscription', 'license', 'lock screen', 'access key']):
        STRONG_SIGNALS[rva] = ('AUTH', 100)
    elif any(s in st for s in ['hook installed', 'hook mismatch', 'call-site', 'code cave', 'aob not found', 'handler install']):
        STRONG_SIGNALS[rva] = ('HOOK_SYSTEM', 100)
    elif any(s in st for s in ['god mode', 'godmode', 'inf stamina', 'speed', 'rage doll', 'no recoil', 'no ragdoll']):
        STRONG_SIGNALS[rva] = ('PLAYER_CHEATS', 100)
    elif any(s in st for s in ['stratagem', 'turret', 'grenade', 'stim', 'ammo', 'reload', 'laser', 'railgun', 'killstreak',
                                'hellbomb', 'hover', 'landing', 'boundary', 'shield', 'freeze mission', 'instant shuttle',
                                'mass strat', 'nop ', 'bypass']):
        STRONG_SIGNALS[rva] = ('COMBAT_CHEATS', 90)
    elif any(s in st for s in ['armory', 'unlock all', 'armor passive', 'weapon stats editor', 'weapon editor']):
        STRONG_SIGNALS[rva] = ('ARMORY', 100)
    elif any(s in st for s in ['imgui', 'dear imgui', 'begin(', '##']):
        STRONG_SIGNALS[rva] = ('IMGUI_RENDER', 90)
    elif any(s in st for s in ['pattern', 'signature', 'aob']):
        STRONG_SIGNALS[rva] = ('PATTERN_SCAN', 80)
    elif any(s in st for s in ['crash', 'exception', 'seh', 'veh']):
        STRONG_SIGNALS[rva] = ('CRASH_HANDLER', 90)
    elif any(s in st for s in ['update', 'inbox', 'letter from']):
        STRONG_SIGNALS[rva] = ('UPDATE', 80)
    elif any(s in st for s in ['machineguid', 'hwid', 'bcrypt', 'base64', 'encrypt', 'decrypt']):
        STRONG_SIGNALS[rva] = ('CRYPTO', 80)
    elif any(s in st for s in ['config', 'imgui.ini', '.json']):
        STRONG_SIGNALS[rva] = ('CONFIG', 70)
    elif any(s in st for s in ['virtualprotect', 'virtualalloc', 'syscall stub', 'protection layer']):
        STRONG_SIGNALS[rva] = ('MEMORY', 80)
    elif any(s in st for s in ['dllmain', 'attach', 'detach', 'helldivers']):
        STRONG_SIGNALS[rva] = ('INIT', 70)
    elif any(s in st for s in ['log', 'printf', 'debug', '%s', '%d', '%p']):
        STRONG_SIGNALS[rva] = ('LOGGING', 40)

print(f"  Primary signals: {len(STRONG_SIGNALS)}")

# ==== Phase 7: Call-graph propagation ====
print("Phase 7: Call-graph propagation...")

queue = deque()
module_votes = defaultdict(lambda: defaultdict(int))  # rva -> {module -> weight}

# Seed with primary signals
for rva, (module, weight) in STRONG_SIGNALS.items():
    module_votes[rva][module] = weight
    queue.append(rva)

# BFS propagation
BFS_MAX_DEPTH = 3
depth = {rva: 0 for rva in STRONG_SIGNALS}

propagation_count = 0
while queue:
    rva = queue.popleft()
    cur_depth = depth.get(rva, 0)
    if cur_depth > BFS_MAX_DEPTH: continue
    
    # Get dominant module
    if rva not in module_votes or not module_votes[rva]: continue
    main_module = max(module_votes[rva], key=module_votes[rva].get)
    main_weight = module_votes[rva][main_module]
    
    # Only propagate strong signals (weight > 30)
    if main_weight < 40: continue
    
    decay = 0.65 ** cur_depth  # Weight decays with distance
    
    # Propagate to callers
    for caller in call_graph_rev.get(rva, set()):
        new_weight = main_weight * decay * 0.5
        if new_weight > module_votes[caller].get(main_module, 0):
            module_votes[caller][main_module] = new_weight
            if caller not in depth:
                depth[caller] = cur_depth + 1
                queue.append(caller)
                propagation_count += 1
    
    # Propagate to callees
    for callee in call_graph.get(rva, set()):
        new_weight = main_weight * decay * 0.5
        if new_weight > module_votes[callee].get(main_module, 0):
            module_votes[callee][main_module] = new_weight
            if callee not in depth:
                depth[callee] = cur_depth + 1
                queue.append(callee)
                propagation_count += 1

print(f"  Propagation: {propagation_count} function module assignments")

# ==== Phase 8: Heuristic classification for remaining unknowns ====
print("Phase 8: Heuristic classification...")

for rva, fn in functions.items():
    if rva in module_votes: continue
    mnems = fn['mnem_counter']
    strings = fn['strings']
    st = ' '.join(strings)
    size = fn['size']
    insn_count = fn['insn_count']
    
    # Check if it's an ImGui function by instruction pattern
    if fn['call_count'] >= 3 and insn_count <= 30:
        # Small coordinator
        module_votes[rva]['UNKNOWN'] = 10
        continue
    
    # Check for XMM-heavy functions (likely math/graphics)
    if fn['has_xmm'] and insn_count > 20:
        module_votes[rva]['UNKNOWN'] = 10
    
    # Check for typical "feature toggle" pattern
    if fn['call_count'] == 1 and insn_count <= 10:
        callee = fn['calls'][0]
        if callee in module_votes:
            callee_mod = max(module_votes[callee], key=module_votes[callee].get)
            module_votes[rva][callee_mod] = 20
        else:
            module_votes[rva]['UNKNOWN'] = 5
    else:
        module_votes[rva]['UNKNOWN'] = 5

# ==== Phase 9: Final module assignment and naming ====
print("Phase 9: Final module assignment and naming...")

def get_module(rva):
    if rva not in module_votes or not module_votes[rva]: return 'UNKNOWN'
    return max(module_votes[rva], key=module_votes[rva].get)

def get_name(rva, fn):
    module = get_module(rva)
    strings = fn['strings']
    st = ' '.join(strings).lower()
    size = fn['size']
    calls = fn['calls']
    callers = sorted(call_graph_rev.get(rva, set()))
    insn_count = fn['insn_count']
    
    # === SC_FARMING ===
    if module == 'SC_FARMING':
        if 'scactivityapc' in st: return "ScActivityAPC::ActivityCallback"
        if 'scloop' in st and 'actobj' in st: return "ScActivityAPC::ScLoop"
        if 'midswap' in st: return "ScActivityAPC::MissionIdSwap"
        if ('batch' in st or 'firing' in st) and 'medal' in st: return "ScActivityAPC::FireMedalBatch"
        if ('batch' in st or 'firing' in st) and 'sc' in st: return "ScActivityAPC::FireSCBatch"
        if 'syncnow' in st or 'sync' in st: return "ScActivityAPC::SyncPlayers"
        if 'auto sync' in st: return "ScActivityAPC::AutoSyncRenderer"
        if 'cooldown' in st: return "ScActivityAPC::CooldownTimer"
        if 'goal' in st: return "ScActivityAPC::GoalChecker"
        if 'sc tracker' in st: return "ScActivityAPC::RenderSCTracker"
        if 'sc loop' in st and 'on' in st: return "ScActivityAPC::RenderSCLoopToggle"
        if 'sc goal' in st: return "ScActivityAPC::RenderSCGoal"
        if 'super credit' in st: return "ScActivityAPC::SuperCreditsUI"
        if 'add sample' in st: return "ScActivityAPC::AddSamplesUI"
        if 'sample' in st and 'reward' in st: return "ScActivityAPC::SampleRewardUI"
        if 'medal' in st: return "ScActivityAPC::MedalOptionsUI"
        if 'reduce aggro' in st: return "ScActivityAPC::ReduceAggroToggle"
        if 'zero perception' in st: return "ScActivityAPC::ZeroPerceptionToggle"
        if 'instant arrow' in st: return "ScActivityAPC::InstantArrowsToggle"
        if 'remove sc limit' in st: return "ScActivityAPC::RemoveSCLimitToggle"
        if 'queue' in st or 'postmessage' in st: return "ScActivityAPC::QueueSCCallback"
        if '[sc' in st: return "ScActivityAPC::LogHelper"
        if size > 2000: return "ScActivityAPC::MainPanelRenderer"
        return f"ScActivityAPC::Helper_{rva:06X}"
    
    # === NETWORK ===
    if module == 'NETWORK':
        if 'replay' in st and ('queued' in st or 'sent' in st): return "ReplayCapture::LogEntry"
        if 'replay' in st and 'log' in st: return "ReplayCapture::MissionLogRenderer"
        if 'storemission' in st or 'store mission' in st: return "ReplayCapture::StoreMissionData"
        if 'buildpayload' in st or 'build payload' in st: return "ReplayCapture::BuildPayload"
        if 'dispatch' in st: return "ReplayCapture::DispatchReplay"
        if 'golden' in st or 'golden-capt' in st: return "ReplayCapture::GoldenCaptureHandler"
        if 'probe' in st: return "ReplayCapture::ProbeThread"
        if 'auto-replay' in st or 'auto replay' in st: return "ReplayCapture::AutoReplayLoop"
        if 'burst loop' in st and 'fire' in st: return "ReplayCapture::BurstLoopFire"
        if 'burst' in st and 'looping' in st: return "ReplayCapture::BurstLoopRender"
        if 'burst' in st and 'send' in st: return "ReplayCapture::BurstDispatch"
        if 'burst' in st: return "ReplayCapture::BurstHandler"
        if 'watchdog' in st: return "ReplayCapture::WatchdogTimer"
        if 'crash' in st and 'buildpayload' in st: return "ReplayCapture::BuildPayloadCrash"
        if 'weaponstats' in st and 'crash' in st: return "ReplayCapture::WeaponStatsCrash"
        if 'weaponstats' in st: return "ReplayCapture::SendWeaponStats"
        if 'weaponovr' in st: return "ReplayCapture::PatchWeaponOverride"
        if 'allgun' in st and 'weapon' in st: return "ReplayCapture::AllGunsCycleEntry"
        if 'selectedgun' in st: return "ReplayCapture::SelectedGunsCycleEntry"
        if 'replay' in st: return "ReplayCapture::ReplayUtil"
        if 'http' in st and 'swap' in st: return "HttpClient::MissionIdSwap"
        if 'http' in st and 'inject' in st: return "HttpClient::RequestInjector"
        if 'http' in st and 'setopt' in st: return "HttpClient::SetCurlOption"
        if 'http' in st and 'perform' in st: return "HttpClient::PerformRequest"
        if 'http' in st and 'body' in st: return "HttpClient::ReconBodyChunk"
        if 'http' in st and 'header' in st: return "HttpClient::ReconHeader"
        if 'http' in st and 'resp' in st: return "HttpClient::ReconResponse"
        if 'http' in st and 'found' in st: return "HttpClient::FindLibcurl"
        if 'http' in st and 'resolved' in st: return "HttpClient::ResolveCurlExports"
        if 'http' in st and 'clone' in st: return "HttpClient::CloneCurl"
        if 'http' in st and 'activity' in st: return "HttpClient::ActivityWriteCallback"
        if 'recon-' in st: return "HttpClient::ReconLogger"
        if 'mission/end' in st: return "HttpClient::MissionEndPost"
        if 'sig-capture' in st or 'sig-chunk' in st: return "HttpClient::SignatureCapture"
        if 'call-site' in st: return "HttpClient::CallSiteAnalyzer"
        if size > 3000: return "HttpClient::MainNetworkHandler"
        return f"HttpClient::NetHelper_{rva:06X}"
    
    # === WEAPON_XP ===
    if module == 'WEAPON_XP':
        if 'override' in st or 'weaponovr' in st: return "WeaponXP::OverridePrimaryWeapon"
        if 'allgun' in st and 'weapon' in st: return "WeaponXP::AllGunsRenderer"
        if 'selectedgun' in st: return "WeaponXP::SelectedGunsRenderer"
        if 'patch' in st and 'weapon' in st: return "WeaponXP::PatchWeaponSlots"
        if 'rotate' in st or 'next weapon' in st: return "WeaponXP::RotateToNextWeapon"
        if 'xp tracker' in st: return "WeaponXP::XPTrackerRenderer"
        if 'id:' in st: return "WeaponXP::WeaponIdDisplay"
        return f"WeaponXP::Helper_{rva:06X}"
    
    # === AUTH ===
    if module == 'AUTH':
        if 'lock screen' in st or 'lock_screen' in st: return "AuthClient::RenderLockScreen"
        if 'login with' in st or 'username' in st:
            if 'password' in st: return "AuthClient::RenderLoginForm"
            return "AuthClient::RenderUsernameInput"
        if 'enter your access key' in st: return "AuthClient::RenderKeyInput"
        if 'subscription active' in st: return "AuthClient::RenderSubscriptionInfo"
        if 'lifetime access' in st: return "AuthClient::CheckLifetimeAccess"
        if 'remaining' in st: return "AuthClient::FormatRemainingTime"
        if 'checking...' in st: return "AuthClient::ValidateCredentials"
        if 'network error' in st: return "AuthClient::NetworkErrorHandler"
        if 'invalid key' in st or 'access revoked' in st: return "AuthClient::AccessDeniedHandler"
        if 'invalid username' in st: return "AuthClient::InvalidCredentialsHandler"
        if 'session expired' in st: return "AuthClient::SessionExpiredHandler"
        if 'hwid' in st: return "AuthClient::HardwareIdCollector"
        if 'discord' in st: return "AuthClient::DiscordLinkHandler"
        if 'made by' in st or 'liber' in st: return "AuthClient::CreditsRenderer"
        return f"AuthClient::Helper_{rva:06X}"
    
    # === HOOK_SYSTEM ===
    if module == 'HOOK_SYSTEM':
        if 'install' in st and 'hook' in st: return "HookManager::InstallHook"
        if 'verify' in st and 'hook' in st: return "HookManager::VerifyHooks"
        if 'mismatch' in st: return "HookManager::DetectMismatch"
        if 'code cave' in st: return "HookManager::AllocateCodeCave"
        if 'call-site' in st and 'readable' in st: return "HookManager::AnalyzeCallSite"
        if 'call-site' in st: return "HookManager::CallSiteResolver"
        if 'function prologue mismatch' in st: return "HookManager::ValidatePrologue"
        if 'function prologue' in st: return "HookManager::ReadPrologue"
        if 'aob not found' in st: return "HookManager::ReportMissingAOB"
        if 'cave alloc failed' in st: return "HookManager::CaveAllocFailure"
        if 'handler install failed' in st: return "HookManager::HandlerFailure"
        if 'setup failed' in st: return "HookManager::SetupFailure"
        if '[features]' in st and 'found' in st: return "HookManager::FeatureFoundReport"
        if '[features]' in st and 'not found' in st: return "HookManager::FeatureNotFoundReport"
        if '[features]' in st and 'toggle' in st: return "HookManager::ToggleFeature"
        if '[features]' in st and 'layer' in st: return "HookManager::ProtectionLayerStatus"
        if '[features]' in st and 'ntdll' in st: return "HookManager::NtdllHandleStatus"
        if '[features]' in st: return "HookManager::FeatureLogger"
        if 'hook installed' in st: return "HookManager::InstallConfirmation"
        return f"HookManager::Util_{rva:06X}"
    
    # === PLAYER_CHEATS ===
    if module == 'PLAYER_CHEATS':
        if 'god mode' in st: return "PlayerCheats::GodMode"
        if 'godmode' in st: return "PlayerCheats::GodModeRenderer"
        if 'inf stamina' in st: return "PlayerCheats::InfiniteStamina"
        if 'movement speed' in st: return "PlayerCheats::SpeedHackRenderer"
        if 'speed' in st: return "PlayerCheats::SpeedHack"
        if 'no ragdoll' in st: return "PlayerCheats::NoRagdoll"
        if 'no recoil' in st: return "PlayerCheats::NoRecoil"
        if 'player' in st: return "PlayerCheats::PlayerOptionsRenderer"
        return f"PlayerCheats::Helper_{rva:06X}"
    
    # === COMBAT_CHEATS ===
    if module == 'COMBAT_CHEATS':
        if 'infinite stratagem' in st or 'inf strat' in st: return "CombatCheats::InfiniteStratagems"
        if 'instant strat callin' in st or 'isc' in st: return "CombatCheats::InstantStratCallin"
        if 'mass strat drop' in st: return "CombatCheats::MassStratDrop"
        if 'no turret overheat' in st: return "CombatCheats::NoTurretOverheat"
        if 'inf turret duration' in st: return "CombatCheats::InfTurretDuration"
        if 'expire all turrets' in st: return "CombatCheats::ExpireAllTurrets"
        if 'inf ammo' in st: return "CombatCheats::InfiniteAmmo"
        if 'no reload' in st: return "CombatCheats::NoReload"
        if 'inf grenades' in st: return "CombatCheats::InfiniteGrenades"
        if 'inf stims' in st: return "CombatCheats::InfiniteStims"
        if 'instant charge' in st: return "CombatCheats::InstantCharge"
        if 'no laser overheat' in st: return "CombatCheats::NoLaserOverheat"
        if 'map hack' in st: return "CombatCheats::MapHack"
        if 'hoverpack control' in st: return "CombatCheats::HoverpackControl"
        if 'instant shuttle' in st: return "CombatCheats::InstantShuttle"
        if 'instant complete' in st: return "CombatCheats::InstantComplete"
        if 'freeze mission timer' in st: return "CombatCheats::FreezeMissionTimer"
        if 'instant hellbomb' in st: return "CombatCheats::InstantHellbomb"
        if 'skip launch code' in st: return "CombatCheats::SkipLaunchCode"
        if 'instant railgun' in st: return "CombatCheats::InstantRailgun"
        if 'grenade fuse time' in st: return "CombatCheats::GrenadeFuseTime"
        if 'fast landing' in st: return "CombatCheats::FastLanding"
        if 'no boundary' in st: return "CombatCheats::NoBoundary"
        if 'longer hover' in st: return "CombatCheats::LongerHover"
        if 'shield cooldown' in st: return "CombatCheats::ShieldCooldown"
        if 'takeoff force' in st: return "CombatCheats::TakeoffForce"
        if 'dark fluid pack' in st: return "CombatCheats::DarkFluidPack"
        if 'instant arrows' in st: return "CombatCheats::InstantArrows"
        if 'instant coordinates' in st: return "CombatCheats::InstantCoordinates"
        if 'instant pipes' in st: return "CombatCheats::InstantPipes"
        if 'arcade' in st: return "CombatCheats::ArcadeCheats"
        if 'correct combo' in st: return "CombatCheats::CorrectCombo"
        if 'killstreak' in st: return "CombatCheats::KillstreakHandler"
        if 'eraser' in st or 'eradication' in st: return "CombatCheats::EradicationEditor"
        if 'combat' in st: return "CombatCheats::CombatOptionsRenderer"
        if 'stratagem' in st: return "CombatCheats::StratagemOptionsUI"
        if 'turret' in st: return "CombatCheats::TurretOptionsUI"
        if 'stealth' in st: return "CombatCheats::StealthOptionsUI"
        if 'spawning' in st: return "CombatCheats::SpawningUI"
        return f"CombatCheats::Util_{rva:06X}"
    
    # === ARMORY ===
    if module == 'ARMORY':
        if 'unlock all armory' in st: return "Armory::UnlockAllArmory"
        if 'armor passive' in st: return "Armory::ArmorPassiveEditor"
        if 'weapon stats editor' in st: return "Armory::WeaponStatsEditor"
        if 'weapon editor' in st and 'populate' in st: return "Armory::WeaponEditorPopulate"
        if 'scan armor' in st: return "Armory::ScanArmorButton"
        return f"Armory::Helper_{rva:06X}"
    
    # === IMGUI_RENDER ===
    if module == 'IMGUI_RENDER':
        if 'imgui' in st and '1.91' in st: return "ImGuiRenderer::VersionString"
        if 'overlay' in st: return "ImGuiRenderer::OverlayRenderer"
        if 'farming' in st: return "ImGuiRenderer::FarmingTabRenderer"
        if 'weapon' in st and 'xp' in st: return "ImGuiRenderer::WeaponXPTabRenderer"
        if 'super credit' in st: return "ImGuiRenderer::SCTabRenderer"
        if 'replay' in st: return "ImGuiRenderer::ReplayTabRenderer"
        if 'log' in st: return "ImGuiRenderer::LogsTabRenderer"
        if 'credit' in st: return "ImGuiRenderer::CreditsTabRenderer"
        if 'misc' in st: return "ImGuiRenderer::MiscTabRenderer"
        if 'update' in st: return "ImGuiRenderer::UpdatesTabRenderer"
        if 'liber' in st and 'tool' in st: return "ImGuiRenderer::TitleBarRenderer"
        if 'boost' in st or 'afk' in st: return "ImGuiRenderer::StatusBarRenderer"
        if 'l i b e r t e a' in st: return "ImGuiRenderer::CreditsRenderer"
        if 'feature' in st and 'active' in st: return "ImGuiRenderer::ActiveFeaturesFooter"
        if 'mode' in st: return "ImGuiRenderer::ModeToggleRenderer"
        if 'imgui' in st: return "ImGuiRenderer::ImGuiContext"
        return f"ImGuiRenderer::UIFunction_{rva:06X}"
    
    # === MEMORY ===
    if module == 'MEMORY':
        if 'virtualprotect' in st: return "Memory::VirtualProtect_impl"
        if 'ntprotectvirtualmemory' in st: return "Memory::NtProtectVirtualMemory"
        if 'syscall stub' in st: return "Memory::SyscallStubBuilder"
        if 'protection layer' in st: return "Memory::ProtectionLayerManager"
        if 'all layers failed' in st: return "Memory::AllLayersFailedHandler"
        return f"Memory::Helper_{rva:06X}"
    
    # === PATTERN_SCAN ===
    if module == 'PATTERN_SCAN':
        if 'found' in st: return "PatternScanner::ReportFound"
        if 'not found' in st: return "PatternScanner::ReportMissing"
        return f"PatternScanner::Helper_{rva:06X}"
    
    # === CRASH_HANDLER ===
    if module == 'CRASH_HANDLER':
        if 'crash log' in st or '=== liber' in st.lower(): return "CrashHandler::WriteCrashLog"
        if 'crash' in st and 'absorbed' in st: return "CrashHandler::CrashCounter"
        return f"CrashHandler::Helper_{rva:06X}"
    
    # === CRYPTO ===
    if module == 'CRYPTO':
        if 'machineguid' in st: return "Crypto::GetHardwareId"
        if 'bcrypt' in st: return "Crypto::HashData"
        if 'base64' in st: return "Crypto::Base64Codec"
        return f"Crypto::CryptoUtil_{rva:06X}"
    
    # === CONFIG ===
    if module == 'CONFIG':
        if 'imgui.ini' in st: return "Config::ImGuiConfigLoader"
        return f"Config::ConfigUtil_{rva:06X}"
    
    # === LOGGING ===
    if module == 'LOGGING':
        return f"Logging::DebugPrintf_{rva:06X}"
    
    # === INIT ===
    if module == 'INIT':
        if 'dllmain' in st: return "Init::DllMain"
        if 'helldivers' in st: return "Init::WaitForGameModule"
        if 'module' in st: return "Init::ModuleHelper"
        if 'wndproc' in st: return "Window::WndProc"
        if 'scpresent' in st: return "Window::ScPresentInstall"
        return f"Init::Helper_{rva:06X}"
    
    # === UPDATE ===
    if module == 'UPDATE':
        if 'inbox' in st: return "UpdateSystem::InboxRenderer"
        if 'letter from' in st: return "UpdateSystem::MessageRenderer"
        return f"UpdateSystem::Helper_{rva:06X}"
    
    # === UNKNOWN - heuristic naming ===
    callers_cnt = len(callers)
    if fn['call_count'] == 0 and insn_count <= 5:
        return f"Leaf_{rva:06X}"
    if fn['call_count'] == 0 and insn_count <= 20:
        return f"SmallUtil_{rva:06X}"
    if fn['call_count'] == 0:
        return f"Standalone_{rva:06X}"
    if fn['call_count'] == 1 and insn_count <= 8:
        return f"Wrapper_{rva:06X}"
    if fn['has_xmm']:
        return f"FloatCalc_{rva:06X}"
    if callers_cnt >= 10:
        return f"SharedUtil_{rva:06X}"
    if callers_cnt >= 3:
        return f"Helper_{rva:06X}"
    return f"Func_{rva:06X}"

# Assign final names
for rva, fn in functions.items():
    fn['module'] = get_module(rva)
    fn['name'] = get_name(rva, fn)

# ==== Build output ====
print("Writing final catalog...")
module_counts = Counter()
module_sizes = Counter()
for fn in functions.values():
    module_counts[fn['module']] += 1
    module_sizes[fn['module']] += fn['size']

sorted_funcs = sorted(functions.items(), key=lambda x: (x[1]['module'], x[1]['name'], x[0]))

with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
    f.write("=" * 110 + "\n")
    f.write("  AGENT B: COMPLETE FUNCTION CATALOG\n")
    f.write(f"  Binary: .text_unpacked_mem.bin (3,489,792 bytes, ~3.3 MB)\n")
    f.write(f"  Total functions cataloged: {len(functions)}\n")
    f.write("=" * 110 + "\n\n")
    
    f.write("MODULE SUMMARY\n" + "-" * 90 + "\n")
    for mod in sorted(module_counts.keys()):
        f.write(f"  {mod:<22} {module_counts[mod]:>6} functions  ({module_sizes[mod]:>10} bytes)\n")
    f.write("-" * 90 + "\n")
    total_size = sum(module_sizes.values())
    f.write(f"  {'TOTAL':<22} {sum(module_counts.values()):>6} functions  ({total_size:>10} bytes)\n")
    f.write(f"\n  Code coverage: {total_size}/{BIN_SIZE} bytes = {total_size*100/BIN_SIZE:.1f}%\n")
    f.write("=" * 110 + "\n\n")
    
    f.write("CALL GRAPH STATISTICS\n" + "-" * 90 + "\n")
    total_edges = sum(len(v) for v in call_graph.values())
    f.write(f"  Total directed call edges: {total_edges}\n\n")
    
    f.write(f"  Top-20 Most Called Functions:\n")
    most_called = sorted(call_graph_rev.items(), key=lambda x: -len(x[1]))[:20]
    for rva, callers in most_called:
        name = functions[rva]['name'] if rva in functions else f"0x{rva:06X}"
        f.write(f"    [0x{rva:06X}] {len(callers):>4} callers -> {name}\n")
    
    f.write(f"\n  Top-20 Largest Functions:\n")
    biggest = sorted(functions.items(), key=lambda x: -x[1]['size'])[:20]
    for rva, fn in biggest:
        f.write(f"    [0x{rva:06X}] {fn['size']:>6} bytes -> [{fn['module']}] {fn['name']}\n")
    
    f.write(f"\n  Fan-Out Top-20 (most calls to others):\n")
    most_calls = sorted(functions.items(), key=lambda x: -x[1]['call_count'])[:20]
    for rva, fn in most_calls:
        f.write(f"    [0x{rva:06X}] {fn['call_count']:>4} outgoing -> [{fn['module']}] {fn['name']}\n")
    
    f.write("=" * 110 + "\n\n")
    
    f.write("DETAILED FUNCTION CATALOG\n" + "=" * 110 + "\n\n")
    
    for rva, fn in sorted_funcs:
        name = fn['name']; module = fn['module']; size = fn['size']
        calls = fn['calls']; strings = fn['strings']
        callers = sorted(call_graph_rev.get(rva, set()))
        
        f.write(f"[0x{rva:06X}] [{size:>6}] [{module}] {name}\n")
        
        if calls:
            shown = 0
            for callee in sorted(calls):
                if callee in functions and functions[callee]['module'] in ('SC_FARMING', 'NETWORK', 'HOOK_SYSTEM', 'MEMORY', 'CRYPTO', 'AUTH', 'WEAPON_XP', 'PLAYER_CHEATS', 'COMBAT_CHEATS'):
                    cn = functions[callee]['name']
                    f.write(f"  -> [0x{callee:06X}] {cn}\n")
                    shown += 1
            # Show a few unnamed ones too
            for callee in sorted(calls):
                if shown >= 8: break
                if (callee not in functions) or (functions[callee]['module'] not in ('SC_FARMING', 'NETWORK', 'HOOK_SYSTEM', 'MEMORY', 'CRYPTO', 'AUTH', 'WEAPON_XP', 'PLAYER_CHEATS', 'COMBAT_CHEATS')):
                    cn = functions[callee]['name'] if callee in functions else f"0x{callee:06X}"
                    f.write(f"  -> [0x{callee:06X}] {cn}\n")
                    shown += 1
            if len(calls) > shown:
                f.write(f"  ... +{len(calls)-shown} more calls\n")
        
        if callers:
            shown = 0
            for caller in sorted(callers):
                if caller in functions and functions[caller]['module'] not in ('UNKNOWN',):
                    cname = functions[caller]['name']
                    f.write(f"  <- [0x{caller:06X}] {cname}\n")
                    shown += 1
            for caller in sorted(callers):
                if shown >= 8: break
                if (caller not in functions) or (functions[caller]['module'] in ('UNKNOWN',)):
                    cname = functions[caller]['name'] if caller in functions else f"0x{caller:06X}"
                    f.write(f"  <- [0x{caller:06X}] {cname}\n")
                    shown += 1
            if len(callers) > shown:
                f.write(f"  ... +{len(callers)-shown} more callers\n")
        
        if strings:
            uniq = list(dict.fromkeys(strings))
            f.write(f"  Strings: {', '.join(repr(s[:60]) for s in uniq[:6])}\n")
            if len(uniq) > 6:
                f.write(f"           +{len(uniq)-6} more strings\n")
        
        f.write("\n")

print(f"\nDone! {len(functions)} functions cataloged.")
print(f"Output: {OUTPUT_PATH}")

print(f"\nModule breakdown:")
for mod, cnt in module_counts.most_common():
    print(f"  {mod:<22} {cnt:>6}")
print(f"  {'TOTAL':<22} {sum(module_counts.values()):>6}")
