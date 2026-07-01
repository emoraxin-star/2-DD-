"""
LIBERTEA.DLL - COMPLETE DEEP DIVE EXTRACTION
Owns every inch of this binary.
"""
import struct, re, hashlib
from collections import Counter

with open(r'C:\Users\emora\OneDrive\Desktop\2\.text_unpacked_mem.bin', 'rb') as f:
    data = f.read()

L = []
W = lambda s='': L.append(s)

def hx(b):
    return ' '.join(f'{x:02X}' for x in b)

W('=' * 80)
W('  LIBERTEA.DLL - ABSOLUTE DEEP DIVE')
W('  Every pointer, offset, constant, string, and structure')
W('=' * 80)
W()

# ============================================================
# 1. BINARY FINGERPRINT
# ============================================================
W('=== SECTION 1: BINARY FINGERPRINT ===')
W()
W(f'  Total .text size:    {len(data):,} bytes ({len(data)/1024/1024:.2f} MB)')
W(f'  Non-zero bytes:      {sum(1 for b in data if b!=0):,}')
W(f'  Zero bytes:          {sum(1 for b in data if b==0):,}')
W(f'  Density:             {sum(1 for b in data if b!=0)/len(data)*100:.1f}%')
W(f'  MD5 (1st MB):        {hashlib.md5(data[:1048576]).hexdigest()}')
W(f'  SHA256 (1st MB):     {hashlib.sha256(data[:1048576]).hexdigest()}')
W()

# ============================================================
# 2. MEMORY REGION MAP
# ============================================================
W('=== SECTION 2: MEMORY REGION MAP ===')
W()
W('  Region          Range              Size       Density  Description')
W('  ------          -----              ----       -------  -----------')

regions = [
    (0x000000, 0x0B8000, 'Executable code (.text functions)'),
    (0x0B8000, 0x0BC000, 'Code/data transition zone'),
    (0x0BC000, 0x0C8000, 'Read-only data (rdata/strings/tables)'),
    (0x0C8000, 0x0F9000, 'Read-only data (encoded structures, IAT)'),
    (0x0F9000, 0x0FC000, 'Dense packed data (ImGui config/strings)'),
    (0x0FC000, 0x100000, 'Widget strings, menu labels'),
    (0x100000, 0x10A000, 'Dear ImGui compiled source + feature strings'),
    (0x10A000, 0x112000, 'Hook handlers, cheat logic strings'),
    (0x112000, 0x11D000, 'RTTI, unwind info, exception tables'),
    (0x11D000, 0x11F000, 'Import/export metadata tail'),
]
for start, end, desc in regions:
    chunk = data[start:end]
    nonzero = sum(1 for b in chunk if b != 0)
    density = nonzero / len(chunk) * 100
    W(f'  CODE   0x{start:06X}-0x{end:06X}  {end-start:7,}  {density:5.1f}%  {desc}')
W()

# Zero regions
zero_runs = []
in_zero = False
zero_start = 0
for i in range(len(data)):
    if data[i] == 0:
        if not in_zero:
            zero_start = i
            in_zero = True
    else:
        if in_zero:
            run_len = i - zero_start
            if run_len >= 256:
                zero_runs.append((zero_start, run_len))
            in_zero = False
if in_zero:
    run_len = len(data) - zero_start
    if run_len >= 256:
        zero_runs.append((zero_start, run_len))

W('  Major zero-byte runs (padding/alignment gaps):')
for start, length in zero_runs[:30]:
    W(f'    0x{start:06X}: {length:,} zero bytes (until 0x{start+length:06X})')
W()

# ============================================================
# 3. FUNCTION BOUNDARY MAP
# ============================================================
W('=== SECTION 3: FUNCTION BOUNDARY MAP (first 0x10000 bytes) ===')
W()
W('  Function prologue patterns found (sub rsp, XX / push rbx / mov [rsp+8]):')
func_starts = set()
for i in range(min(0x10000, len(data)) - 10):
    # sub rsp, imm8: 48 83 EC XX
    if data[i:i+3] == b'\x48\x83\xEC' and data[i-1:i] not in (b'\xCC', b'\xC3', b'\x90'):
        func_starts.add(i)
    # push rbx: 40 53 or 53
    elif data[i] == 0x53 and data[i-1:i] not in (b'\xCC', b'\xC3'):
        if data[i+1:i+3] in (b'\x48\x83', b'\x48\x8B'):
            func_starts.add(i)
    # mov [rsp+8], rcx: 48 89 4C 24 08
    elif data[i:i+5] == b'\x48\x89\x4C\x24\x08':
        func_starts.add(i)
    # mov [rsp+0x10], rdx: 48 89 54 24 10
    elif data[i:i+5] == b'\x48\x89\x54\x24\x10':
        func_starts.add(i-5)  # prologue started 5 bytes earlier
    # int3 padding (end of prev function): CC CC CC
    elif data[i:i+3] == b'\xCC\xCC\xCC' and data[i+3] not in (b'\xCC', b'\x00'):
        func_starts.add(i+3)

sorted_funcs = sorted(func_starts)
W(f'  Found {len(sorted_funcs)} function starts in first 64KB')
W()
W('  Key function addresses:')
notable = {
    0x1000: 'DllMain entry point',
    0x1020: 'Import stub #1 (lea rcx, jmp resolver)',
    0x1030: 'Import stub #2',
    0x1040: 'Import stub #3',
    0x1050: 'Import stub #4',
    0x1060: 'Import stub #5',
    0x1070: 'Import stub #6',
    0x1080: 'Import stub #7',
    0x1090: 'Import stub #8',
    0x10A0: 'Import stub #9',
    0x10B0: 'Init: alloc + setup SC hash table',
    0x10F0: 'Init: second alloc + setup',
    0x1130: 'Import stub #10',
    0x1140: 'Import stub #11',
    0x1150: 'Import stub #12 + init: calls helper first',
    0x1170: 'Import stub #13',
    0x1180: 'Import stub #14',
    0x1190: 'Import stub #15',
    0x11A0: 'Import stub #16 + calls helper',
    0x11C0: 'Getter: returns global data pointer',
    0x11D0: 'Lock/acquire function (6 args, stack frame)',
    0x1230: 'Object constructor (2 args)',
    0x1270: 'Get string/pointer (conditional)',
    0x1290: 'Object constructor with flag',
    0x12E0: 'Object constructor (simple)',
    0x1300: 'Init with nested constructor call',
    0x1330: 'Larger init function',
    0x1350: 'Object constructor #5',
    0x1390: 'Object constructor #6',
    0x13D0: 'Helper: calls sub-function',
    0x13F0: 'Memcpy-like or string operation',
}

for addr in sorted_funcs[:80]:
    desc = notable.get(addr, '')
    if desc:
        W(f'    0x{addr:06X}: {desc}')
    elif addr in func_starts:
        W(f'    0x{addr:06X}: (unnamed function)')
W()

# ============================================================
# 4. IMPORT STUB MAP
# ============================================================
W('=== SECTION 4: IMPORT STUB MAP ===')
W()
W('  Import resolution stubs (pattern: lea rcx, [rip+X]; jmp resolver):')
# Find lea rcx, [rip+disp32]; jmp target
imports = []
for i in range(0x1000, 0x1200):
    if data[i:i+3] == b'\x48\x8D\x0D':  # lea rcx, [rip+disp32]
        disp = struct.unpack_from('<i', data, i+3)[0]
        target = i + 7 + disp
        # Next should be jmp
        if i+7 < len(data) and data[i+7] in (0xE9, 0xEB):
            imports.append((i, target))
            
for addr, target in imports:
    # Read the string at target
    end = data.find(b'\x00', target)
    if end != -1:
        s = data[target:end].decode('ascii', errors='replace')
        W(f'  RVA 0x{addr:06X} -> string at 0x{target:06X}: {repr(s)}')
W()

# ============================================================
# 5. COMPLETE STRING EXTRACTION
# ============================================================
W('=== SECTION 5: ALL MEANINGFUL STRINGS (non-ImGui, non-STL) ===')
W()
strings = set()
for match in re.finditer(b'[\x20-\x7E]{6,}', data):
    s = match.group().decode('ascii', errors='replace').strip()
    if len(s) >= 6:
        strings.add(s)

# Filter for game-specific / cheat-specific strings
interesting = []
for s in sorted(strings):
    sl = s.lower()
    if any(kw in sl for kw in ['libertea', 'helldiver', 'super credit', 'sample', 'medal',
                                 'requisition', 'stratagem', 'turret', 'weapon', 'armory',
                                 'god mode', 'recoil', 'ammo', 'grenade', 'stim', 'stealth',
                                 'horde', 'fov', 'noclip', 'teleport', 'infinite', 'unlock',
                                 'hook', 'pattern', 'syscall', 'bypass', 'inject', 'crash',
                                 'mission', 'extraction', 'shuttle', 'hud', 'overlay',
                                 'discord', 'account', 'subscription', 'access key',
                                 'api.', 'endpoint', 'https://', '.json', 'replay',
                                 'boost', 'farming', 'xp ', 'xp:', 'difficulty',
                                 'cannon', 'laser', 'quasar', 'flame', 'railgun',
                                 'autocannon', 'sentry', 'eagle', 'orbital', 'pelican',
                                 'dark fluid', 'hover', 'jetpack', 'ragdoll', 'damage',
                                 'kill count', 'enemy', 'spawn', 'heat', 'overheat',
                                 'charge', 'fuse', 'boundary', 'landing', 'speed',
                                 'ntdll', 'syscall', 'protect', 'virtual', 'alloc',
                                 'thread', 'process', 'debug', 'error', 'warning',
                                 'TheOGcup', 'legend', 'hotpocket', 'shout',
                                 'prod.', 'thehelldiversgame', 'sc:', 'sc ',
                                 'capture', 'fire', 'batch', 'cooldown', 'retry',
                                 'mid=%', 'actObj', 'actId', 'objId', 'TID=',
                                 'qDelta', 'ring', 'ctr=', 'flag=',
                                 'entityDeep', 'entityData', 'warTime',
                                 'serObjOrig', 'serverInfo', 'GetActive',
                                 ]):
        interesting.append(s)

for s in interesting[:200]:
    W(f'  {repr(s)}')
W(f'  ... ({len(interesting)} total interesting strings)')
W()

# ============================================================
# 6. ALL CONSTANTS / IMMEDIATES WITH CONTEXT
# ============================================================
W('=== SECTION 6: CONSTANT VALUES WITH 8-BYTE CONTEXT ===')
W()

# Extract all 32-bit and 64-bit immediate constants
constants = Counter()
const_context = {}
for i in range(len(data) - 4):
    b = data[i]
    # MOV EAX, imm32
    if b == 0xB8 and i+4 < len(data):
        val = struct.unpack_from('<I', data, i+1)[0]
        if 0x100 <= val <= 0xFFFFFF:
            constants[val] += 1
            if val not in const_context:
                const_context[val] = []
            ctx = data[max(0,i-4):min(len(data),i+12)]
            const_context[val].append((i, ctx))
    # MOV reg, imm32 with REX.W
    if b == 0x48 and i+1 < len(data) and data[i+1] in (0xC7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF):
        op = data[i+1]
        if op in (0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF) and i+6 < len(data):
            val = struct.unpack_from('<I', data, i+2)[0]
            if 0x1000 <= val <= 0xFFFFFF:
                constants[val] += 1

# Show top constants
W('  Most frequently referenced constants:')
for val, cnt in constants.most_common(60):
    ctxs = const_context.get(val, [])
    ctx_str = ''
    if ctxs:
        ctx = ctxs[0][1]
        ctx_str = hx(ctx)
    W(f'    0x{val:08X} ({val:8d}) x{cnt:3d}  context: {ctx_str}')
W()

# ============================================================
# 7. ALL PATTERN SIGNATURES
# ============================================================
W('=== SECTION 7: COMPLETE BYTE PATTERN SIGNATURES ===')
W()
patterns_raw = set()
for match in re.finditer(b'(?:[0-9A-Fa-f]{2} ){4,}(?:[0-9A-Fa-f?]{2} )*(?:[0-9A-Fa-f?]{2})', data):
    s = match.group().decode('ascii', errors='replace').strip()
    if '?' in s and len(s) > 15:
        patterns_raw.add(s)

for p in sorted(patterns_raw):
    W(f'  {p}')
W()

# ============================================================
# 8. ImGui WIDGET MAP
# ============================================================
W('=== SECTION 8: DEAR IMGUI FULL WIDGET MAP ===')
W()
imgui_ids = set()
for match in re.finditer(b'##[a-zA-Z0-9_]{2,20}', data):
    imgui_ids.add(match.group().decode())
for tid in sorted(imgui_ids):
    W(f'  {tid}')
W(f'  Total unique ImGui IDs: {len(imgui_ids)}')
W()

# ============================================================
# 9. SC LOOP PROTOCOL DETAIL
# ============================================================
W('=== SECTION 9: SC/MEDAL FARMING PROTOCOL (FULL) ===')
W()
sc_strings = []
for match in re.finditer(b'[\x20-\x7E]{6,}', data):
    s = match.group().decode('ascii', errors='replace').strip()
    sl = s.lower()
    if any(kw in sl for kw in ['scloop', 'sc[', '[sc]', 'batch', 'cooldown', 
                                 'midswap', 'retry', 'autosync', 'sc goal',
                                 'firing', 'medal batch', 'sc batch', 'qdelta',
                                 'replay', 'capture', 'probe', 'entity',
                                 'serobj', 'actobj', 'activity', 'actid',
                                 'missionid', 'objid', 'ctr=', 'flag=',
                                 'ring', 'delta', 'timeout', 'empty',
                                 'bail', 'no data', 'recovered', 'absorb',
                                 'monitoring', 'stopping', 'busy',
                                 ]):
        sc_strings.append(s)

for s in sorted(set(sc_strings))[:80]:
    W(f'  {repr(s)}')
W()

# ============================================================
# 10. GAME FUNCTION HOOK TARGETS
# ============================================================
W('=== SECTION 10: GAME FUNCTION HOOK TARGETS (DETAILED) ===')
W()
hook_info = [
    ('[God Mode]', [
        'Hook1=0x%llX Hook2=0x%llX Hook3=0x%llX',
        '3 hooks installed for player god mode',
        'Likely targets: damage receive, death flag, health check',
    ]),
    ('[Grenade Count]', [
        'Signature: 0F 5B DB F3 41 0F 59 4E ?? F3 ...',
        'NOP grenade count conversion (CVTSS2SD + MULSS patched)',
        'Conditional jump bypass for strategem count decrement',
        'Pattern at: 42 83 2C 81 ?? 48',
    ]),
    ('[No Boundary]', [
        'Signature: 0F 84 ?? ?? ?? ?? 80 7F ?? ?? 0F 85 ?? ?? ?? ?? F3 0F',
        'Bypasses mission boundary kill trigger',
        'Patches conditional jump to always bypass',
    ]),
    ('[Landing Speed]', [
        'Signature: F3 0F 11 44 3B ?? F3 0F 59 C7 F3 0F 5A C0',
        'Modifies landing speed multiplier',
    ]),
    ('[Stratagem Unlock]', [
        'Signature: 48 8B 0D ?? ?? ?? ?? 44 89 80 60 0C',
        'Patches stratagem/weapon/armor unlock checks',
        'Unlock All Armory: bypasses all gating',
    ]),
    ('[Turret Overheat]', [
        'Signature: F3 0F 11 4C A8 ?? 49',
        'NOPs turret overheat accumulation',
    ]),
    ('[Turret Duration]', [
        'Signature: F3 45 0F 11 5E ?? E9',
        'Sets turret duration to infinite',
    ]),
    ('[Active Session]', [
        'Signature: 48 8B 35 ?? ?? ?? ?? 49 8B E9 41 8B D8 48 8B 88 28 01',
        'Alternate: 48 8B 35 ?? ?? ?? ?? 33 C9 49 8B E9 41 8B D8 4C 8B 90 28 01',
        'GetActiveSession() returns session pointer',
        'Session+0x28 and +0x128 are key offsets',
    ]),
    ('[Reward Multiplier]', [
        'Signature: 41 8B 47 ?? 4C 8B 7C 24 ?? 4C',
        'Multiplies XP, Medals, Requisition Slips',
        'Sliders: fxp, fmed, fslips',
    ]),
    ('[Stratagem Count]', [
        'Signature: 42 83 2C 81 ?? 48',
        'Decrements stratagem use count -> patch to NOP',
    ]),
    ('[Kill Counter]', [
        'Signature: 39 46 ?? 75 ?? FF C5',
        'Increments kill counter -> hook for stats',
        'Display: Kill Count: %.0f',
    ]),
    ('[Stim Use]', [
        'Stims (No Use) - prevents stim consumption',
    ]),
    ('[Laser Overheat]', [
        'No Laser Overheat - patches heat accumulation for laser weapons',
    ]),
    ('[Instant Charge]', [
        'Instant Charge - patches charge time for Quasar/Railgun/etc.',
    ]),
    ('[Grenade Fuse]', [
        'Signature: F3 0F 11 44 C8 ?? 0F',
        'Modifies grenade fuse time',
    ]),
    ('[SC Hash Table]', [
        'NOP both hash table INSERT calls',
        'Prevents server from detecting duplicate SC reward claims',
        'Critical for SC farming loop',
    ]),
    ('[Stratagem Call-in]', [
        'Instant Strat Callin - patches call-in time to zero',
    ]),
    ('[Mass Strat Drop]', [
        'Signature: N/A (marked [N/A] in UI - not currently hooked)',
    ]),
    ('[Weapon Stats Editor]', [
        'Hook: [WeaponEditor] Hook log message',
        'Populates when clicking weapon on ship',
        'Edits: FireRate, damage, penetration, etc.',
    ]),
    ('[Armor Passive]', [
        'Scan Armor -> reads current armor stats',
        'Apply -> writes modified passive values',
    ]),
    ('[Dark Fluid Pack]', [
        'Pack editor accessed in-mission',
        'Edits jetpack parameters: fly speed, gravity, fuel, impulse',
    ]),
    ('[Present/Overlay]', [
        'ScPresent::Install: hwnd=%p origWndProc=%p',
        'Hooks wglSwapIntervalEXT for ImGui rendering',
        'Overlay class: LIBERTEAOverlay, font: Segoe UI',
    ]),
]

for name, details in hook_info:
    W(f'  {name}:')
    for d in details:
        W(f'    {d}')
    W()

# ============================================================
# 11. CRASH RECOVERY SYSTEM
# ============================================================
W('=== SECTION 11: CRASH RECOVERY SYSTEM (VEH) ===')
W()
W('  Vectored Exception Handler registered at init')
W('  Handles: ACCESS_VIOLATION, ILLEGAL_INSTRUCTION, STACK_OVERFLOW')
W('  State saved: SC loop position, batch progress, replay data')
W('  Recovery:')
W('    [SC] VEH recovered crash - restores SC loop state')
W('    [Replay] Watchdog: reset stuck replayInProgress flag')
W('    Crashes absorbed counter increments')
W('  Crash log written to:')
W('    === LIBERTEA CRASH LOG ===')
W('    Time: %04u-%02u-%02u %02u:%02u:%02u')
W('    (format implies local file logging)')
W()

# ============================================================
# 12. ANTI-ANALYSIS / OBFUSCATION
# ============================================================
W('=== SECTION 12: ANTI-ANALYSIS & OBFUSCATION TECHNIQUES ===')
W()
W('  1. DLL Packing:')
W('     - Custom aPLib variant (not standard; inverted bit semantics)')
W('     - Entry point in .rsrc section (unusual, trips analysis tools)')
W('     - .text section: zero bytes on disk, decompressed at runtime')
W('     - Timestamp zeroed to epoch (1970-01-01) in PE header')
W()
W('  2. String Obfuscation:')
W('     - Game-related strings stored in .rdata only')
W('     - Feature names use ImGui ## IDs (opaque to string search)')
W('     - Debug strings embedded but only visible under runtime conditions')
W()
W('  3. Import Obfuscation:')
W('     - Direct syscall stubs (bypass IAT for critical APIs)')
W('     - SSN resolved dynamically from ntdll.dll on disk')
W('     - Late-bound imports via GetProcAddress')
W()
W('  4. Control Flow:')
W('     - Many small functions with int3 padding (complicates linear disassembly)')
W('     - Tail-call optimization (jmp instead of call/ret pairs)')
W('     - Import stubs use jmp to common resolver')
W()
W('  5. Runtime Checks:')
W('     - Subscription validation against Cloudflare Workers')
W('     - Pattern count check: if < expected, warns of game update')
W('     - Version check on injector startup')
W()

# ============================================================
# 13. STRUCTURE LAYOUT RECONSTRUCTION
# ============================================================
W('=== SECTION 13: RECONSTRUCTED STRUCTURE LAYOUTS ===')
W()
W('  // ScActivityAPC (SC farming activity object)')
W('  struct ScActivityAPC {')
W('      void*    vtable;         // +0x00')
W('      uint32_t actId32;        // +0x08')
W('      uint32_t objId;          // +0x0C')
W('      uint32_t ctr;            // +0x10  (control counter)')
W('      uint32_t flag;           // +0x14  (flags)')
W('      uint32_t ring;           // +0x18  (ring buffer index)')
W('      char     url[0x40];      // +0x20  (API endpoint URL)')
W('      uint32_t qDelta;         // +0x60  (queue delta)')
W('      uint32_t retry;          // +0x64  (retry count)')
W('      void*    missionData;    // +0x68')
W('      char     missionId[0x40];// +0x70')
W('      // ... more fields ...')
W('  };')
W()
W('  // MissionCapture (replay data)')
W('  struct MissionCapture {')
W('      char     missionId[64];      // mission identifier')
W('      uint64_t capturedWarTime;    // war time at capture')
W('      void*    serObjOrigAddr;     // server object original addr')
W('      char*    entityDeep;         // JSON: entity hierarchy')
W('      char*    entityDataDeep;     // JSON: entity data payload')
W('      uint32_t replayCount;        // number of replays available')
W('      // ... stored in C:\\libertea_replay_cap.json ...')
W('  };')
W()
W('  // Session (from game.dll)')
W('  struct GameSession {')
W('      void*    vtable;         // +0x00')
W('      // ... unknown fields ...')
W('      void*    subObj28;       // +0x28  (activity container?)')
W('      // ... unknown fields ...')
W('      void*    subObj128;      // +0x128 (alternate reference)')
W('      // ...')
W('  };')
W()

# ============================================================
# 14. COMPLETE FEATURE FEATURE MATRIX
# ============================================================
W('=== SECTION 14: COMPLETE FEATURE MATRIX ===')
W()
features = [
    ('FARMING', [
        ('Max Mission Reward', 'Multiplier', 'XP/Medals/Slips multipliers with MAX ALL button'),
        ('Force Difficulty', 'Toggle+Combo', 'Override mission difficulty 1-10 for reward scaling'),
        ('Add Samples Instantly', 'Toggle+Sliders', 'Inject Common/Rare/Super samples (auto-clamped to 34/33/33)'),
        ('Samples Over Limit', 'Toggle+Sliders', 'Override end-of-mission sample rewards'),
        ('Instant Shuttle', 'Toggle', 'Skip extraction shuttle timer'),
        ('Instant Complete', 'Toggle', 'Skip mission complete sequence'),
        ('Freeze Mission Timer', 'Toggle', 'Freeze all countdown timers (marked [N/A])'),
    ]),
    ('SUPER CREDITS', [
        ('SC Loop', 'Toggle+Timer', 'Auto-fire batches of 9 API calls, configurable timer'),
        ('SC Goal', 'Input+Button', 'Auto-stop when goal reached'),
        ('SC Tracker', 'Display', 'Tracks calls sent, SC earned, x100 bonuses'),
        ('Medal Batch', 'Toggle', 'Alternates SC/Medal farming per batch'),
        ('Medals Only', 'Toggle', 'Every batch fires medals (no SC)'),
        ('Auto Sync', 'Toggle', 'Distributes SC across all lobby players'),
    ]),
    ('WEAPON XP', [
        ('Primary Override', 'Toggle+Combo', 'Select weapon to give XP to all lobby members'),
        ('All Guns', 'Toggle', 'Cycle through all 51 weapons automatically'),
        ('Selected Guns', 'Toggle+List', 'Custom weapon selection with search/filter'),
        ('Replays/Gun', 'Counter', 'Configurable replays per weapon'),
    ]),
    ('PLAYER', [
        ('God Mode', 'Toggle', 'Player only - patches damage/death'),
        ('Movement Speed', 'Slider', 'Multiplier with .1f precision'),
        ('No Ragdoll', 'Toggle', 'Disable ragdoll physics'),
        ('No Recoil', 'Toggle', 'Disable weapon recoil'),
    ]),
    ('COMBAT', [
        ('Infinite Stratagems', 'Toggle', 'Unlimited strategem uses'),
        ('Instant Strat Call-in', 'Toggle', 'Zero call-in time'),
        ('Mass Strat Drop', 'Toggle+N', 'Drop N stratagems at once (marked [N/A])'),
        ('No Turret Overheat', 'Toggle', 'Prevent turret weapon overheating'),
        ('Inf Turret Duration', 'Toggle', 'Infinite turret lifetime'),
        ('Expire All Turrets', 'Button', 'Destroy all placed turrets'),
        ('Kill Count', 'Display', 'Shows kill counter (%.0f)'),
        ('Infinite Horde Mode', 'Toggle', 'Endless enemy spawns'),
    ]),
    ('VISUAL/EXPLORATION', [
        ('FOV Editor', 'Slider', 'Custom field of view'),
        ('Map Hack', 'Toggle', 'Reveal full map'),
        ('No Laser Overheat', 'Toggle', 'Infinite laser weapon fire'),
        ('Instant Charge', 'Toggle', 'Instant Quasar/Railgun charge'),
        ('Dark Fluid Pack', 'Editor', 'Jetpack parameters (fly speed, gravity, fuel, impulse)'),
        ('Instant Arrows', 'Toggle', 'Unlimited mission arrows'),
        ('No Boundary', 'Toggle', 'Bypass mission boundary kill'),
        ('Longer Hover', 'Toggle', 'Extended hover time'),
    ]),
    ('ARMORY', [
        ('Unlock All', 'Toggle', 'Patches stratagem/weapon/armor unlock gating'),
        ('Weapon Stats Editor', 'Dynamic', 'Click weapon on ship to populate; edit damage/fire rate/etc.'),
        ('Armor Passive Editor', 'Dynamic', 'Scan armor -> select passive -> apply'),
    ]),
    ('INF AMMO/STIMS', [
        ('Inf Ammo', 'Toggle', 'Unlimited ammunition'),
        ('No Reload', 'Toggle', 'Skip reload animation/sequence'),
        ('Inf Grenades', 'Toggle', 'Unlimited grenades'),
        ('Inf Stims', 'Toggle', 'Unlimited stims'),
    ]),
]

for category, items in features:
    W(f'  [{category}]')
    for name, itype, desc in items:
        W(f'    {name:<28s} {itype:<16s} {desc}')
    W()

# ============================================================
# 15. BUILD/COMPILE ARTIFACTS
# ============================================================
W('=== SECTION 15: BUILD ARTIFACTS & COMPILER FINGERPRINTS ===')
W()
W('  Compiler:    Microsoft Visual C++ (MSVC)')
W('  Evidence:')
W('    - __CxxFrameHandler exception handling')
W('    - RTTI format: .?AV (MSVC mangled names)')
W('    - std::_Generic_error_category (MSVC STL)')
W('    - std::_System_error (MSVC-specific)')
W('    - __clrcall, __vectorcall, __preserve_none (MSVC extensions)')
W('    - Guard CF (Control Flow Guard) check function references')
W('    - /GS (Buffer Security Check) cookie references')
W()
W('  Linker version: Probably VS2022 (v143 toolset)')
W('  CRT:          Statically linked (/MT or /MTd)')
W('  Evidence:      No msvcp140.dll or vcruntime140.dll references')
W()
W('  Third-party code:')
W('    - Dear ImGui (ocornut/imgui) - in-tree, compiled directly')
W('      Version: appears to be v1.89+ (based on widget API)')
W('    - aPLib compression library (customized)')
W('    - Cloudflare Workers for backend')
W()
W('  Discord:       https://discord.gg/exCgdvYPxd')
W('  Author:        TheOGcup')
W('  Contributors:  Legend, HotPocket')
W('  Version:       v414 (from UI: "TOOL  v414")')
W('  Brand:         LIBERTEA / LiberTea')
W()

# ============================================================
# 16. IAT / DLL DEPENDENCIES
# ============================================================
W('=== SECTION 16: DLL DEPENDENCIES (IAT) ===')
W()
dlls = {}
for match in re.finditer(b'([a-zA-Z][a-zA-Z0-9_]+\\.dll)', data.lower()):
    dlls[match.group().decode()] = True
for d in sorted(dlls):
    if not d.startswith('api-ms-') and not d.startswith('ext-ms-'):
        W(f'  {d}')
W()
W('  (api-ms-win-* / ext-ms-win-* are API set schemas, resolved to real DLLs)')
W()

# ============================================================
# 17. GAME DATA FILE REFERENCES
# ============================================================
W('=== SECTION 17: GAME DATA & FILE REFERENCES ===')
W()
file_refs = set()
for match in re.finditer(b'[A-Za-z]:\\\\[^\x00]{3,100}', data):
    file_refs.add(match.group().decode('ascii', errors='replace'))
for match in re.finditer(b'[a-zA-Z0-9_/\\.]{5,80}\\\\[a-zA-Z0-9_/\\.]{5,80}', data):
    s = match.group().decode('ascii', errors='replace')
    if '\\\\' in s or '\\' in s:
        file_refs.add(s)

for f in sorted(file_refs):
    W(f'  {f}')
W()

# ============================================================
# 18. SECURITY IMPLICATIONS
# ============================================================
W('=== SECTION 18: SECURITY IMPLICATIONS & RISK ASSESSMENT ===')
W()
W('  For Users:')
W('    - Injects DLL into game process (full memory access)')
W('    - Phones home to Cloudflare Workers (data exfiltration possible)')
W('    - Reads Steam game directory from disk')
W('    - Modifies ntdll.dll syscall stubs (could be used for persistence)')
W('    - Captures and replays HTTPS API calls (session hijacking)')
W('    - Stores credentials (username/password/access key)')
W()
W('  For Game Developer (Arrowhead):')
W('    - SC/Medal farming bypasses economy via API replay')
W('    - Hash table NOP prevents duplicate detection')
W('    - GameGuard bypass renders anti-cheat ineffective')
W('    - Pattern-based hooks survive minor patches')
W('    - VEH crash recovery masks instability from hooks')
W('    - Workers.dev C2 is hard to disrupt')
W()
W('  Mitigations available:')
W('    1. Server-side: rate-limit Mission/end API, validate entityData hash,')
W('       require nonce/timestamp that prevents replay')
W('    2. Anti-cheat: monitor GameMon.des file integrity, detect syscall stubs,')
W('       scan for wglSwapIntervalEXT hooks, verify .text section hash')
W('    3. Legal: Cloudflare abuse report for Workers endpoints, Discord TOS report')
W()

# ============================================================
W('=' * 80)
W('  END OF ABSOLUTE DEEP DIVE')
W(f'  Total lines: {len(L)}')
W('=' * 80)

output = '\n'.join(L)
with open(r'C:\Users\emora\OneDrive\Desktop\2\libertea_deep_dive.txt', 'w', encoding='utf-8') as f:
    f.write(output)

print(f'Written {len(output):,} chars')
print(output[:4000])
