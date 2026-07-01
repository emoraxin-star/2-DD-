import struct, re
from collections import Counter

with open(r'C:\Users\emora\OneDrive\Desktop\2\.text_unpacked_mem.bin', 'rb') as f:
    data = f.read()

L = []
def a(s=''):
    L.append(s)

a('=' * 78)
a('  LIBERTEA.DLL - TECHNICAL BREAKDOWN & BUILD STRATEGY')
a('  Helldivers 2 Internal Cheat - Reverse Engineering Report')
a('=' * 78)
a()

# ============================================================
a('SECTION 1: BUILD ARCHITECTURE & TOOLCHAIN')
a('-' * 78)
a()
a('  Language:     C++ (MSVC - Microsoft Visual C++)')
a('  Standard:     C++17 or later (std::bad_array_new_length, lambdas)')
a('  GUI Library:  Dear ImGui (ocornut/imgui) - in-tree compilation')
a('  Graphics:     OpenGL hook via wglSwapIntervalEXT')
a('  Packer:       Custom aPLib variant (see Section 3)')
a('  Packer Tools: aPLib compression library + custom PE packer stub')
a('  Linker:       MSVC LINK.EXE with /DYNAMICBASE /NXCOMPAT /GUARD:CF')
a('  Optimization: /O2 (size-focused, heavy inlining)')
a('  CRT:          Static-linked (no msvcp140.dll dependency)')
a('  Auth:         HTTPS to Cloudflare Workers backend with key/subscription check')
a()

# ============================================================
a('SECTION 2: BUILD STRATEGY - HOW TO REPLICATE')
a('-' * 78)
a()
a('  Phase 1 - Development:')
a('    1. Write cheat core in C++ using Dear ImGui for overlay')
a('    2. Implement pattern scanner (byte signature matching) for game offsets')
a('    3. Use direct syscalls for NtProtectVirtualMemory (bypass user-mode hooks)')
a('    4. Hook wglSwapIntervalEXT or IDXGISwapChain::Present for overlay rendering')
a('    5. Implement feature modules:')
a('       - Reward multiplier (patch game.dll mission end rewards)')
a('       - SC/Medal farming (replay captured API calls via HTTPS)')
a('       - Weapon XP override (patch lobby weapon slots)')
a('       - Player cheats (god mode, speed, no recoil, infinite stratagems)')
a('       - Turret/combat mods (overheat bypass, duration, stratagem count)')
a()
a('  Phase 2 - Packing:')
a('    1. Compile DLL normally with MSVC')
a('    2. Extract .text section')
a('    3. Compress .text with aPLib (custom variant with sar/xor NOT encoding)')
a('    4. Replace .text with zero-size section, store compressed data in .rsrc')
a('    5. Write unpacking stub in assembly, place at entry point')
a('    6. Stub decompresses .text into memory at DllMain(DLL_PROCESS_ATTACH)')
a('    7. Stub then resolves imports (Phase 2 of unpacking)')
a()
a('  Phase 3 - Injector (LIBERTEA_Bypass.exe):')
a('    1. Enable SeDebugPrivilege via ntdll.dll')
a('    2. Target process: helldivers2.exe')
a('    3. Block GameMon.des / GameMon64.des (GameGuard kernel drivers)')
a('       - Methods: rename/delete driver files, suspend GameGuard threads,')
a('         or inject before GameGuard initializes')
a('    4. Allocate memory in target process (VirtualAllocEx)')
a('    5. Write DLL path and call LoadLibraryW via CreateRemoteThread')
a('    6. Self-update: check Workers endpoint for new DLL version')
a()

# ============================================================
a('SECTION 3: CUSTOM aPLib DECOMPRESSION ALGORITHM')
a('-' * 78)
a()
a('  Entry point: RVA 0x3C4F30 (in .rsrc section #1)')
a('  Source data: RVA 0x355000 (beginning of .rsrc section = raw offset 0x400)')
a('  Destination: RVA 0x001000 (start of .text section, 0x354000 bytes)')
a()
a('  Bit Reader (GETBIT):')
a('    Uses add ebx, ebx / adc ebx, ebx for carry-flag-based bit extraction.')
a('    ebx holds 31 bits; when exhausted, refills 4 bytes from source.')
a('    Key: adc propagates carry from previous zero-detection through refill.')
a()
a('  Main Loop:')
a('    1. Preload byte from source (mov dl, [rsi])')
a('    2. GETBIT -> CF')
a('    3. jb (CF=1): LITERAL  - inc rsi, store dl, preload next')
a('    4. jae (CF=0): MATCH')
a()
a('  Offset Gamma Decode (custom, differs from standard aPLib):')
a('    eax = prev_len + 1  (carried over from previous match)')
a('    First pass (jmp to LENGTH_LOOP_ENTRY):')
a('      read 1 bit -> eax = eax*2 + bit')
a('      read 1 stop bit -> if 0: continue loop')
a('    Subsequent passes (jae -> LENGTH_DEC):')
a('      dec eax')
a('      read 2 bits -> eax = eax*2 + bit (each)')
a('      read 1 stop bit -> if 0: continue loop')
a('    After loop: eax -= 3')
a()
a('  Offset Classification:')
a('    eax < 0 (unsigned): SHORT MATCH - reuses ebp (last_offset)')
a('    eax >= 0: LONG MATCH - explicit offset:')
a('      eax = (eax << 8) | dl     (merge next byte)')
a('      src++')
a('      eax = eax XOR 0xFFFFFFFF (NOT)')
a('      if eax == 0: END OF PHASE 1 (import resolution phase)')
a('      sar eax, 1 -> last_offset (signed, movsxd to rbp)')
a('      LSB shifted out determines COPY_SETUP_A vs alternate path')
a()
a('  Length Decode (ecx manipulation):')
a('    COPY_SETUP_A: getbit -> ecx = ecx*2 + bit')
a('    Alt path (0x3C5024):')
a('      inc ecx, getbit; if 1 -> COPY_SETUP_A')
a('      else: gamma-decode bits into ecx, then ecx += 2')
a('    COPY_SETUP_B:')
a('      if last_offset < -0x500: ecx += 3')
a('      else: ecx += 2')
a('    Final length = ecx (copy_len)')
a()
a('  Match Copy:')
a('    copy_src = dst + last_offset')
a('    if copy_len <= 5 or last_offset > -4: byte-by-byte copy')
a('    else: dword copy loop (sub ecx,4; jae loop; add ecx,4; byte remainder)')
a()

# ============================================================
a('SECTION 4: SYSCALL STUBS')
a('-' * 78)
a()
a('  Direct syscall stubs found at RVAs:')
a('    0x00F304 - NtProtectVirtualMemory (syscall stub)')
a('    0x02EB95 - NtQueryInformationProcess or similar')
a('    0x02FCC6 - (syscall stub)')
a('    0x030591 - (syscall stub)')
a('    0x030852 - (syscall stub)')
a('    0x030CFE - (syscall stub)')
a('    0x030FF2 - (syscall stub)')
a('    0x03458D - (syscall stub)')
a()
a('  Syscall pattern:')
a('    48 8D 0D ?? ?? ?? ??   lea rcx, [ntdll_function_name]')
a('    48 8B 1D ?? ?? ?? ??   mov rbx, [ssn_table]')
a('    B8 ?? ?? ?? ??         mov eax, SSN  (syscall number)')
a('    48 89 ??              mov [stack], rbx (setup params)')
a('    0F 05                 syscall')
a()
a('  SSN values are resolved dynamically from ntdll.dll at runtime')
a('  by parsing the function prologue for the mov eax, imm pattern.')
a()

# ============================================================
a('SECTION 5: CONCRETE OFFSETS & POINTERS')
a('-' * 78)
a()

# Get call target data
call_targets = Counter()
for i in range(len(data) - 5):
    if data[i] == 0xE8:
        disp = struct.unpack_from('<i', data, i+1)[0]
        target = 0x1000 + i + 5 + disp
        if 0x1000 < target < 0x400000:
            call_targets[target] += 1

a('  Top .text internal functions by call frequency:')
for addr, cnt in call_targets.most_common(25):
    a(f'    RVA 0x{addr:06X}  - {cnt:4d} calls')
a()

a('  VTable virtual function indices (offset / slot):')
vtable_data = [
    (0x00, 0), (0x08, 1), (0x10, 2), (0x18, 3), (0x20, 4),
    (0x28, 5), (0x30, 6), (0x38, 7), (0x40, 8), (0x48, 9),
    (0x50, 10), (0x58, 11), (0x60, 12), (0x68, 13), (0x70, 14),
    (0x80, 16), (0x90, 18), (0xA0, 20), (0xA8, 21), (0xB0, 22),
    (0xB8, 23), (0xC0, 24), (0xC8, 25), (0xD0, 26), (0xD8, 27),
    (0xE0, 28), (0xE8, 29), (0xF0, 30), (0xF8, 31),
    (0x100, 32), (0x108, 33), (0x110, 34), (0x118, 35),
    (0x120, 36), (0x128, 37), (0x3BB, 119), (0x5B9, 183),
]
for off, slot in vtable_data:
    a(f'    vtable+0x{off:03X} = slot #{slot}')
a()

a('  Game structure member offsets (extracted from immediate values):')
struct_offs = [0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48,
               0x50, 0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0xA0, 0xB0,
               0xC8, 0x100, 0x110, 0x150, 0x158, 0x170, 0x1B0, 0x1C0,
               0x1D8, 0x200, 0x208, 0x238, 0x268, 0x340, 0x3C0, 0x3E8,
               0x440, 0x4D0, 0x5B0, 0x610, 0x7E0, 0x800, 0xBA0, 0xBB8,
               0xBE0, 0xC88, 0xCD0, 0xCE0, 0xD00, 0xD08, 0xD10,
               0xE60, 0xE68, 0xE88, 0xEA0, 0xEA8, 0xEC0, 0xEE0, 0xEE8,
               0xF20, 0xF80, 0x1000, 0x1060, 0x1078, 0x1120, 0x12F0,
               0x1388, 0x19E8, 0x1DC0, 0x1E00,
]
for o in struct_offs:
    a(f'    +0x{o:04X} ({o})')
a()

# C++ RTTI
a('  C++ RTTI type names (recovered class hierarchy):')
rtti_names = [
    'std::exception',
    'std::bad_exception', 
    'std::bad_alloc',
    'std::bad_array_new_length',
    'std::logic_error',
    'std::length_error',
    'std::out_of_range',
    'std::runtime_error',
    'std::system_error',
    'std::_System_error',
    'std::error_category',
    'std::_Generic_error_category',
    'std::type_info',
]
for n in rtti_names:
    a(f'    {n}')
a()

a('  ScActivityAPC (SC farming object):')
a('    actObj=%p          - pointer to activity object')
a('    TID=%u             - thread ID')
a('    actId32=0x%08X     - 32-bit activity identifier')
a('    objId=0x%08X       - object identifier')
a('    ctr=0x%X           - control counter')
a('    flag=0x%X          - flags')
a('    ring=%u            - ring buffer index')
a('    url="%.40s"        - API endpoint URL')
a('    qDelta=%d          - delta queue count')
a('    retry=%d           - retry counter')
a()

a('  Mission capture data:')
a('    missionId=%s        - mission ID string')
a('    capturedWarTime     - war time at capture moment') 
a('    serObjOrigAddr      - original server object address')
a('    entityDeep          - entity hierarchy JSON')
a('    entityDataDeep      - entity data payload JSON')
a('    file: C:\\libertea_replay_cap.json')
a()

a('  Hook target pattern types (game.dll):')
a('    GetActiveSession() -> Session*')
a('    Session+0x28 -> sub-object pointer')
a('    Session+0x128 -> activity list')
a('    Unlock check -> 48 8B 0D ?? ?? ?? ?? 44 89 80 60 0C')
a('    Grenade count -> 0F 5B DB F3 41 0F 59 4E ?? F3')
a('    Turret overheat -> F3 0F 11 4C A8 ?? 49')
a('    Turret duration -> F3 45 0F 11 5E ?? E9')
a('    Boundary check -> 0F 84 ?? ?? ?? ?? 80 7F ?? ??')
a('    Stratagem count -> 42 83 2C 81 ?? 48')
a('    Kill counter -> 39 46 ?? 75 ?? FF C5')
a('    Hash table INSERT (x2) -> NOP both for SC bypass')
a('    Laser overheat -> [pattern in .text]')
a('    Stim use -> [pattern in .text]')
a()

# ============================================================
a('SECTION 6: PROTOCOL & NETWORK ANALYSIS')
a('-' * 78)
a()
a('  Update Check:')
a('    GET https://libertea.libertea4.workers.dev/menu/version')
a('    Returns: version number (integer, e.g. "15")')
a('    Compared against LIBERTEA.version file')
a()
a('  DLL Download:')
a('    GET https://libertea.libertea4.workers.dev/menu/download')
a('    Returns: new LIBERTEA.DLL binary')
a('    Saved as LIBERTEA.DLL.tmp then atomically renamed')
a('    Retry: --retry %d flag passed to injector')
a()
a('  Game API (SC/Medal farming):')
a('    POST https://api.live.prod.thehelldiversgame.com/api/Operation/Mission/end')
a('    Content-Type: application/json')
a('    Body includes: missionId, entityDataDeep, warTime, reward data')
a('    Batch: 9 requests spaced 500ms, 58s cooldown between batches')
a('    Alternates: SC batches <-> Medal batches')
a()
a('  Authentication:')
a('    Login with username + password OR access key')
a('    Cloudflare Workers backend validates subscription')
a('    States: Active, Lifetime, Expired')
a('    Stores: subscription expiry, key hash')
a()
a('  Discord:')
a('    https://discord.gg/exCgdvYPxd')
a('    Community/distribution hub')
a()

# ============================================================
a('SECTION 7: GAME FUNCTION HOOK CHAIN')
a('-' * 78)
a()
a('  Hook installation sequence at DllMain:')
a('    1. Decompress .text section')
a('    2. Resolve imports (IAT)')
a('    3. Read ntdll.dll from disk, parse syscall stubs (SSN extraction)')
a('    4. Find game.dll base via GetModuleHandle/module enumeration')
a('    5. For each pattern: scan game.dll .text for byte signature')
a('    6. Install hooks via NtProtectVirtualMemory + write')
a('    7. Hooks verified: GodMode, UnlockArmory, WeaponEditor, etc.')
a('    8. If pattern count < expected: WARNING - Game may have updated')
a('    9. Create ImGui window (LIBERTEAWnd class, LIBERTEA title)')
a('    10. Hook wglSwapIntervalEXT for overlay render loop')
a('    11. Enter message loop / overlay render loop')
a()
a('  Hook types used:')
a('    - Mid-function hooks (detour at pattern match address)')
a('    - NOP patches (disable specific code paths)')
a('    - Conditional jump inversion (JE->JMP or JNE->JMP)')
a('    - Memory value write (direct struct member write)')
a('    - Hash table NOP (prevent SC entity tracking)')
a()

# ============================================================
a('SECTION 8: IMPLEMENTATION NOTES')
a('-' * 78)
a()
a('  Pattern Scanner:')
a('    - IDA-style byte signatures with ?? wildcards')
a('    - References: "Patterns: %d/%d found"')
a('    - Missing patterns: features disabled but UI shown')
a('    - Update resilience: works across minor game patches')
a()
a('  Crash Recovery:')
a('    - Vectored Exception Handler (VEH): "[SC] VEH recovered crash"')
a('    - Captures exceptions, saves state, resumes operation')
a('    - "Crashes absorbed: %d" counter in UI')
a('    - Replay watchdog: resets stuck replayInProgress flag')
a()
a('  Overlay Render Loop:')
a('    - Dear ImGui rendered via OpenGL (wglSwapIntervalEXT hook)')
a('    - Window class: LIBERTEAWnd')
a('    - Font: Segoe UI')
a('    - Custom styling with LiberTea branding')
a('    - Tab interface: Farming, Weapon XP, Super Credits, Replay, Logs, Credits, Misc, Updates')
a('    - Login screen overlay before main UI')
a()
a('  Memory Management:')
a('    - Custom allocator at RVA 0x8BB24 (called 236 times)')
a('    - Object lifetime managed via C++ RAII patterns')
a('    - Fiber Local Storage (FlsAlloc/FlsGetValue/FlsSetValue)')
a('    - std::vector usage (vector constructor/destructor iterators in RTTI)')
a()
a('  Threading:')
a('    - Main thread: overlay render loop')
a('    - Worker threads: API calls, replay injection')
a('    - Thread ID tracking: TID=%u in activity objects')
a('    - Synchronization likely via CriticalSections (InitializeCriticalSectionEx)')
a()

# ============================================================
a('SECTION 9: DETECTION VECTORS & COUNTERMEASURES')
a('-' * 78)
a()
a('  Evasion techniques employed:')
a('    1. Packed DLL (no static signatures for AV/anti-cheat)')
a('    2. GameGuard bypass (GameMon.des / GameMon64.des disabled)')
a('    3. Direct syscalls (bypasses ntdll.dll user-mode hooks)')
a('    4. Pattern-based offsets (survives minor game updates)')
a('    5. VEH crash recovery (survives game crashes during farming)')
a('    6. Hash table NOP (prevents server-side SC duplicate detection)')
a('    7. Cloudflare Workers backend (obfuscated C2 infrastructure)')
a()
a('  Attack surfaces for detection:')
a('    1. GameGuard driver file modification (detectable by anti-cheat)')
a('    2. wglSwapIntervalEXT hook (detectable by anti-cheat overlays)')
a('    3. HTTP traffic to thehelldiversgame.com (non-standard request patterns)')
a('    4. NtProtectVirtualMemory calls on game.dll pages')
a('    5. Discord server (intelligence gathering)')
a('    6. Workers.dev DNS (Cloudflare abuse reporting)')
a('    7. LIBERTEA.DLL signatures (hash: 95C0E0A655906BDE...)')
a('    8. LIBERTEA_Bypass.exe signatures (hash: 3DE503976D6E5EB6...)')
a('    9. Memory pattern: SeDebugPrivilege elevation + GameMon targeting')
a()

a('=' * 78)
a('  END OF TECHNICAL BREAKDOWN')
a('  Extracted from LIBERTEA.DLL v15, unpacked via LoadLibrary + memory dump')
a('  File: .text_unpacked_mem.bin  (3,489,792 bytes)')
a('=' * 78)

output = '\n'.join(L)
with open(r'C:\Users\emora\OneDrive\Desktop\2\libertea_tech_breakdown.txt', 'w', encoding='utf-8') as f:
    f.write(output)

print(f'Written {len(output):,} chars to libertea_tech_breakdown.txt')
print(output[:2000])
