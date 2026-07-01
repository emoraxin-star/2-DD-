"""
Niche detail extraction - every edge case, byte-level detail
"""
import struct, re
from collections import Counter

with open(r'C:\Users\emora\OneDrive\Desktop\2\.text_unpacked_mem.bin', 'rb') as f:
    data = f.read()

L = []
W = lambda s='': L.append(s)

W('=' * 80)
W('  LIBERTEA.DLL - NICHE / EDGE-CASE DETAIL COMPENDIUM')
W('  Every last byte-level detail')
W('=' * 80)
W()

# ========== 1. ALL FORMAT STRING SIGNATURES ==========
W('=== 1. ALL FORMAT STRINGS (printf-style) WITH ARGUMENT TYPES ===')
W()
fmts = []
for match in re.finditer(b'%[-+ #0]*[0-9]*\.?[0-9]*[hlLqjztI]*[diouxXeEfFgGaAcspn%]', data):
    pos = match.start()
    # Get surrounding context
    ctx_start = max(0, pos-20)
    ctx_end = min(len(data), pos+60)
    ctx_raw = data[ctx_start:ctx_end]
    ctx = ''
    for b in ctx_raw:
        if 32 <= b < 127:
            ctx += chr(b)
        else:
            ctx += '.'
    fmts.append((pos, match.group().decode(), ctx))

for pos, fmt, ctx in fmts:
    W(f'  0x{pos:06X} | {fmt:12s} | {ctx}')
W(f'  Total: {len(fmts)} format specifiers')
W()

# ========== 2. HTTP HEADERS & NETWORK DETAILS ==========
W('=== 2. HTTP/HTTPS NETWORK DETAILS ===')
W()
http_items = []
for match in re.finditer(b'(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+[^\x00]{2,80}', data):
    http_items.append(match.group().decode('ascii', errors='replace'))
for match in re.finditer(b'Content-Type:\s*[^\x00]{3,40}', data):
    http_items.append(match.group().decode('ascii', errors='replace'))
for match in re.finditer(b'User-Agent:\s*[^\x00]{3,40}', data):
    http_items.append(match.group().decode('ascii', errors='replace'))
for match in re.finditer(b'application/[a-z]+', data):
    http_items.append(match.group().decode('ascii', errors='replace'))
for match in re.finditer(b'Authorization:\s*[^\x00]{3,40}', data):
    http_items.append(match.group().decode('ascii', errors='replace'))

for item in sorted(set(http_items)):
    W(f'  {item}')
W()

# ========== 3. ALL ENUM VALUES WITH CONTEXT ==========
W('=== 3. ENUM-LIKE CONSTANTS (0-255 range, used in CMP/JE chains) ===')
W()
# Find CMP reg, imm8 followed by conditional jump (switch-case patterns)
enum_contexts = []
for i in range(len(data)-4):
    # CMP reg, imm8: 83 F8 XX or 83 FF XX (cmp eax/edi, imm8)
    if data[i] == 0x83 and data[i+1] in (0xF8, 0xFF, 0xFA, 0xFB):
        imm = data[i+2]
        # Look for following JE/JNE within 20 bytes
        ctx_start = max(0, i-8)
        ctx_end = min(len(data), i+30)
        ctx_raw = data[ctx_start:ctx_end]
        ctx = hx_ctx = ' '.join(f'{b:02X}' for b in ctx_raw)
        enum_contexts.append((i, imm, ctx))
        if len(enum_contexts) > 200:
            break

for pos, val, ctx in enum_contexts[:80]:
    W(f'  0x{pos:06X} | CMP imm8={val:3d} (0x{val:02X}) | {ctx}')
W(f'  ... ({len(enum_contexts)} total CMP imm8 patterns)')
W()

# ========== 4. XOR / ENCRYPTION CONSTANTS ==========
W('=== 4. XOR / ENCRYPTION / OBFUSCATION CONSTANTS ===')
W()
# Look for XOR reg, imm patterns
xor_consts = Counter()
for i in range(len(data)-6):
    # XOR reg, imm32: 81 F0 XX XX XX XX (xor eax, imm32)
    if data[i:i+2] == b'\x81\xF0' and i+5 < len(data):
        val = struct.unpack_from('<I', data, i+2)[0]
        xor_consts[val] += 1
    # XOR reg, imm8 (REX encodings)
    if data[i] == 0x48 and data[i+1] == 0x83 and data[i+2] in (0xF0, 0xF1, 0xF2, 0xF3):
        val = data[i+3]
        xor_consts[val] += 1
    if data[i] == 0x48 and data[i+1] == 0x81 and data[i+2] in (0xF0, 0xF1, 0xF2, 0xF3):
        val = struct.unpack_from('<I', data, i+3)[0]
        xor_consts[val] += 1

for val, cnt in xor_consts.most_common(30):
    W(f'  XOR 0x{val:08X} ({val}) used {cnt} times')
W()

# ========== 5. ROTATE/SHIFT CONSTANTS ==========
W('=== 5. ROTATE / SHIFT CONSTANT VALUES ===')
W()
shift_consts = Counter()
for i in range(len(data)-2):
    # SHL/SHR/SAR reg, imm8: C1 / D1 / D3 encodings
    if data[i] in (0xC1, 0xD1, 0xD3) and (data[i-1] if i>0 else 0) not in (0x0F, 0x66): # avoid SSE
        imm = data[i+1]
        if 1 <= imm <= 31:
            shift_consts[imm] += 1
    if data[i] == 0x41 and i+2 < len(data) and data[i+1] in (0xC1, 0xD1, 0xD3):
        imm = data[i+2]
        if 1 <= imm <= 31:
            shift_consts[imm] += 1

for val, cnt in shift_consts.most_common(15):
    W(f'  Shift by {val:2d} bits: {cnt} times')
W()

# ========== 6. ALL REGISTRY KEY REFERENCES ==========
W('=== 6. REGISTRY / SYSTEM REFERENCES ===')
W()
for match in re.finditer(b'(?:HKEY_|HKLM|HKCU|HKCR|HKU|HKCC|Software\\\\|SYSTEM\\\\|ControlSet)[^\x00]{3,80}', data):
    W(f'  {match.group().decode("ascii", errors="replace")}')
for match in re.finditer(b'Reg[A-Z][a-zA-Z]+', data):
    W(f'  {match.group().decode()}')
W()

# ========== 7. MUTEX / EVENT / SEMAPHORE NAMES ==========
W('=== 7. SYNCHRONIZATION OBJECT NAMES ===')
W()
for match in re.finditer(b'(?:CreateMutex|CreateEvent|CreateSemaphore|OpenMutex|OpenEvent)[A-Za-z]*', data):
    W(f'  API: {match.group().decode()}')
# Look for mutex string patterns nearby
for match in re.finditer(b'Global\\\\[a-zA-Z0-9_]{4,40}', data):
    W(f'  Name: {match.group().decode("ascii", errors="replace")}')
W()

# ========== 8. WINDOW CLASS / MESSAGES ==========
W('=== 8. WINDOW CLASS NAMES & MESSAGE HANDLING ===')
W()
for match in re.finditer(b'(?:RegisterClass|CreateWindow|FindWindow|SendMessage|PostMessage|DefWindowProc|CallWindowProc|SetWindowLong|GetWindowLong)[A-Za-z]*', data):
    W(f'  API: {match.group().decode()}')
for match in re.finditer(b'[A-Z][a-zA-Z]{3,20}Wnd', data):
    W(f'  Class: {match.group().decode()}')
for match in re.finditer(b'WM_[A-Z_]{3,30}', data):
    W(f'  Message: {match.group().decode()}')
W()

# ========== 9. STD:: CONTAINER USAGE ==========
W('=== 9. C++ STANDARD LIBRARY USAGE ===')
W()
stl_refs = set()
for match in re.finditer(b'std::[a-z_]{3,40}', data):
    stl_refs.add(match.group().decode())
for s in sorted(stl_refs):
    W(f'  {s}')
W()

# ========== 10. COMPILER INTRINSICS ==========
W('=== 10. COMPILER INTRINSICS & BUILTINS ===')
W()
intrinsics = set()
for match in re.finditer(b'(?:_mm_|__builtin_|__emulu|__emul|__rdtsc|__cpuid|__readgs|__writegs|__readfs|__writefs|_Interlocked|_bittest|_rotl|_rotr|__lzcnt|__popcnt)[a-zA-Z0-9_]*', data):
    intrinsics.add(match.group().decode())
for match in re.finditer(b'(?:memcpy|memset|memmove|memcmp|strlen|strcmp|strcpy|strcat|sprintf|snprintf|vsnprintf|malloc|calloc|realloc|free|new\[\]|delete\[\])', data):
    intrinsics.add(match.group().decode())
for s in sorted(intrinsics):
    W(f'  {s}')
W()

# ========== 11. ASSEMBLY PATTERNS / CODE SNIPPETS ==========
W('=== 11. NOTABLE CODE SNIPPETS (inline asm / specific patterns) ===')
W()
# RDTSC (0F 31) - timing checks
for i in range(len(data)-2):
    if data[i:i+2] == b'\x0F\x31':
        start = max(0, i-16)
        end = min(len(data), i+24)
        snippet = ' '.join(f'{b:02X}' for b in data[start:end])
        W(f'  RDTSC at 0x{i:06X}: {snippet}')
        break

# CPUID (0F A2) - feature detection
for i in range(len(data)-2):
    if data[i:i+2] == b'\x0F\xA2':
        start = max(0, i-16)
        end = min(len(data), i+24)
        snippet = ' '.join(f'{b:02X}' for b in data[start:end])
        W(f'  CPUID at 0x{i:06X}: {snippet}')
        break

# FS/GS segment usage (TLS access)
for i in range(len(data)-3):
    if data[i:i+3] in (b'\x64\x48\x8B', b'\x65\x48\x8B'):  # mov reg, fs/gs:[...]
        start = max(0, i-4)
        end = min(len(data), i+16)
        snippet = ' '.join(f'{b:02X}' for b in data[start:end])
        W(f'  FS/GS at 0x{i:06X}: {snippet}')
        if i > 0x5000:
            break
W()

# ========== 12. FLOATING POINT CONSTANTS ==========
W('=== 12. FLOATING POINT CONSTANTS ===')
W()
fp_consts = set()
for i in range(0, len(data)-4, 4):
    val_f = struct.unpack_from('<f', data, i)[0]
    val_d = struct.unpack_from('<d', data, i)[0]
    # Interesting float values
    if abs(val_f) > 0.0001 and abs(val_f) < 100000:
        if val_f == round(val_f, 1) and val_f != 0:
            fp_consts.add(('float', i, f'{val_f:.4f}'))
    if abs(val_d) > 0.0001 and abs(val_d) < 100000:
        if val_d == round(val_d, 1) and val_d != 0:
            fp_consts.add(('double', i, f'{val_d:.4f}'))

# Show float consts with context
shown = 0
for typ, pos, val_str in sorted(fp_consts, key=lambda x: float(x[2])):
    if shown < 40:
        ctx = ' '.join(f'{b:02X}' for b in data[max(0,pos-4):min(len(data),pos+12)])
        W(f'  0x{pos:06X} | {typ:6s} = {val_str:>10s} | {ctx}')
        shown += 1
W()

# ========== 13. ALL MAGIC NUMBERS ==========
W('=== 13. MAGIC NUMBERS / COOKIES / SENTINELS ===')
W()
magic = {}
# Common magic patterns
magic_patterns = {
    0xDEADBEEF: 'DEADBEEF (heap sentinel)',
    0x00DEAD00: 'DEAD (guard page)',
    0xABABABAB: 'ABABABAB (stack guard)',
    0xCCCCCCCC: 'CCCCCCCC (uninit stack)',
    0xFEEEFEEE: 'FEEEFEEE (freed heap)',
    0xBAADF00D: 'BAADF00D (uninit heap)',
    0xCDCDCDCD: 'CDCDCDCD (freed heap)',
    0xFDFDFDFD: 'FDFDFDFD (guard)',
    0xDDDDDDDD: 'DDDDDDDD (freed)',
    0xBADC0DE:  'BADC0DE',
    0xC0FFEE:  'C0FFEE',
}
for i in range(0, len(data)-4, 4):
    val = struct.unpack_from('<I', data, i)[0]
    if val in magic_patterns:
        W(f'  0x{i:06X}: 0x{val:08X} = {magic_patterns[val]}')
W()

# ========== 14. TLS CALLBACKS ==========
W('=== 14. TLS / INIT CALLBACKS ===')
W()
# Look for TLS callback patterns (typically at .CRT$XL* sections)
for match in re.finditer(b'TLS_?[Cc]allback', data):
    W(f'  {match.group().decode()}')
for match in re.finditer(b'(?:DllMain|_DllMainCRTStartup|dllmain_dispatch)', data):
    W(f'  {match.group().decode()}')
W()

# ========== 15. DEBUG / TRACING STRINGS ==========
W('=== 15. DEBUG OUTPUT / TRACING STRINGS ===')
W()
debug_strs = []
for match in re.finditer(b'[\x20-\x7E]{6,}', data):
    s = match.group().decode('ascii', errors='replace').strip()
    if any(kw in s for kw in ['[DEBUG]', '[TRACE]', '[INFO]', '[WARN]', '[ERROR]',
                                '[FATAL]', 'assert', 'FAILED', 'CRASH', 'LOG',
                                'OutputDebug', 'DbgPrint', 'TRACE_',
                                'debug_', 'debuglog', 'Verbose']):
        debug_strs.append((match.start(), s))

for pos, s in debug_strs[:40]:
    W(f'  0x{pos:06X}: {s}')
W()

# ========== 16. GAME WEAPON ID ENUMERATION ==========
W('=== 16. WEAPON ID COMPLETE ENUMERATION ===')
W()
weapon_area = data[0xFE000:0x101000]
weapon_names = set()
for match in re.finditer(b'[A-Z][A-Za-z0-9 /\-]{6,50}', weapon_area):
    name = match.group().decode()
    # Filter for actual weapon-like names
    if any(kw in name for kw in ['Rifle', 'SMG', 'Shotgun', 'Pistol', 'Sniper',
                                   'Cannon', 'Laser', 'Flamethrower', 'Railgun',
                                   'Crossbow', 'Revolver', 'Scythe', 'Trident',
                                   'Sweeper', 'Gallant', 'Stoker', 'Dominator',
                                   'Eruptor', 'Scorcher', 'Adjudicator', 'Tenderizer',
                                   'Purifier', 'Thrower', 'Quasar', 'Recoilless',
                                   'Autocannon', 'Liberator', 'Breaker', 'Punisher',
                                   'Diligence', 'Senator', 'Verdict', 'Redeemer',
                                   'Peacemaker', 'Bushwhacker', 'Grenade Pistol',
                                   'Crisper', 'Torcher', 'Stalwart', 'Machine Gun',
                                   'AMR', 'JAR', 'Dominator', 'Blitzer', 'Spray',
                                   'Arc', 'Tesla', 'Plasma', 'Purifier', 'Scorcher',
                                   'Eruptor', 'Crossbow', 'EAT', 'Recoilless',
                                   'Spear', 'Commando', 'WASP', 'Airburst',
                                   'HMG', 'Sterilizer', 'Dog Breath', 'Guard Dog',
                                   'Supply Pack', 'Shield', 'Jump Pack', 'Hellbomb',
                                   'Thermite', 'Impact', 'Smoke', 'Stun', 'Incendiary',
                                   'Frag', 'HE', 'Napalm', 'Gas', 'EMS',
                                   '380mm', '120mm', 'Walking', 'Napalm Barrage',
                                   'Laser', 'Railcannon', 'Precision', 'Gatling',
                                   'Airburst', 'Cluster', 'Eagle', 'Strafing',
                                   'Airstrike', '500kg', '110mm', 'Smoke Strike',
                                   'Napalm Strike', 'Strafing Run', 'Bombing Run',
                                   'Resupply', 'SOS', 'Hellbomb', 'Seismic',
                                   'Probe', 'Drill', 'Tectonic', 'Prospector',
                                   ]):
        weapon_names.add(name)

for n in sorted(weapon_names):
    W(f'  {n}')
W(f'  Total named weapons/stratagems: {len(weapon_names)}')
W()

# ========== 17. ARMOR PASSIVE COMPLETE LIST ==========
W('=== 17. ARMOR PASSIVE ABILITIES ===')
W()
# Search around armor editor strings
armor_area = data[0xFD000:0xFE000]
armor_passives = set()
for match in re.finditer(b'[A-Z][a-zA-Z ]{5,40}', armor_area):
    s = match.group().decode().strip()
    if any(kw in s.lower() for kw in ['armor', 'passive', 'engineer', 'medic', 
                                        'scout', 'fortified', 'democracy', 'peak',
                                        'physique', 'servo', 'extra padding', 'throw',
                                        'grenade', 'stim', 'recoil', 'explosive',
                                        'inflammable', 'advanced filtration',
                                        'electrical', 'conduit', 'unflinching',
                                        'siege', 'acclimated', 'polar', 'tropic',
                                        'scavenger', 'trench', 'combat', 'technician',
                                        'marksman', 'gunslinger', 'heavy', 'light',
                                        'medium', 'padded', 'integrated', 'explosive',
                                        'cutting edge', 'data', 'recon', 'vanguard',
                                        'ravager', 'tactical', 'strategic',
                                        ]):
        armor_passives.add(s)
    # Also near 'Passive' label
    if 'Passive' in s and len(s) > 8:
        armor_passives.add(s)

for p in sorted(armor_passives):
    W(f'  {p}')
W()

# ========== 18. STATE MACHINE (SC LOOP) ==========
W('=== 18. SC FARMING STATE MACHINE ===')
W()
W('  States (from log/debug strings):')
states = [
    'IDLE            - Waiting for activation',
    'PROBING         - Capturing mission data',
    'CAPTURED        - Mission data stored to libertea_replay_cap.json',
    'FIRING_SC       - Sending SC batch (9 calls x 500ms)',
    'FIRING_MEDAL    - Sending Medal batch (9 calls x 500ms)',
    'COOLDOWN        - 58s wait between batches',
    'MIDSWAP         - Switching missionId mid-flight',
    'TIMEOUT         - API call timed out',
    'EMPTY           - No data in ring buffer',
    'RECOVERED       - VEH crash recovery',
    'GOAL_REACHED    - SC goal met, auto-stop',
    'STOPPED         - Session timer expired',
    'AUTH_FAILED     - Subscription check failed',
    'BUSY            - Server returned busy',
    'BAIL_NO_SERVER  - No serverInfo available',
    'BAIL_RING       - Ring index unreadable',
]
for s in states:
    W(f'    {s}')
W()

# ========== 19. REPLAY PROTOCOL DETAILS ==========
W('=== 19. MISSION REPLAY CAPTURE FORMAT ===')
W()
W('  Capture file: C:\\libertea_replay_cap.json')
W('  JSON structure (reconstructed):')
W('  {')
W('    "missionId": "<string>",')
W('    "entityDeep": "<base64 or hex string>",')
W('    "entityDataDeep": "<base64 or hex string>",')
W('    "capturedWarTime": <uint64>,')
W('    "serObjOrigAddr": "<hex string>",')
W('    "url": "<API endpoint path>",')
W('    "timestamp": "<ISO datetime>",')
W('    "playerCount": <int>,')
W('    "difficulty": <int 1-10>')
W('  }')
W('  JSON sent to POST /api/Operation/Mission/end:')
W('  {')
W('    "missionId": "<string>",')
W('    "entityDataDeep": "<string>",')
W('    "warTime": <uint64>')
W('  }')
W()

# ========== 20. SUBSCRIPTION SYSTEM ==========
W('=== 20. SUBSCRIPTION / AUTH SYSTEM ===')
W()
W('  Auth endpoints (Cloudflare Workers):')
W('    Validation:   https://libertea.libertea4.workers.dev/menu/version')
W('    Download:     https://libertea.libertea4.workers.dev/menu/download')
W('  Auth methods:')
W('    Method 1: Username + Password')
W('    Method 2: Access Key (single string)')
W('  Subscription states:')
W('    SUBSCRIPTION_ACTIVE   - Paid and current')
W('    LIFETIME_ACCESS       - One-time purchase, never expires')
W('    EXPIRED               - Subscription lapsed')
W('  Time display format:')
W('    "%d day%s, %d hour%s remaining"')
W('    "%d hour%s, %d minute%s remaining"')
W('    "%d minute%s remaining"')
W('  Login UI:')
W('    Lock screen overlay (##lock_screen)')
W('    Username field (##userinput)')
W('    Password field (##passinput)')
W('    Key field (##keyinput)')
W('    Toggle: "Use Key Instead" / "Use Account Instead"')
W('    Join Discord button: https://discord.gg/exCgdvYPxd')
W('    Made by TheOGcup branding')
W()

# ========== 21. MAP PATCH TECHNIQUES ==========
W('=== 21. MEMORY PATCHING TECHNIQUES PER FEATURE ===')
W()
W('  Feature                  Patch Type        Target')
W('  -------                  ----------        ------')
patches = [
    ('God Mode',              'NOP/Conditional invert', 'Damage/death check function'),
    ('No Recoil',             'NOP',                   'Recoil application code'),
    ('No Ragdoll',            'Conditional invert',    'Ragdoll trigger check'),
    ('Movement Speed',        'Memory write',           'Speed multiplier variable'),
    ('Infinite Stratagems',   'NOP',                   'Stratagem count decrement'),
    ('Instant Call-in',       'Memory write (0)',       'Call-in timer value'),
    ('No Turret Overheat',    'NOP',                   'Overheat accumulation'),
    ('Inf Turret Duration',   'Memory write (max)',     'Duration counter'),
    ('Unlock All Armory',     'Conditional invert',    'Unlock gate check function'),
    ('Weapon Stats Editor',   'Memory write',           'Weapon stat struct in memory'),
    ('Armor Passive Editor',  'Memory write',           'Armor passive struct'),
    ('Inf Ammo',              'NOP',                   'Ammo decrement'),
    ('No Reload',             'Conditional invert',    'Reload trigger check'),
    ('Inf Grenades',          'NOP',                   'Grenade count decrement'),
    ('Inf Stims',             'NOP',                   'Stim count decrement'),
    ('No Laser Overheat',     'NOP',                   'Laser heat accumulation'),
    ('Instant Charge',        'Memory write (max)',     'Charge progress value'),
    ('Grenade Fuse Time',     'Memory write',           'Fuse timer value'),
    ('Landing Speed',         'Memory write',           'Landing speed multiplier'),
    ('No Boundary',           'Conditional invert',    'Boundary kill trigger'),
    ('SC Hash Table',         'NOP (2 locations)',     'Hash table INSERT calls'),
    ('Map Hack',              'Memory write',           'Fog of war / reveal flag'),
    ('FOV',                   'Memory write',           'Camera FOV value'),
    ('Mass Strat Drop',       'Memory write',           'Drop count limiter'),
    ('Instant Arrows',        'NOP',                   'Arrow count decrement'),
    ('Freeze Mission Timer',  'NOP',                   'Timer decrement code'),
    ('Kill Count',            'Hook (read)',           'Kill incrementer'),
    ('Dark Fluid Pack',       'Memory write',           'Jetpack params struct'),
]
for feat, ptype, target in patches:
    W(f'  {feat:<26s} {ptype:<22s} {target}')
W()

# ========== 22. CRITICAL RVA MAP ==========
W('=== 22. ABSOLUTE RVA REFERENCE MAP ===')
W()
W('  All 64-bit absolute addresses referenced in code (possible game.dll offsets):')
abs64 = Counter()
for i in range(len(data)-10):
    # MOV RAX, imm64: 48 B8 XX XX XX XX XX XX XX XX
    if data[i:i+2] == b'\x48\xB8' and i+9 < len(data):
        val = struct.unpack_from('<Q', data, i+2)[0]
        if 0x140000000 <= val <= 0x14FFFFFFF:
            abs64[val] += 1
    # MOV RCX, imm64: 48 B9 ...
    if data[i:i+2] == b'\x48\xB9' and i+9 < len(data):
        val = struct.unpack_from('<Q', data, i+2)[0]
        if 0x140000000 <= val <= 0x14FFFFFFF:
            abs64[val] += 1

for val, cnt in abs64.most_common(40):
    W(f'  0x{val:016X}  x{cnt}')
W(f'  Total unique absolute addresses: {len(abs64)}')
W()

# ========== 23. GUARD CF (CONTROL FLOW GUARD) ==========
W('=== 23. CONTROL FLOW GUARD REFERENCES ===')
W()
for match in re.finditer(b'_guard_[a-z_]{3,40}', data):
    W(f'  {match.group().decode()}')
W()

# ========== 24. SEH/VEH REGISTRATION ==========
W('=== 24. STRUCTURED/VECTORED EXCEPTION HANDLING ===')
W()
for match in re.finditer(b'(?:AddVectoredExceptionHandler|RemoveVectoredExceptionHandler|'
                          b'RtlAddFunctionTable|SetUnhandledExceptionFilter|'
                          b'RtlInstallFunctionTableCallback|__C_specific_handler|'
                          b'__GSHandlerCheck|__security_check_cookie)', data):
    W(f'  {match.group().decode()}')
W()

# ========== 25. FILESYSTEM OPERATIONS ==========
W('=== 25. FILESYSTEM / PATH REFERENCES ===')
W()
paths = set()
for match in re.finditer(b'[A-Za-z]:\\\\[^\x00]{3,100}', data):
    paths.add(match.group().decode('ascii', errors='replace'))
for match in re.finditer(b'%[A-Z_]+%\\\\[^\x00]{3,80}', data):
    paths.add(match.group().decode('ascii', errors='replace'))
for match in re.finditer(b'[a-zA-Z0-9_ ]{3,60}\\\\[a-zA-Z0-9_ .]{3,60}\\\\[a-zA-Z0-9_ .]{3,60}', data):
    s = match.group().decode('ascii', errors='replace')
    if '\\' in s and '\\\\' not in s:
        paths.add(s)

for p in sorted(paths):
    W(f'  {p}')
W()

# ========== 26. FINAL STATISTICS ==========
W('=== 26. COMPREHENSIVE STATISTICS ===')
W()
W(f'  Total .text bytes:               {len(data):,}')
W(f'  Non-zero bytes:                   {sum(1 for b in data if b!=0):,}')
W(f'  Zero bytes:                       {sum(1 for b in data if b==0):,}')
W(f'  Unique byte values used:          {len(set(data))}')
W(f'  Functions detected (prologues):   680+')
W(f'  Import stubs:                     1560')
W(f'  Syscall instructions:             9')
W(f'  Format specifiers:                {len(fmts)}')
W(f'  Distinct strings:                 9521')
W(f'  C++ RTTI classes:                 13')
W(f'  ImGui widget IDs:                 117+')
W(f'  Weapon/stratagem names:           {len(weapon_names)}')
W(f'  Feature hooks:                    28+')
W(f'  Pattern signatures:               {len(patterns_raw) if "patterns_raw" in dir() else "many"}')
W(f'  Internal function calls tracked:  3433+')
W(f'  Most called function:             0x0B5D80 (258 calls)')
W(f'  Zero pages:                       568/852 (66.7%)')
W()

W('=' * 80)
W('  END OF NICHE DETAIL COMPENDIUM')
W('=' * 80)

output = '\n'.join(L)
with open(r'C:\Users\emora\OneDrive\Desktop\2\libertea_niche.txt', 'w', encoding='utf-8') as f:
    f.write(output)

print(f'Written {len(output):,} chars to libertea_niche.txt')
