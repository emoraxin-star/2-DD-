import struct, re

with open(r'C:\Users\emora\OneDrive\Desktop\2\.text_unpacked_mem.bin', 'rb') as f:
    data = f.read()

lines = []
def add(s=''):
    lines.append(s)

add('=' * 70)
add('LIBERTEA.DLL - EXTRACTED POINTERS, OFFSETS & IDs')
add('=' * 70)
add()

# 1. GAME API ENDPOINTS
add('--- GAME API ENDPOINTS ---')
add('  POST api.live.prod.thehelldiversgame.com/api/Operation/Mission/end')
add('  (SC/Medal farming fires batches of 9 calls x 500ms with 58s cooldown)')
add()

# 2. DISCORD / C2
add('--- DISTRIBUTION & AUTH ---')
add('  Discord:      https://discord.gg/exCgdvYPxd')
add('  Update C2:    https://libertea.libertea4.workers.dev/menu/version')
add('  Download C2:  https://libertea.libertea4.workers.dev/menu/download')
add('  Auth:         Username/Password or Access Key (subscription-based)')
add('  GUID:         60862556-ee16-4ae4-b002-64f6acbc66c6')
add()

# 3. IMPORT FUNCTIONS USED
add('--- KEY WIN32 API USED ---')
add('  NtProtectVirtualMemory  (via direct syscall stub, bypasses ntdll hooks)')
add('  NtQueryInformationProcess (via syscall)')
add('  GetModuleInformation')
add('  FlsAlloc / FlsGetValue / FlsSetValue  (Fiber Local Storage)')
add('  XInputGetState / XInputGetCapabilities')
add('  wglSwapIntervalEXT  (OpenGL overlay render hook)')
add('  SeDebugPrivilege     (in Bypass.exe injector)')
add()

# 4. HOOK POINTS & PATTERNS
add('--- HOOK PATTERN SIGNATURES (x86-64 byte patterns in game.dll) ---')
add()
patterns = [
    ('GodMode / Player', [
        'GodMode: N/A (likely patches specific flags)',
        '[GodMode] READY ... Hook1=0x%llX Hook2=0x%llX Hook3=0x%llX',
    ]),
    ('Grenade Count Bypass', [
        '0F 5B DB F3 41 0F 59 4E ?? F3 ...',
        'NOP grenade count conversion',
        'conditional jump (bypass strategem count)',
    ]),
    ('No Boundary', [
        '0F 84 ?? ?? ?? ?? 80 7F ?? ?? 0F 85 ?? ?? ?? ?? F3 0F',
        'conditional jump (bypass boundary)',
    ]),
    ('Landing Speed Multiply', [
        'F3 0F 11 44 3B ?? F3 0F 59 C7 F3 0F 5A C0',
    ]),
    ('Stratagem/Weapon/Armor Unlock', [
        '48 8B 0D ?? ?? ?? ?? 44 89 80 60 0C',
        '[UnlockArmory] Patches stratagem/weapon/armor unlock checks',
    ]),
    ('Grenade Fuse Time', [
        'F3 0F 11 44 C8 ?? 0F',
    ]),
    ('Turret Overheat', [
        'F3 0F 11 4C A8 ?? 49',
        'No Turret Overheat',
    ]),
    ('Turret Duration', [
        'F3 45 0F 11 5E ?? E9',
        'Inf Turret Duration',
    ]),
    ('Active Session Pointer', [
        '48 8B 35 ?? ?? ?? ?? 49 8B E9 41 8B D8 48 8B 88 28 01',
        'GetActiveSession() = 0x%llX',
    ]),
    ('Alternate Session Pattern', [
        '48 8B 35 ?? ?? ?? ?? 33 C9 49 8B E9 41 8B D8 4C 8B 90 28 01',
    ]),
    ('Reward Multiplier', [
        '41 8B 47 ?? 4C 8B 7C 24 ?? 4C',
    ]),
    ('Stratagem Count Decrement', [
        '42 83 2C 81 ?? 48  (patch to NOP/JMP for infinite)',
    ]),
    ('Kill Counter', [
        '39 46 ?? 75 ?? FF C5  (Kill Count: %.0f)',
    ]),
    ('Stim Count', [
        'Stims (No Use) patch',
    ]),
    ('SC Entity Hash Table', [
        'NOP both hash table INSERT calls that mark SC entities as consumed',
    ]),
    ('Laser Overheat', [
        'No Laser Overheat pattern',
    ]),
    ('Instant Charge', [
        'Instant Charge pattern',
    ]),
    ('Stratagem Instant Call', [
        'Instant Strat Callin: patches call-in time',
    ]),
    ('Present Hook (Overlay)', [
        'ScPresent::Install: hwnd=%p origWndProc=%p',
        'wglSwapIntervalEXT hook for ImGui overlay rendering',
    ]),
]
for name, sigs in patterns:
    add(f'  [{name}]')
    for s in sigs:
        add(f'    {s}')
    add()

# 5. GAME STRUCTURE OFFSETS / MEMBERS
add('--- GAME STRUCTURE MEMBER REFERENCES ---')
add()
add('  ScActivityAPC structure:')
add('    actObj=%p TID=%u')
add('    actId32=0x%08X  (activity ID)')
add('    objId=0x%08X    (object ID)')
add('    ctr=0x%X flag=0x%X ring=%u  (control/flag/ring buffer index)')
add('    url="%.40s"  (API URL)')
add()
add('  Mission capture data:')
add('    missionId=%s         (mission string identifier)')
add('    capturedWarTime      (war time during capture)')
add('    serObjOrigAddr       (server object original address)')
add('    entityDeep           (JSON: entity hierarchy snapshot)')
add('    entityDataDeep       (JSON: entity data payload)')
add()
add('  Session data:')
add('    Session+0x28, +0x128, etc. (multiple structure offsets)')
add('    GetActiveSession() -> 0x%llX or NULL')
add('    session active flag checks')
add()
add('  SC Loop state:')
add('    Crashes absorbed: %d  (survives game crashes)')
add('    cooldown: 58 seconds between batch fires')
add('    batch: 9 API calls spaced 500ms')
add('    mid=%s  (mission ID in flight)')
add('    retry #%d/%d  (retry mechanism)')
add()

# 6. WEAPON LIST
add('--- WEAPON LIST (51 primary weapons for XP override) ---')
add()
weapons = [
    'AR-23P Liberator Penetrator',
    'AR-23C Liberator Concussive',
    'AR-23A Liberator Carbine',
    'AR-48 Truth Whisperer',
    'AR-59 Suppressor',
    'R-72 Censor',
    'R-63CS Diligence Counter-Sniper',
    'MA5C Assault Rifle',
    'M7S SMG',
    'SMG-203 Gallant',
    'SMG/FLAM-34 Stoker',
    'SG-8F Punisher Fire of Liberty',
    'SG-225SP Breaker Spray & Pray',
    'SG-97 Sweeper',
    'M90A Shotgun',
    'DBS-2 Double Freedom',
    'AR/GL-21 One-Two',
    'Las-16 Trident',
    'Autocannon',
    'Laser Cannon',
    'Quasar Cannon',
    'Flamethrower',
    'Railgun',
    '...  (+28 more weapons)',
]
for w in weapons:
    add(f'  {w}')
add()

# 7. FEATURE TOGGLES (Dear ImGui ## IDs)
add('--- IMGUI MENU TOGGLE IDs ---')
add()
toggles = [
    ('##mult',      'Reward Multiplier toggle (ON/OFF)'),
    ('##maxrew',    'MAX ALL rewards button'),
    ('##fxp',       'XP Multiplier slider'),
    ('##fmed',      'Medals Multiplier slider'),
    ('##fslips',    'Req Slips Multiplier slider'),
    ('##diff',      'Force Difficulty toggle'),
    ('##difflvl',   'Difficulty tier combo (1-10)'),
    ('##samp',      'Add Samples Instantly toggle'),
    ('##smax',      'Max samples button'),
    ('##fsamp_c',   'Common samples slider'),
    ('##fsamp_r',   'Rare samples slider'),
    ('##fsamp_s',   'Super samples slider'),
    ('##sr',        'Samples Over Limit Reward toggle'),
    ('##srmax',     'Max sample reward button'),
    ('##src',       'Common reward slider'),
    ('##srr',       'Rare reward slider'),
    ('##srs',       'Super reward slider'),
    ('##shut5',     'Instant Shuttle toggle'),
    ('##ic5',       'Instant Complete toggle'),
    ('##spd',       'Movement Speed slider'),
    ('##smult',     'Speed multiplier slider'),
    ('##isc',       'Instant Strat Call-in toggle'),
    ('##msd',       'Mass Strat Drop toggle'),
    ('##msc',       'Mass Strat Drop count'),
    ('##fov',       'FOV slider'),
    ('##ua',        'Unlock All Armory toggle'),
    ('##wxpovr',    'Weapon XP Override toggle'),
    ('##repperwep', 'Replays per gun counter'),
    ('##ag',        'All Guns ON toggle'),
    ('##sg',        'Selected Guns ON toggle'),
    ('##pwcombo',   'Primary weapon combo dropdown'),
    ('##sgall',     'Select all weapons'),
    ('##sgnone',    'Deselect all weapons'),
    ('##sgsearch',  'Weapon search input'),
    ('##sglist',    'Weapon checkbox list'),
    ('##SCTimer',   'SC Timer value (minutes, 0=unlimited)'),
    ('##goal',      'SC Goal value'),
    ('##sct',       'SC Tracker reset button'),
    ('##afk',       'AFK Prevention toggle'),
    ('##erad_ih',   'Infinite Horde Mode toggle'),
    ('##ap_scan',   'Scan Armor button'),
    ('##ap_armor',  'Armor selection dropdown'),
    ('##ap_pass',   'Passive selection dropdown'),
    ('##ap_go',     'Apply armor mod button'),
    ('##ap_rst',    'Reset armor defaults button'),
    ('##lock_screen','Login screen container'),
    ('##userinput', 'Username input field'),
    ('##passinput', 'Password input field'),
    ('##keyinput',  'Access key input field'),
    ('##sub_info',  'Subscription info display'),
    ('##libertea_main', 'Main window container'),
    ('##content_area', 'Content tab area'),
    ('##farming_scroll', 'Farming tab scroll area'),
    ('##sc_scroll', 'Super Credits tab scroll'),
    ('##replay_scroll', 'Replay tab scroll'),
    ('##log_scroll', 'Logs tab scroll'),
    ('##misc_scroll', 'Misc tab scroll'),
    ('##inbox_scroll', 'Updates/Inbox tab scroll'),
    ('##pk',        'Dark Fluid Pack editor'),
    ('##pk_rst',    'Reset pack defaults'),
]
for tid, desc in toggles:
    add(f'  {tid:<16} {desc}')
add()

# 8. DIFFICULTY
add('--- DIFFICULTY TIERS ---')
add()
for t in ['1 - Trivial (0%)', '2 - Easy (0%)', '3 - Medium (25%)', '4 - Challenging (50%)',
          '5 - Hard (75%)', '6 - Extreme (100%)', '7 - Super Helldive (150%)', '8 - (200%)']:
    add(f'  {t}')
add()

# 9. GAME FILES
add('--- GAME FILE PATHS ---')
add()
add('  Steam\\steamapps\\common\\Helldivers 2\\bin\\data\\exploded_dat')
add('  C:\\libertea_replay_cap.json  (replay capture file)')
add('  %s\\ntdll.dll  (resolved at runtime for syscall stubs)')
add()

# 10. CRASH / DEBUG
add('--- DEBUG LOG FORMAT STRINGS ---')
add()
add('  === LIBERTEA CRASH LOG ===')
add('  Time:        %04u-%02u-%02u %02u:%02u:%02u')
add('  [HTTP] INJECT: missionId="%s" (%s) injected (%d ... %d bytes)')
add('  [HTTP-RESP] POST missionId=%s')
add('  [HTTP-RESP] Golden capture: hi2=%p rawPost=%p')
add('  [SC] MIDSWAP call %d/%d: str=%d bin=%d')
add('  [SC] VEH recovered crash  (Vectored Exception Handler crash recovery)')
add('  [GodMode] READY ... Hook1=0x%llX Hook2=0x%llX Hook3=0x%llX')
add('  [WeaponEditor] Hook')
add('  [UnlockArmory] %s')
add('  [AllGuns] Weapon: %s (%d/%d), cycle %d/%d')
add('  [SelectedGuns] Weapon: %s (slot %d/%d), cycle %d/%d')
add('  [WeaponOvr] Patched %d weapon slot(s) -> ID %u (%s)')
add('  [Auto] No capture data - probe a mission first')
add('  [Replay] Watchdog: reset stuck replayInProgress flag')
add('  WARNING: Game may have updated ... %d/%d patterns found. Some features may not work.')
add('  WARNING: Hook mismatch ... update may be needed')
add('  Hook verified')
add('  Handler install failed')
add()

# 11. KEY FUNCTION RVAs
add('--- KEY .TEXT SECTION FUNCTION RVAs (base=RVA 0x1000) ---')
add()
add('  Entry / DllMain:           0x1000')
add('  Core Init (call):          0x1480')
add('  Import Resolver Tail-Call: 0x8BEB8')
add('  Allocator (malloc):        0x8BB24')
add('  Init Helper:               0x8B880')
add('  Object Constructor Helper: 0x8D920 / 0x8D9A0')
add('  Get Data Ptr:              0x11C0')
add('  Lock/Acquire:              0x11D0')
add('  Init/Create:               0x1300')
add('  Import stubs group:        0x1020 - 0x10A0')
add('  Decompression entry:       in .rsrc section (0x3C4F30 RVA)')
add()

# 12. SC LOOP MECHANICS
add('--- SC FARMING LOOP MECHANICS ---')
add()
add('  1. Probe a mission to capture data (entityDeep, entityDataDeep, warTime)')
add('  2. Store capture in C:\\libertea_replay_cap.json')
add('  3. Auto-Replay fires batches of 9 API calls to:')
add('     POST api.live.prod.thehelldiversgame.com/api/Operation/Mission/end')
add('  4. Each batch: 9 calls x 500ms apart')
add('  5. Cooldown between batches: 58 seconds')
add('  6. Alternates SC and Medal batches')
add('  7. Crash recovery via Vectored Exception Handler (VEH)')
add('  8. SC goal auto-stops when reached')
add('  9. Auto-sync distributes SC across lobby players')
add('  10. NOPs hash table INSERT calls to prevent duplicate detection')
add()

# 13. INJECTOR BYPASS TECHNIQUE
add('--- INJECTOR BYPASS TECHNIQUE ---')
add()
add('  1. Enable SeDebugPrivilege via ntdll.dll')
add('  2. Target: helldivers2.exe')
add('  3. Block/remove GameMon.des / GameMon64.des (GameGuard drivers)')
add('  4. Inject LIBERTEA.DLL via CreateRemoteThread or similar')
add('  5. DLL loads, DllMain decompresses .text via custom aPLib variant')
add('  6. Resolve imports, scan for game.dll patterns, install hooks')
add('  7. Create ImGui overlay window (LIBERTEAWnd class)')
add('  8. Hook wglSwapIntervalEXT / Present for overlay rendering')
add()

add('=' * 70)
add('END OF EXTRACTION')
add('=' * 70)

output = '\n'.join(lines)
with open(r'C:\Users\emora\OneDrive\Desktop\2\libertea_analysis.txt', 'w', encoding='utf-8') as f:
    f.write(output)

print(f'Written {len(output):,} chars to libertea_analysis.txt')
print(output[:3000])
