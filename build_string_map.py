#!/usr/bin/env python3
"""
AGENT D v3 - Final: Tight filter, comprehensive categorization.
"""
import re, os
from collections import defaultdict, Counter

DATA_DIR = r"C:\Users\emora\OneDrive\Desktop\2\data"
LOGS_DIR = r"C:\Users\emora\OneDrive\Desktop\2\logs"
OUTPUT = os.path.join(LOGS_DIR, "agentD_string_map.txt")

print("Loading...")
# Load ASCII strings
all_ascii = []
with open(os.path.join(DATA_DIR, 'all_strings.txt'), 'r', encoding='utf-8', errors='replace') as f:
    for line in f:
        line = line.strip().replace('\x00', '').replace('\n', ' ').replace('\r', '')
        if ': ' not in line: continue
        parts = line.split(': ', 1)
        try:
            off = int(parts[0], 16); s = parts[1].strip()
            if len(s) >= 4: all_ascii.append((off, s))
        except: pass

# Load UTF-16LE
utf16_strings = set()
with open(os.path.join(DATA_DIR, 'strings_utf16le.txt'), 'r', encoding='utf-8', errors='replace') as f:
    for line in f:
        s = line.strip()
        if s and len(s) >= 3: utf16_strings.add(s)

print(f"ASCII: {len(all_ascii)}, UTF16: {len(utf16_strings)}")

# ============================================================
# STRICT FILTER - aggressive noise removal
# ============================================================

# List of patterns that are DEFINITELY asm noise
ASM_REJECT = [
    # Stack frame: D$0H, t$@H, etc.
    r'^[A-Za-z]?\$[0-9@A-Za-z]',
    # XMM registers
    r'^[XY]\$', r'^[GT]\$',
    # Prologue/epilogue
    r'^[|\\]?\$?\s*[UVWAHSUWAH_]{3,}',
    # "$ UVWAVAWH" style
    r'^\S*\s*[UVWAHSUWAH]{4,}$',
    # "D$PL", "d$`L", "L$HE3", "L$xE3" etc
    r'^[A-Za-z]\$[\dA-Za-z]+$',
    # "fF9$@u", "F`I;Fht", "D9t$8", "(D$0f", etc
    r'^\S*\$\S*$',  # any single-token with $ is likely asm
    # "pA_A^A]A\_^]", " A_A^_", etc
    r'^[\s_\]\[\^A-Za-z,@]*[A_][\^_]{2,}',
    # "9D$`L", "BD$`H", "GT$PH", "T$hH", "L$PH"
    r'^[A-Z0-9]+\$[\w]+$',
    # "gfffffffH+", "~ufff", "twfff", "333?", "fff?"
    r'^[~\w]*fff+\S*$',
    r'^[0-9?]{3,}$',
    # "yxxxxxxxH", "yxxxxxxxH+"
    r'xxxx+x',
    # "zuusf", "zmuk", "zl"? 
    r'^[a-z]{3,5}$',
    # " P fA", "X VH", "p WH", "X WH", "K SWAVAWH", "p ATAVAWH"
    r'^[A-Za-z ]\s+[A-Za-z]{2,4}$',
    # "|$ UATAUAVAWH" 
    r'^\|?\\?\$',
    # "z0u.H", "u!L+", etc
    r'^[A-Za-z]?\d[A-Za-z,.+]+$',
    # "GU`L", "GU L", "GU0L"
    r'^G[UT][0-9]?[ `]?[A-Z]$',
    # Assembly stack frame patterns: "D$ A", "t$ L", etc.
    r'^[A-Za-z]\$\s[A-Za-z0-9]$',
    r'^[A-Za-z]\$\sE\d?$',
    # Known asm patterns with spaces at low offsets
    r'^[A-Za-z]\d?\$\sE3$',      # "l$ E3", "d$ E3", "t$ E3"
    r'^[A-Za-z]\d?\$\s[A-Za-z0-9]$',  # "t$ H", "D$ 3"
    r'^[A-Za-z]\$\s[A-Za-z0-9]?[A-Za-z0-9]?$',
    r'^[A-Za-z]\$\sU[A-Z]+H$',    # "t$ UWAVH" etc
    r'^(.)?\s*[UVWAHuvwah]+[A-Z]*[UVWAH]*H?$',  # "UATAUAVAWH" etc
    r'^x\s+UATAUAVAWH',
    r'^[|\$]?\s*UVA',  # All UVWAH patterns
    r'^[A-Za-z]\s+E\d$',  # "N E3", "C E3"
    r'^[A-Za-z]\s+D8',  # "u D8", "X D8"
    r'^[A-Za-z0-9]\$\D?[A-Za-z0-9]?\s+E[A-Za-z]?\d?$',  # "l$ E9n"
    r'^\d\$\s',  # "9$ ..."
    r'^[A-Z0-9]+\sH\d$',  # "M H3"
    r'^[\w]?\s*fffff',  # "ffffff", "-ffffff"
    r'^[A-Z]\s+f\d$',  # "E f9"
    r'^[A-Z]\s+@?8',  # "u @8", "X @8u"
    r'^[A-Za-z0-9]+\s+[A-Za-z0-9]\s+8\]?$',  # "U 8]"
    # ".fptable" etc (only from high offset)
]

def is_asm_noise(s):
    for pat in ASM_REJECT:
        if re.match(pat, s):
            return True
    
    # Heuristic: if string has no lowercase letters, no spaces, and length < 10
    has_lower = any(c.islower() for c in s)
    has_space = ' ' in s
    
    # Patterns with space: "t$ H", "D$ D", "D$ A", "t$ L", "l$ E3", etc.
    if re.match(r'^[A-Za-z]\$\s+[A-Za-z0-9]$', s): return True  # "t$ H", "D$ D"
    if re.match(r'^[A-Za-z]\$\s+[EA][A-Za-z]?\d?$', s): return True  # "l$ E3", "D$ A"
    if re.match(r'^[A-Za-z]?\d\$\s+[A-Za-z0-9]$', s): return True  # "3$ D", etc
    if re.match(r'^[A-Za-z]\$\sE$', s): return True  # "D$ E"
    
    # Known asm patterns: "yxxxxxxxH", "yxxxxxxxH+", "gfffffffH+"  
    if re.match(r'^[yg]\w*ffff*\w*H', s): return True
    if re.match(r'^x+\w+H', s): return True  # any start with xxx
    
    # Short patterns with $ and space
    if re.match(r'^\w\$\s\w\w?\d?$', s): return True
    
    if not has_lower and not has_space and len(s) < 10:
        return True
    
    # No digit, no dot = not a version/number
    if not any(c.isdigit() for c in s) and '.' not in s and len(s) < 10:
        if not re.search(r'[a-z]{4}', s):  # no real word
            return True
    
    return False

# Accept ALL strings with real English text
def has_real_content(s):
    """Positive check: does this look like real text?"""
    if ' ' in s: return True
    if re.search(r'[a-z]{3}', s): return True
    if '%' in s and any(c in s for c in 'dsfxul'): return True
    if re.search(r'\.(dll|exe|ini|txt|bin|log|json|h|cpp)$', s, re.I): return True
    if re.search(r'http[s]?://', s): return True
    if s.startswith('##'): return True
    if re.match(r'^[\dA-Fa-f ?]{12,}$', s): return True  # AOB patterns
    return False

def looks_like_text(s):
    if len(s) < 4: return False
    if is_asm_noise(s): return False
    if not has_real_content(s): return False
    return True

print("Filtering...")
clean_strings = [(off, s) for off, s in all_ascii if looks_like_text(s)]
print(f"  Clean: {len(clean_strings)}")

# ============================================================
# CATEGORIZATION (same rules as v2 but slightly expanded)
# ============================================================

def build_cats():
    c = {}
    def add(p, cat):
        try: c[re.compile(p, re.I)] = cat
        except: pass

    # SC_FARMING
    for p in [r'libertea_replay', r'SC\s*Loop', r'SC\s*Goal', r'SC\s*Tracker',
              r'SC\s*REFRESH', r'SC\s*Cooldown', r'SC\s*Calls?', r'SC\s*earned',
              r'SC\s*batch', r'SUPER CREDIT', r'Super Credit', r'Remove SC Limit',
              r'--- SC ---', r'hit Sync', r'Farming', r'##farming', r'##sc_',
              r'##bl\b', r'##blmin', r'##maxreplays', r'##BurstCount', r'##replay',
              r'##goal', r'##limit\b', r'##mult', r'##sr\b', r'##samp', r'##fsamp',
              r'##src\b', r'##srr\b', r'##srs\b', r'##fmed', r'##fxp', r'##fslips',
              r'##xpset', r'##xpr', r'##sct', r'##repperwep', r'InFlight',
              r'SC AutoSync', r'Medal', r'MEDAL', r'Firing MEDAL', r'Firing SC',
              r'Include Medals', r'Medals Only', r'Alternates SC',
              r'Every batch fires', r'f2s7', r'SIG-CAPTURE', r'SIG-CHUNK',
              r'bodyXorLen', r'body chunk', r'nonce captured', r'got f2s7',
              r'unexpected chunk', r'Reduced Signature', r'<\$f2s7', r'Probe data',
              r'Probe aborted', r'\[Probe\]', r'\[P\] Capture', r'Burst Send',
              r'Burst complete', r'Burst Loop', r'capturedWarTime',
              r'serObjOrigAddr', r'MIDSWAP', r'GOLDEN', r'RECON-', r'\[QUEUED\]',
              r'QUEUED = processing', r'\[R\] Auth', r'\[R\] Busy', r'\[R\] Guard',
              r'\[B\] Unavailable', r'\[B\] No data', r'##diff\b', r'##difflvl',
              r'##ic5\b', r'##shut5\b', r'%d calls sent', r'TIMEOUT',
              r'EMPTY\b', r'SWAP.*Activated', r'SC\. On', r'SC\. Off']:
        add(p, 'SC_FARMING')

    # WEAPON_XP
    for p in [r'Weapon XP', r'Weapon Override', r'Primary Weapon Override',
              r'##wxpovr', r'##ag\b', r'##sg\b', r'##sglist', r'##sgsearch',
              r'##pwcombo', r'Selected Guns', r'Select Primary Weapon',
              r'>> Next Weapon', r'Search weapons', r'Give all lobby members',
              r'Hook0.*ReadWeapon', r'Hook1.*Rounds', r'Hook2.*TridentDmg',
              r'Hook3.*TridentFR', r'\[WeaponEditor\]', r'Damage##we',
              r'Pen\..*##we', r'Struct.*Penetration', r'FireRate.*Trident',
              r'Demolition##we', r'Enable##wxpovr']:
        add(p, 'WEAPON_XP')

    # PLAYER_CHEATS
    for p in [r'God Mode', r'##spd\b', r'##smult\b', r'##afk\b',
              r'##session\b', r'##sessionmins', r'NOP stamina', r'NOP railgun',
              r'Inf Stamin', r'SpeedCave', r'Return from recoil', r'Skip ragdoll',
              r'NOP landing speed', r'##misc_scroll']:
        add(p, 'PLAYER_CHEATS')

    # COMBAT_CHEATS
    for p in [r'Infinite Stratagem', r'Instant.*Callin', r'Instant.*Strat',
              r'Instant Shuttle', r'##isc\b', r'##msc\b', r'##msd\b',
              r'TURRETS?', r'turret', r'NOP turret', r'NOP hellbomb',
              r'NOP shield relay', r'NOP killstreak', r'NOP fuse timer',
              r'NOP conditional.*turret', r'Force.*unconditional.*boundary',
              r'Force.*unconditional.*stratagem', r'StratCave', r'SpawnSwapper',
              r'Backpack', r'Eagle Strikes', r'Orbitals', r'STRATAGEMS?',
              r'Stratagem', r'Horde Mode', r'##erad_ih', r'Drag Drop',
              r'Mass Strat', r'Drop Count']:
        add(p, 'COMBAT_CHEATS')

    # VISUAL_CHEATS
    for p in [r'##fov\b', r'NOP resource.*freeze', r'##bmf\b', r'##bmo\b']:
        add(p, 'VISUAL_CHEATS')

    # ARMORY
    for p in [r'Unlock All', r'##ua\b', r'Weapon Editor', r'##ap_go', r'##ap_rst',
              r'##ap_armor', r'##ap_scan', r'##ap_pass', r'NOP unlock check',
              r'NOP both hash table', r'Armor Base']:
        add(p, 'ARMORY')

    # AMMO
    for p in [r'Inf.*Ammo', r'No.*Reload', r'Inf.*Grenade', r'Inf.*Stim',
              r'NOP grenade count']:
        add(p, 'AMMO_CHEATS')

    # EXPLORATION
    for p in [r'Dark Fluid', r'##pk\b', r'##pk_rst', r'Super Helldive',
              r'Force Difficulty']:
        add(p, 'EXPLORATION')

    # IMGUI_UI - capture ALL ## widget IDs
    for p in [r'##\w+', r'imgui\.ini', r'imgui_log\.txt', r'Dear ImGui',
              r'imgui_impl', r'LIBERTEAWnd', r'LIBERTEAOverlay',
              r'wglSwapIntervalEXT', r'MESSAGE FROM DEAR IMGUI', r'Segoe UI',
              r'Consolas', r'Copy Link###', r'Reset order###', r'Size all columns',
              r'#SCROLL', r'#RESIZE', r'Hold CTRL', r'Remap w/', r'Press ESC',
              r'LeftAlt|LeftCtrl|LeftShift|RightAlt|RightCtrl|RightShift',
              r'MouseLeft|MouseRight|MouseMiddle|MouseX\d|MouseWheel',
              r'Alt\+|Ctrl\+|Shift\+', r'frame\d', r'Set io\.ConfigDebug',
              r'\[imgui-error\]', r'Debug Log.*Auto-disabled', r'FAQ\.md',
              r'Tab', r'SCROLL']:
        add(p, 'IMGUI_UI')

    # AUTH
    for p in [r'##keyinput', r'##passinput', r'##userinput',
              r'Invalid username or password', r'X-Signature:', r'X-Session',
              r'X-Token', r'X-Auth', r'Authorization:', r'Cookie:',
              r'Auth failed', r'Reduced Signature', r'TOOL\s*v\d+',
              r'LIBERTEA\b', r'TheOGcup', r'Password', r'login', r'subscription',
              r'key.*valid', r'license', r'##sub_info']:
        add(p, 'AUTH')

    # NETWORK
    for p in [r'api\.live\.prod\.thehelldiversgame', r'https://api',
              r'Mozilla/5\.0', r'Content-Type: application/json',
              r'libcurl\.dll', r'curl\.dll', r'winhttp\.dll', r'wininet\.dll',
              r'not a socket', r'\bPOST\b', r'\bGET\b', r'\bPUT\b', r'\bDELETE\b',
              r'endpoint', r'HTTP', r'headers', r'json_schema']:
        add(p, 'NETWORK')

    # HOOK_SYSTEM
    for p in [r'Hook installed', r'Hook verified', r'Hook mismatch',
              r'\[P\] Hook', r'\[N/A\] Hooks', r'\[CALL-SITE\]',
              r'AOB not found', r'Code cave', r'\[SC-LIMIT\]',
              r'\[SpeedCave\]', r'\[StratCave\]', r'\[SpawnSwapper\]',
              r'DIRECT CALL', r'INDIRECT CALL', r'CONTAINING func',
              r'syscall', r'ntdll_direct', r'VirtualProtect',
              r'NtProtectVirtualMemory', r'\[Features\]', r'Protection layers',
              r'ALL LAYERS FAILED', r'game\.dll not loaded', r'game\.dll\b',
              r'NOP\s', r'Force unconditional jump', r'Return\s+\w+\s+immediately',
              r'Return TRUE.*ragdoll', r'Skip.*timer check', r'NOP timer',
              r'NOP resource value', r'NOP grenade count',
              r'^[\dA-Fa-f ?]{12,}$']:
        add(p, 'HOOK_SYSTEM')

    # CRASH_DEBUG
    for p in [r'LIBERTEA CRASH LOG', r'libertea_crash', r'gamedump\.bin',
              r'ERROR = failed', r'MISS\b', r'Information failed',
              r'All paths failed', r'executable format error',
              r'RtlLookupFunctionEntry', r'to break in item', r'##log_scroll',
              r'%[dsfxul]']:
        add(p, 'CRASH_DEBUG')

    # SYSTEM
    for p in [r'kernel32', r'ntdll', r'user32', r'bcrypt\.dll', r'mscoree\.dll',
              r'advapi32', r'kernelbase', r'api-ms-win-', r'ext-ms-win-',
              r'NtQueryInformationProcess', r'GetSystemTimePreciseAsFileTime',
              r'ChainingMode', r'SHA256', r'BCrypt', r'CONOUT\$',
              r'USERPROFILE', r'Steam.*steamapps', r'helldivers2\.exe',
              r'exploded_dat', r'xinput', r'FlsFree', r'FlsAlloc',
              r'game\.dll\b', r'game_current', r'game_live',
              r'minkernel', r'__crt_strtox', r'_is_double', r'_is_float',
              r'en-US', r'UTF-8', r'UTF-16LE', r'\.tls\b',
              r'__preserve_none', r'local static guard', r'"\b\w+\.dll\b']:
        add(p, 'SYSTEM')

    # GAME_DATA - all weapons, armors, titles
    for p in [r'AR-\d', r'R-\d\d', r'SG-\d', r'SMG-\d', r'LAS-\d',
              r'PLAS-\d', r'JAR-', r'FLAM-\d', r'G-\d\d?\s', r'SC-\d\d',
              r'B-\d\d', r'FS-\d\d', r'DP-\d\d', r'SA-\d\d', r'CM-\d\d',
              r'CPH-', r'CW-', r'PH-', r'I-\d\d', r'TR-\d', r'SR-\d\d',
              r'AF-\d\d', r'EX-\d\d', r'AC-\d', r'GS-\d', r'RS-\d',
              r'RE-\d', r'O-\d', r'CPG-\d', r'A-\d\s', r'Liberator',
              r'Diligence', r'Punisher', r'Breaker', r'Defender', r'Scythe',
              r'Sickle', r'Trident', r'Scorcher', r'Purifier', r'Dominator',
              r'Torcher', r'Eruptor', r'Cookout', r'Sweeper', r'Pummeler',
              r'Reprimand', r'Gallant', r'Coyote', r'Suppressor',
              r'Tenderizer', r'Constitution', r'Deadeye', r'Amendment',
              r'Censor', r'Halt\b', r'Slugger', r'One-Two', r'Truth Whisperer',
              r'Pacifier', r'Mach', r'Concussive', r'Infiltrator', r'Legionnaire',
              r'Trailblazer', r'Drone Master', r'Field Chemist', r'Light Gunner',
              r'Enforcer', r'Fortified Commando', r'Steel Trooper',
              r'Exterminator', r'Battle Master', r'Physician', r'Trench Engineer',
              r'Grenadier', r'Eradicator', r'Ravager', r'Devastator',
              r'Dreadnought', r'Executioner', r'Juggernaut', r'Model Citizen',
              r'Champion of the People', r'Hero of the Federation',
              r'Saviour of the Free', r'Demolition Specialist',
              r'Ground Breaker', r'Guerilla Gorilla', r'Combat Technician',
              r'Headfirst', r'Servo Assisted', r'Dynamo', r'Bonesnapper',
              r'Clinician', r'Butcher', r'Trench Paramedic', r'Commandant',
              r'Arctic Ranger', r'White Wolf', r'Kodiak', r'Winter Warrior',
              r'Predator', r'Jaguar', r'Twigsnapper', r'Heatseeker',
              r'Salamander', r'Fire Fighter', r'Draconaught',
              r'Ambassador of the Brand', r'Cavalier of Democracy',
              r'Alpha Commander', r'Roadblock', r'Street Scout', r'Cinderblock',
              r'Haz-Master', r'Noxious Ranger', r'Lockdown', r'Prototype\s*[X\d]',
              r'Dutiful', r'Obedient', r"Democracy.*Deputy",
              r'Frontier Marshall', r'Lawmaker', r'Fiend Destroyer',
              r'Constrictor', r'Beast of Prey', r'Null Cipher',
              r'Shadow Paragon', r'Sanctioner', r'Parade Commander',
              r'Honorary Guard', r'Bearer.*Standard', r'Heavy Operator',
              r'Free Spirit', r'Bonded Pilot', r'Sapper', r'Helljumper',
              r'Helldive', r'Machine Gun', r'Anti-Materiel', r'Arc Thrower',
              r'Autocannon', r'Recoilless', r'Flamethrower', r'Quasar',
              r'Laser Cannon', r'Spire Sterilizer', r'Accelerator',
              r'Double.Edged', r'Spear\b', r'Railgun\b', r'Spray.?Pray',
              r'Incendiary', r'Explosive', r'Marksman', r'Overheat',
              r'Helldiver', r'Tactical', r'Mountain-Scaled', r'Ram\b',
              r'Sprinkle']:
        add(p, 'GAME_DATA')

    # ANTI_ANALYSIS
    for p in [r'Fiddler', r'mitmproxy', r'MITMPROXY', r'Burp\b',
              r'PortSwigger', r'Charles\b', r'Proxyman', r'Telerik',
              r'Requestly', r'HTTP Toolkit', r'httptoolkit', r'DO_NOT_TRUST',
              r'OWASP', r'Cheat Engine', r'cheat[ -]engine', r'cetrainer',
              r'ce-trainer', r'%s detected']:
        add(p, 'ANTI_ANALYSIS')

    return c

CATS = build_cats()

def categorize(s):
    for pat, cat in CATS.items():
        if pat.search(s):
            return cat
    if s.startswith('##'): return 'IMGUI_UI'
    if '%' in s and any(c in s for c in 'dsfxul'): return 'CRASH_DEBUG'
    return 'UNKNOWN'

# ============================================================
# CATEGORIZE
# ============================================================

print("Categorizing...")
cats = defaultdict(list)
for off, s in clean_strings:
    cats[categorize(s)].append((off, s))

utf16_cats = defaultdict(list)
for s in utf16_strings:
    utf16_cats[categorize(s)].append(s)

# ============================================================
# ANALYTICS
# ============================================================

format_specs = [(off, s) for off, s in clean_strings if '%' in s and any(c in s for c in 'dsfxul')]
freq = Counter(s.lower() for _, s in clean_strings)
dups = [(s, c) for s, c in freq.most_common(200) if c > 1]
aob_pats = [(off, s) for off, s in clean_strings if re.match(r'^[\dA-Fa-f ?]{12,}$', s)]
high_ent = [(off, s) for off, s in clean_strings if 0x0F8000 <= off <= 0x10A000]

# ============================================================
# WRITE OUTPUT
# ============================================================

os.makedirs(LOGS_DIR, exist_ok=True)

with open(OUTPUT, 'w', encoding='utf-8') as f:
    f.write("=" * 80 + "\n")
    f.write("AGENT D — COMPLETE STRING-TO-FEATURE MAP\n")
    f.write("LIBERTEA UNPACKED .TEXT SECTION — EXHAUSTIVE ANALYSIS\n")
    f.write("=" * 80 + "\n\n")
    
    f.write(f"INPUT DATA:\n")
    f.write(f"  Binary: .text_unpacked_mem.bin (3,489,792 bytes)\n")
    f.write(f"  Raw strings (all_strings.txt): {len(all_ascii)} entries\n")
    f.write(f"  Filtered meaningful strings: {len(clean_strings)}\n")
    f.write(f"  UTF-16LE strings: {len(utf16_strings)}\n")
    f.write(f"  Cross-referenced: resweep_strings.txt, patterns_extracted.json\n\n")
    
    feat_order = ['SC_FARMING', 'WEAPON_XP', 'PLAYER_CHEATS', 'COMBAT_CHEATS',
                  'VISUAL_CHEATS', 'ARMORY', 'AMMO_CHEATS', 'EXPLORATION',
                  'IMGUI_UI', 'AUTH', 'NETWORK', 'HOOK_SYSTEM', 'CRASH_DEBUG',
                  'SYSTEM', 'GAME_DATA', 'ANTI_ANALYSIS', 'UNKNOWN']
    
    # SECTION 1: FEATURE MAP
    f.write("=" * 80 + "\n")
    f.write("SECTION 1: COMPLETE FEATURE-BY-FEATURE STRING MAP\n")
    f.write("=" * 80 + "\n\n")
    
    total_cat = 0
    for feat in feat_order:
        items = sorted(cats.get(feat, []), key=lambda x: x[0])
        u_items = utf16_cats.get(feat, [])
        total = len(items) + len(u_items)
        total_cat += total
        if total == 0: continue
        
        f.write(f"\n{'='*60}\n")
        f.write(f"### {feat}: {len(items)} ASCII + {len(u_items)} UTF16 = {total} total\n")
        f.write(f"{'='*60}\n\n")
        
        if items:
            f.write(f"  ASCII strings:\n")
            f.write(f"  {'-'*54}\n")
            for off, s in items:
                f.write(f"  +0x{off:06X}  {s}\n")
        if u_items:
            f.write(f"\n  UTF-16LE strings:\n")
            f.write(f"  {'-'*54}\n")
            for s in sorted(u_items):
                f.write(f"  [UTF-16LE] {s}\n")
    
    # SECTION 2: FORMAT STRING ANALYSIS
    f.write("\n\n" + "=" * 80 + "\n")
    f.write("SECTION 2: PRINTF-STYLE FORMAT STRING ARGUMENT ANALYSIS\n")
    f.write("=" * 80 + "\n\n")
    
    f.write(f"Total format strings: {len(format_specs)}\n\n")
    format_by_feature = defaultdict(list)
    for off, s in format_specs:
        format_by_feature[categorize(s)].append((off, s))
    
    for feat in feat_order:
        items = format_by_feature.get(feat, [])
        if not items: continue
        f.write(f"\n  [{feat}] — {len(items)} format strings:\n")
        f.write(f"  {'-'*50}\n")
        for off, s in sorted(items, key=lambda x: x[0]):
            f.write(f"    +0x{off:06X}: {s}\n")
            specs = re.findall(r'%[\-+#0]?[\d]*[.]?[\d]*[lLhzjZt]{0,2}[dsfxupc]', s)
            if specs:
                for spec in specs:
                    type_hint = "int" if any(c in spec for c in 'dui') else \
                               "float" if 'f' in spec else \
                               "string" if any(c in spec for c in 'sS') else \
                               "hex/ptr" if any(c in spec for c in 'xXp') else "other"
                    f.write(f"      {spec} → {type_hint}\n")
    
    # SECTION 3: DUPLICATES
    f.write("\n\n" + "=" * 80 + "\n")
    f.write("SECTION 3: DUPLICATE STRING ANALYSIS\n")
    f.write("=" * 80 + "\n\n")
    f.write(f"Strings with multiple appearances: {len(dups)}\n\n")
    for s, cnt in dups[:100]:
        f.write(f"  [{cnt:3d}x] [{categorize(s)}] {s}\n")
    
    # SECTION 4: AOB PATTERNS
    f.write("\n\n" + "=" * 80 + "\n")
    f.write("SECTION 4: AOB SIGNATURE PATTERNS (HOOK SCAN TARGETS)\n")
    f.write("=" * 80 + "\n\n")
    f.write(f"Byte pattern strings: {len(aob_pats)}\n\n")
    for off, s in sorted(aob_pats, key=lambda x: x[0]):
        f.write(f"  +0x{off:06X}: {s}\n")
    
    # SECTION 5: OBFUSCATED REGION
    f.write("\n\n" + "=" * 80 + "\n")
    f.write("SECTION 5: OBFUSCATED REGION 0x0F8000-0x10A000\n")
    f.write("=" * 80 + "\n\n")
    f.write(f"Strings in likely-obfuscated region: {len(high_ent)}\n")
    f.write(f"(~168KB of high-entropy data, 7.1-7.3 bits/byte)\n\n")
    high_cats = Counter()
    for off, s in high_ent:
        cat = categorize(s)
        high_cats[cat] += 1
        f.write(f"  +0x{off:06X} [{cat}] {repr(s)[:100]}\n")
    f.write(f"\n  Region category breakdown:\n")
    for cat, cnt in high_cats.most_common():
        f.write(f"    {cat}: {cnt}\n")
    
    # SECTION 6: FEATURE COMPLEXITY
    f.write("\n\n" + "=" * 80 + "\n")
    f.write("SECTION 6: FEATURE COMPLEXITY RANKING\n")
    f.write("=" * 80 + "\n\n")
    rankings = [(feat, len(cats.get(feat, [])), len(utf16_cats.get(feat, []))) 
                for feat in feat_order]
    rankings.sort(key=lambda x: -(x[1] + x[2]))
    
    for feat, asc, u16 in rankings:
        total = asc + u16
        bar = "█" * max(1, total // 15)
        f.write(f"  {feat:<25} {asc:>4}A + {u16:>3}U = {total:>4}  {bar}\n")
    
    # SECTION 7: FULL INDEX
    f.write("\n\n" + "=" * 80 + "\n")
    f.write("SECTION 7: FULL STRING INDEX BY OFFSET\n")
    f.write("=" * 80 + "\n\n")
    all_sorted = [(off, s, categorize(s)) for off, s in clean_strings]
    all_sorted.sort(key=lambda x: x[0])
    for off, s, cat in all_sorted:
        f.write(f"  +0x{off:06X}  [{cat:<18}] {s}\n")
    
    # SECTION 8: DEAD STRING FLAGS
    f.write("\n\n" + "=" * 80 + "\n")
    f.write("SECTION 8: UNREFERENCED STRING DETECTION\n")
    f.write("=" * 80 + "\n\n")
    unknown_real = [(off, s) for off, s in cats.get('UNKNOWN', []) if len(s) >= 6]
    f.write(f"Flags: [DEAD?]=possible dead feature [DEBUG?]=debug leftover [FUTURE?]=future feature\n\n")
    for off, s in sorted(unknown_real, key=lambda x: x[0]):
        flag = "[DEAD?]"
        if any(kw in s.lower() for kw in ['debug', 'test', 'todo', 'temp', 'old', 'trace']): flag = "[DEBUG?]"
        if any(kw in s.lower() for kw in ['new', 'wip', 'soon', 'next', 'v2']): flag = "[FUTURE?]"
        f.write(f"  +0x{off:06X}  {flag} {s}\n")
    
    # SECTION 9: CRYPTO INVENTORY
    f.write("\n\n" + "=" * 80 + "\n")
    f.write("SECTION 9: CRYPTOGRAPHY / AUTHENTICATION STRING INVENTORY\n")
    f.write("=" * 80 + "\n\n")
    crypto_kw = ['sha256', 'bcrypt', 'encrypt', 'decrypt', 'base64', 'cipher',
                 'chaining', 'signature', 'token', 'nonce', 'auth', 'hash', 'GUID']
    for off, s in sorted(clean_strings, key=lambda x: x[0]):
        if any(kw in s.lower() for kw in crypto_kw):
            f.write(f"  +0x{off:06X} [{categorize(s)}] {s}\n")
    f.write(f"\n  UTF-16LE:\n")
    for s in sorted(utf16_strings):
        if any(kw in s.lower() for kw in crypto_kw):
            f.write(f"  [UTF-16LE] [{categorize(s)}] {s}\n")
    
    # SECTION 10: SUMMARY
    f.write("\n\n" + "=" * 80 + "\n")
    f.write("SECTION 10: EXECUTIVE SUMMARY\n")
    f.write("=" * 80 + "\n\n")
    f.write(f"  Total strings extracted (filtered): {len(clean_strings)}\n")
    f.write(f"  Total UTF-16LE strings: {len(utf16_strings)}\n")
    f.write(f"  Total categorized: {total_cat}\n")
    f.write(f"  Format strings: {len(format_specs)}\n")
    f.write(f"  Duplicate strings: {len(dups)}\n")
    f.write(f"  AOB patterns: {len(aob_pats)}\n")
    f.write(f"  High-entropy region strings: {len(high_ent)}\n")
    f.write(f"\n  Top features by complexity:\n")
    for feat, asc, u16 in rankings[:8]:
        total = asc + u16
        f.write(f"    {feat:<25} {total:>4} strings\n")

print("\nDone!")
line_count = sum(1 for _ in open(OUTPUT, encoding='utf-8'))
print(f"Lines: {line_count:,}")
print(f"\nCategory counts:")
for feat in feat_order:
    cnt = len(cats.get(feat, []))
    ucnt = len(utf16_cats.get(feat, []))
    if cnt + ucnt > 0:
        print(f"  {feat:<25} {cnt:>4}A + {ucnt:>3}U = {cnt+ucnt:>4}")
