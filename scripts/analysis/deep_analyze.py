#!/usr/bin/env python3
"""
FAST deep analysis of LIBERTEA binary - optimized version.
"""
import struct, re, sys, time
from collections import Counter, defaultdict

BIN_PATH = r'C:\Users\emora\OneDrive\Desktop\2\.text_unpacked_mem.bin'
OUT_PATH = r'C:\Users\emora\OneDrive\Desktop\2\resweep_game_data.txt'

T0 = time.time()
with open(BIN_PATH, 'rb') as f:
    data = f.read()

OUT = []
def W(s):
    OUT.append(s + '\n')
def flush():
    with open(OUT_PATH, 'w', encoding='utf-8') as f:
        f.write(''.join(OUT))

# === String extraction (fast) ===
strings = []
current = b''
for i in range(len(data)):
    b = data[i]
    if 0x20 <= b < 0x7f:
        current += bytes([b])
    else:
        if len(current) >= 4:
            strings.append((i - len(current), current.decode('ascii', errors='replace')))
        current = b''
if len(current) >= 4:
    strings.append((len(data) - len(current), current.decode('ascii', errors='replace')))

W(f'Strings: {len(strings)} ({time.time()-T0:.1f}s)')

# === CAPSTONE: Disassemble only code-dense regions ===
# Code is in 0x000000-0x0BC000, data/strings in 0x0BC000-0x120000
# Only disassemble code region
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

CODE_END = 0x0BC000
all_insns = []
# Disassemble code section only
code_data = data[:CODE_END]
try:
    for insn in md.disasm(code_data, 0):
        all_insns.append(insn)
except Exception as e:
    W(f'Capstone partial: {e}')

W(f'Instructions: {len(all_insns)} ({time.time()-T0:.1f}s)')

# Build lookup
insn_by_addr = {}
for insn in all_insns:
    insn_by_addr[insn.address] = insn

# === HELPER: Find strings matching keywords ===
def find_strings(keywords, min_match=4):
    """Return (offset, string) for strings containing any keyword"""
    results = []
    for offset, s in strings:
        s_lower = s.lower()
        for kw in keywords:
            if len(kw) >= min_match and kw in s_lower:
                results.append((offset, s))
                break
    return results

def find_multi_strings(keyword_sets):
    """For each keyword set, find strings and write section"""
    pass

# ====================================================================
# SECTION 1: ALL WEAPON ENUM VALUES
# ====================================================================
W('#' * 80)
W('#  1. WEAPON ENUM VALUES')
W('#' * 80)

weapon_names = [
    "liberator", "penetrator", "concussive", "carbine", "tenderizer",
    "adjudicator", "diligence", "counter sniper", "deadeye",
    "defender", "pummeler", "knight", "reprimand",
    "punisher", "slugger", "halt", "cookout",
    "breaker", "spray", "incendiary", "crossbow",
    "scorcher", "purifier", "scythe", "sickle", "double-edge",
    "blitzer", "arc thrower", "eruptor", "dominator",
    "torcher", "flamethrower", "peacemaker", "redeemer",
    "verdict", "senator", "crisper", "grenade pistol",
    "stun lance", "stun baton", "talon", "dagger",
    "bushwhacker", "ultimatum", "frag", "high explosive",
    "impact", "gas", "stun", "smoke", "thermite",
    "machine gun", "stalwart", "anti-materiel",
    "expendable anti-tank", "recoilless", "spear", "commando",
    "laser cannon", "quasar", "autocannon", "airburst",
    "w.a.s.p.", "railgun", "sterilizer", "grenade launcher",
    "throwing knife", "seeker",
]

W('--- Weapon Names Found in Binary ---')
seen = set()
for offset, s in strings:
    s_lower = s.lower()
    for w in weapon_names:
        if w in s_lower and len(s) > 3:
            if s not in seen:
                seen.add(s)
                W(f'  {offset:06X}: "{s}"')
    if re.match(r'^[A-Z]{2,4}[- ][0-9]{1,3}[A-Z]?', s):
        if s not in seen:
            seen.add(s)
            W(f'  {offset:06X}: "{s}" [model number]')

W(f'\n  Total weapon name matches: {len(seen)}')
W('')
W('--- Weapon ID Mapping Analysis ---')
W('  The cheat tracks 51 weapons (All Guns: %s  (%d/51, Rep %d/%d)).')
W('  IDs are referenced via combo box "pwcombo" which displays weapon names.')
W('')
W('  SEARCH: Looking for cmp/switch patterns with values 0-51 near weapon strings...')

# Check constants 0-60 used near weapon string offsets
weapon_string_offsets = {off for off, s in strings if s in seen}
id_candidates = Counter()
for insn in all_insns:
    if insn.mnemonic in ('cmp', 'mov'):
        for op in insn.operands:
            if op.type == 2:  # immediate
                val = op.value.imm & 0xFFFFFFFF
                if 0 <= val <= 100:
                    for woff in weapon_string_offsets:
                        if abs(insn.address - woff) < 200:
                            id_candidates[val] += 1
                            break

if id_candidates:
    W('  Values 0-100 near weapon strings:')
    for val, count in id_candidates.most_common(60):
        W(f'    {val:3d} ({val:02X}): {count} refs')
else:
    W('  (Weapon IDs likely loaded dynamically from game, not hardcoded in cheat)')
W('')

flush()

# ====================================================================
# SECTION 2: ARMOR ENUM VALUES
# ====================================================================
W('#' * 80)
W('#  2. ARMOR ENUM VALUES')
W('#' * 80)

armor_kw = [
    "engineering kit", "scout", "medic", "med kit", "servo-assisted",
    "democracy protects", "fortified", "extra padding", "unflinching",
    "peak physique", "siege-ready", "siege ready", "inflammable",
    "advanced filtration", "electrical conduit", "acclimated",
    "integrated explosives", "armor passive", "helmet", "cape",
    "light armor", "medium armor", "heavy armor",
    # Armor set names
    "tactical", "enforcer", "commando", "demolition", "ground breaker",
    "trench engineer", "grenadier", "titan", "juggernaut",
    "bonesnapper", "physician", "butcher", "trench paramedic",
    "arctic ranger", "white wolf", "kodiak", "winter warrior",
    "champion", "hero of the federation", "savior of the free",
    "predator", "prototype", "marksman", "executioner",
    "battle master", "exterminator", "eradicator", "devastator",
    "drone master", "trailblazer scout", "infiltrator", "legionnaire",
    "roadblock", "street scout", "cinder block", "alpha commander",
    "gold eagle", "ambassador", "cavalier", "heatseeker",
    "fire fighter", "salamander", "draconaught", "combat technician",
    "servo assistant", "steel trooper", "hazard ops", "noxious ranger",
    "lockdown", "field chemist", "dutiful", "obedient",
    "hell-bent", "righteous", "avenger", "dynamo", "twigsnapper",
    "model citizen", "light gunner",
]

armor_seen = set()
for offset, s in strings:
    s_lower = s.lower()
    for kw in armor_kw:
        if kw in s_lower and len(kw) > 4:
            if s not in armor_seen:
                armor_seen.add(s)
                W(f'  {offset:06X}: "{s}"')
                break

W(f'\n  Total armor-related strings: {len(armor_seen)}')
W('')
W('  NOTE: Armor passive IDs found in UI as "ap_pass" (armor passive combo).')
W('  The cheat scans current armor via "ap_scan" button.')
W('  Passive values are written via armor passive editor.')
W('')

flush()

# ====================================================================
# SECTION 3: STRATAGEM IDS
# ====================================================================
W('#' * 80)
W('#  3. STRATAGEM IDS')
W('#' * 80)

strat_kw = [
    "sentry", "turret", "eagle", "orbital", "barrage", "strike",
    "minefield", "mines", "shield generator", "tesla",
    "guard dog", "rover", "dog breath", "exosuit", "patriot",
    "emancipator", "supply pack", "jump pack", "hellbomb",
    "reinforce", "resupply", "sos", "seismic probe",
    "rocket pods", "500kg", "110mm", "120mm", "380mm",
    "strafing", "airstrike", "cluster", "napalm",
    "railcannon", "laser", "precision", "walking",
    "smoke", "ems", "gas",
    "hmg emplacement", "anti-tank emplacement",
    "frv", "fast recon", "dark fluid", "hover pack",
    "directional shield", "ballistic shield",
    "prospecting drill", "nux-223",
    "hellpod", "backpack",
    "extraction", "pelican", "shuttle",
    "stratagem", "infinite stratagem",
    "instant strat", "mass strat",
]

strat_seen = set()
for offset, s in strings:
    s_lower = s.lower()
    for kw in strat_kw:
        if kw in s_lower:
            if s not in strat_seen:
                strat_seen.add(s)
                W(f'  {offset:06X}: "{s}"')
                break

W(f'\n  Total stratagem-related strings: {len(strat_seen)}')
W('')
W('--- Turret Types Explicitly Named ---')
for offset, s in strings:
    for t in ['Autocannon Sentry', 'Gatling Sentry', 'Mortar Sentry',
              'Rocket Sentry', 'Machine Gun Sentry', 'EMS Mortar Sentry',
              'Flame Sentry', 'Tesla Tower', 'Anti-Tank Sentry']:
        if t.lower() in s.lower():
            W(f'  {offset:06X}: "{s}"')
W('')

flush()

# ====================================================================
# SECTION 4: DIFFICULTY ENUM
# ====================================================================
W('#' * 80)
W('#  4. DIFFICULTY ENUM')
W('#' * 80)

W('--- Difficulty Strings ---')
for offset, s in strings:
    s_lower = s.lower()
    if any(w in s_lower for w in ['difficulty', 'helldive', 'trivial', 'easy',
                                    'medium', 'challenging', 'hard', 'extreme',
                                    'suicide', 'impossible', 'super helldive']):
        W(f'  {offset:06X}: "{s}"')

W('')
W('--- Difficulty Tier Strings ---')
# Found in existing analysis: "7 - Super Helldive (150%)"
for offset, s in strings:
    if re.search(r'\d\s*-\s*.*\d+%', s):
        W(f'  {offset:06X}: "{s}"')

W('')
W('--- Difficulty Constant Analysis ---')
W('  Known from code: "cmp esi,7" pattern (7 = Suicide Mission threshold)')
W('  "Force unconditional jump (bypass boundary)" references')
W('  "Force unconditional jump (bypass strategem count)" - cmp esi,5')
W('')
W('  INTERNAL DIFFICULTY MAPPING (HD2):')
W('    1 = Trivial')
W('    2 = Easy')
W('    3 = Medium')
W('    4 = Challenging')
W('    5 = Hard')
W('    6 = Extreme')
W('    7 = Suicide Mission')
W('    8 = Impossible')
W('    9 = Helldive')
W('    10 = Super Helldive')
W('')
W('  The cheat patches the difficulty comparison to always give max rewards.')
W('  "NOP difficulty value read" and "Force highest difficulty reward tier"')
W('  Multiplier slider: "Difficulty Mult" applies to rewards.')
W('')

flush()

# ====================================================================
# SECTION 5: MISSION TYPE IDS
# ====================================================================
W('#' * 80)
W('#  5. MISSION TYPE IDS')
W('#' * 80)

mission_kw = [
    "blitz", "eradicate", "evacuate", "icbm", "defend", "launch",
    "eliminate", "escort", "upload", "retrieve", "destroy",
    "nuke", "nursery", "drill", "geo", "survey", "flag",
    "spread democracy", "raise flag", "geological",
    "activate terminal", "destroy eggs", "command bunker",
    "orbital", "air base", "hives", "bile titans",
    "chargers", "hulks",
    "deactivate", "civilians", "extract", "reinforce",
    "purge", "hatchery", "liquidate", "rescue",
    "terminate", "illegal broadcast", "transmission",
    "data upload", "seismic", "probe",
    "tectonic", "disruptor", "spire",
    "mission type", "missiontype",
]

W('--- Mission Type Strings ---')
mission_seen = set()
for offset, s in strings:
    s_lower = s.lower()
    for kw in mission_kw:
        if kw in s_lower:
            if s not in mission_seen:
                mission_seen.add(s)
                W(f'  {offset:06X}: "{s}"')
                break

W(f'\n  Total mission type strings: {len(mission_seen)}')
W('')
W('  NOTE: Mission types are likely referenced via missionId UUIDs.')
W('  The replay capture stores "capturedWarTime" and "missionId".')
W('  Internal mission type might be in entityDeep/entityDataDeep JSON.')
W('')
flush()

# ====================================================================
# SECTION 6: ENEMY TYPE IDS
# ====================================================================
W('#' * 80)
W('#  6. ENEMY TYPE IDS')
W('#' * 80)

enemy_kw = [
    # Terminids
    "scavenger", "warrior", "bile warrior", "alpha warrior",
    "hunter", "bile hunter", "stalker", "bile stalker",
    "bile titan", "charger", "behemoth", "spore charger",
    "impaler", "shrieker", "bile spewer", "nursing spewer",
    "brood commander", "hive guard", "hive lord",
    # Automatons
    "trooper", "raider", "assault raider", "rocket raider",
    "berserker", "devastator", "heavy devastator", "rocket devastator",
    "shredder", "tank", "annihilator tank",
    "hulk", "hulk scorcher", "hulk obliterator", "hulk bruiser",
    "gunship", "dropship", "factory strider", "scout strider",
    "armored scout strider", "jetpack brigade", "mortar emplacement",
    "jammer", "detector tower", "command bunker",
    # Illuminate
    "illuminate", "voteless", "overseer", "elevated overseer",
    "watcher", "harvester", "tripod", "warp ship",
    # General
    "terminid", "automaton", "bug", "bot",
    "enemy spawner", "horde",
]

W('--- Enemy Type Strings ---')
enemy_seen = set()
for offset, s in strings:
    s_lower = s.lower()
    for kw in enemy_kw:
        if kw in s_lower:
            if s not in enemy_seen:
                enemy_seen.add(s)
                W(f'  {offset:06X}: "{s}"')
                break

W(f'\n  Total enemy-related strings: {len(enemy_seen)}')
W('  NOTE: "Enemy Spawner - Coming Soon" suggests future spawn control.')
W('  "Infinite Horde Mode" (##erad_ih) enables endless spawns.')
W('')
flush()

# ====================================================================
# SECTION 7: SAMPLE TYPE IDS
# ====================================================================
W('#' * 80)
W('#  7. SAMPLE TYPE IDS')
W('#' * 80)

W('--- Sample-Related Strings ---')
for offset, s in strings:
    s_lower = s.lower()
    if any(w in s_lower for w in ['sample', 'common', 'rare ', 'super uranium',
                                    'super sample', 'requisition']):
        W(f'  {offset:06X}: "{s}"')

W('')
W('--- Sample Enum Analysis ---')
W('  Common Sample:  ID=0  (slider ##fsamp_c)')
W('  Rare Sample:    ID=1  (slider ##fsamp_r)')
W('  Super Sample:   ID=2  (slider ##fsamp_s)')
W('')
W('  Clamping: "Total %d > 100 ... will auto-clamp to 34/33/33"')
W('  This distributes 100 samples across types: 34 Common, 33 Rare, 33 Super.')
W('')
W('  "Add Samples Instantly" - applies samples at mission start.')
W('  "Samples Over Limit" - overrides end-of-mission reward samples.')
W('')
flush()

# ====================================================================
# SECTION 8: WARBOND IDS
# ====================================================================
W('#' * 80)
W('#  8. WARBOND IDS')
W('#' * 80)

warbond_kw = [
    "warbond", "battle pass", "premium warbond",
    "helldivers mobilize", "steeled veterans", "cutting edge",
    "democratic detonation", "polar patriots", "viper commandos",
    "freedom's flame", "chemical agents", "truth enforcers",
    "servants of freedom", "borderline justice", "urban legends",
    "superstore", "super citizen", "acquisition",
]

W('--- Warbond Strings ---')
wb_seen = set()
for offset, s in strings:
    s_lower = s.lower()
    for kw in warbond_kw:
        if kw in s_lower:
            if s not in wb_seen:
                wb_seen.add(s)
                W(f'  {offset:06X}: "{s}"')
                break

W(f'\n  Total warbond strings: {len(wb_seen)}')
W('  NOTE: The "Unlock All Armory" feature patches warbond unlock checks.')
W('  "NOP unlock check jump" bypasses warbond/premium gating.')
W('')
flush()

# ====================================================================
# SECTION 9: BOOSTER IDS
# ====================================================================
W('#' * 80)
W('#  9. BOOSTER IDS')
W('#' * 80)

booster_kw = [
    "booster", "hellpod space optimization", "vitality enhancement",
    "stamina enhancement", "muscle enhancement",
    "increased reinforcement budget", "uav recon booster",
    "flexible reinforcement budget", "localization confusion",
    "expert extraction pilot", "motivational shocks",
    "experimental infusion", "firebomb hellpods",
    "dead sprint", "armed resupply pods",
    "stamina", "vitality", "infusion", "optimization",
]

W('--- Booster Strings ---')
boost_seen = set()
for offset, s in strings:
    s_lower = s.lower()
    for kw in booster_kw:
        if kw in s_lower:
            if s not in boost_seen:
                boost_seen.add(s)
                W(f'  {offset:06X}: "{s}"')
                break

W(f'\n  Total booster strings: {len(boost_seen)}')
W('')
flush()

# ====================================================================
# SECTION 10: PLANET/BIOME IDS
# ====================================================================
W('#' * 80)
W('#  10. PLANET / BIOME REFERENCES')
W('#' * 80)

planet_kw = [
    "malevelon creek", "heeth", "angel's venture", "hellmire",
    "meridia", "estanu", "fenrir", "turing", "achernar",
    "martale", "mastia", "vermen wells", "aesir pass",
    "durgen", "mara", "fori prime", "curia", "vandalon",
    "zagon", "socorro", "pandion", "vega bay", "ubanea",
    "draupnir", "mantes", "gar haren", "klen dah", "gacrux",
    "moh-gor", "ord fema", "matar bay", "vog-sojoth",
    "clasa", "primordia", "crimson", "choohe", "penta",
    "chort bay", "menkent", "lesath", "gaellivare",
    "imber", "claorell", "tarsh", "darius", "zefia",
    "sigma", "super earth", "planet",
]

W('--- Planet / Biome Strings ---')
planet_seen = set()
for offset, s in strings:
    s_lower = s.lower()
    for kw in planet_kw:
        if kw in s_lower:
            if s not in planet_seen:
                planet_seen.add(s)
                W(f'  {offset:06X}: "{s}"')
                break
    for b in ['jungle', 'desert', 'snow', 'moon', 'swamp', 'volcano',
              'ocean', 'canyon', 'highlands', 'wasteland', 'tundra',
              'ice', 'fog', 'ether', 'acid', 'meteor', 'biome']:
        if b in s_lower and len(s) < 100:
            if s not in planet_seen:
                planet_seen.add(s)
                W(f'  {offset:06X}: [BIOME] "{s}"')
                break

W(f'\n  Total planet/biome strings: {len(planet_seen)}')
W('')
flush()

# ====================================================================
# SECTION 11: GAME PHASE/STATE
# ====================================================================
W('#' * 80)
W('#  11. GAME PHASE / STATE ENUM')
W('#' * 80)

state_kw = [
    "loading", "in_mission", "in_ship", "post_mission", "menu",
    "game_state", "gamestate", "phase", "state",
    "lobby", "matchmaking", "deploying", "returning",
    "destroyer", "ship", "galactic war",
    "results", "debrief", "ready", "playing",
    "idle", "in_game", "in_game", "main_menu",
    "loadingscreen", "inmission", "onship", "inlobby",
    "session", "sessionstate", "playerstate",
    "loading screen", "in game", "post game",
]

W('--- Game State Strings ---')
state_seen = set()
for offset, s in strings:
    s_lower = s.lower()
    for kw in state_kw:
        if kw in s_lower and len(kw) > 4:
            if s not in state_seen:
                state_seen.add(s)
                W(f'  {offset:06X}: "{s}"')
                break

W(f'\n  Total state-related strings: {len(state_seen)}')
W('')
W('  INFERRED GAME STATES (from cheat behavior):')
W('    STATE_LOADING        - Game loading, no module available')
W('    STATE_MAIN_MENU      - On ship, in main menu')
W('    STATE_IN_LOBBY       - In mission lobby/prep screen')
W('    STATE_IN_MISSION     - Active mission gameplay')
W('    STATE_POST_MISSION   - Mission results/debrief')
W('    STATE_EXTRACTING     - Pelican extraction sequence')
W('')
W('  The cheat detects states via:')
W('    - GetActiveSession() = NULL -> not in game')
W('    - "Probe ON - will overwrite on next mission" -> mission start detection')
W('    - "Waiting for mission to capture" -> lobby detection')
W('    - "Session captured" -> mission in progress')
W('')
flush()

# ====================================================================
# SECTION 12: NETWORK MESSAGE IDS
# ====================================================================
W('#' * 80)
W('#  12. NETWORK MESSAGE IDS')
W('#' * 80)

net_kw = [
    "http", "https", "post ", "get ", "put ", "/api/",
    "mission/end", "activity", "/war/", "/v2/",
    "x-signature", "x-session", "authorization", "cookie",
    "content-type", "application/json",
    "curl_easy", "setopt", "perform", "getinfo", "cleanup",
    "slist_append", "slist_free",
    "recon-url", "recon-hdr", "recon-body", "recon-resp",
    "sig-capture", "sig-chunk",
    "payload", "request", "response", "header",
    "workers.dev", "cloudflare",
    "sc_loop", "sc batch", "medal batch",
    "replay", "burst", "queue",
    "network", "socket", "recv", "send",
    "f2s7", "nonce", "golden capture",
    "bcrypt", "hashdata",
]

W('--- Network / API Strings ---')
net_seen = set()
for offset, s in strings:
    s_lower = s.lower()
    for kw in net_kw:
        if kw in s_lower:
            if s not in net_seen:
                net_seen.add(s)
                W(f'  {offset:06X}: "{s}"')
                break

W(f'\n  Total network strings: {len(net_seen)}')
W('')
W('--- Network Message Types (Inferred) ---')
W('  MISSION_END_POST   - POST to Mission/end with JSON body')
W('  ACTIVITY_CALL      - SC farming uses "actFn" with actId32')
W('  WAR_STATUS_GET     - "/war/" API for war progression')
W('  SIGNATURE_HANDSHAKE - X-Signature header auth')
W('  RECON_BODY         - Man-in-the-middle HTTP body interception')
W('')
W('  The replay system:')
W('    1. Captures Mission/end POST body during real mission completion')
W('    2. Stores missionId, entityDeep, entityDataDeep, slotData')
W('    3. Replays by POSTing captured body with new missionId')
W('    4. "mid=%s" replacement swaps mission IDs')
W('')
flush()

# ====================================================================
# SECTION 13: PLAYER CLASS/ROLE
# ====================================================================
W('#' * 80)
W('#  13. PLAYER CLASS / ROLE / SLOT IDS')
W('#' * 80)

player_kw = [
    "player", "slot", "lobby", "member", "host", "client",
    "peer", "squad", "team", "role", "class", "helldiver",
    "pids=", "players",
    "playerstate", "playerslot",
]

W('--- Player-Related Strings ---')
player_seen = set()
for offset, s in strings:
    s_lower = s.lower()
    for kw in player_kw:
        if kw in s_lower:
            if s not in player_seen:
                player_seen.add(s)
                W(f'  {offset:06X}: "{s}"')
                break

W(f'\n  Total player strings: {len(player_seen)}')
W('')
W('  PLAYER SLOTS: 4 players per mission ("%d/4 players" format)')
W('  Auto Sync distributes SC across all lobby members.')
W('  "pids=%d" in SCLoop tracks number of player IDs.')
W('')
flush()

# ====================================================================
# SECTION 14: DAMAGE TYPE IDS
# ====================================================================
W('#' * 80)
W('#  14. DAMAGE TYPE IDS')
W('#' * 80)

damage_kw = [
    "damage", "ballistic", "explosive", "fire", "gas", "arc",
    "plasma", "acid", "incendiary", "electric", "laser",
    "penetrat", "durable", "sustain", "armor pen",
    "damage type", "dmg_type",
]

W('--- Damage Type Strings ---')
dmg_seen = set()
for offset, s in strings:
    s_lower = s.lower()
    for kw in damage_kw:
        if kw in s_lower:
            if s not in dmg_seen:
                dmg_seen.add(s)
                W(f'  {offset:06X}: "{s}"')
                break

W(f'\n  Total damage strings: {len(dmg_seen)}')
W('')
W('  NOTE: The weapon stats editor (##we) edits damage and fire rate.')
W('  "Damage##we" and "FireRate (Trident)##we" are UI labels.')
W('  Damage type enum is NOT explicitly in the cheat binary.')
W('  Likely game-internal enum with values like:')
W('    0 = Ballistic')
W('    1 = Explosive  ')
W('    2 = Fire')
W('    3 = Gas')
W('    4 = Arc')
W('    5 = Plasma')
W('    6 = Laser/Energy')
W('    7 = Acid')
W('')
flush()

# ====================================================================
# SECTION 15: UI STATE IDS
# ====================================================================
W('#' * 80)
W('#  15. UI STATE IDS')
W('#' * 80)

ui_kw = [
    "main menu", "loadout", "armory", "warbond", "acquisition",
    "superstore", "career", "social", "settings", "options",
    "escape menu", "pause menu", "hud",
    "arsenal", "stratagem menu", "ship management",
    "briefing", "results screen", "post game",
    "mission select", "drop pod", "scoreboard",
    "galactic war table", "destroyer bridge",
    "armory terminal", "loadout terminal",
    "ship module", "stratagem hero",
]

W('--- UI State Strings ---')
ui_seen = set()
for offset, s in strings:
    s_lower = s.lower()
    for kw in ui_kw:
        if kw in s_lower:
            if s not in ui_seen:
                ui_seen.add(s)
                W(f'  {offset:06X}: "{s}"')
                break

W(f'\n  Total UI strings: {len(ui_seen)}')
W('')
W('  The cheat overlays on the game via Present hook.')
W('  Key UI sections in cheat:')
W('    - FARMING tab')
W('    - SUPER CREDITS tab')
W('    - WEAPON XP tab')
W('    - PLAYER tab')
W('    - COMBAT tab')
W('    - STRATAGEMS tab')
W('    - SPAWNING tab')
W('    - STEALTH/VISUAL tab')
W('    - EXPLORATION tab')
W('    - ARMORY tab')
W('    - MISSION tab')
W('')
flush()

# ====================================================================
# SECTION 16: STRUCTURE SIZE CONSTANTS
# ====================================================================
W('#' * 80)
W('#  16. STRUCTURE SIZE CONSTANTS')
W('#' * 80)

W('--- Potential Struct Sizes (0x20-0x2000 in mov/cmp) ---')
size_counter = Counter()
for insn in all_insns:
    if insn.mnemonic in ('mov', 'cmp', 'add', 'sub'):
        for op in insn.operands:
            if op.type == 2:  # immediate
                val = op.value.imm & 0xFFFFFFFF
                if 0x20 <= val <= 0x2000 and val % 8 == 0:
                    size_counter[val] += 1

W('  Aligned sizes (multiples of 8):')
for val, count in size_counter.most_common(80):
    if count >= 3:
        W(f'    0x{val:04X} ({val:5d}): {count} refs')
W('')

# Alloc patterns
W('--- Alloc-Size Candidates (mov reg, SIZE; ... call) ---')
alloc = Counter()
for i, insn in enumerate(all_insns):
    if insn.mnemonic == 'mov' and len(insn.operands) >= 2:
        if insn.operands[0].type == 1 and insn.operands[1].type == 2:
            reg_name = insn.reg_name(insn.operands[0].value.reg)
            val = insn.operands[1].value.imm & 0xFFFFFFFF
            if 0x10 <= val <= 0x2000 and reg_name in ('ecx', 'rcx'):
                for j in range(i+1, min(i+5, len(all_insns))):
                    if all_insns[j].mnemonic == 'call':
                        alloc[val] += 1
                        break

W('  Sizes in ecx/rcx before call (likely alloc/malloc):')
for val, count in alloc.most_common(40):
    if count >= 2:
        W(f'    {val:5d} (0x{val:04X}): {count} occurrences')
W('')

# Known struct sizes from existing analysis
W('--- Known Structure Sizes (from existing analysis) ---')
W('  ScActivityAPC struct: ~0xB0+ bytes (large, contains URL[0x40], missionId[0x40])')
W('  MissionCapture:  variable size (JSON strings)')
W('  GameSession:     0x130+ bytes (refs at +0x28, +0x128)')
W('  Player slot data: 0x18 stride ("48 83 C0 18" iterator pattern)')
W('  Hash table entry: unknown but has INSERT operations NOPed')
W('')
flush()

# ====================================================================
# SECTION 17: MAGIC/HASH CONSTANTS
# ====================================================================
W('#' * 80)
W('#  17. MAGIC / HASH CONSTANTS')
W('#' * 80)

W('--- 32-bit Constants (>= 0x1000) in Instructions ---')
all32 = Counter()
for insn in all_insns:
    if insn.mnemonic in ('cmp', 'test', 'and', 'or', 'xor', 'mov'):
        for op in insn.operands:
            if op.type == 2:
                val = op.value.imm & 0xFFFFFFFF
                if val >= 0x1000:
                    all32[val] += 1

W('  Top 60 32-bit constants (>= 0x1000):')
for val, count in all32.most_common(60):
    W(f'    0x{val:08X} ({val:10d}): {count:3d} refs')
W('')

# Known CRC/hash checks
W('--- Known Hash Constant Detection ---')
known_hashes = {
    0x811C9DC5: 'FNV-1 32-bit offset basis',
    0xEDB88320: 'CRC-32 polynomial',
    0x04C11DB7: 'CRC-32 (non-reflected)',
    0x82F63B78: 'CRC-32C polynomial',
    0x9E3779B9: 'Golden ratio (xxHash/lookup3)',
    0xFF51AFD7: 'SpookyHash const',
    0xC6A4A793: 'SipHash const',
    0x5BD1E995: 'MurmurHash2 const',
    0x85EBCA77: 'xxHash32 prime4',
    0x27D4EB2F: 'xxHash32 prime2',
    0xC2B2AE35: 'xxHash32 prime1',
    0x165667B1: 'xxHash32 prime3',
}

hash_hits = Counter()
for insn in all_insns:
    for op in insn.operands:
        if op.type == 2:
            val = op.value.imm & 0xFFFFFFFF
            if val in known_hashes:
                hash_hits[(val, known_hashes[val])] += 1

if hash_hits:
    for (val, desc), count in hash_hits.most_common():
        W(f'    0x{val:08X}: {desc} ({count} refs)')
else:
    W('  No known hash constants found (game hashing done in game.dll, not cheat)')

W('')
W('--- Potential Custom Hashes (values used in comparisons) ---')
cmp_hashes = Counter()
for insn in all_insns:
    if insn.mnemonic == 'cmp' and len(insn.operands) >= 2:
        for op in insn.operands:
            if op.type == 2:
                val = op.value.imm & 0xFFFFFFFF
                if 0xA0000000 <= val <= 0xFFFFFFFF:
                    cmp_hashes[val] += 1

W('  High 32-bit values (0xA0000000-0xFFFFFFFF) in cmp:')
for val, count in cmp_hashes.most_common(20):
    W(f'    0x{val:08X}: {count} refs')
W('')
flush()

# ====================================================================
# SECTION 18: POINTER CHAINS
# ====================================================================
W('#' * 80)
W('#  18. POINTER CHAINS')
W('#' * 80)

W('--- Dereference Chains (2+ levels) ---')
chains = []
for i, insn in enumerate(all_insns):
    if insn.mnemonic == 'mov' and len(insn.operands) == 2:
        op0, op1 = insn.operands[0], insn.operands[1]
        if op0.type == 1 and op1.type == 3:  # reg = [mem]
            mem = op1.value.mem
            if mem.base != 0 and mem.disp != 0:
                chain = [f'[{insn.reg_name(mem.base)}+0x{mem.disp:X}]']
                last_reg = op0.value.reg
                for j in range(i+1, min(i+6, len(all_insns))):
                    insn2 = all_insns[j]
                    if insn2.mnemonic == 'mov' and len(insn2.operands) == 2:
                        op0b, op1b = insn2.operands[0], insn2.operands[1]
                        if op0b.type == 1 and op1b.type == 3:
                            mem2 = op1b.value.mem
                            if mem2.base == last_reg and mem2.disp != 0:
                                next_reg = insn2.reg_name(op0b.value.reg)
                                if mem2.index == 0:
                                    chain.append(f'[{next_reg}+0x{mem2.disp:X}]')
                                else:
                                    chain.append(f'[{next_reg}+r{insn2.reg_name(mem2.index)}*{mem2.scale}+0x{mem2.disp:X}]')
                                last_reg = op0b.value.reg
                if len(chain) >= 2:
                    chains.append(' -> '.join(chain))

chain_counter = Counter(chains)
W('  Most common dereference chains:')
for chain, count in chain_counter.most_common(25):
    if count >= 2:
        W(f'    [{count:3d}x] {chain}')
W('')

W('--- Documented Pointer Chains ---')
W('  Chain 1: GetActiveSession() -> +0x28 -> activity object')
W('  Chain 2: GetActiveSession() -> +0x128 -> alternate activity ref')
W('  Chain 3: session -> ring buffer -> .url[0x40]')
W('  Chain 4: session -> ring buffer -> .ctr, .flag, .ring')
W('  Chain 5: entityDeep -> entityDataDeep -> JSON fields')
W('  Chain 6: slotData -> entity array -> individual entity states')
W('')
flush()

# ====================================================================
# SECTION 19: GLOBAL VARIABLE OFFSETS
# ====================================================================
W('#' * 80)
W('#  19. GLOBAL VARIABLE OFFSETS (game.dll+X patterns)')
W('#' * 80)

W('--- RIP-Relative Targets (potential game.dll globals) ---')
rip_targs = Counter()
for insn in all_insns:
    if insn.mnemonic in ('mov', 'lea', 'movss', 'movsd', 'addss', 'mulss',
                          'comiss', 'ucomiss', 'cvtsi2ss', 'cvtss2sd'):
        for op in insn.operands:
            if op.type == 3:  # memory
                mem = op.value.mem
                if (mem.base == 0 and mem.index == 0 and mem.segment == 0
                    and mem.disp != 0):
                    target = insn.address + insn.size + mem.disp
                    rip_targs[(insn.mnemonic, target)] += 1

W(f'  Total RIP-relative refs: {sum(rip_targs.values())}')
W(f'  Unique targets: {len(rip_targs)}')
W('')
W('  Top 40 most-referenced RIP targets (internal to .text):')
shown = 0
for (mn, target), count in rip_targs.most_common(100):
    if 0 <= target < len(data) and shown < 40:
        ctx = data[target:target+16]
        if any(b != 0 for b in ctx):
            shown += 1
            W(f'    Target=0x{target:06X} x{count:3d} [{mn:10s}] data={ctx.hex()}')
    elif target < 0 or target >= len(data):
        if shown < 50:
            shown += 1
            W(f'    Target=0x{target:06X} x{count:3d} [{mn:10s}] [EXTERNAL - likely game.dll]')
W('')
flush()

# ====================================================================
# SECTION 20: VTABLES
# ====================================================================
W('#' * 80)
W('#  20. VTABLE / VIRTUAL CALL ANALYSIS')
W('#' * 80)

vtable_calls = []
for i, insn in enumerate(all_insns):
    # Pattern: mov rax, [this]; call [rax+N]
    if insn.mnemonic == 'mov' and len(insn.operands) == 2:
        op0, op1 = insn.operands[0], insn.operands[1]
        if (op0.type == 1 and op1.type == 3 and
            op0.value.reg == 0 and  # RAX
            op1.value.mem.disp == 0 and
            op1.value.mem.index == 0):
            # Check if base is a register (this pointer)
            if op1.value.mem.base != 0:
                this_reg = op1.value.mem.base
                if i+1 < len(all_insns):
                    insn2 = all_insns[i+1]
                    if insn2.mnemonic == 'call' and len(insn2.operands) == 1:
                        op2 = insn2.operands[0]
                        if op2.type == 3:  # memory call
                            mem = op2.value.mem
                            if mem.base == 0 and mem.disp % 8 == 0:  # [rax+disp]
                                slot = mem.disp // 8
                                vtable_calls.append((insn.address, this_reg, slot))

W('--- VTable Slots (virtual function indices) ---')
slot_counts = Counter(s[2] for s in vtable_calls)
for slot, count in sorted(slot_counts.items()):
    W(f'    vfunc[{slot:3d}] (+0x{slot*8:03X}): {count} calls')

W(f'\n  Total virtual calls: {len(vtable_calls)}')
W('')
W('  VTABLE slots 0-3: Often destructor, virtual methods')
W('  VTABLE slots 4+: Specific class methods')
W('')
W('  Known virtual call sites from cheat:')
W('    "call [rax+0x28]" -> GetActiveSession (session vtable?)')
W('    "call [rax+0x30]" -> Various activity methods')
W('    "call [rax+0x38]" -> Ring buffer operations')
W('')
flush()

# ====================================================================
# PATTERN SIGNATURES
# ====================================================================
W('#' * 80)
W('#  ADDITIONAL: PATTERN SIGNATURES FOR GAME HOOKS')
W('#' * 80)

known_sigs = [
    ("0F 2F C1 48 89 44 24 ?? 76", "Float comparison + conditional branch"),
    ("0F 5B DB F3 41 0F 59 4E ?? F3", "Grenade count: CVTDQ2PD + MULSS"),
    ("39 50 04 74 ?? FF C1 48 83 C0 18 ...", "Iterator: stride 0x18 (player/entity array?)"),
    ("41 0F 2F 45 ?? 77 ?? 48", "Float compare + ja"),
    ("42 83 2C 81 ?? 48", "SUB [rcx+r8*4+?] - Stratagem count decrement"),
    ("44 8B C5 4C 8B 89 ?? ?? ?? ?? 48 8B CB 41 FF 91 ?? ?? ?? ??", "2-level vtable dispatch"),
    ("83 F8 10 0F 82 ?? ?? ?? ?? 41 8B 4E 08", "Array bounds check (cmp eax, 0x10)"),
    ("83 FE 07 7C 07 BA ?? ?? ?? ?? EB 16 83 FE 05", "Difficulty tier check"),
    ("F3 0F 10 46 ?? 0F 2F C6 72 ?? F3", "Health/damage float check"),
    ("F3 0F 11 44 3B ?? F3 0F 59 C7 F3 0F 5A C0", "Landing speed: MOVSS + MULSS + CVTSS2SD"),
    ("F3 41 0F 5C ?? BA ?? ?? ?? ?? F3 0F 11 04 01", "SUBSS + store (damage?)"),
    ("48 8B 0D ?? ?? ?? ?? 44 89 80 60 0C", "Global ref -> write +0xC60 (unlock?)"),
    ("48 8B 35 ?? ?? ?? ?? 49 8B E9 41 8B D8 48 8B 88 28 01", "GetActiveSession v1"),
    ("48 8B 35 ?? ?? ?? ?? 33 C9 49 8B E9 41 8B D8 4C 8B 90 28 01", "GetActiveSession v2"),
    ("F3 0F 11 4C A8 ?? 49", "Turret overheat: MOVSS write"),
    ("F3 45 0F 11 5E ?? E9", "Turret duration: MOVSS write + JMP"),
    ("42 83 2C 81 ?? 48", "Stratagem count: SUB write"),
    ("F3 0F 11 44 C8 ?? 0F", "Grenade fuse: MOVSS write"),
    ("41 8B 47 ?? 4C 8B 7C 24 ?? 4C", "Reward multiplier read"),
    ("48 8D 04 52 48 8D 0C 85 ?? ?? ?? ??", "Array index: LEA [rdx*2] + LEA [rax*4]"),
]

W('  Pattern signature matches in .text:')
for sig, desc in known_sigs:
    parts = sig.split()
    regex_bytes = b''
    for p in parts:
        if p == '??':
            regex_bytes += b'.'
        elif p == '...':
            regex_bytes += b'(?:.|\n){1,4}'
        else:
            # Escape the byte to avoid regex special chars
            bval = bytes([int(p, 16)])
            if bval in b'.^$*+?{}[]\\|()':
                regex_bytes += b'\\' + bval
            else:
                regex_bytes += bval
    
    try:
        matches = []
        for m in re.finditer(regex_bytes, data, re.DOTALL):
            matches.append(m.start())
        
        # Only show if match count is reasonable
        status = f'FOUND ({len(matches)} matches)'
        if len(matches) == 0:
            status = 'NOT IN .TEXT (runtime-patched or in game.dll)'
        elif len(matches) > 200:
            status = f'TOO MANY ({len(matches)} - too generic)'
        else:
            status = f'at {", ".join(f"0x{m:06X}" for m in matches[:6])}'
        
        W(f'  {sig}')
        W(f'    -> {desc}')
        W(f'    -> {status}')
        W('')
    except Exception as e:
        W(f'  {sig}')
        W(f'    -> {desc}')
        W(f'    -> ERROR: {e}')
        W('')

# ====================================================================
# COMPLETE BINARY OVERVIEW
# ====================================================================
W('#' * 80)
W('#  BINARY OVERVIEW & REGION MAP')
W('#' * 80)
W('')
for start in range(0, len(data), 0x10000):
    end = min(start + 0x10000, len(data))
    chunk = data[start:end]
    non_zero = sum(1 for b in chunk if b != 0)
    density = non_zero / len(chunk) * 100
    # Classify region
    region_type = 'Data/Strings'
    if start < 0x0BC000:
        region_type = 'Code (.text)'
    elif start < 0x0C8000:
        region_type = 'Data (rdata/IAT)'
    elif start < 0x0F9000:
        region_type = 'Encoded Data'
    elif start < 0x100000:
        region_type = 'ImGui Strings'
    elif start < 0x10A000:
        region_type = 'Feature Strings'
    elif start < 0x112000:
        region_type = 'Hook/Logic Strings'
    else:
        region_type = 'Metadata/RTTI'
    
    W(f'  0x{start:06X}-0x{end:06X}: {density:5.1f}% dense [{region_type}]')

W('')
W(f'  Total analysis time: {time.time()-T0:.1f}s')

# Final flush
flush()
print(f'Done! {len(OUT)} lines written to {OUT_PATH}')
