#!/usr/bin/env python3
"""
Exhaustive re-sweep for game-specific offsets, IDs, and data structures
in the LIBERTEA Helldivers 2 cheat.
"""

import struct
import re
import sys
from collections import Counter, defaultdict

BIN_PATH = r'C:\Users\emora\OneDrive\Desktop\2\.text_unpacked_mem.bin'
OUT_PATH = r'C:\Users\emora\OneDrive\Desktop\2\resweep_game_data.txt'

with open(BIN_PATH, 'rb') as f:
    data = f.read()

print(f'Binary: {len(data)} bytes')
print(f'First 64 bytes: {data[:64].hex()}')

# ============================================================
# HELPER: extract all printable ASCII strings
# ============================================================
def extract_strings(data, min_len=4):
    strings = []
    current = b''
    for i in range(len(data)):
        b = data[i]
        if 0x20 <= b < 0x7f:
            current += bytes([b])
        else:
            if len(current) >= min_len:
                strings.append((i - len(current), current.decode('ascii', errors='replace')))
            current = b''
    if len(current) >= min_len:
        strings.append((len(data) - len(current), current.decode('ascii', errors='replace')))
    return strings

strings = extract_strings(data, 4)
print(f'Total strings >=4 chars: {len(strings)}')

# ============================================================
# 1. EXTRACT ALL SIGNATURE PATTERNS (byte patterns for game offsets)
# ============================================================
# Patterns often look like: 48 8B 0D ?? ?? ?? ?? or F3 0F 10 3D ?? ?? ?? ?? 
# These contain RIP-relative offsets that point to game.dll globals

def find_rip_relative_refs(data, base=0):
    """Find RIP-relative LEA/LD references that likely point to game globals"""
    refs = []
    # LEA r64, [rip+disp32] = 4C 8D 0D ?? ?? ?? ?? etc (REX.W + 8D 0D)
    # MOV r64, [rip+disp32] = 48 8B 0D ?? ?? ?? ?? etc
    # MOVSS/MOVSD xmm, [rip+disp32] = F3 0F 10 0D ?? ?? ?? ?? etc
    
    patterns = [
        # opcode, length, description
        (re.compile(rb'\x48\x8B[\x05\x0D\x15\x1D\x25\x2D\x35\x3D]....'), 7, 'MOV r64, [rip+disp32]'),
        (re.compile(rb'\x4C\x8B[\x05\x0D\x15\x1D\x25\x2D\x35\x3D]....'), 7, 'MOV r64, [rip+disp32] (REX.WR)'),
        (re.compile(rb'\x48\x8D[\x05\x0D\x15\x1D\x25\x2D\x35\x3D]....'), 7, 'LEA r64, [rip+disp32]'),
        (re.compile(rb'\x4C\x8D[\x05\x0D\x15\x1D\x25\x2D\x35\x3D]....'), 7, 'LEA r64, [rip+disp32] (REX.WR)'),
        (re.compile(rb'\x8B[\x05\x0D\x15\x1D\x25\x2D\x35\x3D]....'), 6, 'MOV r32, [rip+disp32]'),
        (re.compile(rb'\x8D[\x05\x0D\x15\x1D\x25\x2D\x35\x3D]....'), 6, 'LEA r32, [rip+disp32]'),
        (re.compile(rb'\xF3\x0F\x10[\x05\x0D\x15\x1D\x25\x2D\x35\x3D]....'), 8, 'MOVSS xmm, [rip+disp32]'),
        (re.compile(rb'\xF3\x0F\x11[\x05\x0D\x15\x1D\x25\x2D\x35\x3D]....'), 8, 'MOVSS [rip+disp32], xmm'),
        (re.compile(rb'\x44\x0F\x2F[\x05\x0D\x15\x1D\x25\x2D\x35\x3D]....'), 7, 'COMISS xmm, [rip+disp32]'),
    ]
    
    for pat, length, desc in patterns:
        for m in pat.finditer(data):
            offset = m.start() + base
            # Extract the displacement
            if length == 7:
                disp = struct.unpack('<i', m.group()[3:7])[0]
            elif length == 6:
                disp = struct.unpack('<i', m.group()[2:6])[0]
            elif length == 8:
                disp = struct.unpack('<i', m.group()[4:8])[0]
            else:
                continue
            target_rva = offset + length + disp  # RIP-relative target
            refs.append((offset, target_rva, desc))
    
    return refs

rip_refs = find_rip_relative_refs(data)
print(f'RIP-relative references: {len(rip_refs)}')

# ============================================================
# 2. EXTRACT ALL 32-BIT IMMEDIATE CONSTANTS (potential enum values, hashes, IDs)
# ============================================================
def extract_32bit_constants(data, base=0):
    """Extract 32-bit immediate values from instructions and data"""
    consts_ctx = defaultdict(list)
    
    # Use capstone for more accurate disassembly
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True
        md.skipdata = True
        
        for insn in md.disasm(data, base):
            if insn.mnemonic.startswith('j'):
                continue  # skip jumps
            
            # Check for immediate operands
            if len(insn.operands) > 0:
                for op in insn.operands:
                    if op.type == 2:  # IMM
                        val = op.value.imm
                        if 0 <= val <= 0xFFFFFFFF:
                            # Get context bytes around the instruction
                            ctx_start = max(0, insn.address - base - 4)
                            ctx_end = min(len(data), insn.address - base + insn.size + 4)
                            ctx_bytes = data[ctx_start:ctx_end].hex()
                            consts_ctx[val].append((insn.address, insn.mnemonic, ctx_bytes))
    except Exception as e:
        print(f'Capstone error: {e}')
        # Fallback: brute force scan for 32-bit values in data section
        for i in range(0, len(data) - 3, 4):
            val = struct.unpack('<I', data[i:i+4])[0]
            if val > 0 and val <= 10000:  # Reasonable ID range
                ctx = data[max(0,i-8):min(len(data),i+8)].hex()
                consts_ctx[val].append((i, 'data32', ctx))
    
    return consts_ctx

consts = extract_32bit_constants(data)
print(f'Unique 32-bit constants: {len(consts)}')

# ============================================================
# 3. WRITE COMPREHENSIVE OUTPUT
# ============================================================
with open(OUT_PATH, 'w', encoding='utf-8') as out:
    out.write('=' * 80 + '\n')
    out.write('  RESWEEP: EXHAUSTIVE GAME-SPECIFIC OFFSETS, IDs, AND DATA STRUCTURES\n')
    out.write('  LIBERTEA Helldivers 2 Cheat Analysis\n')
    out.write('=' * 80 + '\n\n')
    
    # -------------------------------------------------------
    # ALL GAME-RELATED STRINGS
    # -------------------------------------------------------
    out.write('=== SECTION A: ALL GAME-RELATED STRINGS ===\n\n')
    
    game_keywords = [
        'weapon', 'armor', 'stratagem', 'sample', 'mission', 'difficulty',
        'warbond', 'booster', 'planet', 'biome', 'enemy', 'turret', 'sentry',
        'grenade', 'stim', 'ammo', 'ragdoll', 'recoil', 'shuttle', 'extraction',
        'landing', 'hover', 'jetpack', 'railgun', 'quasar', 'laser', 'flame',
        'arc', 'ballistic', 'explosive', 'gas', 'fire', 'shield', 'boundary',
        'helldiver', 'super', 'destroy', 'eagle', 'orbital', 'autocannon',
        'gatling', 'mortar', 'rocket', 'machine', 'rifle', 'shotgun', 'smg',
        'pistol', 'sniper', 'marksman', 'explosive', 'incendiary', 'plasma',
        'blitzer', 'breaker', 'liberator', 'diligence', 'punisher', 'scorcher',
        'dominator', 'eruptor', 'tenderizer', 'adjudicator', 'concussive',
        'penetrator', 'counter', 'diligence', 'defender', 'knight', 'stalwart',
        'machinegun', 'recoilless', 'spear', 'commando', 'expendable',
        'bug', 'bot', 'illuminate', 'terminid', 'automaton',
        'charger', 'bile', 'titan', 'hulk', 'devastator', 'warrior', 'scavenger',
        'hunter', 'stalker', 'impaler', 'spore', 'brood', 'factory', 'strider',
        'gunship', 'tank', 'annihilator', 'shredder', 'berserker', 'trooper',
        'common', 'rare', 'super', 'requisition', 'medal', 'slip',
        'blitz', 'eradicate', 'evacuate', 'icbm', 'defend', 'launch',
        'hellmire', 'creek', 'estanu', 'meridia', 'angel', 'venture',
        'trident', 'heatseeker', 'firefighter',
        'cave', 'hook', 'patch', 'nop', 'bypass', 'unlock',
        'samples', 'sc_loop', 'replay', 'capture', 'session', 'missionid',
        'x_super', 'player', 'lobby', 'slot', 'role',
    ]
    
    game_strings = []
    for offset, s in strings:
        s_lower = s.lower()
        for kw in game_keywords:
            if kw in s_lower:
                game_strings.append((offset, s))
                break
    
    # Also include strings that look like identifiers
    for offset, s in strings:
        # Check for camelCase/snake_case game identifiers
        if re.match(r'^[a-zA-Z][a-zA-Z0-9_]{3,40}$', s):
            if any(c.isupper() for c in s[1:]) or '_' in s:
                # Likely an identifier
                game_strings.append((offset, f'[ID] {s}'))
    
    for offset, s in sorted(set(game_strings), key=lambda x: x[1].lower()):
        out.write(f'  {offset:06X}: {s}\n')
    
    out.write(f'\n  Total game-related strings: {len(game_strings)}\n\n')
    
    # -------------------------------------------------------
    # RIP-RELATIVE REFERENCE ANALYSIS
    # -------------------------------------------------------
    out.write('=== SECTION B: RIP-RELATIVE POINTER REFERENCES ===\n\n')
    out.write('  These MOV/LEA [rip+disp32] instructions reference global data.\n')
    out.write('  The target RVA is where a game.dll global variable is likely accessed.\n\n')
    
    # Group by target
    target_counts = Counter(r[1] for r in rip_refs)
    for target, count in target_counts.most_common(100):
        out.write(f'  Target RVA 0x{target:06X}: {count} references\n')
    
    out.write(f'\n  Total unique target RVAs: {len(target_counts)}\n\n')
    
    # -------------------------------------------------------
    # CONSTANT VALUE ANALYSIS
    # -------------------------------------------------------
    out.write('=== SECTION C: 32-BIT CONSTANTS (POTENTIAL ENUM VALUES / IDs / HASHES) ===\n\n')
    
    # Filter constants to interesting ranges
    interesting_consts = {}
    for val, refs in consts.items():
        if len(refs) >= 3 or (0 <= val <= 200 and len(refs) >= 1):
            interesting_consts[val] = refs
    
    for val in sorted(interesting_consts.keys()):
        refs = interesting_consts[val]
        out.write(f'\n  0x{val:08X} ({val}):\n')
        for addr, mnem, ctx in refs[:10]:  # Limit to 10 examples
            out.write(f'    0x{addr:06X}: {mnem:12s}  ctx={ctx}\n')
    
    out.write(f'\n  Total interesting constants: {len(interesting_consts)}\n\n')
    
    # -------------------------------------------------------
    # SEARCH FOR SPECIFIC CATEGORIES
    # -------------------------------------------------------
    out.write('=== SECTION D: CATEGORIZED FINDINGS ===\n\n')
    
    # 4. DIFFICULTY - look for cmp esi,7 pattern
    out.write('--- DIFFICULTY ENUM ---\n')
    for offset, s in strings:
        if 'difficulty' in s.lower():
            out.write(f'  {offset:06X}: {s}\n')
    # Search for cmp esi,7 and similar
    for i in range(len(data) - 3):
        if data[i:i+3] == b'\x83\xFE\x07':  # cmp esi, 7
            ctx = data[max(0,i-4):min(len(data),i+16)].hex()
            out.write(f'  cmp esi,7 found at 0x{i:06X} ctx={ctx}\n')
        if data[i:i+3] == b'\x83\xFE\x05':  # cmp esi, 5
            ctx = data[max(0,i-4):min(len(data),i+16)].hex()
            out.write(f'  cmp esi,5 found at 0x{i:06X} ctx={ctx}\n')
    out.write('\n')
    
    # 5. MISSION TYPES
    out.write('--- MISSION TYPE IDS ---\n')
    mission_types = ['blitz', 'eradicate', 'evacuate', 'icbm', 'defend', 'launch', 
                     'eliminate', 'escort', 'upload', 'retrieve', 'destroy',
                     'nuke', 'nursery', 'drill', 'geo', 'survey', 'flag',
                     'spread', 'democracy', 'liberty', 'freedom']
    for offset, s in strings:
        for mt in mission_types:
            if mt in s.lower():
                out.write(f'  {offset:06X}: {s}\n')
                break
    out.write('\n')
    
    # 6. ENEMY TYPES
    out.write('--- ENEMY TYPE IDS ---\n')
    enemy_types = ['bug', 'bot', 'illuminate', 'terminid', 'automaton',
                   'charger', 'bile', 'titan', 'hulk', 'devastator', 'warrior',
                   'scavenger', 'hunter', 'stalker', 'impaler', 'spore',
                   'brood', 'factory', 'strider', 'gunship', 'tank',
                   'annihilator', 'shredder', 'berserker', 'trooper',
                   'behemoth', 'nursing', 'spewer', 'warrior', 'alpha',
                   'commander', 'rocket', 'heavy', 'scout']
    for offset, s in strings:
        for et in enemy_types:
            if et in s.lower():
                out.write(f'  {offset:06X}: {s}\n')
                break
    out.write('\n')
    
    # 7. SAMPLE TYPES
    out.write('--- SAMPLE TYPE IDS ---\n')
    for offset, s in strings:
        if 'sample' in s.lower() or 'common' in s.lower() or 'rare' in s.lower() or 'super' in s.lower():
            out.write(f'  {offset:06X}: {s}\n')
    # Look for 0/1/2 pattern that could be Common=0, Rare=1, Super=2
    out.write('\n')
    
    # 1 and 2. WEAPONS & ARMOR
    out.write('--- WEAPON & ARMOR IDS ---\n')
    weapon_armor_terms = [
        'weapon', 'armor', 'primary', 'secondary', 'throwable', 'grenade',
        'helmet', 'cape', 'passive', 'medium', 'light', 'heavy',
        'engineering', 'scout', 'medic', 'servo', 'fortified', 'extra',
        'padding', 'democracy', 'protects', 'unflinching', 'peak',
        'physique', 'siege', 'ready', 'flame', 'resistant', 'arc',
        'throw', 'distance', 'limb', 'health', 'explosive', 'resistance',
        'recoil', 'reduction', 'handling', 'reload', 'speed',
        'inflitrator', 'champion', 'devastator', 'titan', 'hero',
        'vanguard', 'paladin', 'executor', 'commando', 'trailblazer',
        'scout', 'ranger', 'pathfinder', 'field', 'chemist', 'doctor',
        'technician', 'engineer', 'demolition', 'breastplate',
        'trench', 'paramedic', 'battle', 'master', 'ground', 'breaker',
        'lockdown', 'dynamo', 'juggernaut', 'butcher', 'exterminator',
        'ravager', 'fury', 'predator', 'salamander', 'draconaught',
        'devourer', 'cinder', 'fireproof', 'flamewrought',
    ]
    for offset, s in strings:
        for term in weapon_armor_terms:
            if term in s.lower():
                out.write(f'  {offset:06X}: {s}\n')
                break
    out.write('\n')
    
    # 3. STRATAGEMS
    out.write('--- STRATAGEM IDS ---\n')
    strat_terms = [
        'stratagem', 'turret', 'sentry', 'eagle', 'orbital',
        'autocannon', 'gatling', 'mortar', 'rocket', 'machine',
        'supply', 'backpack', 'guard', 'dog', 'rover', 'jump', 'pack',
        'shield', 'generator', 'rellay', 'tesla', 'mine', 'incendiary',
        'anti', 'personnel', 'anti-tank', 'ems', 'smoke',
        'precision', 'strike', 'barrage', 'cluster', 'airburst',
        'napalm', '380', '120', 'walking', 'laser', 'railcannon',
        'gas', 'strike', '500kg', '110mm', 'rocket', 'pods',
        'strafing', 'run', 'airstrike', 'bombing',
        'patriot', 'exosuit', 'mech', 'emancipator', 'car', 'vehicle',
        'hellbomb', 'sssd', 'upload', 'data', 'seismic', 'probe',
        'flag', 'raise', 'drill', 'nuke', 'activate', 'terminal',
        'pelican', 'extraction', 'reinforce', 'sos', 'beacon',
        'resupply', 'backpack', 'weapon',
    ]
    for offset, s in strings:
        for term in strat_terms:
            if term in s.lower():
                out.write(f'  {offset:06X}: {s}\n')
                break
    out.write('\n')
    
    # 8. WARBOND IDS
    out.write('--- WARBOND / BATTLE PASS IDS ---\n')
    warbond_terms = ['warbond', 'battle', 'pass', 'premium', 'mobilize',
                     'steeled', 'veteran', 'cutting', 'edge', 'democratic',
                     'detonation', 'polar', 'patriots', 'freedom',
                     'flame', 'chemical', 'agents', 'truth', 'enforcers',
                     'servants', 'urban', 'legends', 'borderline',
                     'justice', 'helldivers', 'mobilize']
    for offset, s in strings:
        for term in warbond_terms:
            if term in s.lower():
                out.write(f'  {offset:06X}: {s}\n')
                break
    out.write('\n')
    
    # 9. BOOSTER IDS
    out.write('--- BOOSTER IDS ---\n')
    booster_terms = ['booster', 'vitality', 'stamina', 'infusion',
                     'muscle', 'enhancement', 'increased', 'reinforcement',
                     'budget', 'localization', 'confusion', 'expert',
                     'extraction', 'pilot', 'motivational', 'shocks',
                     'flexible', 'reinforcement', 'budget', 'hellpod',
                     'space', 'optimization', 'armed', 'resupply',
                     'drop', 'recon', 'scout', 'uav', 'radar',
                     'experimental', 'infusion', 'firebomb', 'hellbomb',
                     'dead', 'sprint']
    for offset, s in strings:
        for term in booster_terms:
            if term in s.lower():
                out.write(f'  {offset:06X}: {s}\n')
                break
    out.write('\n')
    
    # 10. PLANET/BIOME IDS
    out.write('--- PLANET / BIOME REFERENCES ---\n')
    planet_terms = ['planet', 'biome', 'creek', 'estanu', 'meridia',
                    'hellmire', 'angel', 'venture', 'mort', 'turing',
                    'achernar', 'secundus', 'heeth', 'fenrir', 'malevelon',
                    'draupnir', 'ubanea', 'vega', 'durgen', 'pandion',
                    'mara', 'fori', 'pride', 'socorro', 'curia',
                    'mastia', 'martale', 'matar', 'vog', 'sojoth',
                    'clasa', 'gar', 'haren', 'klen', 'dah', 'gacrux',
                    'moh', 'ord', 'fema', 'primordial', 'acid', 'desert',
                    'snow', 'forest', 'swamp', 'moon', 'canyon', 'jungle',
                    'volcanic', 'arctic', 'tundra', 'ocean', 'plains',
                    'highlands', 'wasteland', 'ice', 'crimson', 'ether',
                    'fog', 'swamp', 'bog', 'marsh']
    for offset, s in strings:
        for term in planet_terms:
            if term in s.lower():
                out.write(f'  {offset:06X}: {s}\n')
                break
    out.write('\n')
    
    # 11. GAME PHASE / STATE
    out.write('--- GAME PHASE / STATE IDENTIFIERS ---\n')
    state_terms = ['loading', 'in_mission', 'in_ship', 'post_mission', 'menu',
                   'game_state', 'phase', 'state', 'ready', 'playing',
                   'debriefing', 'results', 'lobby', 'matchmaking',
                   'deploying', 'returning', 'destroyer', 'ship',
                   'galactic', 'war', 'table']
    for offset, s in strings:
        for term in state_terms:
            if term in s.lower():
                out.write(f'  {offset:06X}: {s}\n')
                break
    out.write('\n')
    
    # 12. NETWORK MESSAGE IDS
    out.write('--- NETWORK MESSAGE IDS ---\n')
    net_terms = ['http', 'post', 'get', 'api', 'endpoint', 'curl',
                 'mission/end', 'activity', '/war/', '/api/',
                 'x-signature', 'x-session', 'authorization',
                 'content-type', 'application/json', 'request',
                 'response', 'header', 'cookie', 'payload',
                 'message', 'packet', 'network', 'socket',
                 'send', 'receive', 'queue', 'dispatch']
    for offset, s in strings:
        for term in net_terms:
            if term in s.lower() or term in s:
                out.write(f'  {offset:06X}: {s}\n')
                break
    out.write('\n')
    
    # 13. PLAYER CLASS/ROLE
    out.write('--- PLAYER CLASS / ROLE / SLOT IDS ---\n')
    role_terms = ['player', 'slot', 'role', 'class', 'helldiver', 'lobby',
                  'member', 'host', 'client', 'peer', 'squad', 'team']
    for offset, s in strings:
        for term in role_terms:
            if term in s.lower():
                out.write(f'  {offset:06X}: {s}\n')
                break
    out.write('\n')
    
    # 14. DAMAGE TYPE IDS
    out.write('--- DAMAGE TYPE IDS ---\n')
    dmg_terms = ['damage', 'ballistic', 'explosive', 'fire', 'gas', 'arc',
                 'laser', 'plasma', 'electric', 'acid', 'impact',
                 'penetration', 'armor', 'light', 'medium', 'heavy',
                 'anti-tank', 'concussive', 'incendiary', 'shrapnel',
                 'durable', 'sustainable', 'stagger', 'push', 'force',
                 'bleed', 'burn', 'shock', 'freeze']
    for offset, s in strings:
        for term in dmg_terms:
            if term in s.lower():
                out.write(f'  {offset:06X}: {s}\n')
                break
    out.write('\n')
    
    # 15. UI STATE IDS
    out.write('--- UI STATE IDS ---\n')
    ui_terms = ['main_menu', 'loadout', 'armory', 'warbond', 'acquisition',
                'shop', 'superstore', 'career', 'social', 'settings',
                'options', 'escape', 'pause', 'hud', 'overlay',
                'terminal', 'map', 'minimap', 'compass', 'crosshair',
                'scoreboard', 'inventory', 'equipment']
    for offset, s in strings:
        for term in ui_terms:
            if term in s.lower():
                out.write(f'  {offset:06X}: {s}\n')
                break
    out.write('\n')
    
    # 16. STRUCTURE SIZE CONSTANTS
    out.write('--- STRUCTURE SIZE CONSTANTS ---\n')
    # Look for alloc-like patterns: mov edi, 0x40 etc.
    # and cmp eax, 0x128 etc.
    size_patterns = []
    for i in range(len(data) - 6):
        # mov reg, imm32 then call alloc or similar
        if data[i] in (0xB8, 0xB9, 0xBA, 0xBB, 0xBD, 0xBE, 0xBF):  # mov r32, imm32
            imm = struct.unpack('<I', data[i+1:i+5])[0]
            if 0x20 <= imm <= 0x1000:  # Reasonable struct size
                # Check if followed by malloc/new
                ctx = data[max(0,i-4):min(len(data),i+32)]
                size_patterns.append((i, imm, ctx))
        # cmp reg, imm32 with size-like values
        if data[i:i+2] in (b'\x81\xF8', b'\x81\xF9', b'\x81\xFA', b'\x81\xFB',
                            b'\x83\xF8', b'\x83\xF9', b'\x83\xFA', b'\x83\xFB'):  # cmp reg, imm
            if data[i] == 0x81:
                imm = struct.unpack('<I', data[i+2:i+6])[0]
                insn_len = 6
            else:
                imm = struct.unpack('b', data[i+2:i+3])[0] & 0xFF
                insn_len = 3
            if 0x20 <= imm <= 0x1000:
                ctx = data[max(0,i-4):min(len(data),i+insn_len+16)].hex()
                size_patterns.append((i, imm, f'cmp: {ctx}'))
    
    # Deduplicate by value
    size_counter = Counter()
    for offset, size, ctx in size_patterns:
        size_counter[size] += 1
    
    for size, count in size_counter.most_common(80):
        # Find best examples
        examples = [ctx for o, s, ctx in size_patterns if s == size][:3]
        out.write(f'  0x{size:04X} ({size}) x{count}:')
        for ex in examples:
            out.write(f'  {ex}\n')
        out.write('\n')
    
    out.write('\n')
    
    # 17. MAGIC / HASH CONSTANTS
    out.write('--- MAGIC / HASH / CRC CONSTANTS ---\n')
    # Look for 32-bit values in comparisons that could be hashes
    magic_candidates = []
    for val, refs in consts.items():
        if 0x10000000 <= val <= 0xFFFFFFFF:
            if len(refs) >= 2:
                magic_candidates.append((val, refs))
        # Also check common hash ranges
        if val in [0x811C9DC5, 0xCBF29CE4, 0xEDB88320, 0x04C11DB7, 0x8F1BBCDC]:
            magic_candidates.append((val, refs))
        # Check for values that look like CRC32/Adler/FNV
        if 0x15050000 <= val <= 0xFFFF0000 and len(refs) >= 1:
            magic_candidates.append((val, refs))
    
    for val, refs in sorted(magic_candidates, key=lambda x: -len(x[1]))[:50]:
        out.write(f'\n  0x{val:08X} ({val}):\n')
        for addr, mnem, ctx in refs[:10]:
            out.write(f'    0x{addr:06X}: {mnem:12s}  ctx={ctx}\n')
    
    out.write('\n')
    
    # 18. POINTER CHAINS
    out.write('--- POINTER CHAIN PATTERNS ===\n')
    # Look for sequential dereferences: [reg+X] -> [reg+Y] -> [reg+Z]
    # Pattern: mov reg, [reg+off]; mov reg, [reg+off]; mov reg, [reg+off]
    # We'll search for common dereference offsets
    deref_offsets = Counter()
    for i in range(len(data) - 4):
        # MOV r64, [r64+disp8]
        if data[i] in (0x48, 0x4C):
            rex = data[i]
            if data[i+1] == 0x8B and 0x40 <= data[i+2] <= 0x7F and data[i+3] < 0x80:
                disp = data[i+3]
                if disp & 0x80:
                    disp = disp - 256
                # Check next instruction
                if i + 4 < len(data):
                    modrm = data[i+2]
                    src_reg = modrm & 7
                    dst_reg = (modrm >> 3) & 7
                    deref_offsets[(disp, f'mov r{dst_reg}, [r{src_reg}+{disp:+d}]')] += 1
        # MOV r64, [r64+disp32]
        if data[i] in (0x48, 0x4C):
            if data[i+1] == 0x8B and 0x80 <= data[i+2] <= 0xBF:
                disp = struct.unpack('<i', data[i+3:i+7])[0]
                modrm = data[i+2]
                src_reg = modrm & 7
                dst_reg = (modrm >> 3) & 7
                if -0x200 <= disp <= 0x200 and disp != 0:  # Reasonable offset
                    deref_offsets[(disp, f'mov r{dst_reg}, [r{src_reg}+0x{disp:X}]')] += 1
    
    for (off, desc), count in deref_offsets.most_common(100):
        out.write(f'  0x{off:+04X} ({off:+d}) x{count}: {desc}\n')
    
    out.write('\n')
    
    # 19. GLOBAL VARIABLE OFFSETS (game.dll+...)
    out.write('--- GLOBAL VARIABLE OFFSET PATTERNS ---\n')
    out.write('  (RIP-relative targets that could be game.dll globals)\n\n')
    
    # Find RIP-relative MOV/LEA that targets addresses we can compute
    for offset, target_rva, desc in rip_refs[:200]:
        # Try to understand what's at the target
        target_offset = target_rva
        if 0 <= target_offset < len(data):
            tgt_bytes = data[target_offset:target_offset+16]
            out.write(f'  0x{offset:06X} -> target=0x{target_rva:06X} ({desc}): {tgt_bytes[:16].hex()}\n')
    
    out.write('\n')
    
    # 20. VTABLES
    out.write('--- VTABLE / VIRTUAL CALL ANALYSIS ---\n')
    # Look for virtual calls: mov rax, [rcx]; call [rax+idx*8]
    vtable_calls = []
    for i in range(len(data) - 8):
        # Pattern: MOV RAX, [RCX]  (48 8B 01)
        # Followed by: CALL [RAX+disp8] (FF 50 XX) or CALL [RAX+disp32] (FF 90 XXXXXXXX)
        if data[i:i+3] == b'\x48\x8B\x01':  # mov rax, [rcx]
            if i + 3 < len(data) and data[i+3] == 0xFF:
                if data[i+4] == 0x50:  # call [rax+disp8]
                    slot = data[i+5] // 8
                    vtable_calls.append((i, slot, f'call [rax+0x{data[i+5]:02X}] (vfunc[{slot}])'))
                elif data[i+4] == 0x90:  # call [rax+disp32]
                    disp = struct.unpack('<i', data[i+5:i+9])[0]
                    slot = disp // 8
                    vtable_calls.append((i, slot, f'call [rax+0x{disp:X}] (vfunc[{slot}])'))
        
        # Pattern: MOV RAX, [rcx+off]; CALL [RAX+disp]
        elif data[i] == 0x48 and data[i+1] == 0x8B and data[i+2] & 0x07 == 0x01:
            # mov rax, [rcx+disp8] where dst is RAX and base is RCX
            base = data[i+2] >> 6
            index = (data[i+2] >> 3) & 7
            disp8 = data[i+3]
            if i + 4 < len(data) and data[i+4] == 0xFF:
                if data[i+5] == 0x50:  # call [rax+disp8]
                    slot = data[i+6] // 8
                    vtable_calls.append((i, slot, f'call [[rcx+{disp8}]+0x{data[i+6]:02X}] (vfunc[{slot}] from +{disp8})'))
    
    vtable_slots = Counter(r[1] for r in vtable_calls)
    out.write('  VTable slot frequencies:\n')
    for slot, count in sorted(vtable_slots.items()):
        out.write(f'  vfunc[{slot}]: {count} calls\n')
    
    out.write('\n  Detailed vtable calls:\n')
    for offset, slot, desc in vtable_calls[:100]:
        ctx = data[offset:offset+16].hex()
        out.write(f'  0x{offset:06X}: slot={slot:3d}  {desc:50s}  ctx={ctx}\n')
    
    out.write(f'\n  Total virtual calls found: {len(vtable_calls)}\n\n')
    
    # Additional: Search for specific numeric values that might be weapon IDs
    out.write('=== SECTION E: WEAPON ID ANALYSIS ===\n\n')
    out.write('  Looking for 51-weapon array patterns...\n')
    # The cheat mentions "All Guns: %s  (%d/51, Rep %d/%d)"
    # Weapon IDs are likely 0-50 or 1-51
    # Look for switch/case style dispatch with values 0-200
    for offset, s in strings:
        s_l = s.lower()
        if any(w in s_l for w in ['weapon', 'gun', 'rifle', 'shotgun', 'smg', 'pistol', 
                                    'sniper', 'marksman', 'breaker', 'liberator',
                                    'dominator', 'scorcher', 'eruptor', 'blitzer',
                                    'pummeler', 'defender', 'diligence', 'punisher',
                                    'slugger', 'tenderizer', 'adjudicator',
                                    'concussive', 'penetrator', 'knight', 'stalwart',
                                    'arc', 'blitzer', 'torcher', 'crisper',
                                    'redeemer', 'verdict', 'senator', 'bushwhacker',
                                    'grenade', 'pistol']):
            out.write(f'  {offset:06X}: {s}\n')
    
    out.write('\n=== SECTION F: FULL CONSTANT DUMP (values 0-1000) ===\n\n')
    for val in sorted(consts.keys()):
        if 0 <= val <= 1000:
            refs = consts[val]
            out.write(f'  0x{val:03X} ({val:4d}): {len(refs):3d} refs')
            # Show one example
            if refs:
                addr, mnem, ctx = refs[0]
                out.write(f'  eg. 0x{addr:06X}: {mnem}')
            out.write('\n')
    
    out.write('\n' + '=' * 80 + '\n')
    out.write('  END OF RESWEEP\n')
    out.write('=' * 80 + '\n')

print(f'\nOutput written to {OUT_PATH}')
print('Done!')
