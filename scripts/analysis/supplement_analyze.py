#!/usr/bin/env python3
"""
SUPPLEMENTAL ANALYSIS - Targeted scans for game data strings,
RIP-relative offsets, vtable calls, and constants.
"""

import struct, re, sys
from collections import Counter, defaultdict

BIN_PATH = r'C:\Users\emora\OneDrive\Desktop\2\.text_unpacked_mem.bin'
OUT_PATH = r'C:\Users\emora\OneDrive\Desktop\2\resweep_game_data.txt'

with open(BIN_PATH, 'rb') as f:
    data = f.read()

# Read existing output
with open(OUT_PATH, 'r', encoding='utf-8') as f:
    existing = f.read()

# ============================================================
# Find ALL strings in the game data region (0x0FD000-0x106000)
# ============================================================
def extract_strings_region(data, start, end, min_len=4):
    strings = []
    current = b''
    for i in range(start, min(end, len(data))):
        b = data[i]
        if 0x20 <= b < 0x7f:
            current += bytes([b])
        else:
            if len(current) >= min_len:
                strings.append((i - len(current), current.decode('ascii', errors='replace')))
            current = b''
    if len(current) >= min_len:
        strings.append((end - len(current), current.decode('ascii', errors='replace')))
    return strings

# Full strings for cross-reference
all_strings = []
current = b''
for i in range(len(data)):
    b = data[i]
    if 0x20 <= b < 0x7f:
        current += bytes([b])
    else:
        if len(current) >= 4:
            all_strings.append((i - len(current), current.decode('ascii', errors='replace')))
        current = b''
if len(current) >= 4:
    all_strings.append((len(data) - len(current), current.decode('ascii', errors='replace')))

# ============================================================
# SUPPLEMENT 1: Complete weapon/armor/stratagem name catalog
# ============================================================
game_strings = extract_strings_region(data, 0x0FD000, 0x106000, 4)

# Categorize
weapon_names = []
armor_names = []
stratagem_names = []
enemy_names = []
other_game = []

for offset, s in game_strings:
    s_clean = s.strip()
    if not s_clean or len(s_clean) < 4:
        continue
    
    # Skip ImGui internal stuff
    if s_clean.startswith('##') or s_clean.startswith('[nav]') or s_clean.startswith('[imgui'):
        continue
    if 'ConfigDebug' in s_clean or 'IsItemHovered' in s_clean or 'SetShortcutRouting' in s_clean:
        continue
    if s_clean.startswith('Programmer error') or s_clean.startswith('Invalid flags'):
        continue
    if 'GetActiveSession' in s_clean:
        continue
    
    # Weapon pattern: XX-### Name
    if re.match(r'^[A-Z]{2,4}[ -]\d{1,3}[A-Z]?', s_clean):
        weapon_names.append((offset, s_clean))
    # Armor pattern: XX-## Name
    elif re.match(r'^[A-Z]{2,3}[ -]\d{1,3}', s_clean):
        armor_names.append((offset, s_clean))
    # Stratagem keywords
    elif any(kw in s_clean.lower() for kw in ['sentry', 'eagle', 'orbital', 'guard dog', 
                'exosuit', 'backpack', 'turret', 'minefield', 'strike', 'barrage',
                'hellbomb', 'reinforce', 'resupply', 'extraction', 'seismic',
                'prospecting', 'drill', 'spire', 'plug', 'thumper']):
        stratagem_names.append((offset, s_clean))
    # Enemy keywords
    elif any(kw in s_clean.lower() for kw in ['charger', 'titan', 'hulk', 'devastator',
                'strider', 'spewer', 'brood', 'stalker', 'hunter', 'scavenger',
                'warrior', 'impaler', 'shrieker', 'trooper', 'berserker',
                'gunship', 'harvester', 'overseer', 'bastion', 'tank',
                'guard', 'commander']):
        enemy_names.append((offset, s_clean))
    # Other game-related
    elif any(kw in s_clean.lower() for kw in ['liberator', 'diligence', 'breaker',
                'scorcher', 'dominator', 'eruptor', 'blitzer', 'punisher',
                'defender', 'stalwart', 'machine gun', 'recoilless', 'spear',
                'autocannon', 'railgun', 'flamethrower', 'quasar', 'laser',
                'arc thrower', 'grenade launcher', 'anti-materiel',
                'supply pack', 'jump pack', 'hover pack', 'shield',
                'sickle', 'scythe', 'purifier', 'torcher', 'cookout',
                'pummeler', 'knight', 'slugger', 'deadeye', 'carbine',
                'concussive', 'penetrator', 'tenderizer', 'adjudicator',
                'reprimand', 'halt', 'crossbow', 'bushwhacker',
                'peacemaker', 'redeemer', 'verdict', 'senator',
                'crisper', 'dagger', 'talon', 'stun lance',
                'frag', 'incendiary', 'thermite', 'smoke',
                'ballistic', 'explosive', 'fire resistant',
                'gas resistance', 'arc resistant',
                'peak physique', 'servo-assisted', 'fortified',
                'engineering kit', 'medic', 'scout', 'extra padding',
                'unflinching', 'siege', 'acclimated',
                'democracy protects', 'integrated explosives',
                'electrical conduit', 'advanced filtration',
                'stamina', 'vitality', 'booster']):
        other_game.append((offset, s_clean))

# Write supplemental data
SUPP = []
SUPP.append('\n' + '#' * 80)
SUPP.append('#  SUPPLEMENT A: COMPLETE GAME DATA STRING CATALOG')
SUPP.append('#' * 80)
SUPP.append('')
SUPP.append(f'--- WEAPON NAMES ({len(weapon_names)} found) ---')
for offset, s in sorted(weapon_names, key=lambda x: x[1]):
    SUPP.append(f'  {offset:06X}: "{s}"')

SUPP.append('')
SUPP.append(f'--- ARMOR NAMES ({len(armor_names)} found) ---')
for offset, s in sorted(armor_names, key=lambda x: x[1]):
    SUPP.append(f'  {offset:06X}: "{s}"')

SUPP.append('')
SUPP.append(f'--- STRATAGEM NAMES ({len(stratagem_names)} found) ---')
for offset, s in sorted(stratagem_names, key=lambda x: x[1]):
    SUPP.append(f'  {offset:06X}: "{s}"')

SUPP.append('')
SUPP.append(f'--- ENEMY NAMES ({len(enemy_names)} found) ---')
for offset, s in sorted(enemy_names, key=lambda x: x[1]):
    SUPP.append(f'  {offset:06X}: "{s}"')

SUPP.append('')
SUPP.append(f'--- OTHER GAME DATA ({len(other_game)} found) ---')
for offset, s in sorted(other_game, key=lambda x: x[1]):
    SUPP.append(f'  {offset:06X}: "{s}"')

# ============================================================
# SUPPLEMENT 2: BYTE-LEVEL SCAN FOR RIP-RELATIVE REFERENCES
# ============================================================
SUPP.append('\n' + '#' * 80)
SUPP.append('#  SUPPLEMENT B: BYTE-LEVEL RIP-RELATIVE REFERENCE SCAN')
SUPP.append('#' * 80)
SUPP.append('')

# Byte-level scan for RIP-relative patterns
# MOV r64, [rip+disp32]: REX.W + 8B + modrm(00xxx101) + disp32
# LEA r64, [rip+disp32]: REX.W + 8D + modrm(00xxx101) + disp32
rip_refs = defaultdict(list)

for i in range(len(data) - 7):
    # Check for RIP-relative addressing: mod=00, r/m=101
    b = data[i:i+8]
    
    # MOV r64, [rip+disp32]  (48/4C 8B 0D/15/1D/25/2D/35/3D XXXXXXXX)
    if b[0] in (0x48, 0x4C) and b[1] == 0x8B and (b[2] & 0xC7) == 0x05:
        disp = struct.unpack('<i', b[3:7])[0]
        target_rva = i + 7 + disp
        reg = 'r' + str((b[2] >> 3) & 7)
        if b[0] == 0x4C:
            reg = 'r' + str(8 + ((b[2] >> 3) & 7))
        rip_refs[target_rva].append((i, f'mov {reg}, [rip+disp32]'))
    
    # LEA r64, [rip+disp32]  (48/4C 8D 0D/15/1D/25/2D/35/3D XXXXXXXX)
    elif b[0] in (0x48, 0x4C) and b[1] == 0x8D and (b[2] & 0xC7) == 0x05:
        disp = struct.unpack('<i', b[3:7])[0]
        target_rva = i + 7 + disp
        reg = 'r' + str((b[2] >> 3) & 7)
        if b[0] == 0x4C:
            reg = 'r' + str(8 + ((b[2] >> 3) & 7))
        rip_refs[target_rva].append((i, f'lea {reg}, [rip+disp32]'))

SUPP.append(f'Total unique RIP-relative targets: {len(rip_refs)}')
SUPP.append(f'Total RIP-relative instructions: {sum(len(v) for v in rip_refs.values())}')
SUPP.append('')

# Show targets sorted by reference count
SUPP.append('--- Most Referenced RIP Targets ---')
for target, refs in sorted(rip_refs.items(), key=lambda x: -len(x[1]))[:80]:
    count = len(refs)
    if 0 <= target < len(data):
        tgt_data = data[target:target+16]
        # Show sample source offsets
        sample_offsets = [f'0x{r[0]:06X}' for r in refs[:4]]
        SUPP.append(f'  Target=0x{target:06X} x{count:3d}  data={tgt_data.hex():32s}  from={", ".join(sample_offsets)}')
    else:
        sample_offsets = [f'0x{r[0]:06X}' for r in refs[:4]]
        SUPP.append(f'  Target=0x{target:06X} x{count:3d}  [EXTERNAL - game.dll?]  from={", ".join(sample_offsets)}')

# ============================================================
# SUPPLEMENT 3: BYTE-LEVEL VTABLE CALL SCAN
# ============================================================
SUPP.append('\n' + '#' * 80)
SUPP.append('#  SUPPLEMENT C: BYTE-LEVEL VTABLE CALL SCAN')
SUPP.append('#' * 80)
SUPP.append('')

vtable_calls = []
for i in range(len(data) - 6):
    # mov rax, [this] = 48 8B (00 | 01 | 02...) where modrm r/m = this_reg
    # Then call [rax+disp]
    if data[i] == 0x48 and data[i+1] == 0x8B:
        modrm = data[i+2]
        rm = modrm & 7
        # Check if followed by call [rax+disp8]
        if i + 6 <= len(data):
            next_bytes = data[i+3:i+6]
            if next_bytes[0] == 0xFF and next_bytes[1] == 0x50:  # call [rax+disp8]
                disp = next_bytes[2]
                slot = disp // 8
                vtable_calls.append((i, slot, f'this_reg=r{rm}, call [rax+0x{disp:02X}] vfunc[{slot}]'))
            elif next_bytes[0] == 0xFF and next_bytes[1] == 0x90:  # call [rax+disp32]
                if i + 7 <= len(data):
                    disp = struct.unpack('<i', data[i+5:i+9])[0]
                    if disp % 8 == 0:
                        slot = disp // 8
                        vtable_calls.append((i, slot, f'this_reg=r{rm}, call [rax+0x{disp:X}] vfunc[{slot}]'))

# Also look for mov rax, [this+off]; call [rax+N]
for i in range(len(data) - 10):
    # 48 8B 4X ?? = mov rax, [this+disp8]
    # 48 8B 8X ?? ?? ?? ?? = mov rax, [this+disp32]
    if data[i] == 0x48 and data[i+1] == 0x8B and (data[i+2] & 0xC0) != 0:  # has displacement
        modrm = data[i+2]
        rm = modrm & 7
        if rm in (1, 2, 3, 4, 5, 6, 7):  # this is a register base
            # Determine disp size
            mod = (modrm >> 6) & 3
            if mod == 1:  # disp8
                disp8 = data[i+3]
                insn_len = 4
            elif mod == 2:  # disp32
                disp32 = struct.unpack('<i', data[i+3:i+7])[0]
                insn_len = 7
            else:
                continue
            
            # Check next instruction
            j = i + insn_len
            if j + 2 < len(data):
                if data[j] == 0xFF and data[j+1] == 0x50:  # call [rax+disp8]
                    cd = data[j+2]
                    slot = cd // 8
                    if mod == 1:
                        vtable_calls.append((i, slot, f'[[r{rm}+0x{disp8:02X}]+0x{cd:02X}] vfunc[{slot}]'))
                    else:
                        vtable_calls.append((i, slot, f'[[r{rm}+0x{disp32:X}]+0x{cd:02X}] vfunc[{slot}]'))
                elif data[j] == 0xFF and data[j+1] == 0x90:  # call [rax+disp32]
                    if j + 5 < len(data):
                        cd = struct.unpack('<i', data[j+2:j+6])[0]
                        if cd % 8 == 0:
                            slot = cd // 8
                            if mod == 1:
                                vtable_calls.append((i, slot, f'[[r{rm}+0x{disp8:02X}]+0x{cd:X}] vfunc[{slot}]'))
                            else:
                                vtable_calls.append((i, slot, f'[[r{rm}+0x{disp32:X}]+0x{cd:X}] vfunc[{slot}]'))

slot_counter = Counter(c[1] for c in vtable_calls)
SUPP.append(f'Total virtual calls found: {len(vtable_calls)}')
SUPP.append('')
SUPP.append('--- VTable Slot Distribution ---')
for slot in sorted(slot_counter.keys()):
    count = slot_counter[slot]
    SUPP.append(f'  vfunc[{slot:3d}] (offset +0x{slot*8:03X}): {count:4d} calls')

SUPP.append('')
SUPP.append('--- Detailed VTable Call Sites (most called slots first) ---')
# Show examples for top slots
for slot, count in slot_counter.most_common(30):
    examples = [c for c in vtable_calls if c[1] == slot][:3]
    SUPP.append(f'  Slot {slot:3d} (+0x{slot*8:03X}) x{count}:')
    for addr, _, desc in examples:
        ctx = data[addr:addr+12].hex()
        SUPP.append(f'    0x{addr:06X}: {desc:55s} ctx={ctx}')

# ============================================================
# SUPPLEMENT 4: COMPLETE 32-BIT CONSTANT CATALOG
# ============================================================
SUPP.append('\n' + '#' * 80)
SUPP.append('#  SUPPLEMENT D: ALL 32-BIT IMMEDIATES IN CMP INSTRUCTIONS')
SUPP.append('#' * 80)
SUPP.append('')

# Byte-level scan for cmp with 32-bit immediate
cmp_consts = Counter()
for i in range(len(data) - 6):
    # cmp r/m32, imm32: 81 /7 id -> 81 F8..FF XXXXXXXX
    if data[i] == 0x81 and (data[i+1] & 0xF8) == 0xF8:
        val = struct.unpack('<I', data[i+2:i+6])[0]
        cmp_consts[val] += 1
    # cmp r/m32, imm8: 83 /7 ib -> 83 F8..FF XX
    elif data[i] == 0x83 and (data[i+1] & 0xF8) == 0xF8:
        val = data[i+2]
        if val & 0x80:
            val = val - 256
        cmp_consts[val] += 1
    # cmp rax/eax, imm32: 3D XXXXXXXX (cmp eax) or 48 3D XXXXXXXX (cmp rax)
    elif data[i] == 0x3D:
        val = struct.unpack('<I', data[i+1:i+5])[0]
        cmp_consts[val] += 1
    elif data[i] == 0x48 and data[i+1] == 0x3D:
        val = struct.unpack('<I', data[i+2:i+6])[0]
        cmp_consts[val] += 1

SUPP.append(f'Total cmp immediate values: {len(cmp_consts)}')
SUPP.append('')
SUPP.append('--- Values 0-200 (potential enum IDs) ---')
for val, count in sorted(cmp_consts.items()):
    if 0 <= val <= 200 and count >= 1:
        SUPP.append(f'  {val:3d} (0x{val:02X}): {count} refs')

SUPP.append('')
SUPP.append('--- Values 201-10000 (potential struct offsets, sizes, flags) ---')
for val, count in sorted(cmp_consts.items()):
    if 201 <= val <= 10000 and count >= 2:
        SUPP.append(f'  {val:5d} (0x{val:04X}): {count} refs')

SUPP.append('')
SUPP.append('--- High Values 0x1000-0xFFFFFFFF (potential hashes, magic numbers) ---')
for val, count in cmp_consts.most_common(100):
    if val >= 0x1000 and count >= 2:
        SUPP.append(f'  0x{val:08X} ({val:10d}): {count} refs')

# ============================================================
# SUPPLEMENT 5: ALLOCATION SIZE SCAN
# ============================================================
SUPP.append('\n' + '#' * 80)
SUPP.append('#  SUPPLEMENT E: ALLOCATION SIZE PATTERNS')
SUPP.append('#' * 80)
SUPP.append('')

# Scan for: mov ecx/rcx/edx, SIZE followed by call within N bytes
alloc_sizes = Counter()
for i in range(len(data) - 10):
    # mov ecx, imm32: B9 XXXXXXXX
    if data[i] == 0xB9:
        size = struct.unpack('<I', data[i+1:i+5])[0]
        if 0x10 <= size <= 0x2000:
            for j in range(i+5, min(i+20, len(data))):
                if data[j] == 0xE8 or data[j] == 0xFF:  # call
                    alloc_sizes[size] += 1
                    break
    # mov edx, imm32: BA XXXXXXXX
    elif data[i] == 0xBA:
        size = struct.unpack('<I', data[i+1:i+5])[0]
        if 0x10 <= size <= 0x2000:
            for j in range(i+5, min(i+20, len(data))):
                if data[j] == 0xE8 or data[j] == 0xFF:
                    alloc_sizes[size] += 1
                    break
    # mov rcx, imm32: 48 B9... or 48 C7 C1...
    elif data[i:i+3] == b'\x48\xC7\xC1':
        size = struct.unpack('<I', data[i+3:i+7])[0]
        if 0x10 <= size <= 0x2000:
            for j in range(i+7, min(i+22, len(data))):
                if data[j] == 0xE8 or data[j] == 0xFF:
                    alloc_sizes[size] += 1
                    break

SUPP.append('Top alloc sizes (size -> call pattern):')
for size, count in alloc_sizes.most_common(60):
    if count >= 2:
        SUPP.append(f'  {size:5d} (0x{size:04X}): {count} occurrences')

# ============================================================
# SUPPLEMENT 6: DIFFICULTY-RELATED CONSTANT ENUM
# ============================================================
SUPP.append('\n' + '#' * 80)
SUPP.append('#  SUPPLEMENT F: DIFFICULTY SYSTEM ANALYSIS')
SUPP.append('#' * 80)
SUPP.append('')

# From strings we found:
# "1 - Trivial (0%)" through "10 - (300%)"
# These appear to be DIFFICULTY_MULTIPLIERS, not the actual difficulty enum
SUPP.append('--- Difficulty Tier Display Strings ---')
for offset, s in all_strings:
    if re.match(r'^\d+\s*-\s*.*\d+%', s.strip()):
        SUPP.append(f'  {offset:06X}: "{s}"')

SUPP.append('')
SUPP.append('--- Difficulty Reward Multipliers (from cheat UI) ---')
SUPP.append('  1 - Trivial (0%)          -> No extra reward')
SUPP.append('  2 - Easy (0%)             -> No extra reward')
SUPP.append('  3 - Medium (25%)          -> 1.25x')
SUPP.append('  4 - Challenging (50%)     -> 1.50x')
SUPP.append('  5 - Hard (75%)            -> 1.75x')
SUPP.append('  6 - Extreme (100%)        -> 2.00x')
SUPP.append('  7 - Super Helldive (150%) -> 2.50x')
SUPP.append('  8 - (200%)                -> 3.00x')
SUPP.append('  9 - (250%)                -> 3.50x')
SUPP.append('  10 - (300%)               -> 4.00x')
SUPP.append('')
SUPP.append('  NOTE: Tiers 8-10 exist in cheat but may not be available in-game.')
SUPP.append('  The "cmp esi,7" NOP forces max tier rewards by bypassing the')
SUPP.append('  difficulty comparison that gates higher reward multipliers.')
SUPP.append('  "cmp esi,5" bypasses stratagem count limit check.')
SUPP.append('')

# ============================================================
# SUPPLEMENT 7: ARMOR PASSIVE ENUM
# ============================================================
SUPP.append('\n' + '#' * 80)
SUPP.append('#  SUPPLEMENT G: ARMOR PASSIVE ABILITY ENUM')
SUPP.append('#' * 80)
SUPP.append('')

armor_passives_found = set()
for offset, s in all_strings:
    s_stripped = s.strip()
    for p in ['Peak Physique', 'Servo-Assisted', 'Fortified', 'Engineering Kit',
              'Scout', 'Medic', 'Med-Kit', 'Democracy Protects', 'Extra Padding',
              'Unflinching', 'Siege-Ready', 'Siege Ready', 'Inflammable',
              'Advanced Filtration', 'Electrical Conduit', 'Acclimated',
              'Integrated Explosives', 'Fire Resistant', 'Gas Resistance',
              'Arc Resistant', 'Ballistic Padding', 'Explosive Finale',
              'Battle Hardened', 'Combat Medic', 'Reinforced Epaulettes',
              'Supplemental Stamina', 'Concussive Reinforced', 'Concussive Grenadier',
              'Concussive Hazmat', 'Siege Breaker', 'Desert Stormer',
              'Fire Support']:
        if p.lower() in s_stripped.lower() and len(s_stripped) < 60:
            if s_stripped not in armor_passives_found:
                armor_passives_found.add(s_stripped)

SUPP.append('--- Armor Passive Names Found ---')
for s in sorted(armor_passives_found):
    SUPP.append(f'  "{s}"')

SUPP.append('')
SUPP.append('  NOTE: These are likely the internal armor passive ability names,')
SUPP.append('  mapped to enum values in the game. The cheat scans current armor')
SUPP.append('  and lets the user select a different passive from the combo box.')
SUPP.append('')

# ============================================================
# SUPPLEMENT 8: KNOWN GAME.DLL OFFSETS (from signature patterns)
# ============================================================
SUPP.append('\n' + '#' * 80)
SUPP.append('#  SUPPLEMENT H: KNOWN GAME.DLL OFFSET REFERENCES')
SUPP.append('#' * 80)
SUPP.append('')

SUPP.append('--- Documented Pattern Offsets (from existing analysis) ---')
SUPP.append('  These patterns are searched for in game.dll at runtime:')
SUPP.append('')
SUPP.append('  [God Mode]')
SUPP.append('    - 3 hooks for player god mode')
SUPP.append('    - Patches damage receive, death flag, health check')
SUPP.append('')
SUPP.append('  [Grenade Count]')
SUPP.append('    - 0F 5B DB F3 41 0F 59 4E ?? F3')
SUPP.append('    - CVTSS2SD + MULSS (conversion + multiply)')
SUPP.append('    - NOPed to prevent grenade consumption')
SUPP.append('')
SUPP.append('  [No Boundary]')
SUPP.append('    - "Force unconditional jump (bypass boundary)"')
SUPP.append('    - Patches mission boundary kill trigger')
SUPP.append('')
SUPP.append('  [Landing Speed]')
SUPP.append('    - F3 0F 11 44 3B ?? F3 0F 59 C7 F3 0F 5A C0')
SUPP.append('    - MOVSS write + MULSS + CVTSS2SD')
SUPP.append('')
SUPP.append('  [Stratagem Unlock]')
SUPP.append('    - 48 8B 0D ?? ?? ?? ?? 44 89 80 60 0C')
SUPP.append('    - Global reference with write to offset +0xC60')
SUPP.append('    - "Unlock All Armory" patches this')
SUPP.append('')
SUPP.append('  [Turret Overheat]')
SUPP.append('    - F3 0F 11 4C A8 ?? 49')
SUPP.append('    - "NOP turret heat accumulation"')
SUPP.append('')
SUPP.append('  [Turret Duration]')
SUPP.append('    - F3 45 0F 11 5E ?? E9')
SUPP.append('    - "Inf Turret Duration" -> sets timer to infinite')
SUPP.append('')
SUPP.append('  [Active Session]')
SUPP.append('    - 48 8B 35 ?? ?? ?? ?? 49 8B E9 41 8B D8 48 8B 88 28 01')
SUPP.append('    - GetActiveSession() entry point')
SUPP.append('    - Session+0x28 -> activity container')
SUPP.append('    - Session+0x128 -> alternate reference')
SUPP.append('')
SUPP.append('  [Reward Multiplier]')
SUPP.append('    - 41 8B 47 ?? 4C 8B 7C 24 ?? 4C')
SUPP.append('    - XP/Medals/Slips multiplier hooks')
SUPP.append('')
SUPP.append('  [Stratagem Count]')
SUPP.append('    - 42 83 2C 81 ?? 48')
SUPP.append('    - SUB [rcx+r8*4+imm8], imm8 -> NOPed for infinite uses')
SUPP.append('')
SUPP.append('  [Kill Counter]')
SUPP.append('    - 39 46 ?? 75 ?? FF C5')
SUPP.append('    - Increment counter hook for stats display')
SUPP.append('')
SUPP.append('  [Stim Use]')
SUPP.append('    - NOP stim count decrement -> infinite stims')
SUPP.append('')
SUPP.append('  [Laser Overheat]')
SUPP.append('    - "NOP turret heat accumulation" (applies to laser weapons)')
SUPP.append('')
SUPP.append('  [Instant Charge]')
SUPP.append('    - "NOP railgun charge calculation"')
SUPP.append('    - 0x103250: "NOP railgun charge calculation"')
SUPP.append('')
SUPP.append('  [Grenade Fuse]')
SUPP.append('    - F3 0F 11 44 C8 ?? 0F')
SUPP.append('    - "NOP fuse timer write"')
SUPP.append('')
SUPP.append('  [SC Hash Table]')
SUPP.append('    - "NOP both hash table INSERT calls"')
SUPP.append('    - Prevents server from marking SC as collected')
SUPP.append('')
SUPP.append('  [Instant Strat Call-in]')
SUPP.append('    - Patches call-in time to zero')
SUPP.append('')
SUPP.append('  [Instant Shuttle]')
SUPP.append('    - "Instant Shuttle: ON ##shut5"')
SUPP.append('    - Skips shuttle timer')
SUPP.append('')
SUPP.append('  [No Recoil]')
SUPP.append('    - Patches recoil pattern')
SUPP.append('')
SUPP.append('  [Inf Ammo]')
SUPP.append('    - Patches ammo consumption')
SUPP.append('')
SUPP.append('  [Inf Stamina]')
SUPP.append('    - "NOP stamina read/drain" at 0x102B38')
SUPP.append('')
SUPP.append('  [Longer Hover]')
SUPP.append('    - "NOP hover time limit check"')
SUPP.append('')
SUPP.append('  [Shield Cooldown]')
SUPP.append('    - "NOP shield relay cooldown write"')
SUPP.append('')
SUPP.append('  [Instant Hellbomb]')
SUPP.append('    - "NOP hellbomb arm timer write"')
SUPP.append('')

# ============================================================
# SUPPLEMENT 9: API ENDPOINTS AND NETWORK
# ============================================================
SUPP.append('\n' + '#' * 80)
SUPP.append('#  SUPPLEMENT I: API ENDPOINTS & NETWORK PROTOCOL')
SUPP.append('#' * 80)
SUPP.append('')

SUPP.append('--- Discovered API Endpoint ---')
SUPP.append('  https://api.live.prod.thehelldiversgame.com/api/Operation/Mission/end')
SUPP.append('')
SUPP.append('--- HTTP Headers Used ---')
SUPP.append('  X-Signature:     (cryptographic signature for auth)')
SUPP.append('  X-Session:       (session identifier)')
SUPP.append('  Authorization:   (standard auth header)')
SUPP.append('  Cookie:          (session cookies)')
SUPP.append('  Content-Type:    (likely application/json)')
SUPP.append('')
SUPP.append('--- Signature Capture Protocol ---')
SUPP.append('  The cheat intercepts HTTP traffic (MITM) to capture:')
SUPP.append('    1. "f2s7" - First signature chunk')
SUPP.append('    2. "f2s7+nonce" - Signature + cryptographic nonce')
SUPP.append('    3. "f2s7+partial" - Partial signature data')
SUPP.append('  These are used to reconstruct the X-Signature header for replay.')
SUPP.append('')
SUPP.append('--- JSON Payload Fields (Mission/end POST) ---')
SUPP.append('  "capturedWarTime" - Current war time value (uint)')
SUPP.append('  "missionId"       - UUID mission identifier')
SUPP.append('  "serObj"          - Server object data')
SUPP.append('  "serObjOrigAddr"  - Original server object address (uint64)')
SUPP.append('  "slotData"        - Player slot data')
SUPP.append('  "entityDeep"      - Entity hierarchy (JSON)')
SUPP.append('  "entityDataDeep"  - Entity data payload (JSON)')
SUPP.append('  "ac"              - Activity count (int)')
SUPP.append('  "oi"              - Object ID (uint)')
SUPP.append('  "gs"              - Game state (string)')
SUPP.append('')

# ============================================================
# SUPPLEMENT 10: SC FARMING PROTOCOL DETAILS
# ============================================================
SUPP.append('\n' + '#' * 80)
SUPP.append('#  SUPPLEMENT J: SC/MEDAL FARMING - INTERNAL PROTOCOL')
SUPP.append('#' * 80)
SUPP.append('')

SUPP.append('--- ScActivityAPC Structure (from code analysis) ---')
SUPP.append('  struct ScActivityAPC {')
SUPP.append('      // +0x00: vtable pointer')
SUPP.append('      // +0x08: actId32   (activity identifier)')
SUPP.append('      // +0x0C: objId     (object identifier)')
SUPP.append('      // +0x10: ctr       (control/state counter)')
SUPP.append('      // +0x14: flag      (flags)')
SUPP.append('      // +0x18: ring      (ring buffer index)')
SUPP.append('      // +0x20: url[0x40] (API endpoint URL)')
SUPP.append('      // +0x60: qDelta    (queue delta)')
SUPP.append('      // +0x64: retry     (retry counter)')
SUPP.append('      // +0x68: missionData (pointer)')
SUPP.append('      // +0x70: missionId[0x40] (UUID string)')
SUPP.append('  };')
SUPP.append('')
SUPP.append('--- SC Loop Algorithm ---')
SUPP.append('  1. Wait for game session (GetActiveSession() != NULL)')
SUPP.append('  2. Capture Mission/end POST body via HTTP hook')
SUPP.append('  3. Store: missionId, warTime, entityDeep, entityDataDeep, slotData')
SUPP.append('  4. On loop trigger:')
SUPP.append('     a. Read ring buffer state (ctr, flag, ring)')
SUPP.append('     b. Modify missionId to new UUID')
SUPP.append('     c. POST captured body with new missionId')
SUPP.append('     d. 9 calls per batch, 500ms apart')
SUPP.append('     e. 58 second cooldown between batches')
SUPP.append('  5. If crash: VEH recovers state, increments crash counter')
SUPP.append('  6. If no capture: waits for next mission')
SUPP.append('')
SUPP.append('--- Medal Farming ---')
SUPP.append('  - Alternates between SC and Medal batches')
SUPP.append('  - "Medals Only" mode skips SC, only sends medals')
SUPP.append('  - Same batch pattern: 9 calls x 500ms')
SUPP.append('')
SUPP.append('--- Anti-Duplicate Bypass ---')
SUPP.append('  - "NOP both hash table INSERT calls"')
SUPP.append('  - Prevents game.dll from marking SC entities as already collected')
SUPP.append('  - Allows repeated claims from the same mission data')
SUPP.append('')
SUPP.append('--- SC Goal / Tracker ---')
SUPP.append('  - User sets SC goal count')
SUPP.append('  - Auto-stops when goal reached')
SUPP.append('  - Tracks: calls sent, SC earned, x100 bonuses, crashes')
SUPP.append('  - Auto Sync: distributes SC across all lobby players')
SUPP.append('')
SUPP.append('--- Burst Replay System ---')
SUPP.append('  - Queues N replays instantly (with 5s stagger)')
SUPP.append('  - Server may rate-limit bursts')
SUPP.append('  - Burst Loop: auto-fires every N minutes')
SUPP.append('  - Max replays configurable')
SUPP.append('')

# ============================================================
# SUPPLEMENT 11: WEAPON XP FARMING
# ============================================================
SUPP.append('\n' + '#' * 80)
SUPP.append('#  SUPPLEMENT K: WEAPON XP FARMING SYSTEM')
SUPP.append('#' * 80)
SUPP.append('')

SUPP.append('--- Weapon XP System ---')
SUPP.append('  51 total weapons tracked')
SUPP.append('  IDs: 0-50 or 1-51 (index into weapon array)')
SUPP.append('')
SUPP.append('  Modes:')
SUPP.append('    - All Guns: cycles through all 51 weapons')
SUPP.append('    - Selected Guns: user picks specific weapons')
SUPP.append('    - Primary Override: sets one weapon for all lobby members')
SUPP.append('')
SUPP.append('  "Replays/gun" counter: configurable number of replays per weapon')
SUPP.append('  "Patching %d weapon slot(s) -> ID %u (%s)"')
SUPP.append('')

# ============================================================
# SUPPLEMENT 12: CRASH RECOVERY (VEH)
# ============================================================
SUPP.append('\n' + '#' * 80)
SUPP.append('#  SUPPLEMENT L: VEH CRASH RECOVERY SYSTEM')
SUPP.append('#' * 80)
SUPP.append('')

SUPP.append('--- Vectored Exception Handler ---')
SUPP.append('  Registered via AddVectoredExceptionHandler(1, handler)')
SUPP.append('  Handles: ACCESS_VIOLATION (0xC0000005)')
SUPP.append('           STACK_OVERFLOW (0xC00000FD)')
SUPP.append('           ILLEGAL_INSTRUCTION (0xC000001D)')
SUPP.append('           (and others)')
SUPP.append('')
SUPP.append('  On crash:')
SUPP.append('    1. Save SC loop state (ring index, batch progress)')
SUPP.append('    2. Save replay data')
SUPP.append('    3. Increment crash counter')
SUPP.append('    4. Write crash log: "=== LIBERTEA CRASH LOG ==="')
SUPP.append('    5. Restore state on next loop iteration')
SUPP.append('')
SUPP.append('  Replay watchdog: resets stuck replayInProgress flag')
SUPP.append('')

# ============================================================
# SUPPLEMENT 13: BINARY REGION DETAIL
# ============================================================
SUPP.append('\n' + '#' * 80)
SUPP.append('#  SUPPLEMENT M: DATA REGION STRING MAP')
SUPP.append('#' * 80)
SUPP.append('')

SUPP.append('--- Game Data String Regions ---')
SUPP.append('  0x0FD000-0x0FE400: Weapon and armor name strings')
SUPP.append('  0x0FE400-0x0FF000: SC/Replay/Probe UI strings')
SUPP.append('  0x0FF000-0x100000: Weapon selection, farming UI strings')
SUPP.append('  0x100000-0x101000: Feature descriptions, tooltips')
SUPP.append('  0x101000-0x102000: HTTP/replay/capture strings')
SUPP.append('  0x102000-0x103000: Network/signature/crypto strings')
SUPP.append('  0x103000-0x104000: NOP descriptions, feature details')
SUPP.append('  0x104000-0x105000: Stratagem/enemy/weapon list strings')
SUPP.append('  0x105000-0x106000: ImGui key names, error strings')
SUPP.append('')

# Write the supplemental file
SUPP_PATH = r'C:\Users\emora\OneDrive\Desktop\2\resweep_supplement.txt'
with open(SUPP_PATH, 'w', encoding='utf-8') as f:
    f.write('\n'.join(SUPP))

print(f'Supplement written to {SUPP_PATH} ({len(SUPP)} lines)')

# Now merge supplement into the main file
with open(OUT_PATH, 'a', encoding='utf-8') as f:
    f.write('\n')
    f.write('\n'.join(SUPP))

print(f'Merged into {OUT_PATH}')
print('Done!')
