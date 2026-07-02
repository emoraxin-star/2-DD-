"""
OBFUSCATED STRING INFERENCE AGENT
Decodes the 0x0F8000-0x10A000 high-entropy region in .text_unpacked_mem.bin
"""
import struct
import math
from collections import Counter
from pathlib import Path

BIN_PATH = Path(r"C:\Users\emora\OneDrive\Desktop\2\data\.text_unpacked_mem.bin")
OUT_PATH = Path(r"C:\Users\emora\OneDrive\Desktop\2\logs\infer_obfuscated_strings.txt")

# Region boundaries (byte offsets into file)
REGION_START = 0x0F8000
REGION_END   = 0x10A000
REGION_SIZE  = REGION_END - REGION_START  # 122,880 bytes

def read_region():
    with open(BIN_PATH, 'rb') as f:
        f.seek(REGION_START)
        return f.read(REGION_SIZE)

def entropy(data):
    """Calculate Shannon entropy for a byte sequence."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c/total) * math.log2(c/total) for c in counts.values())

def is_printable_ascii(b):
    return 32 <= b < 127 or b in (9, 10, 13)

def printable_ratio(data):
    """Ratio of printable ASCII bytes."""
    if not data:
        return 0.0
    return sum(1 for b in data if is_printable_ascii(b)) / len(data)

def extract_strings_from_data(data, min_len=3):
    """Extract null-terminated strings from binary data."""
    strings = []
    current = bytearray()
    in_string = False
    for offset, b in enumerate(data):
        if is_printable_ascii(b):
            current.append(b)
            in_string = True
        else:
            if in_string:
                if len(current) >= min_len:
                    strings.append((offset - len(current), bytes(current).decode('ascii', errors='replace')))
                current = bytearray()
                in_string = False
    if in_string and len(current) >= min_len:
        strings.append((len(data) - len(current), bytes(current).decode('ascii', errors='replace')))
    return strings

def xor_decrypt(data, key_bytes):
    """XOR data with repeating key bytes."""
    key_len = len(key_bytes)
    return bytes(data[i] ^ key_bytes[i % key_len] for i in range(len(data)))

def try_single_byte_xor(data, key):
    """Try a single-byte XOR key and return readable ratio."""
    decrypted = bytes(b ^ key for b in data)
    ratio = printable_ratio(decrypted)
    strings = extract_strings_from_data(decrypted, min_len=4)
    return ratio, strings, decrypted

def try_multi_byte_xor(data, key_bytes):
    """Try multi-byte XOR and return results."""
    decrypted = xor_decrypt(data, key_bytes)
    ratio = printable_ratio(decrypted)
    strings = extract_strings_from_data(decrypted, min_len=4)
    return ratio, strings, decrypted

def find_string_boundaries(data):
    """Find null byte positions to identify string boundaries."""
    null_positions = [i for i, b in enumerate(data) if b == 0]
    return null_positions

def try_embedded_key_decode(data):
    """
    Try the format: [4-byte XOR key][encrypted string][null]
    The key is embedded as a DWORD before each string.
    """
    results = []
    i = 0
    while i < len(data) - 4:
        # Read potential 4-byte key
        key_bytes = data[i:i+4]
        # Skip if all zeros
        if all(b == 0 for b in key_bytes):
            i += 1
            continue
        
        # Find the null terminator after the key
        str_start = i + 4
        str_end = data.find(0, str_start)
        if str_end == -1 or str_end <= str_start:
            i += 1
            continue
        
        enc_str = data[str_start:str_end]
        if len(enc_str) < 3:
            i = str_end + 1
            continue
        
        # Try decoding with this key
        decrypted = xor_decrypt(enc_str, key_bytes)
        ratio = printable_ratio(decrypted)
        if ratio >= 0.7 and len(decrypted) >= 3:
            try:
                text = decrypted.decode('ascii')
                results.append((i, len(key_bytes) + len(enc_str) + 1, key_bytes.hex(), text))
            except:
                pass
        
        i = str_end + 1
    
    return results

# Known XOR keys from Agent F analysis
AGENTF_XOR_KEYS_4BYTE = [
    0xB8014A8D, 0x203F3F20, 0x0000026A, 0x7FFCCDEE, 0x2642544B,
    0x00000000, 0x652D3635, 0x65652D36, 0x78826458, 0x1C3D0D69,
    0xFD8F15ED, 0x003D0D69, 0x39383736, 0x05110F00, 0xFFFFFF00,
    0x0D8D4800, 0xFFFFFE00, 0xC0334500, 0x83448B41, 0x8B480000,
    0xC9854800, 0x34322043, 0x00210011, 0x48000001, 0x0FC08400,
    0x736D3030, 0x00292530, 0x0000371B, 0x38342037, 0x4000080F,
    0x48900000, 0x8D480000, 0xC085000B, 0x83480000, 0xC0854800,
    0x44894800, 0x840F0000, 0x05394800, 0x480C7500, 0x4CC2FF48,
    0xE8000DA2, 0x89014A8D, 0xC0850000, 0x740000C4, 0x7400001F,
]

COMMON_MULTIBYTE_KEYS = [
    (0xDEADBEEF, "0xDEADBEEF"),
    (0xCAFEBABE, "0xCAFEBABE"),
    (0xFEEDFACE, "0xFEEDFACE"),
    (0xDEADBEEF, "0xDEADBEEF"),
    (0x00BAB10C, "0x00BAB10C (file checksum pattern)"),
    (0x056A5301, "0x056A5301 (binary checksum)"),
]

# Subscription GUID bytes
SUB_GUID = bytes.fromhex('60862556EE164AE4B00264F6ACBC66C6')

# Base64 alphabet
B64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

# Expected strings by feature category
EXPECTED_STRINGS = {
    "SC_FARMING": [
        "SUPER CREDITS", "SC REFRESH", "SC Loop: ON", "SC Loop: OFF",
        "SC Tracker", "Remove SC Limit", "SC Loop:", "SC Calls:",
        "Include Medals", "Medals Only", "Super Credits", "Farming",
        "SC goal reached", "SC Batch Firing", "SC AutoSync",
        "Reward Multiplier: ON", "Reward Multiplier: OFF",
        "XP Multiplier", "Medals Multiplier", "Req Slips Mult",
        "Force Difficulty: ON", "Force Difficulty: OFF",
        "Add Samples: ON", "Add Samples: OFF",
        "Common", "Rare", "Super",
        "Samples Reward: ON", "Samples Reward: OFF",
        "Common Reward", "Rare Reward", "Super Reward",
        "Instant Shuttle: ON", "Instant Shuttle: OFF",
        "Instant Complete: ON", "Instant Complete: OFF",
        "Stop after", "Burst Loop: ON", "Burst Loop: OFF",
        "Set", "Reset", "Clear", "Max",
    ],
    "WEAPON_XP": [
        "Primary Weapon Override", "Weapon XP", "All Guns ON", "All Guns OFF",
        "Selected Guns ON", "Selected Guns OFF", "Next Weapon",
        "-- Select Primary Weapon --", "Search weapons...",
        "Selected Guns List", "Damage", "Struct. Penetration",
        "Pen. (No Angle)", "Pen. (Angle)", "Demolition", "FireRate (Trident)",
    ],
    "PLAYER_CHEATS": [
        "God Mode (Player Only)", "Movement Speed", "Speed",
        "Inf Stamina", "AFK Prevention: ON", "AFK Prevention: OFF",
        "No Recoil", "Inf Health", "Inf Ammo",
    ],
    "COMBAT_CHEATS": [
        "Infinite Stratagems", "Instant Strat Callin", "Mass Strat Drop",
        "No Turret Overheat", "Inf Turret Duration", "Expire All Turrets",
        "Infinite Horde Mode", "Dark Fluid Pack", "Drop Count",
        "Eagle Strikes", "Backpacks", "Orbitals", "Backpack", "Shield Backpack",
    ],
    "AMMO_CHEATS": [
        "No Reload", "Inf Grenades", "Inf Stims",
    ],
    "ARMORY": [
        "Unlock All Armory", "Armor Base", "Scan Armor", "Armor",
        "Passive", "Apply", "Reset",
    ],
    "VISUAL_CHEATS": [
        "Online", "Offline",
    ],
    "MISC": [
        "Made by TheOGcup", "TOOL v414", "Made for LIBERTEA Discord",
        "LIBERTEA HUD", "LIBERTEAOverlay", "Login with your account",
        "Password", "Subscription Active",
    ],
    "WEAPON_NAMES": [
        # HD2 primary weapons - 51 total
        "AR-23 Liberator", "AR-23P Liberator Penetrator", "AR-23C Liberator Concussive",
        "AR-23A Liberator Carbine", "R-63 Diligence", "R-63CS Diligence Counter Sniper",
        "MP-98 Knight", "STA-11 SMG", "STA-52 Assault Rifle", "BR-14 Adjudicator",
        "AR-61 Tenderizer", "R-36 Eruptor", "CB-9 Exploding Crossbow",
        "PLAS-1 Scorcher", "PLAS-101 Purifier", "SG-8 Punisher", "SG-8S Slugger",
        "SG-8P Punisher Plasma", "SG-225 Breaker", "SG-225SP Breaker Spray&Pray",
        "SG-225IE Breaker Incendiary", "SG-20 Halt", "JAR-5 Dominator",
        "LAS-5 Scythe", "LAS-7 Dagger", "LAS-16 Sickle", "LAS-17 Double-Edge Sickle",
        "ARC-12 Blitzer", "SMG-32 Reprimand", "SMG-72 Pummeler",
        "PLAS-39 Accelerator Rifle", "LAS-98 Laser Cannon",
        "AC-8 Autocannon", "FAF-14 Spear", "MLS-4X Commando",
        "GR-8 Recoilless Rifle", "EAT-17 Expendable Anti-Tank",
        "APW-1 Anti-Materiel Rifle", "FLAM-40 Flamethrower",
        "ARC-3 Arc Thrower", "RS-422 Railgun",
        "StA-X3 W.A.S.P. Launcher", "MG-43 Machine Gun",
        "MG-105 Stalwart", "MG-206 Heavy Machine Gun",
        "GL-21 Grenade Launcher", "RL-77 Airburst Rocket Launcher",
        "R-2124 Constitution", "GP-31 Grenade Pistol", "P-2 Peacemaker",
        "P-4 Senator", "P-19 Redeemer", "P-72 Crisper",
        "P-113 Verdict", "CQC-19 Stun Lance", "CQC-30 Stun Baton",
    ],
    "DIFFICULTY": [
        "1 - Trivial", "2 - Easy", "3 - Medium", "4 - Challenging",
        "5 - Hard", "6 - Extreme", "7 - Super Helldive",
    ],
}

# All known clear-text strings already found (for cross-reference)
KNOWN_CLEAR_STRINGS = {
    0x0BCB40, 0x0BCF08, 0x0C5C78, 0x0C5CA8, 0x0C5CC0, 0x0C5CD0,
    0x0C5D85, 0x0C5F38, 0x0C619F, 0x0C61AB, 0x0C61CA, 0x0FE3C8,
    # ... many more (populated from agentD)
}

def main():
    data = read_region()
    print(f"Region: {REGION_START:#08X} - {REGION_END:#08X} ({REGION_SIZE:,} bytes)")
    print(f"Read {len(data):,} bytes")
    
    lines = []
    def out(s):
        lines.append(s)
        print(s)
    
    out("=" * 80)
    out("OBFUSCATED STRING INFERENCE AGENT - COMPLETE ANALYSIS")
    out(f"Target: {BIN_PATH}")
    out(f"Region: {REGION_START:#08X} - {REGION_END:#08X} ({REGION_SIZE:,} bytes)")
    out("=" * 80)
    
    # ===== SECTION 1: ENTROPY ANALYSIS =====
    out("\n" + "=" * 60)
    out("SECTION 1: ENTROPY ANALYSIS PER 256-BYTE BLOCK")
    out("=" * 60)
    
    block_size = 256
    num_blocks = len(data) // block_size
    entropies = []
    for i in range(num_blocks):
        block = data[i*block_size:(i+1)*block_size]
        e = entropy(block)
        entropies.append(e)
        offset = REGION_START + i * block_size
        bar = "#" * int(e) + "." * (8 - int(e))
        if i % 16 == 0 or e < 5.0 or e > 7.8:
            out(f"  Block {i:3d} @ {offset:#08X}: entropy={e:.4f} [{bar}]  printable={printable_ratio(block):.3f}")
    
    avg_entropy = sum(entropies) / len(entropies)
    min_entropy = min(entropies)
    max_entropy = max(entropies)
    variance = sum((e - avg_entropy)**2 for e in entropies) / len(entropies)
    
    out(f"\n  ENTROPY SUMMARY:")
    out(f"    Average: {avg_entropy:.4f} bits/byte")
    out(f"    Min:     {min_entropy:.4f}")
    out(f"    Max:     {max_entropy:.4f}")
    out(f"    Variance:{variance:.6f}")
    out(f"    Uniform? {'YES - consistent encryption' if variance < 0.5 else 'NO - mixed data types'}")
    
    # ===== SECTION 2: STRING BOUNDARY ANALYSIS =====
    out("\n" + "=" * 60)
    out("SECTION 2: STRING BOUNDARY ANALYSIS")
    out("=" * 60)
    
    null_positions = find_string_boundaries(data)
    out(f"  Total null bytes found: {len(null_positions)}")
    out(f"  Average gap between nulls: {null_positions[-1]/(len(null_positions) or 1):.1f} bytes")
    
    # Find gaps (string lengths between nulls)
    gaps = []
    prev = 0
    for pos in null_positions:
        gap = pos - prev
        if gap > 0:
            gaps.append(gap)
        prev = pos + 1
    
    if gaps:
        avg_gap = sum(gaps) / len(gaps)
        out(f"  Average string length (gap between nulls): {avg_gap:.1f}")
        out(f"  Min gap: {min(gaps)}, Max gap: {max(gaps)}")
        
        # Gap distribution
        gap_buckets = Counter()
        for g in gaps:
            if g < 10: gap_buckets['0-9'] += 1
            elif g < 20: gap_buckets['10-19'] += 1
            elif g < 30: gap_buckets['20-29'] += 1
            elif g < 50: gap_buckets['30-49'] += 1
            elif g < 100: gap_buckets['50-99'] += 1
            else: gap_buckets['100+'] += 1
        out(f"  Gap distribution: {dict(gap_buckets)}")
    
    # ===== SECTION 3: SINGLE-BYTE XOR KEY TRIAL =====
    out("\n" + "=" * 60)
    out("SECTION 3: SINGLE-BYTE XOR KEY TRIAL (0x00-0xFF)")
    out("=" * 60)
    
    out(f"  Testing all 256 single-byte XOR keys on the ENTIRE region...")
    best_single = []
    for key in range(256):
        dec = bytes(b ^ key for b in data)
        ratio = printable_ratio(dec)
        if ratio > 0.3:  # threshold for interesting results
            strs = extract_strings_from_data(dec, min_len=4)
            best_single.append((key, ratio, len(strs), strs[:10]))  # first 10 strings
    
    best_single.sort(key=lambda x: -x[1])
    for key, ratio, nstrs, sample_strs in best_single[:20]:
        out(f"  Key 0x{key:02X} '{chr(key) if 32<=key<127 else '?'}': ratio={ratio:.4f}, strings={nstrs}")
        for s in sample_strs[:5]:
            out(f"    -> \"{s[1]}\"")
    
    # ===== SECTION 4: MULTI-BYTE XOR KEY TRIAL (Agent F keys) =====
    out("\n" + "=" * 60)
    out("SECTION 4: MULTI-BYTE XOR KEY TRIAL (Agent F discovered keys)")
    out("=" * 60)
    
    for key_val in AGENTF_XOR_KEYS_4BYTE:
        key_bytes = struct.pack('<I', key_val)  # Little endian
        ratio, strings, dec = try_multi_byte_xor(data, key_bytes)
        if ratio > 0.4 or len(strings) > 10:
            out(f"  Key 0x{key_val:08X} ({key_bytes.hex()}): ratio={ratio:.4f}, {len(strings)} strings")
            for s in strings[:5]:
                out(f"    @{s[0]:#06x}: \"{s[1]}\"")
    
    # ===== SECTION 5: COMMON MULTI-BYTE KEYS =====
    out("\n" + "=" * 60)
    out("SECTION 5: COMMON MULTI-BYTE XOR KEYS (0xDEADBEEF, etc.)")
    out("=" * 60)
    
    common_keys = [
        (0xDEADBEEF, "0xDEADBEEF"),
        (0xCAFEBABE, "0xCAFEBABE"),
        (0xFEEDFACE, "0xFEEDFACE"),
        (0x0BADF00D, "0x0BADF00D"),
        (0x0BADC0DE, "0x0BADC0DE"),
        (0x600DFACE, "0x600DFACE"),
        (0x1337BEEF, "0x1337BEEF"),
        (0x1337C0DE, "0x1337C0DE"),
        (0xC0CA1337, "0xC0CA1337"),
    ]
    
    for key_val, name in common_keys:
        key_bytes = struct.pack('<I', key_val)
        ratio, strings, dec = try_multi_byte_xor(data, key_bytes)
        if ratio > 0.4 or len(strings) > 10:
            out(f"  {name}: ratio={ratio:.4f}, {len(strings)} strings")
            for s in strings[:5]:
                out(f"    @{s[0]:#06x}: \"{s[1]}\"")
    
    # Subscription GUID as XOR key
    out(f"\n  Subscription GUID as key:")
    ratio, strings, dec = try_multi_byte_xor(data, SUB_GUID)
    out(f"    ratio={ratio:.4f}, {len(strings)} strings")
    for s in strings[:5]:
        out(f"    @{s[0]:#06x}: \"{s[1]}\"")
    
    # Base64 alphabet fragments as keys
    out(f"\n  Base64 alphabet as key:")
    ratio, strings, dec = try_multi_byte_xor(data, B64_ALPHABET[:4])
    out(f"    B64[:4]: ratio={ratio:.4f}")
    ratio, strings, dec = try_multi_byte_xor(data, B64_ALPHABET[26:30])
    out(f"    B64[26:30]: ratio={ratio:.4f}")
    ratio, strings, dec = try_multi_byte_xor(data, B64_ALPHABET[52:56])
    out(f"    B64[52:56]: ratio={ratio:.4f}")
    
    # ===== SECTION 6: EMBEDDED KEY PATTERN DECODE =====
    out("\n" + "=" * 60)
    out("SECTION 6: EMBEDDED KEY PATTERN DECODE")
    out("=" * 60)
    out(f"  Format: [4-byte XOR key][encrypted string][null] ...")
    
    embedded_results = try_embedded_key_decode(data)
    out(f"  Found {len(embedded_results)} potential key+string pairs")
    for offset, total_len, key_hex, text in embedded_results[:50]:
        abs_offset = REGION_START + offset
        out(f"  @{abs_offset:#08X} key={key_hex} len={total_len}: \"{text}\"")
    
    # Also try with the key as the FIRST 4 bytes of each string (alternative format)
    out(f"\n  Alternative: key IS first 4 bytes of each string:")
    out(f"  Format: [4-byte XOR key][encrypted remainder][null]")
    
    alt_results = []
    i = 0
    while i < len(data) - 5:
        # Check if at a potential string boundary (non-null start)
        if data[i] == 0 or data[i] < 32:
            i += 1
            continue
        
        key_bytes = data[i:i+4]
        str_start = i + 4
        str_end = data.find(0, str_start)
        if str_end == -1:
            break
        
        remainder = data[str_start:str_end]
        if len(remainder) < 2:
            i = str_end + 1
            continue
        
        decrypted = xor_decrypt(remainder, key_bytes)
        if printable_ratio(decrypted) >= 0.7 and len(decrypted) >= 3:
            try:
                text = decrypted.decode('ascii')
                alt_results.append((i, key_bytes, text, len(remainder)+4))
            except:
                pass
        i = str_end + 1
    
    out(f"  Found {len(alt_results)} potential strings")
    for offset, key, text, tot_len in alt_results[:50]:
        abs_offset = REGION_START + offset
        out(f"  @{abs_offset:#08X} key={key.hex()} tot={tot_len}: \"{text}\"")
    
    # ===== SECTION 7: ROT CIPHER TRIAL =====
    out("\n" + "=" * 60)
    out("SECTION 7: ROT/XOR CHAIN TRIAL")
    out("=" * 60)
    
    # ROT13 on the region
    rot13 = bytes(((b - 65 + 13) % 26 + 65) if 65 <= b <= 90 else
                  ((b - 97 + 13) % 26 + 97) if 97 <= b <= 122 else b
                  for b in data)
    out(f"  ROT13: printable_ratio={printable_ratio(rot13):.4f}")
    strs = extract_strings_from_data(rot13, 4)
    for s in strs[:10]:
        out(f"    -> \"{s[1]}\"")
    
    # Try XOR 0x55 (common in malware)
    dec = bytes(b ^ 0x55 for b in data)
    out(f"  XOR 0x55: printable_ratio={printable_ratio(dec):.4f}")
    strs = extract_strings_from_data(dec, 4)
    for s in strs[:10]:
        out(f"    -> \"{s[1]}\"")
    
    # ROT13 -> XOR 0x55
    dec = bytes(b ^ 0x55 for b in rot13)
    out(f"  ROT13 -> XOR 0x55: printable_ratio={printable_ratio(dec):.4f}")
    strs = extract_strings_from_data(dec, 4)
    for s in strs[:10]:
        out(f"    -> \"{s[1]}\"")
    
    # XOR 0xAA (inverse of 0x55)
    dec = bytes(b ^ 0xAA for b in data)
    out(f"  XOR 0xAA: printable_ratio={printable_ratio(dec):.4f}")
    
    # ===== SECTION 8: STRUCTURAL ANALYSIS =====
    out("\n" + "=" * 60)
    out("SECTION 8: STRUCTURAL ANALYSIS - PATTERN SEARCH")
    out("=" * 60)
    
    # Look for repeated 4-byte sequences (potential keys)
    from collections import Counter as Ctr
    fourbyte_counts = Ctr()
    for i in range(0, len(data) - 4, 4):
        fourbyte_counts[data[i:i+4]] += 1
    
    most_common_4byte = fourbyte_counts.most_common(30)
    out(f"  Most common 4-byte sequences:")
    for seq, count in most_common_4byte:
        try:
            ascii_repr = ''.join(chr(b) if 32<=b<127 else '.' for b in seq)
        except:
            ascii_repr = '????'
        out(f"    {seq.hex()} '{ascii_repr}': {count}x")
    
    # Look for DWORD-aligned patterns suggesting string table structure
    out(f"\n  DWORD value analysis (every 4 bytes interpreted as LE u32):")
    dwords = []
    for i in range(0, len(data) - 4, 4):
        dwords.append(struct.unpack('<I', data[i:i+4])[0])
    
    # Check for values that look like lengths
    potential_lengths = [d for d in dwords if 3 <= d <= 150]
    out(f"    Values in range [3, 150] (potential string lengths): {len(potential_lengths)}")
    
    # Check for values that look like offsets
    potential_offsets = [d for d in dwords if REGION_START <= d <= REGION_END]
    out(f"    Values in region range (potential pointers): {len(potential_offsets)}")
    
    # ===== SECTION 9: CODE CROSS-REFERENCE ANALYSIS =====
    out("\n" + "=" * 60)
    out("SECTION 9: CROSS-REFERENCE ANALYSIS")
    out("=" * 60)
    out("  Searching code region 0x0B8000-0x0F8000 for references to 0x0F8000-0x10A000")
    
    # Read the code region
    with open(BIN_PATH, 'rb') as f:
        f.seek(0x0B8000)
        code_data = f.read(0x0F8000 - 0x0B8000)  # 256KB of code
    
    # Search for LEA instructions that reference addresses in our region
    # LEA reg, [RIP+disp32] pattern: 48 8D 0D xx xx xx xx (or variants)
    lea_patterns = [
        bytes.fromhex('488d0d'),  # lea rcx, [rip+...]
        bytes.fromhex('488d15'),  # lea rdx, [rip+...]
        bytes.fromhex('4c8d05'),  # lea r8, [rip+...]
        bytes.fromhex('4c8d0d'),  # lea r9, [rip+...]
    ]
    
    refs_found = []
    for pat in lea_patterns:
        pos = 0
        while True:
            pos = code_data.find(pat, pos)
            if pos == -1:
                break
            if pos + 7 <= len(code_data):
                disp = struct.unpack('<i', code_data[pos+3:pos+7])[0]
                # RIP-relative: target = position_of_lea + 7 + disp
                target = 0x0B8000 + pos + 7 + disp
                if REGION_START <= target <= REGION_END:
                    refs_found.append((0x0B8000 + pos, target))
            pos += 1
    
    out(f"  Found {len(refs_found)} LEA references to the obfuscated region")
    for code_addr, target_addr in refs_found[:50]:
        out(f"    Code @{code_addr:#08X} -> data @{target_addr:#08X} (offset {target_addr - REGION_START:#06X})")
    
    # ===== SECTION 10: STRING INFERENCE BY POSITION =====
    out("\n" + "=" * 60)
    out("SECTION 10: STRING INFERENCE BY POSITION AND LENGTH")
    out("=" * 60)
    
    # Map the obfuscated string positions/lengths
    out("  Mapping all null-terminated byte sequences:")
    i = 0
    obf_strings = []
    while i < len(data):
        if data[i] == 0:
            i += 1
            continue
        end = data.find(0, i)
        if end == -1:
            remaining = data[i:]
            obf_strings.append((i, len(remaining), remaining))
            break
        seq = data[i:end]
        if len(seq) >= 3:
            obf_strings.append((i, len(seq), seq))
        i = end + 1
    
    out(f"  Total strings >= 3 bytes: {len(obf_strings)}")
    
    # Length distribution
    len_counts = Counter()
    for offset, length, seq in obf_strings:
        if length < 5: len_counts['  3-4'] += 1
        elif length < 10: len_counts['  5-9'] += 1
        elif length < 15: len_counts['10-14'] += 1
        elif length < 20: len_counts['15-19'] += 1
        elif length < 30: len_counts['20-29'] += 1
        elif length < 50: len_counts['30-49'] += 1
        else: len_counts['  50+'] += 1
    out(f"  Length distribution:")
    for k in sorted(len_counts):
        out(f"    {k}: {len_counts[k]}")
    
    # ===== SECTION 11: SPECIALIZED PATTERN SEARCH =====
    out("\n" + "=" * 60)
    out("SECTION 11: SPECIALIZED PATTERN SEARCH (known cheat patterns)")
    out("=" * 60)
    
    # Check for common substring patterns in encrypted data
    # Look for lengths that match known cheat strings
    expected_lens = Counter()
    for category, strings in EXPECTED_STRINGS.items():
        for s in strings:
            expected_lens[len(s)] += 1
    
    out("  Expected string lengths from known features:")
    for length in sorted(expected_lens)[:20]:
        out(f"    len={length}: {expected_lens[length]} strings")
    
    # Match obfuscated strings to expected strings by length
    out("\n  Matching obfuscated strings to expected strings by length:")
    matches = {}
    for offset, length, seq in obf_strings:
        matching = []
        for category, strings in EXPECTED_STRINGS.items():
            for s in strings:
                if len(s) == length:
                    matching.append((category, s))
        if matching:
            matches[(offset, length)] = matching
    
    out(f"  {len(matches)} obfuscated strings match expected string lengths")
    for (offset, length), expected in sorted(matches.items())[:100]:
        abs_offset = REGION_START + offset
        exp_str = ' | '.join(f"[{cat}] {s}" for cat, s in expected[:3])
        out(f"    @{abs_offset:#08X} len={length}: matches -> {exp_str}")
    
    # ===== SECTION 12: WINDOWED XOR DECODE =====
    out("\n" + "=" * 60)
    out("SECTION 12: WINDOWED XOR DECODE (per-null-terminal segment)")
    out("=" * 60)
    out("  Trying all 256 single-byte keys on each individual string segment...")
    
    decodeable_strings = []
    for offset, length, enc_bytes in obf_strings:
        for key in range(256):
            dec = bytes(b ^ key for b in enc_bytes)
            ratio = printable_ratio(dec)
            if ratio >= 0.85 and length >= 4:
                try:
                    text = dec.decode('ascii')
                    abs_offset = REGION_START + offset
                    decodeable_strings.append((abs_offset, key, text, ratio))
                except:
                    pass
                break  # Found a good key, move on
    
    out(f"  Strings with >=85% printable after single-byte XOR: {len(decodeable_strings)}")
    for abs_offset, key, text, ratio in decodeable_strings[:100]:
        out(f"    @{abs_offset:#08X} XOR 0x{key:02X}: \"{text}\" (ratio={ratio:.3f})")
        # Mark as decoded
    
    # Also try 4-byte keys on each individual string
    out("\n  Trying per-string 4-byte XOR decode...")
    fourbyte_decoded = []
    for offset, length, enc_bytes in obf_strings:
        if length < 5:
            continue
        # Try each 4-byte key from Agent F
        for key_val in AGENTF_XOR_KEYS_4BYTE:
            if key_val == 0:
                continue
            key_bytes = struct.pack('<I', key_val)
            dec = xor_decrypt(enc_bytes, key_bytes)
            ratio = printable_ratio(dec)
            if ratio >= 0.85:
                try:
                    text = dec.decode('ascii')
                    abs_offset = REGION_START + offset
                    fourbyte_decoded.append((abs_offset, key_val, text, ratio))
                    break
                except:
                    pass
    
    out(f"  Strings decoded with 4-byte keys: {len(fourbyte_decoded)}")
    for abs_offset, key_val, text, ratio in fourbyte_decoded[:100]:
        out(f"    @{abs_offset:#08X} key=0x{key_val:08X}: \"{text}\" (ratio={ratio:.3f})")
    
    # ===== SECTION 13: FINAL SUMMARY =====
    out("\n" + "=" * 60)
    out("SECTION 13: SUMMARY AND INFERENCE TABLE")
    out("=" * 60)
    out(f"  Total obfuscated strings (>=3 bytes): {len(obf_strings)}")
    out(f"  Decoded via single-byte XOR: {len(decodeable_strings)}")
    out(f"  Decoded via 4-byte XOR: {len(fourbyte_decoded)}")
    out(f"  Matched to expected strings by length: {len(matches)}")
    out(f"  Still unreadable: {len(obf_strings) - len(decodeable_strings)}")
    
    # Write output
    with open(OUT_PATH, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    
    print(f"\nOutput written to: {OUT_PATH}")
    print(f"Total lines: {len(lines)}")

if __name__ == '__main__':
    main()
