"""
Deep analysis of obfuscated region at 0x0F8000-0x10A000 in ground truth .text
1,133 garbled strings, high entropy (7.26 bits/byte)
"""
import struct

gt = open(r'C:\Users\emora\OneDrive\Desktop\2\data\.text_unpacked_mem.bin', 'rb').read()

# Region: 0x0F8000 to 0x10A000 (size 0x12000 = 73,728 bytes)
REGION_START = 0x0F8000
REGION_END = 0x10A000
region = gt[REGION_START:REGION_END]
print(f"Region size: {len(region)} bytes (0x{len(region):X})")

# Entropy check
import math
from collections import Counter
freq = Counter(region)
entropy = -sum((c/len(region)) * math.log2(c/len(region)) for c in freq.values())
print(f"Entropy: {entropy:.4f} bits/byte")

# Look for structure
# First 256 bytes
print(f"\nFirst 256 bytes:")
for i in range(0, 256, 16):
    hex_str = ' '.join(f'{b:02X}' for b in region[i:i+16])
    print(f"  {REGION_START+i:06X}: {hex_str}")

# Search for pointer-like values (VA in .text range 0x1000-0x355000)
print("\n=== Potential pointers (VA 0x1000-0x355000) ===")
for i in range(0, len(region), 4):
    if i + 4 <= len(region):
        val = struct.unpack('<I', region[i:i+4])[0]
        if 0x1000 <= val <= 0x355000:
            print(f"  Offset 0x{i:04X} (VA 0x{REGION_START+i:06X}): ptr -> 0x{val:08X}")

# Search for string table: sequences of printable ASCII
print("\n=== ASCII strings (len >= 4) ===")
ascii_strings = []
i = 0
while i < len(region):
    if 32 <= region[i] <= 126:
        start = i
        while i < len(region) and 32 <= region[i] <= 126:
            i += 1
        if i - start >= 4:
            s = region[start:i].decode('ascii', errors='ignore')
            ascii_strings.append((REGION_START+start, s))
    else:
        i += 1

print(f"Found {len(ascii_strings)} ASCII strings:")
for addr, s in ascii_strings[:50]:
    print(f"  0x{addr:06X}: {s}")
if len(ascii_strings) > 50:
    print(f"  ... and {len(ascii_strings)-50} more")

# XOR key search: try single-byte XOR on region, look for printable output
print("\n=== Single-byte XOR key search (sample) ===")
for key in [0x00, 0x20, 0x27, 0x41, 0x55, 0x5A, 0x61, 0x7F, 0xAA, 0xFF]:
    test = bytes([b ^ key for b in region[:1024]])
    printable = sum(1 for b in test if 32 <= b <= 126 or b in (9, 10, 13))
    if printable > 400:
        print(f"  Key 0x{key:02X}: {printable}/1024 printable")
        # Show first 64 bytes
        for i in range(0, 64, 16):
            hex_str = ' '.join(f'{b:02X}' for b in test[i:i+16])
            ascii_str = ''.join(chr(b) if 32<=b<=126 else '.' for b in test[i:i+16])
            print(f"    {i:04X}: {hex_str}  {ascii_str}")

# Multi-byte XOR pattern search
print("\n=== Multi-byte XOR pattern search ===")
# Try common patterns
patterns = [
    bytes([0x01, 0xFF, 0xFE, 0xFD]),  # 1, -1, -2, -3 (mod 256)
    bytes([0x5A, 0x5A, 0x5A, 0x5A]),  # 0x5A repeating
    bytes([0x41, 0x42, 0x43, 0x44]),  # ABCD
]
for i, pat in enumerate(patterns):
    test = bytes([region[j] ^ pat[j % len(pat)] for j in range(min(512, len(region)))])
    printable = sum(1 for b in test if 32 <= b <= 126 or b in (9, 10, 13))
    if printable > 200:
        print(f"  Pattern {i}: {printable}/512 printable")

# Check if region might be compressed with same aPLib
print("\n=== aPLib signature check in region ===")
for i in range(len(region)-4):
    if region[i] == 0x01 and i+5 < len(region):
        size = struct.unpack('<I', region[i+1:i+5])[0]
        if size == 0x354000 or abs(size - len(region)) < 1000:
            print(f"  aPLib header at 0x{REGION_START+i:X}: size={size}")

# Look for double-indirection structure: pointer array -> string table
print("\n=== Double indirection search ===")
# Look for arrays of pointers that point within the region
ptr_candidates = []
for i in range(0, len(region), 4):
    if i + 4 <= len(region):
        val = struct.unpack('<I', region[i:i+4])[0]
        # Pointer to somewhere in .text
        if 0x1000 <= val <= 0x355000:
            ptr_candidates.append((REGION_START+i, val))

print(f"Found {len(ptr_candidates)} pointer candidates")
if ptr_candidates:
    # Group by target
    from collections import defaultdict
    target_groups = defaultdict(list)
    for src, tgt in ptr_candidates:
        target_groups[tgt].append(src)
    
    # Show targets with multiple pointers
    for tgt, srcs in sorted(target_groups.items(), key=lambda x: -len(x[1]))[:20]:
        print(f"  Target 0x{tgt:08X} <- {len(srcs)} pointers: {srcs[:10]}")

# Save raw region for external analysis
with open(r'C:\Users\emora\OneDrive\Desktop\2\data\obfuscated_region.bin', 'wb') as f:
    f.write(region)
print(f"\nSaved raw region to data/obfuscated_region.bin ({len(region)} bytes)")

# Entropy by block
print("\n=== Entropy by 1KB block ===")
for i in range(0, len(region), 1024):
    block = region[i:i+1024]
    if len(block) < 100:
        continue
    freq = Counter(block)
    ent = -sum((c/len(block)) * math.log2(c/len(block)) for c in freq.values())
    print(f"  0x{REGION_START+i:06X}: {ent:.4f} bits/byte")

# Check for LZ77-style references within region
print("\n=== Self-referential LZ77 check ===")
for i in range(18, min(5000, len(region))):
    # Look for offset/length pairs
    if i + 3 < len(region):
        offset = struct.unpack('<H', region[i:i+2])[0]
        length = struct.unpack('<H', region[i+2:i+4])[0]
        if 1 <= offset <= i and 3 <= length <= 256:
            # Potential LZ77 reference
            pass

print("\n=== DONE ===")