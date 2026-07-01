#!/usr/bin/env python3
"""
HYPER AGENT 3: Detailed struct field accessor cross-reference
Finds which functions access which struct offsets near known string references
"""
import struct

TEXT_PATH = r"C:\Users\emora\OneDrive\Desktop\2\data\.text_unpacked_mem.bin"

def load():
    with open(TEXT_PATH, "rb") as f:
        return f.read()

def find_string_offsets(data):
    strings = []
    current = b""
    start = 0
    for i, b in enumerate(data):
        if 0x20 <= b <= 0x7E:
            if not current:
                start = i
            current += bytes([b])
        else:
            if len(current) >= 6:
                strings.append((start, current.decode("ascii", errors="replace")))
            current = b""
    return strings

data = load()

# Find all allocations and their context
print("# ALLOCATION SIZES NEAR FUNCTION CALLS")
for off in range(0, min(0x0B8000, len(data)) - 15):
    if data[off] == 0xB9:  # mov ecx, imm32
        size = struct.unpack_from("<I", data, off+1)[0] if off+5 <= len(data) else 0
        if 0x18 <= size <= 0x4000:
            for j in range(off+5, min(off+20, len(data)-5)):
                if data[j] == 0xE8:
                    rel = struct.unpack_from("<i", data, j+1)[0]
                    target = j + 5 + rel
                    if 0 <= target < len(data):
                        # Get string context within 256 bytes
                        context = ""
                        for si, st in [(s,d) for s,d in find_string_offsets(data[off-50:off+50])]:
                            pass
                    break

# Find all 0x128 and 0x28 offsets used with session
print("\n# SESSION-RELATED OFFSET REFERENCES (GetActiveSession usage)")
# look around the "GetActiveSession" string
for soff, s in find_string_offsets(data):
    if "ActiveSession" in s:
        print(f"  String at {soff:#x}: '{s}'")
        # Disassemble nearby
        ctx = data[soff-200:soff+200]
        # Look for mov/cmp with 0x28 or 0x128 patterns
        for j in range(len(ctx)-10):
            if ctx[j:j+4] == b'\x00\x00\x00' and ctx[j-1:j] in (b'\x28', b'\x29'):
                pass

# Look for cmp instructions near specific strings to identify enum values
print("\n# ENUM VALUE PATTERNS NEAR KNOWN STRINGS")
known_terms = {
    "Difficulty": ["1 - Trivial", "2 - Easy", "3 - Medium", "4 - Challenging",
                   "5 - Hard", "6 - Extreme", "7 - Super Helldive", "8 -", "9 -", "10 -"],
    "Sample": ["Common", "Rare", "Super"],
    "Stratagem": ["Eagle", "Orbital", "Turret", "Backpack", "Support"],
    "Hook": ["NOP_PATCH", "CODE_PATCH", "FUNCTION_PROLOGUE", "POINTER_RESOLVE",
             "FUNCTION_RETURN", "CONDITIONAL_INVERT"],
    "Auth": ["SUCCESS", "FAIL", "EXPIRED", "INVALID", "PENDING"],
}

strings = find_string_offsets(data)
for cat, terms in known_terms.items():
    for t in terms:
        for soff, s in strings:
            if t in s:
                print(f"  [{cat}] {soff:#08x}: {s}")

# Scan near 0x0F9000 - 0x10A000 for ImGui struct references
print("\n# IMGUI STRUCT OFFSET ANALYSIS")
# ImGui context is at RVA ~0x0F9000-0x10A000
# Common ImGui struct patterns
for off in range(0x0F9000, min(0x10A000, len(data)) - 8, 4):
    val = struct.unpack_from("<Q", data, off)[0]
    # Look for vtable-like pointers (aligned, 0x1000-0x200000 range)
    if 0x1000 < val < 0x200000 and val % 8 == 0:
        pass
    # Look for float values
    fval = struct.unpack_from("<f", data, off)[0]
    if 100.0 < fval < 1000.0:
        pass

print("Done.")
