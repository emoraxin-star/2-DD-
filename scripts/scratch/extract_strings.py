import sys
import struct
import re

def extract_ascii(data, min_len=4):
    results = []
    buf = bytearray()
    start = -1
    for i, b in enumerate(data):
        if 32 <= b < 127:
            if start == -1:
                start = i
            buf.append(b)
        else:
            if len(buf) >= min_len:
                s = buf.decode('ascii', errors='replace')
                results.append((start, s, len(buf)))
            buf.clear()
            start = -1
    if len(buf) >= min_len:
        s = buf.decode('ascii', errors='replace')
        results.append((start, s, len(buf)))
    return results

def extract_utf16le(data, min_len=4):
    results = []
    buf = bytearray()
    start = -1
    i = 0
    while i < len(data) - 1:
        lo = data[i]
        hi = data[i + 1]
        ch = lo | (hi << 8)
        if 32 <= ch < 0xD800:
            if start == -1:
                start = i
            buf.extend(data[i:i+2])
            i += 2
            continue
        else:
            if len(buf) // 2 >= min_len:
                s = buf.decode('utf-16-le', errors='replace')
                if not is_mostly_garbage(s):
                    results.append((start, s, len(buf) // 2))
            buf.clear()
            start = -1
            if ch == 0:
                i += 1
            i += 2
            continue
    if len(buf) // 2 >= min_len:
        s = buf.decode('utf-16-le', errors='replace')
        if not is_mostly_garbage(s):
            results.append((start, s, len(buf) // 2))
    return results

def is_mostly_garbage(s):
    # Filter strings that are clearly assembly fragments
    if len(s) < 5:
        return False
    
    # Assembly register patterns
    asm_patterns = [
        r'^[A-Z]\$\s*[A-Z]',      # D$ H style
        r'^[\$\|]?[tldr]\$',      # stack offsets
        r'^[UVWAH_]{3,}$',        # push prologue/epilogue
        r'^[A-Za-z\$][0-9A-Fa-f]', # hex-like
        r'^[0-9A-Fa-f]{4,}$',     # pure hex
        r'^\$[0-9A-Fa-f]+$',      # hex constants
        r'^[xXHh_]\$',             # more asm patterns
        r'^[A-Fa-f0-9]{3,}$',     # short hex
    ]
    for p in asm_patterns:
        if re.match(p, s):
            return True
    
    # Count printable characters vs non-alpha
    alpha = sum(1 for c in s if c.isalpha())
    if alpha <= 2 and len(s) >= 5:
        return True
    
    return False

# Main
print("Loading binary...")
with open(r"C:\Users\emora\OneDrive\Desktop\2\data\.text_unpacked_mem.bin", "rb") as f:
    data = f.read()

print(f"Binary size: {len(data)} bytes")

print("Extracting ASCII strings (min 5 chars)...")
ascii_strings = extract_ascii(data, min_len=5)
print(f"Found {len(ascii_strings)} ASCII strings")

print("Extracting UTF-16LE strings (min 4 chars)...")
utf16le_strings = extract_utf16le(data, min_len=4)
print(f"Found {len(utf16le_strings)} UTF-16LE strings")

# Write ASCII strings
with open(r"C:\Users\emora\OneDrive\Desktop\2\logs\extracted_ascii.txt", "w", encoding="utf-8") as f:
    for offset, s, length in ascii_strings:
        if offset < 0x1000:
            f.write(f"+0x{offset:04X}\t{s}\n")
        else:
            f.write(f"+0x{offset:06X}\t{s}\n")

# Write UTF-16LE strings
with open(r"C:\Users\emora\OneDrive\Desktop\2\logs\extracted_utf16le.txt", "w", encoding="utf-8") as f:
    for offset, s, length in utf16le_strings:
        if offset < 0x1000:
            f.write(f"+0x{offset:04X}\t{s}\n")
        else:
            f.write(f"+0x{offset:06X}\t{s}\n")

print("Done!")
print(f"ASCII: {len(ascii_strings)} strings")
print(f"UTF-16LE: {len(utf16le_strings)} strings")
