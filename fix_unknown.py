#!/usr/bin/env python3
"""Fix unknown strings re-categorization"""

import re

OUTPUT = r"C:\Users\emora\OneDrive\Desktop\2\logs\agentD_string_map.txt"

with open(OUTPUT, 'r', encoding='utf-8') as f:
    text = f.read()

# Find the UNKNOWN section in SECTION 1
start_marker = '### UNKNOWN: '
end_marker = '\n\n'  # sections are separated by blank lines

idx = text.find(start_marker)
if idx < 0:
    print("UNKNOWN section not found!")
    exit(1)

# Find end of UNKNOWN section (next section)
next_section = text.find('\n###', idx + len(start_marker))
if next_section < 0:
    next_section = text.find('\nSECTION 2:', idx + len(start_marker))
    if next_section < 0:
        next_section = len(text)

unknown_section = text[idx:next_section]
rest_before = text[:idx]
rest_after = text[next_section:]

# Categorization patterns for SYSTEM
SYSTEM_PATS = [
    # C++ runtime errors
    r'device or resource busy', r'invalid argument', r'no such process',
    r'not enough memory', r'operation not permitted', r'resource deadlock',
    r'resource unavailable', r'generic$', r'bad allocation',
    r'^success$', r'address family not supported', r'address in use',
    r'address not available', r'connection aborted', r'connection refused',
    r'connection reset', r'network down', r'network unreachable',
    r'not connected', r'timed out', r'unknown error', r'Unknown exception',
    # MSVC/RTTI
    r'^\.\?AV\w+@@', r"^`local", r"^`vftable", r"^`vbtable", r"^`RTTI",
    # C runtime
    r'^\(null\)$', r'^Eccs$',
]

SYSTEM_LOCALE_PATS = [
    r'^(Sunday|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday)$',
    r'^(January|February|March|April|May|June|July|August|September|October|November|December)$',
    r'^MM/dd/yy$', r'^dddd, MMMM dd, yyyy$', r'^HH:mm:ss$', r'^am/pm$',
    r'^[a-z]{2}-[A-Z]{2}(-[A-Za-z]+)?$',  # en-US, ja-JP
    r'^[a-z]{2}-[a-z]{2,4}(-[a-z]+)?$',   # zh-cht, en-us
    r'^[a-z]{2}-[a-z]{2}-[a-z]{3,5}$',     # az-az-cyrl
]

AOB_PAT = re.compile(r'^[\dA-Fa-f ?]{12,}$')

HOOK_PATS = [
    r'game\.dll\b', r'game\.dll not loaded',
    r'NOP ', r'Force unconditional jump', r'Return .* immediately',
    r'Skip .* timer', r'NtProtectVirtualMemory',
]

def recategorize(s):
    # Try SYSTEM first
    for pat in SYSTEM_LOCALE_PATS:
        if re.match(pat, s): return 'SYSTEM'
    for pat in SYSTEM_PATS:
        if re.search(pat, s, re.IGNORECASE): return 'SYSTEM'
    # AOB patterns -> HOOK_SYSTEM
    if AOB_PAT.match(s): return 'HOOK_SYSTEM'
    # Hook patterns
    for pat in HOOK_PATS:
        if re.search(pat, s, re.IGNORECASE): return 'HOOK_SYSTEM'
    return None

# Process each line in unknown section
lines = unknown_section.split('\n')
new_lines = []
recategorized = 0

for line in lines:
    m = re.match(r'^(\s+\+0x[\dA-F]+\s+)(.*)', line)
    if m:
        prefix = m.group(1)
        s = m.group(2).strip()
        new_cat = recategorize(s)
        if new_cat:
            new_lines.append(f'{prefix}[{new_cat}] {s}')
            recategorized += 1
            continue
    elif re.match(r'^\s+\[UTF-16LE\]\s+(.*)', line):
        m2 = re.match(r'^(\s+\[UTF-16LE\]\s+)(.*)', line)
        if m2:
            prefix = m2.group(1)
            s = m2.group(2).strip()
            new_cat = recategorize(s)
            if new_cat:
                new_lines.append(f'{prefix}[{new_cat}] {s}')
                recategorized += 1
                continue
    new_lines.append(line)

unknown_section = '\n'.join(new_lines)
final_text = rest_before + unknown_section + rest_after

with open(OUTPUT, 'w', encoding='utf-8') as f:
    f.write(final_text)

# Count remaining unknowns
remaining = sum(1 for line in new_lines if re.match(r'^\s+\+0x[\dA-F]+', line) and 'UNKNOWN' not in line)
true_unknown = sum(1 for line in new_lines if re.match(r'^\s+\+0x[\dA-F]+', line))

print(f"Recategorized: {recategorized}")
print(f"Remaining UNKNOWN ASCII entries: {true_unknown}")
