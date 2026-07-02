"""
CRITICAL FINDING: Recomputed the lea rsi displacement.

Instruction at 0x3C4F4C: 48 8D 35 AD 00 F9 FF
Displacement = 0xFFF900AD = -0x6FF53
RIP after instruction = 0x3C4F53

EA = 0x3C4F53 - 0x6FF53 = ?

0x3C4F53 = 3,952,467
0x6FF53  =   458,579
Result   = 3,493,888 = 0x355000

rsi = 0x355000 = START of .rsrc1 = file offset 0x400

So our Python script IS reading from the correct offset!
The 5-byte match is NOT a coincidence from wrong data.
The compressed data at offset 0x400 IS what the decompressor reads.

But it only produces 26 bytes then fails.
The issue must be in the algorithm, not the data offset.
"""
import struct

# Verify the arithmetic
print("=== Verifying lea rsi calculation ===")
rip_after = 0x3C4F4C + 7  # = 0x3C4F53
disp = struct.unpack('<i', bytes([0xAD, 0x00, 0xF9, 0xFF]))[0]
ea = (rip_after + disp) & 0xFFFFFFFF
print(f"RIP after instruction: 0x{rip_after:X}")
print(f"Displacement: {disp} (0x{disp & 0xFFFFFFFF:08X})")
print(f"Effective address: 0x{ea:X}")

# Verify with reverse calculation
print(f"0x3C4F53 - 0x355000 = 0x{0x3C4F53 - 0x355000:X}")
print(f"Expected displacement: -0x{0x3C4F53 - 0x355000:X} = {-(0x3C4F53 - 0x355000)}")
print(f"Actual displacement: {disp}")
print(f"Match: {disp == -(0x3C4F53 - 0x355000)}")

# So rsi = 0x355000, which IS the start of .rsrc1
# .rsrc1: VA=0x355000, RawOff=0x400
# So rsi corresponds to file offset 0x400

# This means our Python decompressor IS reading the correct data.
# The issue is NOT with the offset.

# Let me now carefully re-examine what happens after the 16 literals.
# The first dword 0xFFFF6FF6 has 16 leading 1-bits (MSB-first).
# After 16 LITERALs, the 17th bit is 0 (MATCH).

# But the ground truth needs:
# Byte 5: 0x77 (not 0x27 from compressed[9])
# This means byte 5 should come from a MATCH, not a LITERAL.

# For byte 5 to come from a MATCH, the 6th bit (after 5 LITERALs) must be 0.
# But the first dword has 16 leading 1-bits, so the 6th bit is 1.

# This means the first dword interpretation is wrong.
# The first 4 bytes cannot all be part of the bitstream.

# What if the first dword is NOT the bitstream start?
# What if there's a different initial state for the bit reader?

# Let me check: the assembly does:
# 0x3C4F5B: xor ebx, ebx    ; ebx = 0
# This is clear. ebx starts at 0.

# What if there's a SECOND call to the decompressor that sets up ebx differently?
# The entry point checks dl == 1 (DLL_PROCESS_ATTACH).
# If dl != 1, it jumps to 0x3C51B4.

# At 0x3C51B4:
# 0x3C51B4: mov r8, [rsp+18h]  ; restore r8
# This is the DllMain return path for non-PROCESS_ATTACH calls.

# So there's only ONE call path that runs the decompressor.

# The conclusion is: the compressed data at offset 0x400 is correct,
# but our bit reading produces incorrect output after 5 bytes.
# This means our understanding of the algorithm is wrong somewhere.

# Let me check one more thing: the `call r11` function.
# r11 = 0x3C4F68. What does `call r11` actually do?
# It pushes the return address and jumps to 0x3C4F68.

# At 0x3C4F68:
# 0x3C4F68: add ebx, ebx    ; shift left
# 0x3C4F6A: je 0x3c4f6e     ; if 0, reload
# 0x3C4F6C: repz ret        ; return

# After the reload:
# 0x3C4F6E: mov ebx, [rsi]  ; reload 4 bytes
# 0x3C4F70: sub rsi, -4     ; rsi += 4
# 0x3C4F74: adc ebx, ebx    ; shift left with CF
# 0x3C4F76: mov dl, [rsi]   ; preload byte
# 0x3C4F78: repz ret        ; return

# This is the SAME bit reading as the main loop.
# The only difference is that the main loop at 0x3C4FC5 also does
# `mov dl, [rsi]` BEFORE the shift, which preloads the byte.

# In the main loop:
# 0x3C4FC5: mov dl, [rsi]   ; preload BEFORE shift
# 0x3C4FC7: add ebx, ebx    ; shift
# 0x3C4FC9: jne .has_bits
# 0x3C4FCB: mov ebx, [rsi]  ; reload
# 0x3C4FCD: sub rsi, -4
# 0x3C4FD1: adc ebx, ebx    ; shift with CF
# 0x3C4FD3: mov dl, [rsi]   ; preload AFTER reload

# The key difference: in the main loop, dl is loaded at 0x3C4FC5 (before shift)
# and potentially overwritten at 0x3C4FD3 (after reload).
# In the call r11 path, dl is only loaded at 0x3C4F76 (after reload).

# When there's NO reload (ebx != 0 after first shift):
# Main loop: dl was loaded at 0x3C4FC5 (before shift)
# call r11: dl was NOT loaded (it was already set from a previous iteration)

# This means the dl value in the call r11 path might be STALE!
# It could be the dl from a PREVIOUS iteration, not the current one.

# Wait, but in the main loop at 0x3C4FC5, dl is ALWAYS loaded from [rsi].
# So dl always has the byte at the current rsi position.

# But in the call r11 path at 0x3C4F68, there's no `mov dl, [rsi]` before the shift.
# dl is only updated at 0x3C4F76 (after reload).

# So if there's no reload, dl retains its previous value!
# This is different from the main loop, where dl is always refreshed.

# Hmm, but the call r11 is only used in the MATCH decoding (length decode),
# not in the main literal/match decision. So dl in the call r11 path
# should be the dl from the last `mov dl, [rsi]` in the main loop.

# Actually, looking more carefully at the MATCH decoding:
# After the main loop determines it's a MATCH (CF=0 at 0x3C4FD5):
# 0x3C4FD7: lea eax, [rcx + 1]
# 0x3C4FDA: jmp 0x3c4fe3

# At 0x3C4FE3:
# 0x3C4FE3: call r11    ; get bit
# 0x3C4FE6: adc eax, eax

# Then at 0x3C4FE8:
# 0x3C4FE8: add ebx, ebx   ; get ANOTHER bit (inline, not via call r11)
# 0x3C4FEA: jne 0x3c4ff6
# ... reload if needed ...
# 0x3C4FF6: jae 0x3c4fdc   ; if CF=0, continue loop

# So the length decode uses BOTH `call r11` (for some bits) and inline `add ebx, ebx` (for others).

# The inline `add ebx, ebx` at 0x3C4FE8 is the SAME as the main loop's bit reading.
# It does NOT update dl.

# So dl is only updated:
# 1. In the main loop at 0x3C4FC5 (before shift) and 0x3C4FD3 (after reload)
# 2. In the call r11 path at 0x3C4F76 (after reload)

# This means dl should always be correct, as long as rsi is correct.

# OK, I think the algorithm is correct. The issue must be something else.
# Let me try a COMPLETELY different hypothesis: what if bit=0 means LITERAL
# and bit=1 means MATCH?

# In the assembly:
# 0x3C4FD5: jb 0x3c4fbd    ; CF=1 -> LITERAL
# This is unambiguous: CF=1 means LITERAL.

# Unless... the `jb` is NOT testing CF from the shift, but from something else.
# Let me check: what instruction sets CF before the `jb`?

# The `jb` at 0x3C4FD5 is preceded by:
# 0x3C4FD1: adc ebx, ebx    ; sets CF
# OR
# (if no reload)
# 0x3C4FC7: add ebx, ebx    ; sets CF

# So CF is always from the last shift operation. `jb` tests this CF.
# CF=1 -> LITERAL, CF=0 -> MATCH.

# This is correct in our implementation.

# I'm stuck. Let me try something radical: what if the decompressor
# does NOT use add ebx, ebx for bit reading, but uses a DIFFERENT mechanism?

# Looking at the instruction bytes:
# 0x3C4FC7: 01 DB    add ebx, ebx
# This is definitely `add ebx, ebx`. There's no ambiguity.

# 0x3C4FD1: 11 DB    adc ebx, ebx
# This is definitely `adc ebx, ebx`.

# 0x3C4FD5: 72 E6    jb 0x3c4fbd
# This is definitely `jb` (jump if below / carry set).

# So the bit reading is: shift left, test CF, CF=1 -> LITERAL.
# Our implementation does the same thing.

# The only remaining possibility: the first dword 0xFFFF6FF6 is NOT the start
# of the bitstream. There must be some mechanism to skip it.

# But the assembly clearly shows:
# 0x3C4F5B: xor ebx, ebx    ; ebx = 0
# 0x3C4F63: call 0x3c4fb8    ; setup r11 and enter main loop
# And the main loop reads from rsi, which points to the start of compressed data.

# Unless rsi is NOT pointing to the start of compressed data.
# What if rsi points to the MIDDLE of the compressed data?

# rsi = 0x355000 = .rsrc1 start. This is definitely the start of the section.
# But maybe the compressed data doesn't start at the beginning of .rsrc1?

# What if .rsrc1 has a header (resource directory) followed by compressed data?
# The resource directory would be at the start, and compressed data would follow.

# But we checked: the first 16 bytes at offset 0x400 don't look like a resource directory.
# And our Python script decompresses from offset 0x400 and gets 5 matching bytes.

# Unless the "resource directory" is encrypted/obfuscated, and the first few bytes
# happen to produce matching output when interpreted as a bitstream.

# OK, I really need to move on. Let me write the report.
print("\n=== CONCLUSION ===")
print("The decompressor reads from rsi = 0x355000 = file offset 0x400")
print("Our Python implementation reads from the same offset")
print("The bit reading algorithm matches the assembly")
print("But the output diverges at byte 5 (0x27 vs 0x77)")
print()
print("The compressed data at offset 0x400 has 16 leading 1-bits in the first dword,")
print("producing 16 consecutive LITERALs. The ground truth needs a MATCH after 5 LITERALs.")
print()
print("Possible explanations:")
print("1. The first dword is a HEADER that should be skipped (but assembly shows no skip)")
print("2. The initial ebx value is NOT 0 (but assembly shows xor ebx, ebx)")
print("3. The bit reading direction is different (but assembly shows MSB-first via CF)")
print("4. The DLL file has been modified since ground truth extraction")
print("5. There's a runtime code patch or memory modification we can't detect statically")
