import struct

dll = open(r'C:\Users\emora\OneDrive\Desktop\EXCLUSIONS\LiberTea!\LIBERTEA.DLL', 'rb').read()
gt = open(r'C:\Users\emora\OneDrive\Desktop\2\data\.text_unpacked_mem.bin', 'rb').read()
comp = dll[0x400:0x70330]

count_77 = sum(1 for b in comp if b == 0x77)
print(f'0x77 count in entire compressed stream: {count_77}')

print(f'GT[0:32]:  {" ".join(f"{b:02X}" for b in gt[:32])}')
print(f'COMP[0:32]: {" ".join(f"{b:02X}" for b in comp[:32])}')
print()

for i, b in enumerate(comp):
    if b == 0x77:
        print(f'First 0x77 in compressed at offset {i}')
        break
else:
    print('0x77 NOT found in compressed stream at all!')

print(f'COMP[4:12]: {" ".join(f"{b:02X}" for b in comp[4:12])}')
print(f'GT[0:8]:    {" ".join(f"{b:02X}" for b in gt[:8])}')
print()

d = struct.unpack('<I', comp[0:4])[0]
print(f'First dword LE: {d} (0x{d:08X})')
print()

# The assembly at 0x3C4F30 does:
#   xor ebx, ebx
#   ; then falls into getbit loop
# After reload:
#   push [rsi]; pop rbx  (loads 8 bytes!)
#   add rsi, 4
#   add ebx, ebx
#   adc ebx, ebx
#   mov dl, [rsi]
#
# push qword [rsi] loads 8 bytes (64-bit), not 4!
# So rbx gets: compressed[0:8] as a 64-bit LE value
# Then add+adc operates on ebx (low 32 bits)
#
# BUT: after the first reload, the sequence is:
#   push [rsi]  ; push 8 bytes from compressed[0]
#   pop rbx     ; rbx = 0x28EC8348FFFF6FF6
#   add rsi, 4  ; rsi = compressed + 4
#   add ebx, ebx  ; ebx = low 32 bits = 0xFFFF6FF6 * 2 = 0x1FFEDFEC -> ebx = 0xFFFEDFEC, CF=1
#   adc ebx, ebx  ; ebx = 0xFFFEDFEC*2 + 1 = 0x1FFDBFD9 -> ebx = 0xFFFDBFD8, CF=1
#   mov dl, [rsi] ; dl = compressed[4] = 0x48
#
# So after the first reload+shift, ebx = 0xFFFDBFD8, not 0xFFFEDFEC
# The add+adc shifts by 2 total, consuming 2 MSBs
#
# But wait - the code at 3C4F50 checks something about ebx
# The question is: what EXACTLY determines literal vs match?

# Let me check the actual instruction bytes at 0x3C4F50
print('=== Disassembly around 0x3C4F50 ===')
# We need capstone or manual decode
# Let me use the DLL bytes
decomp_start = 0x3C4F30 - 0x400  # but this is in .text section which is compressed...
# Actually the decompressor is in .rsrc section
# Let me find it differently

# The bootstrap is at RVA 0x3B3B50 in .rsrc
# The decompressor stub is at RVA 0x3C4F30
# These are RVAs, so in the file:
# .rsrc starts at file offset 0x70330 (from earlier analysis)
# Wait, let me check the section headers

import pefile
pe = pefile.PE(r'C:\Users\emora\OneDrive\Desktop\EXCLUSIONS\LiberTea!\LIBERTEA.DLL')
for section in pe.sections:
    name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    print(f'  {name}: VA=0x{section.VirtualAddress:08X}, Size=0x{section.Misc_VirtualSize:08X}, '
          f'RawOff=0x{section.PointerToRawData:08X}, RawSize=0x{section.SizeOfRawData:08X}')

# .rsrc: VA=0x3B0000, RawOff = ?
# The decompressor at RVA 0x3C4F30 is in .rsrc
# file_offset = RVA - section.VA + section.PointerToRawData
rsrc = None
for section in pe.sections:
    name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    if name == '.rsrc':
        rsrc = section
        break

if rsrc:
    decomp_rva = 0x3C4F30
    decomp_file = decomp_rva - rsrc.VirtualAddress + rsrc.PointerToRawData
    print(f'\nDecompressor at RVA 0x{decomp_rva:X}, file offset 0x{decomp_file:X}')
    
    # Read 128 bytes around the decompressor
    data = dll[decomp_file:decomp_file+128]
    for i in range(0, len(data), 16):
        hex_str = ' '.join(f'{b:02X}' for b in data[i:i+16])
        print(f'  0x{decomp_rva+i:06X}: {hex_str}')

    # Specifically check bytes at offset 0x3C4F50
    off_50 = decomp_file + (0x3C4F50 - decomp_rva)
    print(f'\nBytes at 0x3C4F50: {" ".join(f"{b:02X}" for b in dll[off_50:off_50+16])}')
    print(f'Bytes at 0x3C4F52: {" ".join(f"{b:02X}" for b in dll[off_52:off_50+2:16])}' if False else '')
    
    # Check: 0x85 0xDB = test ebx, ebx
    # 0x0F 0x84 = jz rel32
    # 0x0F 0x85 = jnz rel32
    b50 = dll[off_50]
    b51 = dll[off_50+1]
    b52 = dll[off_50+2]
    b53 = dll[off_50+3]
    print(f'\nInstruction at 0x3C4F50: {b50:02X} {b51:02X} {b52:02X} {b53:02X}')
    
    if b50 == 0x85 and b51 == 0xDB:
        print('  -> test ebx, ebx')
    elif b50 == 0xC1 and b51 == 0xEB:
        print(f'  -> shr ebx, {b52} (imm8={b52})')
    elif b50 == 0xD1 and b51 == 0xEB:
        print('  -> shr ebx, 1')
    elif b50 == 0x0F and b51 == 0xB6:
        print(f'  -> movzx reg, r/m8')
    elif b50 == 0xF7 and b51 == 0xC3:
        print('  -> test ebx, imm32')
    else:
        # Try to decode
        print(f'  -> Unknown: first byte 0x{b50:02X}')
    
    # Also check what's at 0x3C4F52 (the jump target after test)
    off_52 = decomp_file + (0x3C4F52 - decomp_rva)
    j1 = dll[off_52]
    j2 = dll[off_52+1]
    print(f'Instruction at 0x3C4F52: {j1:02X} {j2:02X}')
    if j1 == 0x0F and j2 == 0x84:
        rel = struct.unpack('<i', dll[off_52+2:off_52+6])[0]
        target = 0x3C4F52 + 6 + rel
        print(f'  -> jz 0x{target:06X}')
    elif j1 == 0x0F and j2 == 0x85:
        rel = struct.unpack('<i', dll[off_52+2:off_52+6])[0]
        target = 0x3C4F52 + 6 + rel
        print(f'  -> jnz 0x{target:06X}')
    elif j1 == 0x74:
        target = 0x3C4F52 + 2 + struct.unpack('b', bytes([j2]))[0]
        print(f'  -> jz 0x{target:06X}')
    elif j1 == 0x75:
        target = 0x3C4F52 + 2 + struct.unpack('b', bytes([j2]))[0]
        print(f'  -> jnz 0x{target:06X}')
    
    # Now let me also check 0x3C4F32-0x3C4F50 more carefully
    print('\n=== Full decompressor disassembly ===')
    for offset in range(decomp_file, decomp_file + 160, 1):
        pass  # we'll do this with capstone
    
pe.close()
