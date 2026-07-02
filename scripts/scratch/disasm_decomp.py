import struct
from capstone import *

dll = open(r'C:\Users\emora\OneDrive\Desktop\EXCLUSIONS\LiberTea!\LIBERTEA.DLL', 'rb').read()

import pefile
pe = pefile.PE(r'C:\Users\emora\OneDrive\Desktop\EXCLUSIONS\LiberTea!\LIBERTEA.DLL')

# Find .rsrc section
rsrc = None
for section in pe.sections:
    name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    if name == '.rsrc':
        rsrc = section
        break

print(f'.rsrc: VA=0x{rsrc.VirtualAddress:X}, RawOff=0x{rsrc.PointerToRawData:X}')

decomp_rva = 0x3C4F30
decomp_file = decomp_rva - rsrc.VirtualAddress + rsrc.PointerToRawData
print(f'Decompressor at RVA 0x{decomp_rva:X}, file offset 0x{decomp_file:X}')

# Read a good chunk
data = dll[decomp_file:decomp_file+512]

# Disassemble with capstone
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

for inst in md.disasm(data, decomp_rva):
    # Print bytes and assembly
    hex_bytes = ' '.join(f'{b:02X}' for b in inst.bytes)
    print(f'  0x{inst.address:06X}: {hex_bytes:<40} {inst.mnemonic} {inst.op_str}')
    
    # Stop after we see enough
    if inst.address >= decomp_rva + 480:
        break

# Now specifically look for the getbit pattern
print('\n=== Searching for add ebx, ebx / adc ebx, ebx pattern ===')
for i in range(len(data)-5):
    if data[i:i+2] == b'\x13\xDB':  # adc ebx, ebx
        # Look back for add ebx, ebx
        for j in range(max(0, i-5), i):
            if data[j:j+2] == b'\x03\xDB':  # add ebx, ebx
                rva = decomp_rva + j
                print(f'  Found add+adc at RVA 0x{rva:X} (file offset 0x{decomp_file+j:X})')
                # Print context
                start = max(0, j-8)
                end = min(len(data), j+16)
                for inst2 in md.disasm(data[start:end], decomp_rva + start):
                    if inst2.address >= rva - 8 and inst2.address <= rva + 16:
                        hb = ' '.join(f'{b:02X}' for b in inst2.bytes)
                        print(f'    0x{inst2.address:06X}: {hb:<40} {inst2.mnemonic} {inst2.op_str}')
                break

# Also search for xor ebx, ebx (31 DB) as the init
print('\n=== Searching for xor ebx, ebx (31 DB) ===')
for i in range(len(data)-1):
    if data[i] == 0x31 and data[i+1] == 0xDB:
        print(f'  Found xor ebx, ebx at RVA 0x{decomp_rva+i:X}')

# Search for push [rsi] / pop rbx pattern
print('\n=== Searching for push qword [rsi] / pop rbx ===')
for i in range(len(data)-2):
    if data[i] == 0xFF and data[i+1] == 0x36:  # push qword [rsi]
        if i+2 < len(data) and data[i+2] == 0x5B:  # pop rbx
            print(f'  Found push [rsi]; pop rbx at RVA 0x{decomp_rva+i:X}')

pe.close()
