import struct

dll = open(r'C:\Users\emora\OneDrive\Desktop\EXCLUSIONS\LiberTea!\LIBERTEA.DLL', 'rb').read()
gt = open(r'C:\Users\emora\OneDrive\Desktop\2\data\.text_unpacked_mem.bin', 'rb').read()

# .rsrc: VA=0x355000, RawOff=0x400
# Decompressor lea rsi, [rip-0x6FF53] → rsi = 0x3C4F53 - 0x6FF53 = 0x35A000
# That's VA 0x35A000 = .rsrc_base(0x355000) + 0x5000
# So compressed data starts at file offset: 0x400 + 0x5000 = 0x5400

RSRC_VA = 0x355000
RSRC_FILE_OFF = 0x400
DECOMP_RSI_VA = 0x35A000
OFFSET_IN_RSRC = DECOMP_RSI_VA - RSRC_VA  # 0x5000
COMP_FILE_START = RSRC_FILE_OFF + OFFSET_IN_RSRC  # 0x5400

print(f'.rsrc VA=0x{RSRC_VA:X}, file_offset=0x{RSRC_FILE_OFF:X}')
print(f'Decompressor rsi = 0x{DECOMP_RSI_VA:X} = .rsrc + 0x{OFFSET_IN_RSRC:X}')
print(f'Compressed data starts at file offset 0x{COMP_FILE_START:X}')
print()

# Extract compressed data from the correct offset
comp = dll[COMP_FILE_START:COMP_FILE_START + 0x70330 - 0x5000]
print(f'Compressed data length: {len(comp)} bytes')

print(f'COMP[0:32]:  {" ".join(f"{b:02X}" for b in comp[:32])}')
print(f'GT[0:32]:    {" ".join(f"{b:02X}" for b in gt[:32])}')
print()

# Check first dword
d = struct.unpack('<I', comp[0:4])[0]
print(f'First dword: 0x{d:08X}')
# Count leading 1-bits MSB-first
count = 0
for i in range(32):
    if d & (1 << (31-i)):
        count += 1
    else:
        break
print(f'Leading 1-bits MSB-first: {count}')
print()

# Check if comp[4:8] matches gt[0:4]
print(f'COMP[4:8]:  {" ".join(f"{b:02X}" for b in comp[4:8])}')
print(f'GT[0:4]:    {" ".join(f"{b:02X}" for b in gt[:4])}')
print(f'Match: {comp[4:8] == bytes(gt[:4])}')
print()

# Check first few bytes of comp for expected values
print(f'COMP[0:16]: {" ".join(f"{b:02X}" for b in comp[:16])}')
print(f'COMP[4:16]: {" ".join(f"{b:02X}" for b in comp[4:16])}')
print()

# Check the second .rsrc section too
# .rsrc2: VA=0x3C6000, RawOff=0x70800
# The bootstrap at RVA 0x3B3B50 is in first .rsrc
# Let me also check if there's an import table or something between
# Check bytes between old comp start and new comp start
print('=== Bytes at old start (file offset 0x400) vs new start (0x5400) ===')
print(f'At 0x0400: {" ".join(f"{b:02X}" for b in dll[0x400:0x410])}')
print(f'At 0x5400: {" ".join(f"{b:02X}" for b in dll[0x5400:0x5410])}')
print()

# Now let me also check: what's the rsi value used by the bootstrap?
# Bootstrap at RVA 0x3B3B50
import pefile
pe = pefile.PE(r'C:\Users\emora\OneDrive\Desktop\EXCLUSIONS\LiberTea!\LIBERTEA.DLL')
rsrc = None
for section in pe.sections:
    name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    if name == '.rsrc':
        rsrc = section
        break

bootstrap_rva = 0x3B3B50
bootstrap_file = bootstrap_rva - rsrc.VirtualAddress + rsrc.PointerToRawData
print(f'Bootstrap at RVA 0x{bootstrap_rva:X}, file offset 0x{bootstrap_file:X}')
bootstrap_data = dll[bootstrap_file:bootstrap_file+128]

from capstone import *
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
print('\nBootstrap disassembly:')
for inst in md.disasm(bootstrap_data, bootstrap_rva):
    hb = ' '.join(f'{b:02X}' for b in inst.bytes)
    print(f'  0x{inst.address:06X}: {hb:<40} {inst.mnemonic} {inst.op_str}')
    if inst.address >= bootstrap_rva + 120:
        break

pe.close()
