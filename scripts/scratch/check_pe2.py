import struct
import pefile
from capstone import *

dll_path = r'C:\Users\emora\OneDrive\Desktop\EXCLUSIONS\LiberTea!\LIBERTEA.DLL'
dll = open(dll_path, 'rb').read()
pe = pefile.PE(dll_path)

print(f'ImageBase: 0x{pe.OPTIONAL_HEADER.ImageBase:X}')
print(f'Entry: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}')
print()

for section in pe.sections:
    name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    va = section.VirtualAddress
    size = section.Misc_VirtualSize
    raw_off = section.PointerToRawData
    raw_size = section.SizeOfRawData
    print(f'{name:8s}: VA=0x{va:08X} VSize=0x{size:08X} RawOff=0x{raw_off:08X} RawSize=0x{raw_size:08X}')

print()

# Key insight: the decompressor at 0x3C4F30 is in .rsrc1 (VA 0x355000)
# It does: lea rsi, [rip - 0x6FF53] → rsi = 0x35A000
# This is an RVA in the process address space
# .rsrc1 maps file offset 0x400 → VA 0x355000
# So VA 0x35A000 = file offset 0x400 + (0x35A000 - 0x355000) = 0x400 + 0x5000 = 0x5400

# BUT WAIT: this DLL is packed. The .rsrc section in the packed DLL contains
# the bootstrap + compressed data. When the packer loads the DLL:
# 1. Maps the DLL into memory
# 2. Executes the bootstrap (TLS callback or DllMain)
# 3. Bootstrap decompresses .text section
# 4. Fixes up imports
# 5. Jumps to original entry point

# The bootstrap is NOT at the entry point. It's likely a TLS callback.
# Let me check for TLS directory

if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
    print('TLS directory found!')
    tls = pe.DIRECTORY_ENTRY_TLS
    print(f'  StartAddressOfRawData: 0x{tls.struct.StartAddressOfRawData:X}')
    print(f'  EndAddressOfRawData: 0x{tls.struct.EndAddressOfRawData:X}')
    print(f'  AddressOfIndex: 0x{tls.struct.AddressOfIndex:X}')
    print(f'  AddressOfCallBacks: 0x{tls.struct.AddressOfCallBacks:X}')
    print(f'  SizeOfZeroFill: {tls.struct.SizeOfZeroFill}')
    print(f'  Characteristics: 0x{tls.struct.Characteristics:X}')
    
    # The TLS callbacks are pointers. Let me read them.
    # AddressOfCallBacks is an RVA to an array of RVAs
    cb_rva = tls.struct.AddressOfCallBacks
    # Convert to file offset
    cb_file = None
    for section in pe.sections:
        name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
        if section.VirtualAddress <= cb_rva < section.VirtualAddress + section.Misc_VirtualSize:
            cb_file = cb_rva - section.VirtualAddress + section.PointerToRawData
            break
    
    if cb_file:
        print(f'  Callbacks file offset: 0x{cb_file:X}')
        i = 0
        while True:
            cb_ptr = struct.unpack('<Q', dll[cb_file + i*8:cb_file + (i+1)*8])[0]
            if cb_ptr == 0:
                break
            # Convert to RVA
            cb_rva_val = cb_ptr - pe.OPTIONAL_HEADER.ImageBase if pe.OPTIONAL_HEADER.ImageBase else cb_ptr
            print(f'  Callback {i}: VA=0x{cb_ptr:X}, RVA=0x{cb_rva_val:X}')
            i += 1
else:
    print('No TLS directory')

# Also check for delay load imports (some packers use these)
print()

# Let me also check the actual bootstrap. The conversation says it's at RVA 0x3B3B50.
# But the .rsrc section starts at VA 0x355000, so 0x3B3B50 = 0x355000 + 0x5EB50
# That's file offset 0x400 + 0x5EB50 = 0x5EF50
bootstrap_rva = 0x3B3B50
bootstrap_file = 0x5EF50  # approximate

# But wait, let me check if this is within .rsrc1
rsrc1_va = 0x355000
rsrc1_size = 0x71000
if rsrc1_va <= bootstrap_rva < rsrc1_va + rsrc1_size:
    bootstrap_file = bootstrap_rva - rsrc1_va + 0x400
    print(f'Bootstrap at RVA 0x{bootstrap_rva:X}, file offset 0x{bootstrap_file:X}')
    
    data = dll[bootstrap_file:bootstrap_file+256]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    print('\nBootstrap disassembly (first 256 bytes):')
    for inst in md.disasm(data, bootstrap_rva):
        hb = ' '.join(f'{b:02X}' for b in inst.bytes)
        print(f'  0x{inst.address:06X}: {hb:<40} {inst.mnemonic} {inst.op_str}')
        if inst.address >= bootstrap_rva + 250:
            break

# Let me also look for the REAL packer entry point
# Some packers use the entry point RVA as the bootstrap
print(f'\n=== Entry point code ===')
entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
# Find which section contains it
for section in pe.sections:
    name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    if section.VirtualAddress <= entry_rva < section.VirtualAddress + section.Misc_VirtualSize:
        entry_file = entry_rva - section.VirtualAddress + section.PointerToRawData
        print(f'Entry RVA 0x{entry_rva:X} is in {name} at file offset 0x{entry_file:X}')
        data = dll[entry_file:entry_file+256]
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for inst in md.disasm(data, entry_rva):
            hb = ' '.join(f'{b:02X}' for b in inst.bytes)
            print(f'  0x{inst.address:06X}: {hb:<40} {inst.mnemonic} {inst.op_str}')
            if inst.address >= entry_rva + 100:
                break
        break

pe.close()
