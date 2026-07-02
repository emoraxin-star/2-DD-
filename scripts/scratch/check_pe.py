import struct
import pefile

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
    print(f'          VA range: 0x{pe.OPTIONAL_HEADER.ImageBase+va:08X} - 0x{pe.OPTIONAL_HEADER.ImageBase+va+size:08X}')

print()

# The decompressor at RVA 0x3C4F30 does:
# lea rsi, [rip - 0x6FF53]
# RIP after instruction = 0x3C4F53
# EA = 0x3C4F53 + (-0x6FF53) = 0x35A000
#
# But this is a VA. With ImageBase, the actual address would be ImageBase + 0x35A000.
# However, RIP-relative addressing uses VA, not RVA. So rsi = 0x35A000 (as a VA).
#
# If ImageBase = 0 (ASLR), then VA = RVA, and rsi = 0x35A000.
# If ImageBase != 0, then VA = ImageBase + RVA, and the instruction would compute differently.
#
# Wait, RIP-relative addressing always uses the actual VA at runtime.
# The displacement is encoded in the instruction, and at runtime:
# EA = RIP + displacement
# where RIP is the actual VA of the next instruction.
#
# If ImageBase = 0x10000000 (for example):
# The instruction at file offset 0x70330 corresponds to RVA 0x3C4F30.
# At runtime, it's loaded at VA 0x10000000 + 0x3C4F30 = 0x103C4F30.
# RIP after instruction = 0x103C4F53.
# EA = 0x103C4F53 + (-0x6FF53) = 0x1035A000.
# In memory, VA 0x1035A000 corresponds to RVA 0x35A000.
# So rsi points to RVA 0x35A000 regardless of ImageBase!
# (Because the displacement compensates for the ImageBase.)

print('=== RVA mapping ===')
print(f'Decompressor rsi RVA = 0x35A000')
print()

# .rsrc1: VA(RVA)=0x355000, RawOff=0x400
# rsi RVA 0x35A000 = .rsrc1 + 0x5000
# File offset = 0x400 + 0x5000 = 0x5400

# BUT: maybe the lea instruction is NOT part of the decompressor.
# Let me check if 0x3C4F30 is really the decompressor entry point.
# The conversation says "bootstrap stub at RVA 0x3B3B50 calls decompressor at 0x3C4F30"
# But maybe 0x3C4F30 is a different function.

# Let me check what's at the entry point
entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
print(f'Entry point RVA: 0x{entry_rva:X}')

# Also check: the .rsrc section might contain resource data before the compressed payload
# Let me look at the resource directory structure at the start of .rsrc

# The first .rsrc starts at file offset 0x400, VA 0x355000
rsrc_start = 0x400
print(f'\n=== Resource directory at file offset 0x{rsrc_start:X} ===')
# IMAGE_RESOURCE_DIRECTORY
Characteristics = struct.unpack('<I', dll[rsrc_start:rsrc_start+4])[0]
TimeDateStamp = struct.unpack('<I', dll[rsrc_start+4:rsrc_start+8])[0]
MajorVer = struct.unpack('<H', dll[rsrc_start+8:rsrc_start+10])[0]
MinorVer = struct.unpack('<H', dll[rsrc_start+10:rsrc_start+12])[0]
NamedEntries = struct.unpack('<H', dll[rsrc_start+12:rsrc_start+14])[0]
IDEntries = struct.unpack('<H', dll[rsrc_start+14:rsrc_start+16])[0]
print(f'Characteristics: 0x{Characteristics:08X}')
print(f'TimeDateStamp: 0x{TimeDateStamp:08X}')
print(f'Version: {MajorVer}.{MinorVer}')
print(f'Named entries: {NamedEntries}')
print(f'ID entries: {IDEntries}')

# Print first few resource directory entries
offset = rsrc_start + 16
for i in range(IDEntries):
    Id = struct.unpack('<I', dll[offset:offset+4])[0]
    DataOrDir = struct.unpack('<I', dll[offset+4:offset+8])[0]
    is_dir = bool(DataOrDir & 0x80000000)
    if is_dir:
        print(f'  Entry {i}: Id=0x{Id:X}, Subdirectory at offset 0x{DataOrDir & 0x7FFFFFFF:X}')
    else:
        print(f'  Entry {i}: Id=0x{Id:X}, Data at offset 0x{DataOrDir:X}')
    offset += 8

# Check: what's the size of the resource directory?
# It should be relatively small (a few hundred bytes at most)
# The compressed data should come after it

# Let me scan for the compressed data start signature
# Standard aPLib starts with 0x01 "a" but this is custom
# The original extraction used COMP_START=0x400 and COMP_END=0x70330
# Total: 0x70330 - 0x400 = 0x70000 - 0x30 = 0x6FF30 = 458,544 - 48 = ...

# Actually, COMP_END was 0x70330 which is the start of the second .rsrc section
# So the compressed data spans file offset 0x400 to 0x70330

# Let me check: does the bootstrap pass the compressed data pointer, or does the decompressor hardcode it?
# Bootstrap at RVA 0x3B3B50:
# The bootstrap calls the decompressor. What arguments does it pass?

# Let me look at what calls 0x3C4F30
print('\n=== Looking for call to 0x3C4F30 ===')
# Search for E8 xx xx xx xx where target = 0x3C4F30
target = 0x3C4F30
for i in range(len(dll) - 5):
    if dll[i] == 0xE8:
        offset_val = struct.unpack('<i', dll[i+1:i+5])[0]
        call_target = i + 5 + offset_val  # approximate, need to account for RVA vs file offset
        # Actually, the call target is RVA-based, not file offset based
        # We need to convert file offset to RVA
        # But this is complex. Let me just search in the .rsrc area.

# Better approach: search in the .rsrc file range
rsrc_file_start = 0x400
rsrc_file_end = 0x70400
for i in range(rsrc_file_start, rsrc_file_end - 5):
    if dll[i] == 0xE8:  # call rel32
        rel = struct.unpack('<i', dll[i+1:i+5])[0]
        # File offset to RVA conversion
        # For first .rsrc: RVA = file_offset - 0x400 + 0x355000
        caller_rva = i - 0x400 + 0x355000
        target_rva = caller_rva + 5 + rel
        if target_rva == 0x3C4F30:
            print(f'  Found call at file offset 0x{i:X} (RVA 0x{caller_rva:X})')
            # Print context
            context_start = max(rsrc_file_start, i-16)
            context = dll[context_start:i+20]
            for inst in Cs(CS_ARCH_X86, CS_MODE_64).disasm(context, i - 0x400 + 0x355000 - (i - context_start)):
                pass  # too complex, just print raw bytes
            print(f'    Context: {" ".join(f"{b:02X}" for b in dll[i-8:i+8])}')

# Also search for jmp to 0x3C4F30
for i in range(rsrc_file_start, rsrc_file_end - 5):
    if dll[i] == 0xE9:  # jmp rel32
        rel = struct.unpack('<i', dll[i+1:i+5])[0]
        caller_rva = i - 0x400 + 0x355000
        target_rva = caller_rva + 5 + rel
        if target_rva == 0x3C4F30:
            print(f'  Found jmp at file offset 0x{i:X} (RVA 0x{caller_rva:X})')

# Search in .rsrc2 as well
rsrc2_start = 0x70800
rsrc2_end = rsrc2_start + 0x42600
for i in range(rsrc2_start, rsrc2_end - 5):
    if dll[i] == 0xE8:
        rel = struct.unpack('<i', dll[i+1:i+5])[0]
        caller_file_off = i
        # .rsrc2: RVA = file_offset - 0x70800 + 0x3C6000
        caller_rva = i - 0x70800 + 0x3C6000
        target_rva = caller_rva + 5 + rel
        if target_rva == 0x3C4F30:
            print(f'  Found call at file offset 0x{i:X} (RVA 0x{caller_rva:X})')

from capstone import *
pe.close()
