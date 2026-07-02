import struct
from capstone import *

dll = open(r'C:\Users\emora\OneDrive\Desktop\EXCLUSIONS\LiberTea!\LIBERTEA.DLL', 'rb').read()
gt = open(r'C:\Users\emora\OneDrive\Desktop\2\data\.text_unpacked_mem.bin', 'rb').read()

import pefile
pe = pefile.PE(r'C:\Users\emora\OneDrive\Desktop\EXCLUSIONS\LiberTea!\LIBERTEA.DLL')

rsrc = None
for section in pe.sections:
    name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    if name == '.rsrc':
        rsrc = section
        break

# Disassemble the FULL decompressor function (0x3C4F30 to 0x3C51B4)
decomp_rva = 0x3C4F30
decomp_file = decomp_rva - rsrc.VirtualAddress + rsrc.PointerToRawData
data = dll[decomp_file:decomp_file+0x290]  # ~656 bytes

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

print("=== FULL DECOMPRESSOR DISASSEMBLY ===")
for inst in md.disasm(data, decomp_rva):
    hb = ' '.join(f'{b:02X}' for b in inst.bytes)
    # Highlight key instructions
    marker = ""
    if inst.mnemonic in ('jb', 'jne', 'je', 'jae', 'ja'):
        marker = " <<<< BRANCH"
    elif 'ebx' in inst.op_str and inst.mnemonic in ('add', 'adc'):
        marker = " <<<< BIT OP"
    elif inst.mnemonic == 'call':
        marker = " <<<< CALL"
    elif inst.mnemonic in ('ret', 'repz ret'):
        marker = " <<<< RETURN"
    print(f'  0x{inst.address:06X}: {hb:<40} {inst.mnemonic} {inst.op_str}{marker}')
    if inst.address >= 0x3C51B4:
        break

# Now focus on the key section: the LITERAL vs MATCH decision
# and the getbit function
print("\n=== KEY OBSERVATIONS ===")
print("1. Entry point at 0x3C4F30 IS the decompressor (confirmed)")
print("2. lea rsi, [rip-0x6FF53] → rsi = RVA 0x35A000")
print("3. lea rdi, [rsi - 0x354000] → rdi = RVA 0x6000")
print("4. xor ebx, ebx → bits = 0")
print("5. call 0x3C4FB8 → sets up r11 = getbit function")
print()
print("6. The getbit loop at 0x3C4FC5:")
print("   mov dl, [rsi]     ; preload byte")
print("   add ebx, ebx      ; shift left, CF = MSB")
print("   jne .has_bits     ; if non-zero, skip reload")
print("   mov ebx, [rsi]    ; reload 4 bytes")
print("   sub rsi, -4       ; rsi += 4")
print("   adc ebx, ebx      ; shift left with CF")
print("   mov dl, [rsi]     ; preload next byte")
print("   .has_bits:")
print("   jb .literal       ; CF=1 → LITERAL, CF=0 → MATCH")
print()
print("7. CRITICAL: the entry point function signature is:")
print("   void __fastcall Decompress(HINSTANCE hinst, DWORD reason, LPVOID reserved)")
print("   rcx = DLL base (0x180000000)")
print("   rdx = 1 (DLL_PROCESS_ATTACH)")
print("   r8 = reserved")
print()

# Check if the bootstrap stub might do something BEFORE calling the decompressor
# The entry point IS the decompressor - there's no separate bootstrap
# But maybe there's TLS or other init

# Check the second .rsrc section for any code
rsrc2 = None
for section in pe.sections:
    name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    if section.VirtualAddress == 0x3C6000:
        rsrc2 = section
        break

if rsrc2:
    print(f"\n=== Second .rsrc section ===")
    print(f"VA=0x{rsrc2.VirtualAddress:X}, RawOff=0x{rsrc2.PointerToRawData:X}, RawSize=0x{rsrc2.SizeOfRawData:X}")
    
    # Check what's at the start
    rsrc2_data = dll[rsrc2.PointerToRawData:rsrc2.PointerToRawData+32]
    print(f"First 32 bytes: {' '.join(f'{b:02X}' for b in rsrc2_data)}")
    
    # Disassemble first few instructions
    print("First instructions:")
    for inst in md.disasm(rsrc2_data, rsrc2.VirtualAddress):
        hb = ' '.join(f'{b:02X}' for b in inst.bytes)
        print(f'  0x{inst.address:06X}: {hb:<40} {inst.mnemonic} {inst.op_str}')
        if inst.address >= rsrc2.VirtualAddress + 30:
            break

# Check: the decompressor at 0x3C4F30 is within .rsrc1
# .rsrc1: VA=0x355000, VSize=0x71000, ends at 0x3C6000
# Decompressor at 0x3C4F30 is 0x1930 bytes from the end of .rsrc1
# So the decompressor is AT THE END of .rsrc1, near the boundary with .rsrc2

# The compressed data pointer (0x35A000) is near the START of .rsrc1
# This means the compressed data is at .rsrc1+0x5000, and the decompressor code is at .rsrc1+0x6FF30

# Let me check: is the data at .rsrc1+0x5000 (file offset 0x5400) the actual compressed data?
# Or is there a resource directory that we need to parse first?

# Check the resource directory at .rsrc1 start
print("\n=== Resource directory at .rsrc1 start ===")
rsrc1_data = dll[0x400:0x420]
print(f"First 32 bytes: {' '.join(f'{b:02X}' for b in rsrc1_data)}")

# IMAGE_RESOURCE_DIRECTORY
chars = struct.unpack('<I', rsrc1_data[0:4])[0]
stamp = struct.unpack('<I', rsrc1_data[4:8])[0]
maj = struct.unpack('<H', rsrc1_data[8:10])[0]
min = struct.unpack('<H', rsrc1_data[10:12])[0]
named = struct.unpack('<H', rsrc1_data[12:14])[0]
ids = struct.unpack('<H', rsrc1_data[14:16])[0]
print(f"Named entries: {named}, ID entries: {ids}")

# Print ID entries
for i in range(min(ids, 20)):
    entry_off = 16 + i * 8
    if entry_off + 8 > len(rsrc1_data):
        break
    eid = struct.unpack('<I', rsrc1_data[entry_off:entry_off+4])[0]
    data_or_dir = struct.unpack('<I', rsrc1_data[entry_off+4:entry_off+8])[0]
    is_dir = bool(data_or_dir & 0x80000000)
    print(f"  Entry {i}: ID=0x{eid:X}, {'Dir' if is_dir else 'Data'} offset=0x{data_or_dir & 0x7FFFFFFF:X}")

pe.close()
