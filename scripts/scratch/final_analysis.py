"""
Key analysis: The decompressor at 0x3C4F30 is the DLL entry point (DllMain).
It reads compressed data from rsi=0x35A000 (file offset 0x5400).
Our Python decompressor reads from file offset 0x400, which is WRONG.
The 5-byte coincidence match is because compressed[4:9] = 48 83 EC 28 E8 = ground truth[0:5].

The REAL compressed data at offset 0x5400 starts with 2D 01 C6 00...
which does NOT produce correct output with our current bit reading.

This means either:
1. The bit reading semantics are different from what we implemented
2. There's an initial state we're not modeling (preloaded ebx?)
3. The compressed data pointer is different from what the lea computes

Let me trace the ACTUAL assembly flow step by step to find the issue.
"""
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

# The entry point at 0x3C4F30:
# 0x3C4F30: mov [rsp+8], rcx      ; save hinst
# 0x3C4F35: mov [rsp+10h], rdx    ; save reason
# 0x3C4F3A: mov [rsp+18h], r8     ; save reserved
# 0x3C4F3F: cmp dl, 1             ; DLL_PROCESS_ATTACH?
# 0x3C4F42: jne 0x3c51b4          ; if not, skip to DllMain return
# 0x3C4F48-4B: push rbx, rsi, rdi, rbp
# 0x3C4F4C: lea rsi, [rip-0x6ff53]  ; rsi = 0x35A000
# 0x3C4F53: lea rdi, [rsi-0x354000] ; rdi = 0x6000
# 0x3C4F5A: push rdi                 ; save output ptr
# 0x3C4F5B: xor ebx, ebx             ; ebx = 0
# 0x3C4F5D: xor ecx, ecx             ; ecx = 0 (prev_len)
# 0x3C4F5F: or rbp, -1               ; rbp = -1 (last_offset)
# 0x3C4F63: call 0x3c4fb8            ; setup r11 = getbit function

# The call at 0x3C4F63 calls 0x3C4FB8:
# 0x3C4FB8: cld
# 0x3C4FB9: pop r11       ; r11 = 0x3C4F68 (return addr)
# 0x3C4FBB: jmp 0x3c4fc5  ; enter main loop

# Main loop at 0x3C4FC5:
# 0x3C4FC5: mov dl, [rsi]       ; preload byte
# 0x3C4FC7: add ebx, ebx        ; shift left
# 0x3C4FC9: jne 0x3c4fd5        ; if ebx != 0, skip reload
# 0x3C4FCB: mov ebx, [rsi]      ; reload 4 bytes
# 0x3C4FCD: sub rsi, -4         ; rsi += 4
# 0x3C4FD1: adc ebx, ebx        ; shift left with CF
# 0x3C4FD3: mov dl, [rsi]       ; preload next byte
# 0x3C4FD5: jb 0x3c4fbd         ; CF=1 -> LITERAL

# Wait! There's a subtlety I missed.
# When ebx=0 initially:
# 1. mov dl, [rsi] -> dl = compressed[0]
# 2. add ebx, ebx -> ebx = 0, CF = 0
# 3. jne not taken
# 4. mov ebx, [rsi] -> ebx = compressed[0:4] = dword at [rsi]
# 5. sub rsi, -4 -> rsi += 4
# 6. adc ebx, ebx -> ebx = 2*ebx + CF(from step 2) = 2*dword + 0
# 7. mov dl, [rsi] -> dl = compressed[4]
# 8. jb -> test CF from step 6

# BUT: in step 4, mov ebx, [rsi] loads from [rsi] which is STILL the original rsi!
# Because step 5 (rsi += 4) happens AFTER step 4.
# So ebx gets the dword at the ORIGINAL rsi position.

# Step 6: adc ebx, ebx
# This shifts ebx left by 1, adding the CF from step 2 (which is 0).
# So: ebx = 2 * dword + 0
# CF from this = MSB of (2*dword) = bit 30 of dword (NOT bit 31!)

# Wait, that's wrong. Let me re-trace:
# step 2: add ebx, ebx -> CF = MSB of original ebx (0) = 0
# step 4: mov ebx, [rsi] -> ebx = dword (e.g., 0xFFFF6FF6)
# step 6: adc ebx, ebx -> ebx = ebx + ebx + CF = 2*dword + 0
#         CF = carry from bit 31

# For dword = 0xFFFF6FF6:
# 2 * 0xFFFF6FF6 = 0x1FFEDFEC
# CF = 1 (carry out of bit 31)
# ebx = 0xFFFEDFEC (truncated to 32 bits)

# So the first bit extracted is CF = 1 (from the adc).
# This is the MSB of the dword shifted left by 1.

# Hmm, but this is the same as what our Python implementation does.
# The Python does: bits = (dword << 1 | 0) & 0xFFFFFFFF, returns new_cf = MSB of dword.
# The assembly does: ebx = 2*dword + 0, CF = MSB of result.

# For dword = 0xFFFF6FF6:
# Python: bits = 0xFFFEDFEC, returns 1 (MSB of 0xFFFF6FF6)
# Assembly: ebx = 0xFFFEDFEC, CF = 1 (carry from 2*0xFFFF6FF6)

# These agree! The first bit is 1.

# Now the second iteration:
# ebx = 0xFFFEDFEC
# step 2: add ebx, ebx -> ebx = 0xFFFDBFD8, CF = 1 (MSB of 0xFFFEDFEC)
# step 3: jne taken (ebx != 0)
# step 8: jb -> CF = 1 -> LITERAL

# Python: cf = 1 (MSB of 0xFFFEDFEC), bits = 0xFFFDBFD8
# Assembly: CF = 1 from add ebx, ebx

# These also agree!

# So the bit extraction is correct. The issue must be with the DATA, not the algorithm.

# Let me check: what if there's a SECOND section of compressed data?
# The .rsrc2 section starts at VA 0x3C6000, file offset 0x70800
# What if the decompressor reads from .rsrc2?

# rsi = 0x35A000 is definitely in .rsrc1, not .rsrc2.

# What if there's a relocation that changes the lea instruction?
# Some packers modify their own code at runtime.

# Let me check: are there any relocations that affect the decompressor code?
print("=== Checking for relocations in decompressor area ===")
# Search for relocation entries that affect RVA 0x3C4F4C (the lea instruction)
# Relocation table is usually in .reloc section
for section in pe.sections:
    name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    print(f"  {name}: VA=0x{section.VirtualAddress:X}, Size=0x{section.Misc_VirtualSize:X}")

# Check if there's a .reloc section
has_reloc = False
for section in pe.sections:
    name = section.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    if name == '.reloc':
        has_reloc = True
        print(f"\n  .reloc found! VA=0x{section.VirtualAddress:X}, RawOff=0x{section.PointerToRawData:X}")
        
        # Parse relocation directory
        reloc_off = section.PointerToRawData
        reloc_data = dll[reloc_off:reloc_off + section.SizeOfRawData]
        
        # Look for relocations in the 0x3C4xxx range
        # (RVA 0x3C4F4C would be the lea instruction)
        target_rva = 0x3C4F4C
        page_rva = target_rva & 0xFFFFF000
        offset_in_page = target_rva & 0xFFF
        
        # Search for the page
        pos = 0
        while pos + 8 <= len(reloc_data):
            pva = struct.unpack('<I', reloc_data[pos:pos+4])[0]
            block_size = struct.unpack('<I', reloc_data[pos+4:pos+8])[0]
            if block_size == 0:
                break
            
            num_entries = (block_size - 8) // 2
            if pva == page_rva:
                print(f"  Found page 0x{page_rva:X} with {num_entries} entries")
                for i in range(num_entries):
                    entry = struct.unpack('<H', reloc_data[pos+8+i*2:pos+10+i*2])[0]
                    entry_type = entry >> 12
                    entry_offset = entry & 0xFFF
                    if entry_offset == offset_in_page:
                        print(f"    Relocation at RVA 0x{target_rva:X}: type={entry_type}")
            
            pos += block_size

if not has_reloc:
    print("  No .reloc section found")

# Alternative: check if the PE has IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
print(f"\n  DLL characteristics: 0x{pe.OPTIONAL_HEADER.DllCharacteristics:04X}")
print(f"  DYNAMIC_BASE: {bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x40)}")

# Check if there are any TLS callbacks that might modify memory
print(f"\n  TLS AddressOfCallBacks: 0x{pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks else 0:X}")

# Final check: what if the lea instruction is patched at runtime?
# Let me check if the instruction bytes match what we decoded
decomp_file = 0x3C4F30 - rsrc.VirtualAddress + rsrc.PointerToRawData
lea_file = decomp_file + (0x3C4F4C - 0x3C4F30)
print(f"\n  Raw bytes at 0x3C4F4C: {' '.join(f'{b:02X}' for b in dll[lea_file:lea_file+7])}")
print(f"  Expected: 48 8D 35 AD 00 F9 FF")

pe.close()
