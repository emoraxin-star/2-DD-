"""
Dynamic analysis: Load DLL, dump .rsrc from memory, compare with file.
The ground truth was extracted via LoadLibrary + memory dump, meaning
the decompressor works at runtime. The question is: what does the
decompressor actually read from memory at rsi=0x355000?
"""
import ctypes
import ctypes.wintypes
import struct
import hashlib

dll_path = r"C:\Users\emora\OneDrive\Desktop\EXCLUSIONS\LiberTea!\LIBERTEA.DLL"

kernel32 = ctypes.windll.kernel32

# Load the DLL
print("Loading DLL...")
hmod = kernel32.LoadLibraryW(dll_path)
if not hmod:
    err = kernel32.GetLastError()
    print(f"LoadLibrary failed: {err}")
    exit(1)

print(f"Loaded at base: 0x{hmod:X}")

# Get module info to find sections
class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", ctypes.c_ulong),
        ("EntryPoint", ctypes.c_void_p),
    ]

import psapi
psapi = ctypes.windll.psapi
mi = MODULEINFO()
if not psapi.GetModuleInformation(kernel32.GetCurrentProcess(), hmod, ctypes.byref(mi), ctypes.sizeof(mi)):
    print("GetModuleInformation failed")
else:
    print(f"Base: 0x{mi.lpBaseOfDll:X}, Size: 0x{mi.SizeOfImage:X}, Entry: 0x{mi.EntryPoint:X}")

# Parse PE headers to find .rsrc section
# The DLL is already mapped in memory at hmod
# Read DOS header
dos_hdr = ctypes.string_at(hmod, 64)
pe_offset = struct.unpack('<I', dos_hdr[0x3C:0x40])[0]
print(f"PE header at offset 0x{pe_offset:X}")

# Read PE header
pe_hdr = ctypes.string_at(hmod + pe_offset, 248)
machine, num_sections, _, _, _, _, opt_hdr_size = struct.unpack('<HHIIIHH', pe_hdr[:20])
print(f"Machine: 0x{machine:X}, Sections: {num_sections}, OptHdr: {opt_hdr_size}")

# Read optional header
opt_hdr = ctypes.string_at(hmod + pe_offset + 24, opt_hdr_size)
magic = struct.unpack('<H', opt_hdr[:2])[0]
print(f"Magic: 0x{magic:X} ({'PE32+' if magic==0x20B else 'PE32'})")

# Section headers start after optional header
section_base = hmod + pe_offset + 24 + opt_hdr_size
for i in range(num_sections):
    sec_hdr = ctypes.string_at(section_base + i * 40, 40)
    name = sec_hdr[:8].rstrip(b'\x00').decode('ascii', errors='replace')
    vsize, vaddr, size, raw_ptr, _, _, _, chars = struct.unpack('<IIIIIIII', sec_hdr[8:40])
    print(f"  {name}: VA=0x{vaddr:08X} VSize=0x{vsize:08X} Raw=0x{raw_ptr:08X} Size=0x{size:08X} Char=0x{chars:08X}")

# Now dump the .rsrc section from memory
# .rsrc1 at VA 0x355000 (relative to image base)
# Image base = hmod
rsrc1_va = hmod + 0x355000
rsrc1_vsize = 0x71000

print(f"\nDumping .rsrc1 from memory at VA 0x{rsrc1_va:X}...")
mem_data = ctypes.string_at(rsrc1_va, rsrc1_vsize)

# Compare with file
with open(dll_path, 'rb') as f:
    file_data = f.read()

file_rsrc1 = file_data[0x400:0x400+0x70400]

print(f"Memory .rsrc1 size: {len(mem_data)}")
print(f"File .rsrc1 size: {len(file_rsrc1)}")

# Check first 64 bytes
print(f"\nMemory .rsrc1[0:64]: {' '.join(f'{b:02X}' for b in mem_data[:64])}")
print(f"File .rsrc1[0:64]:   {' '.join(f'{b:02X}' for b in file_rsrc1[:64])}")

# Check if they match
if mem_data == file_rsrc1:
    print("\n*** MEMORY AND FILE .rsrc1 ARE IDENTICAL ***")
else:
    print("\n*** MEMORY AND FILE .rsrc1 DIFFER ***")
    for i in range(min(len(mem_data), len(file_rsrc1))):
        if mem_data[i] != file_rsrc1[i]:
            print(f"  First diff at offset 0x{i:X}: mem=0x{mem_data[i]:02X} file=0x{file_rsrc1[i]:02X}")
            break

# Also check the decompressor's source pointer: rsi = 0x355000 + 0x5000 = 0x35A000
# Wait, earlier we computed lea rsi, [rip-0x6FF53] -> rsi = 0x355000
# Let me re-verify: the instruction is at RVA 0x3C4F4C
# RIP after = 0x3C4F53
# disp = -0x6FF53
# rsi = 0x3C4F53 - 0x6FF53 = 0x355000
# So rsi = image_base + 0x355000 = start of .rsrc1

# The compressed data starts at .rsrc1 start (offset 0x400 in file)
# Let me check what the decompressor actually reads

# Let's dump from the decompressor's perspective
comp_start_mem = rsrc1_va  # 0x355000
comp_data_mem = ctypes.string_at(comp_start_mem, 256)
print(f"\nMemory at decompressor rsi (0x355000): {' '.join(f'{b:02X}' for b in comp_data_mem[:32])}")

# Also check at offset 0x5000 within .rsrc (where the OLD analysis said rsi points)
comp_start_mem2 = rsrc1_va + 0x5000
comp_data_mem2 = ctypes.string_at(comp_start_mem2, 256)
print(f"Memory at rsi+0x5000 (0x35A000): {' '.join(f'{b:02X}' for b in comp_data_mem2[:32])}")

kernel32.FreeLibrary(hmod)