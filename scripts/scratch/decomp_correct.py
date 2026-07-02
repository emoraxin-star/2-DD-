import struct
import sys

dll = open(r'C:\Users\emora\OneDrive\Desktop\EXCLUSIONS\LiberTea!\LIBERTEA.DLL', 'rb').read()
gt = open(r'C:\Users\emora\OneDrive\Desktop\2\data\.text_unpacked_mem.bin', 'rb').read()

# The correct compressed data starts at file offset 0x5400
# (.rsrc1 VA=0x355000, RawOff=0x400, decompressor rsi=RVA 0x35A000 = .rsrc1+0x5000 = file 0x5400)
CORRECT_OFFSET = 0x5400
# .rsrc1 ends at file offset 0x400 + 0x70400 = 0x70800
# But the decompressor code is near the end of .rsrc1 (RVA 0x3C4F30)
# The compressed data should span from 0x5400 to somewhere before the decompressor code
# .rsrc1 ends at RVA 0x3C6000, file 0x70800
# But the decompressor is at RVA 0x3C4F30, which is file 0x70330
# So compressed data: file 0x5400 to 0x70330
COMP_END = 0x70330
TEXT_SIZE = 0x354000

compressed = bytearray(dll[CORRECT_OFFSET:COMP_END])
print(f"Compressed data: offset 0x{CORRECT_OFFSET:X} to 0x{COMP_END:X}, size={len(compressed)} bytes")
print(f"First 32 bytes: {' '.join(f'{b:02X}' for b in compressed[:32])}")
print()

# Check first dword
d = struct.unpack('<I', compressed[0:4])[0]
print(f"First dword: 0x{d:08X}")
# MSB-first bits
bits_str = f'{d:032b}'
print(f"MSB-first: {bits_str}")
count = 0
for i in range(32):
    if d & (1 << (31-i)):
        count += 1
    else:
        break
print(f"Leading 1-bits: {count}")
print()

# Now try decompressing
class Decomp:
    def __init__(self, data):
        self.data = data
        self.src = 0
        self.bits = 0
        self.dl = 0
        self.out = bytearray()
        self.prev_len = 0
        self.last_off = -1
        self.iters = 0
        if len(data) > 0:
            self.dl = data[0]
    
    def getbit(self):
        cf = (self.bits >> 31) & 1
        self.bits = (self.bits << 1) & 0xFFFFFFFF
        if self.bits == 0:
            if self.src + 3 >= len(self.data):
                self.bits, self.dl = 0, 0
                return 0
            self.bits = (self.data[self.src] | 
                        (self.data[self.src+1] << 8) | 
                        (self.data[self.src+2] << 16) | 
                        (self.data[self.src+3] << 24))
            self.src += 4
            new_cf = (self.bits >> 31) & 1
            self.bits = ((self.bits << 1) | cf) & 0xFFFFFFFF
            if self.src < len(self.data):
                self.dl = self.data[self.src]
            else:
                self.dl = 0
            return new_cf
        return cf
    
    def decompress(self, max_bytes=256):
        try:
            while self.src < len(self.data) and len(self.out) < max_bytes:
                self.iters += 1
                if self.iters > 10000000:
                    return "too_many"
                
                bit = self.getbit()
                
                if self.iters <= 30:
                    print(f"  [{self.iters}] bit={bit} src={self.src} bits=0x{self.bits:08X} dl=0x{self.dl:02X} out={len(self.out)}")
                
                if bit == 1:
                    self.src += 1
                    self.out.append(self.dl)
                    if self.src < len(self.data):
                        self.dl = self.data[self.src]
                    else:
                        self.dl = 0
                else:
                    eax = self.prev_len + 1
                    b1 = self.getbit()
                    eax = (eax << 1) | b1
                    stop = self.getbit()
                    
                    while stop == 0:
                        eax -= 1
                        b0 = self.getbit()
                        eax = (eax << 1) | b0
                        b1 = self.getbit()
                        eax = (eax << 1) | b1
                        stop = self.getbit()
                    
                    eax -= 3
                    
                    if eax < 0:
                        bit2 = self.getbit()
                        if bit2 == 1:
                            b = self.getbit()
                            self.prev_len = (self.prev_len << 1) | b
                        else:
                            self.prev_len = (self.prev_len + 1) & 0xFFFFFFFF
                            bit3 = self.getbit()
                            if bit3 == 1:
                                b = self.getbit()
                                self.prev_len = (self.prev_len << 1) | b
                            else:
                                while True:
                                    b = self.getbit()
                                    self.prev_len = (self.prev_len << 1) | b
                                    ctrl = self.getbit()
                                    if ctrl == 1:
                                        break
                                self.prev_len = (self.prev_len + 2) & 0xFFFFFFFF
                    else:
                        eax = ((eax & 0xFFFFFFFF) << 8) | self.dl
                        self.src += 1
                        eax ^= 0xFFFFFFFF
                        
                        if eax == 0:
                            return "done_term"
                        
                        eax_32 = eax & 0xFFFFFFFF
                        if eax_32 >= 0x80000000:
                            eax_s = eax_32 - 0x100000000
                        else:
                            eax_s = eax_32
                        lsb = eax_s & 1
                        eax_s >>= 1
                        self.last_off = eax_s
                        
                        if lsb == 1:
                            b = self.getbit()
                            self.prev_len = (self.prev_len << 1) | b
                        else:
                            self.prev_len = (self.prev_len + 1) & 0xFFFFFFFF
                            bit3 = self.getbit()
                            if bit3 == 1:
                                b = self.getbit()
                                self.prev_len = (self.prev_len << 1) | b
                            else:
                                while True:
                                    b = self.getbit()
                                    self.prev_len = (self.prev_len << 1) | b
                                    ctrl = self.getbit()
                                    if ctrl == 1:
                                        break
                                self.prev_len = (self.prev_len + 2) & 0xFFFFFFFF
                    
                    if self.last_off < -0x500:
                        self.prev_len = (self.prev_len + 3) & 0xFFFFFFFF
                    else:
                        self.prev_len = (self.prev_len + 2) & 0xFFFFFFFF
                    
                    copy_len = max(self.prev_len, 1)
                    copy_src = len(self.out) + self.last_off
                    
                    if copy_src < 0:
                        return f"neg_copy_{copy_src}_iter{self.iters}"
                    
                    if self.iters <= 30:
                        print(f"  [{self.iters}] MATCH off={self.last_off} len={copy_len} src={copy_src}")
                    
                    for _ in range(copy_len):
                        if copy_src < len(self.out):
                            self.out.append(self.out[copy_src])
                        else:
                            self.out.append(0)
                        copy_src += 1
                    
                    if self.src < len(self.data):
                        self.dl = self.data[self.src]
                    else:
                        self.dl = 0
        except Exception as e:
            return f"exception_{e}"
        return "ended"

d = Decomp(compressed)
result = d.decompress(max_bytes=256)
print(f"\nResult: {result}")
print(f"Output: {len(d.out)} bytes, iters: {d.iters}")
if len(d.out) > 0:
    print(f"First 64 bytes:")
    for i in range(0, min(64, len(d.out)), 16):
        hex_str = ' '.join(f'{b:02X}' for b in d.out[i:i+16])
        gt_hex = ' '.join(f'{b:02X}' for b in gt[i:i+16])
        match = all(d.out[j] == gt[j] for j in range(i, min(i+16, min(len(d.out), len(gt)))))
        print(f"  {i:04X}: {hex_str:<48} {'OK' if match else 'DIFF'}")
        print(f"  GT:   {gt_hex}")
