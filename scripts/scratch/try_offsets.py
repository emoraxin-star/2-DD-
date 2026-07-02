import struct
import sys

dll = open(r'C:\Users\emora\OneDrive\Desktop\EXCLUSIONS\LiberTea!\LIBERTEA.DLL', 'rb').read()
gt = open(r'C:\Users\emora\OneDrive\Desktop\2\data\.text_unpacked_mem.bin', 'rb').read()

COMP_START = 0x400
COMP_END = 0x70330
TEXT_SIZE = 0x354000

compressed_full = dll[COMP_START:COMP_END]

class Decompressor:
    def __init__(self, data):
        self.compressed = data
        self.src = 0
        self.bits = 0
        self.dl = 0
        self.output = bytearray()
        self.prev_len = 0
        self.last_offset = -1
        self.iteration = 0
        if len(data) > 0:
            self.dl = data[0]
    
    def getbit(self):
        cf = (self.bits >> 31) & 1
        self.bits = (self.bits << 1) & 0xFFFFFFFF
        if self.bits == 0:
            if self.src + 3 >= len(self.compressed):
                self.bits, self.dl = 0, 0
                return 0
            self.bits = (self.compressed[self.src] | 
                        (self.compressed[self.src+1] << 8) | 
                        (self.compressed[self.src+2] << 16) | 
                        (self.compressed[self.src+3] << 24))
            self.src += 4
            new_cf = (self.bits >> 31) & 1
            self.bits = ((self.bits << 1) | cf) & 0xFFFFFFFF
            if self.src < len(self.compressed):
                self.dl = self.compressed[self.src]
            else:
                self.dl = 0
            return new_cf
        return cf
    
    def decompress(self, max_bytes=TEXT_SIZE, trace=False):
        try:
            while self.src < len(self.compressed) and len(self.output) < max_bytes:
                self.iteration += 1
                if self.iteration > 10000000:
                    return "too_many_iterations"
                
                bit = self.getbit()
                
                if trace and self.iteration <= 20:
                    print(f"  [{self.iteration}] bit={bit} src={self.src} bits=0x{self.bits:08X} dl=0x{self.dl:02X} out={len(self.output)}")
                
                if bit == 1:
                    self.src += 1
                    self.output.append(self.dl)
                    if self.src < len(self.compressed):
                        self.dl = self.compressed[self.src]
                    else:
                        self.dl = 0
                else:
                    eax = self.prev_len + 1
                    b1 = self.getbit()
                    eax = (eax << 1) | b1
                    stop_bit = self.getbit()
                    
                    while stop_bit == 0:
                        eax -= 1
                        b0 = self.getbit()
                        eax = (eax << 1) | b0
                        b1 = self.getbit()
                        eax = (eax << 1) | b1
                        stop_bit = self.getbit()
                    
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
                            return "done_normal"
                        
                        eax_32 = eax & 0xFFFFFFFF
                        if eax_32 >= 0x80000000:
                            eax_signed = eax_32 - 0x100000000
                        else:
                            eax_signed = eax_32
                        lsb = eax_signed & 1
                        eax_signed = eax_signed >> 1
                        self.last_offset = eax_signed
                        
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
                    
                    if self.last_offset < -0x500:
                        self.prev_len = (self.prev_len + 3) & 0xFFFFFFFF
                    else:
                        self.prev_len = (self.prev_len + 2) & 0xFFFFFFFF
                    
                    copy_len = self.prev_len
                    if copy_len == 0:
                        copy_len = 1
                    
                    copy_src = len(self.output) + self.last_offset
                    
                    if copy_src < 0:
                        return f"neg_copy_src_{copy_src}"
                    
                    for _ in range(copy_len):
                        if copy_src < len(self.output):
                            self.output.append(self.output[copy_src])
                        else:
                            self.output.append(0)
                        copy_src += 1
                    
                    if trace and self.iteration <= 20:
                        print(f"  [{self.iteration}] MATCH: off={self.last_offset} len={copy_len} out={len(self.output)}")
                    
                    if self.src < len(self.compressed):
                        self.dl = self.compressed[self.src]
                    else:
                        self.dl = 0
        
        except Exception as e:
            return f"exception_{e}"
        
        return "ended"

# Try different starting offsets
for stream_start in [0, 4, 8, 12, 16]:
    comp = compressed_full[stream_start:]
    d = Decompressor(comp)
    result = d.decompress(max_bytes=64, trace=(stream_start == 0))
    
    match_len = 0
    for i in range(min(len(d.output), 64)):
        if d.output[i] == gt[i]:
            match_len += 1
        else:
            break
    
    first_diff = match_len
    extra = ""
    if first_diff < min(len(d.output), 64):
        extra = f"got=0x{d.output[first_diff]:02X} exp=0x{gt[first_diff]:02X}"
    
    print(f"  offset={stream_start:3d}: {len(d.output):3d} bytes, match={match_len}, first_diff@{first_diff} {extra}, result={result}, iters={d.iteration}")

# Also try with MSB extraction (bit=1 means match, bit=0 means literal)
print("\n=== With INVERTED bit semantics (bit=0=LITERAL, bit=1=MATCH) ===")
for stream_start in [0, 4]:
    comp = compressed_full[stream_start:]
    d = Decompressor(comp)
    # Monkey-patch to invert
    orig_getbit = d.getbit
    def inv_getbit():
        return 1 - orig_getbit()
    d.getbit = inv_getbit
    result = d.decompress(max_bytes=64)
    
    match_len = 0
    for i in range(min(len(d.output), 64)):
        if d.output[i] == gt[i]:
            match_len += 1
        else:
            break
    
    first_diff = match_len
    extra = ""
    if first_diff < min(len(d.output), 64):
        extra = f"got=0x{d.output[first_diff]:02X} exp=0x{gt[first_diff]:02X}"
    
    print(f"  offset={stream_start:3d}: {len(d.output):3d} bytes, match={match_len}, first_diff@{first_diff} {extra}, result={result}, iters={d.iteration}")

# Try LSB-first extraction
print("\n=== With LSB-first bit extraction ===")
class DecompressorLSB:
    def __init__(self, data):
        self.compressed = data
        self.src = 0
        self.bits = 0
        self.bit_pos = 0
        self.dl = 0
        self.output = bytearray()
        self.prev_len = 0
        self.last_offset = -1
        self.iteration = 0
        if len(data) > 0:
            self.dl = data[0]
    
    def getbit(self):
        if self.bit_pos == 0:
            if self.src + 3 >= len(self.compressed):
                return 0
            self.bits = (self.compressed[self.src] | 
                        (self.compressed[self.src+1] << 8) | 
                        (self.compressed[self.src+2] << 16) | 
                        (self.compressed[self.src+3] << 24))
            self.src += 4
            if self.src < len(self.compressed):
                self.dl = self.compressed[self.src]
            else:
                self.dl = 0
        bit = (self.bits >> self.bit_pos) & 1
        self.bit_pos = (self.bit_pos + 1) & 31
        return bit
    
    def decompress(self, max_bytes=64):
        try:
            while self.src < len(self.compressed) and len(self.output) < max_bytes:
                self.iteration += 1
                if self.iteration > 1000000:
                    return "too_many"
                bit = self.getbit()
                if bit == 1:
                    self.src += 1
                    self.output.append(self.dl)
                    if self.src < len(self.compressed):
                        self.dl = self.compressed[self.src]
                    else:
                        self.dl = 0
                else:
                    return "match_at_" + str(len(self.output))
        except:
            return "exception"
        return "ended"

for stream_start in [0, 4]:
    comp = compressed_full[stream_start:]
    d = DecompressorLSB(comp)
    result = d.decompress()
    match_len = 0
    for i in range(min(len(d.output), 64)):
        if d.output[i] == gt[i]:
            match_len += 1
        else:
            break
    print(f"  offset={stream_start:3d}: {len(d.output):3d} bytes, match={match_len}, result={result}, iters={d.iteration}")
