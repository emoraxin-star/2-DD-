import struct

dll = open(r'C:\Users\emora\OneDrive\Desktop\EXCLUSIONS\LiberTea!\LIBERTEA.DLL', 'rb').read()
gt = open(r'C:\Users\emora\OneDrive\Desktop\2\data\.text_unpacked_mem.bin', 'rb').read()

COMP_START = 0x400
COMP_END = 0x70330
TEXT_SIZE = 0x354000
compressed_full = dll[COMP_START:COMP_END]

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
                if self.iters > 1000000:
                    return "too_many"
                bit = self.getbit()
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
                                    if ctrl == 1: break
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
                        self.last_off = eax_s >> 1
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
                                    if ctrl == 1: break
                                self.prev_len = (self.prev_len + 2) & 0xFFFFFFFF
                    if self.last_off < -0x500:
                        self.prev_len = (self.prev_len + 3) & 0xFFFFFFFF
                    else:
                        self.prev_len = (self.prev_len + 2) & 0xFFFFFFFF
                    copy_len = max(self.prev_len, 1)
                    copy_src = len(self.out) + self.last_off
                    if copy_src < 0:
                        return f"neg_{copy_src}"
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
            return f"exc_{e}"
        return "ended"

# Brute force offsets 0-32
print("=== Brute force starting offsets ===")
for off in range(33):
    comp = compressed_full[off:]
    if len(comp) < 4:
        continue
    d = Decomp(comp)
    result = d.decompress(max_bytes=128)
    
    ml = 0
    for i in range(min(len(d.out), len(gt))):
        if d.out[i] == gt[i]:
            ml += 1
        else:
            break
    
    if ml > 0 or off < 5:
        print(f"  off={off:3d}: {len(d.out):4d} bytes, match={ml:3d}, result={result}, first={' '.join(f'{b:02X}' for b in d.out[:8])}")

# Also check: what if the first dword is a SIZE header?
print("\n=== Check if first 4 bytes encode decompressed size ===")
d_le = struct.unpack('<I', compressed_full[0:4])[0]
d_be = struct.unpack('>I', compressed_full[0:4])[0]
print(f"  LE: {d_le} (0x{d_le:08X})")
print(f"  BE: {d_be} (0x{d_be:08X})")
print(f"  Expected: {TEXT_SIZE} (0x{TEXT_SIZE:08X})")

# Check the 2nd .rsrc section  
print("\n=== Second .rsrc section ===")
rsrc2 = dll[0x70800:0x70800+0x42600]
print(f"  Size: {len(rsrc2)} bytes")
print(f"  First 32: {' '.join(f'{b:02X}' for b in rsrc2[:32])}")

# Check if there's a standard aPLib header
print("\n=== Check for aPLib signatures ===")
for i in range(min(256, len(compressed_full))):
    # Standard aPLib: first byte is 0x01 (signature "a")
    if compressed_full[i] == 0x01 and i+4 < len(compressed_full):
        size_le = struct.unpack('<I', compressed_full[i+1:i+5])[0]
        if size_le == TEXT_SIZE:
            print(f"  Found aPLib header at offset {i}: sig=0x{compressed_full[i]:02X}, size={size_le} (MATCH!)")
        elif abs(size_le - TEXT_SIZE) < 1000:
            print(f"  Near match at offset {i}: sig=0x{compressed_full[i]:02X}, size={size_le}")
