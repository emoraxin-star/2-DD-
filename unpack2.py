"""
Simplified aPLib fast decompressor.
Based on assembly analysis and standard aPLib depacks.asm.
Key: bit=1 = literal, bit=0 = match
"""
import struct

with open(r'C:\Users\emora\OneDrive\Desktop\EXCLUSIONS\LiberTea!\LIBERTEA.DLL', 'rb') as f:
    dll = f.read()

COMP_START = 0x400
COMP_END = 0x70330
TEXT_SIZE = 0x354000
compressed = dll[COMP_START:COMP_END]

# Fast decompressor state
src = bytearray(compressed)
rsi = 0     # source pointer
rdi = 0     # dest index (into output list)
ebx = 0     # bit buffer
ebp = -1    # last offset (signed)
ecx = 0     # length carryover
output = bytearray()
dl = 0      # preload byte

def getbit():
    """call r11: return CF (0 or 1)"""
    global rsi, ebx, dl
    # add ebx, ebx
    cf = (ebx >> 31) & 1
    ebx = (ebx << 1) & 0xFFFFFFFF
    if ebx == 0:
        # refill
        if rsi + 3 >= len(src):
            ebx = 0
            return 0
        ebx = src[rsi] | (src[rsi+1] << 8) | (src[rsi+2] << 16) | (src[rsi+3] << 24)
        rsi += 4
        # adc ebx, ebx
        new_cf = (ebx >> 31) & 1
        ebx = ((ebx << 1) | cf) & 0xFFFFFFFF
        # preload next byte
        dl = src[rsi] if rsi < len(src) else 0
        return new_cf
    return cf

# Preload first byte: main loop does mov dl, [rsi]
dl = src[rsi] if rsi < len(src) else 0

iteration = 0
max_iter = 500000

def debug(msg):
    pass  # disable debug for speed

try:
    while rsi < len(src):
        iteration += 1
        if iteration > max_iter:
            print(f"MAX ITER at {iteration}")
            break

        # GETBIT for literal/match decision
        bit = getbit()

        if bit == 1:
            # LITERAL
            rsi += 1
            output.append(dl)
            dl = src[rsi] if rsi < len(src) else 0
        else:
            # MATCH
            # Decode offset (gamma): start from ecx + 1
            # Standard aPLib style: 1 bit per iter, stop=1 exits
            eax = ecx + 1
            
            # Gamma loop: read bit, shift in, check stop
            while True:
                b = getbit()
                eax = (eax << 1) | b
                stop = getbit()
                if stop == 1:
                    break

            eax -= 3

            if eax < 0:
                # SHORT MATCH - offset uses last_offset
                ecx = (ecx + 1) & 0xFFFFFFFF
                b = getbit()
                if b == 1:
                    b2 = getbit()
                    ecx = (ecx << 1) | b2
                else:
                    while True:
                        b2 = getbit()
                        ecx = (ecx << 1) | b2
                        ctrl = getbit()
                        if ctrl == 1:
                            break
                    ecx = (ecx + 2) & 0xFFFFFFFF
            else:
                # LONG MATCH - explicit offset
                eax = ((eax & 0xFFFFFFFF) << 8) | dl
                rsi += 1
                eax ^= 0xFFFFFFFF
                
                if eax == 0:
                    print(f"DONE at iter {iteration}, output={len(output)}")
                    break

                # sar eax, 1 → rbp
                eax32 = eax & 0xFFFFFFFF
                if eax32 >= 0x80000000:
                    eaxs = eax32 - 0x100000000
                else:
                    eaxs = eax32
                lsb = eaxs & 1
                eaxs >>= 1
                ebp = eaxs

                if lsb == 1:
                    b = getbit()
                    ecx = (ecx << 1) | b
                else:
                    ecx = (ecx + 1) & 0xFFFFFFFF
                    b = getbit()
                    if b == 1:
                        b2 = getbit()
                        ecx = (ecx << 1) | b2
                    else:
                        while True:
                            b2 = getbit()
                            ecx = (ecx << 1) | b2
                            ctrl = getbit()
                            if ctrl == 1:
                                break
                        ecx = (ecx + 2) & 0xFFFFFFFF

            # COPY_SETUP_B
            ecx_before = ecx
            if ebp < -0x500:
                ecx = (ecx + 3) & 0xFFFFFFFF
            else:
                ecx = (ecx + 2) & 0xFFFFFFFF

            copy_len = ecx
            if copy_len == 0:
                copy_len = 1

            copy_src = len(output) + ebp
            if copy_src < 0 or copy_len > 10000000:
                print(f"BAD: off={ebp}, len={copy_len}, out={len(output)}, iter={iteration}")
                print(f"  ecx_before={ecx_before}, eaxs after sar={eaxs}")
                break

            if copy_len <= 5 or ebp > -4:
                for _ in range(copy_len):
                    b = output[copy_src] if copy_src < len(output) else 0
                    output.append(b)
                    copy_src += 1
            else:
                ecx_rem = (copy_len - 4) & 0xFFFFFFFF
                while True:
                    for _ in range(4):
                        b = output[copy_src] if copy_src < len(output) else 0
                        output.append(b)
                        copy_src += 1
                    prev = ecx_rem
                    ecx_rem = (ecx_rem - 4) & 0xFFFFFFFF
                    if prev < 4:
                        break
                ecx_rem = (ecx_rem + 4) & 0xFFFFFFFF
                while ecx_rem > 0:
                    b = output[copy_src] if copy_src < len(output) else 0
                    output.append(b)
                    copy_src += 1
                    ecx_rem -= 1

            # Preload next byte for main loop
            dl = src[rsi] if rsi < len(src) else 0

        if iteration % 50000 == 0:
            print(f"  iter {iteration}: output={len(output)}, rsi={rsi}")

except Exception as e:
    print(f"EXC: {e}")
    import traceback
    traceback.print_exc()

print(f"\nDone: {len(output)} bytes")
# Save
with open(r'C:\Users\emora\OneDrive\Desktop\2\.text_decompressed.bin', 'wb') as f:
    f.write(bytes(output))

if len(output) >= 64:
    print("\nFirst 128 bytes:")
    for i in range(0, min(128, len(output)), 16):
        h = ' '.join(f'{b:02X}' for b in output[i:i+16])
        print(f'  {i:04X}: {h}')
