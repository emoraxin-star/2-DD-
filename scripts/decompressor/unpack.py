import struct
import sys

with open(r'C:\Users\emora\OneDrive\Desktop\EXCLUSIONS\LiberTea!\LIBERTEA.DLL', 'rb') as f:
    dll = f.read()

COMP_START = 0x400
COMP_END = 0x70330
TEXT_SIZE = 0x354000

compressed = bytearray(dll[COMP_START:COMP_END])
output = bytearray()

src = 0
bits = 0
dl = 0

def getbit():
    global src, bits, dl
    cf = (bits >> 31) & 1
    bits = (bits << 1) & 0xFFFFFFFF
    if bits == 0:
        if src + 3 >= len(compressed):
            bits, dl = 0, 0
            return 0
        bits = compressed[src] | (compressed[src+1] << 8) | (compressed[src+2] << 16) | (compressed[src+3] << 24)
        src += 4
        new_cf = (bits >> 31) & 1
        bits = ((bits << 1) | cf) & 0xFFFFFFFF
        if src < len(compressed):
            dl = compressed[src]
        else:
            dl = 0
        return new_cf
    return cf

def getbit_inline():
    global src, bits, dl
    cf = (bits >> 31) & 1
    bits = (bits << 1) & 0xFFFFFFFF
    if bits == 0:
        if src + 3 >= len(compressed):
            bits, dl = 0, 0
            return 0
        bits = compressed[src] | (compressed[src+1] << 8) | (compressed[src+2] << 16) | (compressed[src+3] << 24)
        src += 4
        new_cf = (bits >> 31) & 1
        bits = ((bits << 1) | cf) & 0xFFFFFFFF
        if src < len(compressed):
            dl = compressed[src]
        else:
            dl = 0
        return new_cf
    return cf

prev_len = 0
last_offset = -1

# Preload first byte (main loop: mov dl, [rsi])
if len(compressed) > 0:
    dl = compressed[0]

phase1_done = False
iteration = 0

try:
    while not phase1_done and src < len(compressed):
        iteration += 1
        if iteration > 10000000:
            print(f"ERROR: too many iterations ({iteration}), output={len(output)}")
            break

        if iteration <= 30:
            print(f"  [{iteration}] START: src={src}, out_len={len(output)}, bits=0x{bits:08X}, dl=0x{dl:02X}, prev_len={prev_len}")

        bit = getbit_inline()

        if iteration <= 30:
            print(f"  [{iteration}] bit={bit}, after: src={src}, bits=0x{bits:08X}, dl=0x{dl:02X}")

        if bit == 1:
            # LITERAL: inc rsi; mov [rdi], dl; inc rdi; mov dl, [rsi]
            src += 1
            output.append(dl)
            if src < len(compressed):
                dl = compressed[src]
            else:
                dl = 0
            if iteration <= 30:
                print(f"  [{iteration}] LITERAL: out+={chr(output[-1]) if 32<=output[-1]<127 else '?'}(0x{output[-1]:02X}), src={src}, dl=0x{dl:02X}")
        else:
            # MATCH: decode length
            # lea eax, [rcx + 1]
            eax = prev_len + 1

            # First pass: jmp LENGTH_LOOP_ENTRY (skips dec eax + first call r11)
            # Only 1 data bit (via call r11) + stop bit
            b1 = getbit()
            eax = (eax << 1) | b1
            stop_bit = getbit_inline()

            # Subsequent passes: dec eax + 2 data bits + stop bit
            while stop_bit == 0:
                eax -= 1
                b0 = getbit()
                eax = (eax << 1) | b0
                b1 = getbit()
                eax = (eax << 1) | b1
                stop_bit = getbit_inline()

            eax -= 3

            if eax < 0:
                # SHORT MATCH
                bit2 = getbit_inline()
                if bit2 == 1:
                    b = getbit()
                    prev_len = (prev_len << 1) | b
                else:
                    prev_len = (prev_len + 1) & 0xFFFFFFFF
                    bit3 = getbit_inline()
                    if bit3 == 1:
                        b = getbit()
                        prev_len = (prev_len << 1) | b
                    else:
                        while True:
                            b = getbit()
                            prev_len = (prev_len << 1) | b
                            ctrl = getbit_inline()
                            if ctrl == 1:
                                break
                        prev_len = (prev_len + 2) & 0xFFFFFFFF
            else:
                # LONG MATCH
                eax = ((eax & 0xFFFFFFFF) << 8) | dl
                src += 1
                eax ^= 0xFFFFFFFF

                if eax == 0:
                    phase1_done = True
                    print(f"Phase 1 done at iter {iteration}, output={len(output)}, src={src}")
                    break

                # sar eax, 1
                eax_32 = eax & 0xFFFFFFFF
                if eax_32 >= 0x80000000:
                    eax_signed = eax_32 - 0x100000000
                else:
                    eax_signed = eax_32
                lsb = eax_signed & 1
                eax_signed = eax_signed >> 1
                last_offset = eax_signed

                if lsb == 1:
                    b = getbit()
                    prev_len = (prev_len << 1) | b
                else:
                    prev_len = (prev_len + 1) & 0xFFFFFFFF
                    bit3 = getbit_inline()
                    if bit3 == 1:
                        b = getbit()
                        prev_len = (prev_len << 1) | b
                    else:
                        while True:
                            b = getbit()
                            prev_len = (prev_len << 1) | b
                            ctrl = getbit_inline()
                            if ctrl == 1:
                                break
                        prev_len = (prev_len + 2) & 0xFFFFFFFF

            if phase1_done:
                break

            # COPY_SETUP_B
            if last_offset < -0x500:
                prev_len = (prev_len + 3) & 0xFFFFFFFF
            else:
                prev_len = (prev_len + 2) & 0xFFFFFFFF

            copy_len = prev_len
            if copy_len == 0:
                copy_len = 1

            # COPY_MATCH
            copy_src = len(output) + last_offset

            if copy_src < 0:
                print(f"ERROR: neg copy src {copy_src} iter {iteration}, off={last_offset}, len={copy_len}, out_len={len(output)}")
                break

            if copy_len <= 5 or last_offset > -4:
                for _ in range(copy_len):
                    if copy_src < len(output):
                        output.append(output[copy_src])
                    else:
                        output.append(0)
                    copy_src += 1
            else:
                ecx = (copy_len - 4) & 0xFFFFFFFF
                while True:
                    for _ in range(4):
                        if copy_src < len(output):
                            output.append(output[copy_src])
                        else:
                            output.append(0)
                        copy_src += 1
                    ecx_prev = ecx
                    ecx = (ecx - 4) & 0xFFFFFFFF
                    if ecx_prev < 4:
                        break
                ecx = (ecx + 4) & 0xFFFFFFFF
                while ecx > 0:
                    if copy_src < len(output):
                        output.append(output[copy_src])
                    else:
                        output.append(0)
                    copy_src += 1
                    ecx -= 1

            if iteration <= 30:
                print(f"  [{iteration}] MATCH: off={last_offset}, len={copy_len}, out_len={len(output)}")

            # Preload next byte for main loop
            if src < len(compressed):
                dl = compressed[src]
            else:
                dl = 0

except Exception as e:
    print(f"Exception: {e}")
    import traceback
    traceback.print_exc()

print(f"\nDecompressed: {len(output)} bytes (expected {TEXT_SIZE})")
print(f"Raw src position: {src}/{len(compressed)}")

with open(r'C:\Users\emora\OneDrive\Desktop\2\.text_decompressed.bin', 'wb') as f:
    f.write(bytes(output))

if len(output) >= 128:
    print(f"\nFirst 128 bytes:")
    for i in range(0, 128, 16):
        hex_str = ' '.join(f'{b:02X}' for b in output[i:i+16])
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in output[i:i+16])
        print(f'  {i:04X}: {hex_str:<48} {ascii_str}')
