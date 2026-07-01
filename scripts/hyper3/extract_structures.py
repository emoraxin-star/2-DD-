#!/usr/bin/env python3
"""
HYPER-SPECIALIZED AGENT 3: Data Structure Reconstruction
Extracts struct layouts, vtables, enums, globals, bitfields from unpacked .text
"""

import struct
import re
import os

TEXT_PATH = r"C:\Users\emora\OneDrive\Desktop\2\data\.text_unpacked_mem.bin"

def load_binary():
    with open(TEXT_PATH, "rb") as f:
        return f.read()

def find_all_strings(data):
    """Find all printable ASCII strings 4+ chars"""
    strings = []
    current = b""
    start_off = 0
    for i, b in enumerate(data):
        if 0x20 <= b <= 0x7E:
            if not current:
                start_off = i
            current += bytes([b])
        else:
            if len(current) >= 4:
                strings.append((start_off, current.decode("ascii", errors="replace")))
            current = b""
    return strings

def disasm_at(data, offset, max_len=30):
    """Basic x86-64 disassembly at offset"""
    result = []
    i = offset
    while i < len(data) and len(result) < max_len:
        b = data[i]
        if b == 0x48:  # REX.W prefix
            next_b = data[i+1] if i+1 < len(data) else 0
            if next_b == 0x8B:  # mov r64, r/m
                modrm = data[i+2] if i+2 < len(data) else 0
                mod = (modrm >> 6) & 3
                reg = (modrm >> 3) & 7
                rm = modrm & 7
                if mod == 0:
                    result.append((i, 3, f"mov r{reg}, [r{rm}]"))
                    i += 3
                elif mod == 1:
                    disp = data[i+3] if i+3 < len(data) else 0
                    if disp >= 0x80: disp -= 256
                    result.append((i, 4, f"mov r{reg}, [r{rm}+{disp:#x}]"))
                    i += 4
                elif mod == 2:
                    disp = struct.unpack_from("<i", data, i+3)[0] if i+3 < len(data)-4 else 0
                    result.append((i, 7, f"mov r{reg}, [r{rm}+{disp:#x}]"))
                    i += 7
                elif mod == 3:
                    result.append((i, 3, f"mov r{reg}, r{rm}"))
                    i += 3
                else:
                    i += 1
            elif next_b == 0x89:  # mov r/m64, r64
                modrm = data[i+2] if i+2 < len(data) else 0
                mod = (modrm >> 6) & 3
                reg = (modrm >> 3) & 7
                rm = modrm & 7
                if mod == 0:
                    result.append((i, 3, f"mov [r{rm}], r{reg}"))
                    i += 3
                elif mod == 1:
                    disp = data[i+3] if i+3 < len(data) else 0
                    if disp >= 0x80: disp -= 256
                    result.append((i, 4, f"mov [r{rm}+{disp:#x}], r{reg}"))
                    i += 4
                elif mod == 2:
                    disp = struct.unpack_from("<i", data, i+3)[0] if i+3 < len(data)-4 else 0
                    result.append((i, 7, f"mov [r{rm}+{disp:#x}], r{reg}"))
                    i += 7
                elif mod == 3:
                    result.append((i, 3, f"mov r{rm}, r{reg}"))
                    i += 3
                else:
                    i += 1
            elif next_b == 0x83:  # add/sub/cmp r64, imm8
                if i+3 < len(data):
                    modrm = data[i+2]
                    imm = data[i+3]
                    op = (modrm >> 3) & 7
                    rm = modrm & 7
                    op_name = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"][op]
                    result.append((i, 4, f"{op_name} r{rm}, {imm:#x}"))
                    i += 4
                else:
                    i += 1
            elif next_b == 0xC7:  # mov r/m64, imm32
                modrm = data[i+2] if i+2 < len(data) else 0
                mod = (modrm >> 6) & 3
                rm = modrm & 7
                if mod == 1:
                    disp = data[i+3] if i+3 < len(data) else 0
                    if disp >= 0x80: disp -= 256
                    imm = struct.unpack_from("<I", data, i+4)[0] if i+7 < len(data) else 0
                    result.append((i, 8, f"mov qword [r{rm}+{disp:#x}], {imm:#x}"))
                    i += 8
                elif mod == 2:
                    disp = struct.unpack_from("<i", data, i+3)[0] if i+6 < len(data) else 0
                    imm = struct.unpack_from("<I", data, i+7)[0] if i+10 < len(data) else 0
                    result.append((i, 11, f"mov qword [r{rm}+{disp:#x}], {imm:#x}"))
                    i += 11
                else:
                    i += 1
            elif next_b == 0x8D:  # lea r64, [r/m]
                modrm = data[i+2] if i+2 < len(data) else 0
                mod = (modrm >> 6) & 3
                reg = (modrm >> 3) & 7
                rm = modrm & 7
                if mod == 2:
                    disp = struct.unpack_from("<i", data, i+3)[0] if i+6 < len(data) else 0
                    result.append((i, 7, f"lea r{reg}, [r{rm}+{disp:#x}]"))
                    i += 7
                elif mod == 1:
                    disp = data[i+3] if i+3 < len(data) else 0
                    if disp >= 0x80: disp -= 256
                    result.append((i, 4, f"lea r{reg}, [r{rm}+{disp:#x}]"))
                    i += 4
                else:
                    i += 1
            elif next_b == 0xC1:  # shift r64, imm8
                if i+3 < len(data):
                    modrm = data[i+2]
                    imm = data[i+3]
                    op = (modrm >> 3) & 7
                    rm = modrm & 7
                    op_name = ["rol", "ror", "rcl", "rcr", "shl", "shr", "shl", "sar"][op]
                    result.append((i, 4, f"{op_name} r{rm}, {imm:#x}"))
                    i += 4
                else:
                    i += 1
            else:
                i += 1
        elif b == 0x41 or b == 0x42 or b == 0x43 or b == 0x44 or b == 0x45 or b == 0x46 or b == 0x47:
            # REX.* prefix with R8-R15 access
            if i+1 < len(data) and data[i+1] == 0x8B:  # mov r64, [r/m]
                modrm = data[i+2] if i+2 < len(data) else 0
                mod = (modrm >> 6) & 3
                reg = (modrm >> 3) & 7
                rm = modrm & 7
                if b & 0x04: reg += 8  # REX.R
                if b & 0x01: rm += 8   # REX.B
                if mod == 2 and i+6 < len(data):
                    disp = struct.unpack_from("<i", data, i+3)[0]
                    result.append((i, 7, f"mov r{reg}, [r{rm}+{disp:#x}]"))
                    i += 7
                elif mod == 1:
                    disp = data[i+3] if i+3 < len(data) else 0
                    if disp >= 0x80: disp -= 256
                    result.append((i, 4, f"mov r{reg}, [r{rm}+{disp:#x}]"))
                    i += 4
                else:
                    i += 3
            else:
                i += 1
        elif b == 0x8B:  # mov r32, r/m32
            if i+2 < len(data):
                modrm = data[i+1]
                mod = (modrm >> 6) & 3
                reg = (modrm >> 3) & 7
                rm = modrm & 7
                if mod == 2 and i+5 < len(data):
                    disp = struct.unpack_from("<i", data, i+2)[0]
                    result.append((i, 6, f"mov r{reg}d, [r{rm}+{disp:#x}]"))
                    i += 6
                elif mod == 1:
                    disp = data[i+2] if i+2 < len(data) else 0
                    if disp >= 0x80: disp -= 256
                    result.append((i, 3, f"mov r{reg}d, [r{rm}+{disp:#x}]"))
                    i += 3
                else:
                    i += 3
            else:
                i += 1
        elif b == 0x89:  # mov r/m32, r32
            if i+2 < len(data):
                modrm = data[i+1]
                mod = (modrm >> 6) & 3
                reg = (modrm >> 3) & 7
                rm = modrm & 7
                if mod == 2 and i+5 < len(data):
                    disp = struct.unpack_from("<i", data, i+2)[0]
                    result.append((i, 6, f"mov [r{rm}+{disp:#x}], r{reg}d"))
                    i += 6
                elif mod == 1:
                    disp = data[i+2] if i+2 < len(data) else 0
                    if disp >= 0x80: disp -= 256
                    result.append((i, 3, f"mov [r{rm}+{disp:#x}], r{reg}d"))
                    i += 3
                else:
                    i += 3
            else:
                i += 1
        elif b == 0x83:  # op r/m32, imm8
            if i+3 < len(data):
                modrm = data[i+1]
                imm = data[i+2]
                op = (modrm >> 3) & 7
                rm = modrm & 7
                op_name = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"][op]
                if modrm < 0xC0:  # memory operand
                    result.append((i, 3, f"{op_name} dword [r{rm}], {imm:#x}"))
                else:
                    result.append((i, 3, f"{op_name} r{rm}d, {imm:#x}"))
                i += 3
            else:
                i += 1
        elif b == 0xFF:  # call/jmp/push [r/m]
            if i+1 < len(data):
                modrm = data[i+1]
                rm = modrm & 7
                op = (modrm >> 3) & 7
                mod = (modrm >> 6) & 3
                if mod == 2 and op == 2 and i+5 < len(data):
                    disp = struct.unpack_from("<i", data, i+2)[0]
                    result.append((i, 6, f"call [r{rm}+{disp:#x}]"))
                    i += 6
                elif mod == 0 and rm == 4:
                    # SIB byte
                    if i+3 < len(data):
                        sib = data[i+2]
                        if sib == 0x25:
                            # disp32 only
                            if i+6 < len(data):
                                disp = struct.unpack_from("<i", data, i+3)[0]
                                if op == 2:
                                    result.append((i, 7, f"call [{disp:#x}]"))
                                i += 7
                            else:
                                i += 1
                        else:
                            i += 3
                    else:
                        i += 1
                else:
                    i += 3
            else:
                i += 1
        elif b == 0xE8:  # call rel32
            if i+4 < len(data):
                rel = struct.unpack_from("<i", data, i+1)[0]
                target = i + 5 + rel
                result.append((i, 5, f"call {target:#x}"))
                i += 5
            else:
                i += 1
        elif b == 0xE9:  # jmp rel32
            if i+4 < len(data):
                rel = struct.unpack_from("<i", data, i+1)[0]
                target = i + 5 + rel
                result.append((i, 5, f"jmp {target:#x}"))
                i += 5
            else:
                i += 1
        elif b == 0x0F:
            next_b = data[i+1] if i+1 < len(data) else 0
            if next_b == 0x1F and i+2 < len(data) and data[i+2] == 0x00:
                result.append((i, 3, "nop dword [rax]"))
                i += 3
            elif next_b == 0x1F and i+3 < len(data):
                result.append((i, 4, "nop dword [rax+0]"))
                i += 4
            elif next_b == 0x10 and i+3 < len(data):
                modrm = data[i+2]
                reg = (modrm >> 3) & 7
                rm = modrm & 7
                mod = (modrm >> 6) & 3
                if mod == 2 and i+6 < len(data):
                    disp = struct.unpack_from("<i", data, i+3)[0]
                    result.append((i, 7, f"movups xmm{reg}, [r{rm}+{disp:#x}]"))
                    i += 7
                else:
                    i += 3
            elif next_b == 0x11 and i+3 < len(data):
                modrm = data[i+2]
                reg = (modrm >> 3) & 7
                rm = modrm & 7
                mod = (modrm >> 6) & 3
                if mod == 2 and i+6 < len(data):
                    disp = struct.unpack_from("<i", data, i+3)[0]
                    result.append((i, 7, f"movups [r{rm}+{disp:#x}], xmm{reg}"))
                    i += 7
                else:
                    i += 3
            elif next_b == 0x84:  # conditional jump rel32
                if i+5 < len(data):
                    rel = struct.unpack_from("<i", data, i+2)[0]
                    target = i + 6 + rel
                    result.append((i, 6, f"je {target:#x}"))
                    i += 6
                else:
                    i += 1
            elif next_b == 0x85:  # jne rel32
                if i+5 < len(data):
                    rel = struct.unpack_from("<i", data, i+2)[0]
                    target = i + 6 + rel
                    result.append((i, 6, f"jne {target:#x}"))
                    i += 6
                else:
                    i += 1
            elif next_b == 0xB6:  # movzx r32, r/m8
                if i+2 < len(data):
                    modrm = data[i+2]
                    reg = (modrm >> 3) & 7
                    rm = modrm & 7
                    mod = (modrm >> 6) & 3
                    if mod == 2 and i+5 < len(data):
                        disp = struct.unpack_from("<i", data, i+3)[0]
                        result.append((i, 7, f"movzx r{reg}d, byte [r{rm}+{disp:#x}]"))
                        i += 7
                    else:
                        i += 3
                else:
                    i += 1
            elif next_b == 0xB7:  # movzx r32, r/m16
                if i+2 < len(data):
                    modrm = data[i+2]
                    reg = (modrm >> 3) & 7
                    rm = modrm & 7
                    mod = (modrm >> 6) & 3
                    if mod == 2 and i+5 < len(data):
                        disp = struct.unpack_from("<i", data, i+3)[0]
                        result.append((i, 7, f"movzx r{reg}d, word [r{rm}+{disp:#x}]"))
                        i += 7
                    else:
                        i += 3
                else:
                    i += 1
            else:
                i += 2
        elif b == 0xC7:  # mov r/m32, imm32
            if i+6 < len(data):
                modrm = data[i+1]
                rm = modrm & 7
                mod = (modrm >> 6) & 3
                if mod == 2:
                    disp = struct.unpack_from("<i", data, i+2)[0]
                    imm = struct.unpack_from("<I", data, i+6)[0]
                    result.append((i, 10, f"mov dword [r{rm}+{disp:#x}], {imm:#x}"))
                    i += 10
                elif mod == 1:
                    disp = data[i+2] if i+2 < len(data) else 0
                    if disp >= 0x80: disp -= 256
                    imm = struct.unpack_from("<I", data, i+3)[0] if i+6 < len(data) else 0
                    result.append((i, 7, f"mov dword [r{rm}+{disp:#x}], {imm:#x}"))
                    i += 7
                else:
                    i += 6
            else:
                i += 1
        elif b == 0x90:  # nop
            result.append((i, 1, "nop"))
            i += 1
        elif b == 0xCC:  # int3
            result.append((i, 1, "int3"))
            i += 1
        elif b == 0xC3:  # ret
            result.append((i, 1, "ret"))
            i += 1
        elif b == 0xB8:  # mov eax, imm32
            if i+4 < len(data):
                imm = struct.unpack_from("<I", data, i+1)[0]
                result.append((i, 5, f"mov eax, {imm:#x}"))
                i += 5
            else:
                i += 1
        elif b == 0xC6:  # mov byte [r/m], imm8
            if i+3 < len(data):
                modrm = data[i+1]
                imm = data[i+2]
                mod = (modrm >> 6) & 3
                rm = modrm & 7
                if mod == 2 and i+5 < len(data):
                    disp = struct.unpack_from("<i", data, i+2)[0]
                    result.append((i, 7, f"mov byte [r{rm}+{disp:#x}], {imm:#x}"))
                    i += 7
                elif mod == 1:
                    disp = data[i+2] if i+2 < len(data) else 0
                    if disp >= 0x80: disp -= 256
                    result.append((i, 4, f"mov byte [r{rm}+{disp:#x}], {imm:#x}"))
                    i += 4
                else:
                    i += 3
            else:
                i += 1
        elif b == 0x85:  # test r/m32, r32
            if i+1 < len(data):
                modrm = data[i+1]
                i += 2
            else:
                i += 1
        elif b in (0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57):  # push
            reg = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"][b - 0x50]
            result.append((i, 1, f"push {reg}"))
            i += 1
        elif b in (0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F):  # pop
            reg = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"][b - 0x58]
            result.append((i, 1, f"pop {reg}"))
            i += 1
        elif b >= 0x6A and b <= 0x70 and b != 0x6F:  # push imm8 or conditional jumps
            if b == 0x6A and i+1 < len(data):
                imm = data[i+1]
                result.append((i, 2, f"push {imm:#x}"))
                i += 2
            elif b == 0x74 and i+1 < len(data):
                rel = data[i+1]
                if rel >= 0x80: rel -= 256
                result.append((i, 2, f"je {i+2+rel:#x}"))
                i += 2
            elif b == 0x75 and i+1 < len(data):
                rel = data[i+1]
                if rel >= 0x80: rel -= 256
                result.append((i, 2, f"jne {i+2+rel:#x}"))
                i += 2
            elif b == 0x7E and i+1 < len(data):
                rel = data[i+1]
                if rel >= 0x80: rel -= 256
                result.append((i, 2, f"jle {i+2+rel:#x}"))
                i += 2
            elif b == 0x7D and i+1 < len(data):
                rel = data[i+1]
                if rel >= 0x80: rel -= 256
                result.append((i, 2, f"jge {i+2+rel:#x}"))
                i += 2
            elif b == 0x7C and i+1 < len(data):
                rel = data[i+1]
                if rel >= 0x80: rel -= 256
                result.append((i, 2, f"jl {i+2+rel:#x}"))
                i += 2
            elif b == 0x7F and i+1 < len(data):
                rel = data[i+1]
                if rel >= 0x80: rel -= 256
                result.append((i, 2, f"jg {i+2+rel:#x}"))
                i += 2
            elif b == 0x68 and i+4 < len(data):
                imm = struct.unpack_from("<I", data, i+1)[0]
                result.append((i, 5, f"push {imm:#x}"))
                i += 5
            else:
                i += 2
        elif b >= 0xD8 and b <= 0xDF:
            # FPU instructions (skip for now)
            i += 2
        elif b == 0xF3:  # SSE prefix
            next_b = data[i+1] if i+1 < len(data) else 0
            if next_b == 0x0F:
                b2 = data[i+2] if i+2 < len(data) else 0
                if b2 == 0x10:  # movss xmm, [r/m]
                    modrm = data[i+3] if i+3 < len(data) else 0
                    mod = (modrm >> 6) & 3
                    reg = (modrm >> 3) & 7
                    rm = modrm & 7
                    if mod == 2 and i+7 < len(data):
                        disp = struct.unpack_from("<i", data, i+4)[0]
                        result.append((i, 8, f"movss xmm{reg}, [r{rm}+{disp:#x}]"))
                        i += 8
                    else:
                        i += 4
                elif b2 == 0x11:  # movss [r/m], xmm
                    modrm = data[i+3] if i+3 < len(data) else 0
                    mod = (modrm >> 6) & 3
                    reg = (modrm >> 3) & 7
                    rm = modrm & 7
                    if mod == 2 and i+7 < len(data):
                        disp = struct.unpack_from("<i", data, i+4)[0]
                        result.append((i, 8, f"movss [r{rm}+{disp:#x}], xmm{reg}"))
                        i += 8
                    else:
                        i += 4
                else:
                    i += 4
            else:
                i += 2
        elif b == 0x33:  # xor
            if i+2 < len(data):
                modrm = data[i+1]
                reg = (modrm >> 3) & 7
                rm = modrm & 7
                if reg == rm:
                    result.append((i, 2, f"xor r{reg}d, r{reg}d"))
                i += 2
            else:
                i += 1
        elif b == 0x31:  # xor r/m32, r32
            if i+2 < len(data):
                modrm = data[i+1]
                reg = (modrm >> 3) & 7
                rm = modrm & 7
                if reg == rm:
                    result.append((i, 2, f"xor r{reg}d, r{reg}d"))
                i += 2
            else:
                i += 1
        elif b == 0xC1:  # shift/rotate r/m32, imm8
            if i+3 < len(data):
                modrm = data[i+1]
                i += 3
            else:
                i += 1
        else:
            i += 1
    return result

# ============================================================
# PHASE 1: Extract all RIP-relative LEA addresses (global references)
# ============================================================
def find_rip_relative_addresses(data):
    """
    lea rX, [rip + offset] pattern: 48 8D 0D XX XX XX XX (or 48 8D 15/1D/05/3D...)
    This finds all global/static data references
    """
    results = []
    i = 0
    while i < len(data) - 7:
        # 48 8D XX XX XX XX XX - REX.W LEA
        if data[i] == 0x48 and data[i+1] == 0x8D:
            modrm = data[i+2]
            mod = (modrm >> 6) & 3
            reg = (modrm >> 3) & 7
            rm = modrm & 7
            # RIP-relative: mod=00, rm=101
            if mod == 0 and rm == 5:
                disp = struct.unpack_from("<i", data, i+3)[0]
                target = i + 7 + disp
                reg_names = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
                results.append((i, 7, target, f"lea {reg_names[reg]}, [rip-{(-disp) if disp<0 else disp:#x}]"))
                i += 7
            else:
                i += 3
        else:
            i += 1
    return results

def find_mov_rip_relative(data):
    """
    mov rCX, [rip+offset] pattern: 48 8B 0D XX XX XX XX (and other reg variants)
    This finds direct loads from global data
    """
    results = []
    i = 0
    while i < len(data) - 7:
        if data[i] == 0x48 and data[i+1] == 0x8B:
            modrm = data[i+2]
            mod = (modrm >> 6) & 3
            reg = (modrm >> 3) & 7
            rm = modrm & 7
            if mod == 0 and rm == 5:
                disp = struct.unpack_from("<i", data, i+3)[0]
                target = i + 7 + disp
                reg_names = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
                results.append((i, 7, target, f"mov {reg_names[reg]}, [rip-{(-disp) if disp<0 else disp:#x}]"))
                i += 7
            else:
                i += 3
        else:
            i += 1
    return results

# ============================================================
# PHASE 2: Extract struct offset patterns from mov/cmp instructions
# ============================================================
def analyze_struct_offsets(data, start_offset=0x000000, end_offset=0x0B8000):
    """Scan code region for member access patterns: [reg+offset]"""
    
    offset_usage = {}  # offset -> list of (rva, instruction_hint)
    offset_dword_usage = {}  # offset -> list for dword-sized accesses
    offset_byte_usage = {}
    offset_qword_usage = {}
    offset_float_usage = {}
    
    # Pattern matching for memory offsets
    for off in range(start_offset, min(end_offset, len(data)) - 10, 1):
        b = data[off]
        
        # 48 8B XX XX XX XX XX — REX.W mov r64, [reg + disp32] (REG=01 if rm=1XX)
        # 48 89 XX XX XX XX XX — REX.W mov [reg + disp32], r64
        if b == 0x48:
            next_b = data[off+1]
            if next_b in (0x8B, 0x89):
                modrm = data[off+2]
                mod = (modrm >> 6) & 3
                reg_val = (modrm >> 3) & 7
                rm = modrm & 7
                if mod == 2:  # disp32
                    if off + 7 <= len(data):
                        disp = struct.unpack_from("<i", data, off+3)[0]
                        if 0 <= disp < 0x2000 and disp % 1 == 0:
                            if next_b == 0x8B:
                                insn = f"mov r{reg_val}, [r{rm}+{disp:#x}]"
                            else:
                                insn = f"mov [r{rm}+{disp:#x}], r{reg_val}"
                            if disp not in offset_qword_usage:
                                offset_qword_usage[disp] = []
                            offset_qword_usage[disp].append((off, insn))
    
            # 48 C7 XX XX XX XX XX XX XX XX — REX.W mov [reg + disp8], imm32
            elif next_b == 0xC7:
                modrm = data[off+2]
                mod = (modrm >> 6) & 3
                rm = modrm & 7
                if mod == 1:  # disp8
                    disp = data[off+3] if off+3 < len(data) else 0
                    if disp >= 0x80: disp -= 256
                    imm = struct.unpack_from("<I", data, off+4)[0] if off+8 <= len(data) else 0
                    insn = f"mov qword [r{rm}+{disp:#x}], {imm:#x}"
                    if disp not in offset_qword_usage:
                        offset_qword_usage[disp] = []
                    offset_qword_usage[disp].append((off, insn))
                elif mod == 2:
                    disp = struct.unpack_from("<i", data, off+3)[0]
                    imm = struct.unpack_from("<I", data, off+7)[0] if off+11 <= len(data) else 0
                    if 0 <= disp < 0x2000:
                        insn = f"mov qword [r{rm}+{disp:#x}], {imm:#x}"
                        if disp not in offset_qword_usage:
                            offset_qword_usage[disp] = []
                        offset_qword_usage[disp].append((off, insn))
    
        # 41 XX REX.B prefixed — handle separately
        elif b in (0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47):
            # 41 8B XX XX XX XX XX — mov r32, [r8-r15 + disp32]
            if off+1 < len(data) and data[off+1] in (0x8B, 0x89):
                modrm = data[off+2]
                mod = (modrm >> 6) & 3
                reg_val = (modrm >> 3) & 7
                rm = modrm & 7
                if b & 0x01: rm += 8
                if mod == 2 and off+7 <= len(data):
                    disp = struct.unpack_from("<i", data, off+3)[0]
                    if 0 <= disp < 0x2000:
                        if data[off+1] == 0x8B:
                            insn = f"mov r{reg_val}d, [r{rm}+{disp:#x}]"
                        else:
                            insn = f"mov [r{rm}+{disp:#x}], r{reg_val}d"
                        if disp not in offset_dword_usage:
                            offset_dword_usage[disp] = []
                        offset_dword_usage[disp].append((off, insn))
        
        # 8B XX XX XX XX XX — mov r32, [r/m + disp32]
        elif b == 0x8B:
            modrm = data[off+1] if off+1 < len(data) else 0
            mod = (modrm >> 6) & 3
            reg_val = (modrm >> 3) & 7
            rm = modrm & 7
            if mod == 2 and off+6 <= len(data):
                disp = struct.unpack_from("<i", data, off+2)[0]
                if 0 <= disp < 0x2000:
                    insn = f"mov r{reg_val}d, [r{rm}+{disp:#x}]"
                    if disp not in offset_dword_usage:
                        offset_dword_usage[disp] = []
                    offset_dword_usage[disp].append((off, insn))
        
        # 89 XX XX XX XX XX — mov [r/m + disp32], r32
        elif b == 0x89:
            modrm = data[off+1] if off+1 < len(data) else 0
            mod = (modrm >> 6) & 3
            reg_val = (modrm >> 3) & 7
            rm = modrm & 7
            if mod == 2 and off+6 <= len(data):
                disp = struct.unpack_from("<i", data, off+2)[0]
                if 0 <= disp < 0x2000:
                    insn = f"mov [r{rm}+{disp:#x}], r{reg_val}d"
                    if disp not in offset_dword_usage:
                        offset_dword_usage[disp] = []
                    offset_dword_usage[disp].append((off, insn))
                    
        # C7 XX XX XX XX XX XX XX XX XX — mov dword [r/m + disp32], imm32
        elif b == 0xC7:
            modrm = data[off+1] if off+1 < len(data) else 0
            mod = (modrm >> 6) & 3
            rm = modrm & 7
            if mod == 2 and off+10 <= len(data):
                disp = struct.unpack_from("<i", data, off+2)[0]
                imm = struct.unpack_from("<I", data, off+6)[0]
                if 0 <= disp < 0x2000:
                    insn = f"mov dword [r{rm}+{disp:#x}], {imm:#x}"
                    if disp not in offset_dword_usage:
                        offset_dword_usage[disp] = []
                    offset_dword_usage[disp].append((off, insn))
        
        # F3 0F 10 XX — movss xmm, [r/m32] (float load)
        # F3 0F 11 XX — movss [r/m32], xmm (float store)
        elif b == 0xF3 and off+1 < len(data) and data[off+1] in (0x0F,):
            b2 = data[off+2] if off+2 < len(data) else 0
            if b2 in (0x10, 0x11) and off+3 < len(data):
                modrm = data[off+3]
                mod = (modrm >> 6) & 3
                reg_val = (modrm >> 3) & 7
                rm = modrm & 7
                if mod == 2 and off+7 <= len(data):
                    disp = struct.unpack_from("<i", data, off+4)[0]
                    if 0 <= disp < 0x2000:
                        if b2 == 0x10:
                            insn = f"movss xmm{reg_val}, [r{rm}+{disp:#x}]"
                        else:
                            insn = f"movss [r{rm}+{disp:#x}], xmm{reg_val}"
                        if disp not in offset_float_usage:
                            offset_float_usage[disp] = []
                        offset_float_usage[disp].append((off, insn))
    
    return {
        "qword": offset_qword_usage,
        "dword": offset_dword_usage,
        "byte": offset_byte_usage,
        "float": offset_float_usage
    }

# ============================================================
# PHASE 3: Find VTable references
# ============================================================
def find_vtable_references(data):
    """
    Look for vtable patterns:
    1. LEA RCX, [RIP+VTABLE_offset] — loading vtable address into a register
    2. CALL [RAX+0xNN] or call [RCX+0xNN] — virtual function calls
    3. RTTI TypeDescriptor strings
    """
    
    vtable_calls = []
    rtti_strings = []
    
    # Find virtual calls: FF 50 XX (call [rax+XX]), FF 51 XX (call [rcx+XX]), etc.
    for off in range(0, len(data) - 3):
        if data[off] == 0xFF:
            modrm = data[off+1]
            reg_val = (modrm >> 3) & 7
            rm = modrm & 7
            mod = (modrm >> 6) & 3
            # call [reg + disp8]: mod=01, rm=000(rax),001(rcx),010(rdx),...
            if mod == 1 and (reg_val == 2 or reg_val == 2):
                disp = data[off+2] if off+2 < len(data) else 0
                if disp >= 0x80: disp -= 256
                reg_names = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
                reg_name = reg_names[rm]
                vtable_calls.append((off, disp, f"call [{reg_name}+{disp:#x}]"))
    
    # Find RTTI strings: .?AVclassname@@
    strings = find_all_strings(data)
    for off, s in strings:
        if s.startswith('.?AV') or s.startswith('.?AU'):
            rtti_strings.append((off, s))
    
    return vtable_calls, rtti_strings

# ============================================================
# PHASE 4: Find allocations (malloc/new calls)
# ============================================================
def find_allocation_patterns(data):
    """Find calls that look like allocations"""
    allocations = []
    
    # Pattern: mov ecx/rcx, SIZE; call [malloc_wrapper]
    for off in range(0, len(data) - 15):
        # B9 XX XX XX XX — mov ecx, imm32
        if data[off] == 0xB9:
            size = struct.unpack_from("<I", data, off+1)[0] if off+5 <= len(data) else 0
            if 0x10 <= size <= 0x1388:  # reasonable allocation sizes
                # Check if next instructions are a call
                for j in range(off+5, min(off+15, len(data)-5)):
                    if data[j] == 0xE8:  # call rel32
                        rel = struct.unpack_from("<i", data, j+1)[0]
                        target = j + 5 + rel
                        allocations.append((off, size, j, target))
                        break
    
    return allocations

print("=" * 80)
print("HYPER AGENT 3: DATA STRUCTURE RECONSTRUCTION — PHASE 1")
print("=" * 80)

data = load_binary()
print(f"Loaded .text: {len(data):,} bytes")

# Extract strings
print("\n--- Extracting RTTI type strings ---")
strings = find_all_strings(data)
rtti_classes = [(off, s) for off, s in strings if '.?AV' in s or '.?AU' in s]
print(f"Total strings: {len(strings):,}")
print(f"RTTI class references: {len(rtti_classes)}")
for off, s in sorted(rtti_classes, key=lambda x: x[1])[:80]:
    print(f"  {off:#08x}: {s}")

# Extract vtable calls
print("\n--- Extracting virtual function calls ---")
vtable_calls, rtti_strs = find_vtable_references(data)
print(f"Virtual calls found: {len(vtable_calls):,}")

# Group vtable calls by offset
from collections import Counter
vslot_counts = Counter(c[1] for c in vtable_calls)
print("\nMost common vtable slot offsets:")
for offset, count in vslot_counts.most_common(40):
    print(f"  [{offset:#04x}]: {count:4d} calls")

# Analyze struct offsets
print("\n--- Analyzing struct field offsets ---")
offsets = analyze_struct_offsets(data, 0x000000, 0x0B8000)

print("\nTop qword struct field offsets (most accessed):")
qword_sorted = sorted(offsets["qword"].items(), key=lambda x: len(x[1]), reverse=True)
for offset, refs in qword_sorted[:60]:
    insn_types = Counter(ref[1].split(' ')[2].split(',')[0].split('+')[0] if '+' in ref[1] else 'direct' for ref in refs)
    print(f"  [+{offset:#06x}]: {len(refs):4d} accesses")

print("\nTop dword struct field offsets:")
dword_sorted = sorted(offsets["dword"].items(), key=lambda x: len(x[1]), reverse=True)
for offset, refs in dword_sorted[:60]:
    print(f"  [+{offset:#06x}]: {len(refs):4d} accesses")

print("\nTop float struct field offsets:")
float_sorted = sorted(offsets["float"].items(), key=lambda x: len(x[1]), reverse=True)
for offset, refs in float_sorted[:40]:
    print(f"  [+{offset:#06x}]: {len(refs):4d} accesses")

# RIP-relative analysis
print("\n--- RIP-relative references (global variables) ---")
rip_leas = find_rip_relative_addresses(data)
rip_movs = find_mov_rip_relative(data)
print(f"RIP-relative LEAs: {len(rip_leas):,}")
print(f"RIP-relative MOVs: {len(rip_movs):,}")

# Group targets by frequency
from collections import Counter
arget_counts = Counter(t[2] for t in rip_leas)
print("\nMost referenced RIP targets (top 40):")
for target, count in target_counts.most_common(40):
    print(f"  RVA {target:#08x}: {count} references")

# Allocation analysis
print("\n--- Allocation patterns ---")
allocs = find_allocation_patterns(data)
print(f"Potential allocations found: {len(allocs):,}")
from collections import Counter
alloc_sizes = Counter(a[1] for a in allocs)
print("Most common allocation sizes:")
for size, count in alloc_sizes.most_common(40):
    print(f"  {size:6d} (0x{size:04x}): {count:4d}")

# Look for key strings to find structure usage
print("\n--- Key structure strings ---")
key_patterns = [
    "ScActivityAPC", "actObj", "missionId", "actId32", "objId", "pids",
    "missionId", "GetActiveSession", "session", "slotData", "entityDeep",
    "capturedWarTime", "BuildPayload", "curl_easy", "SCLoop",
    "libertea_replay_cap", "BEFORE:", "AFTER:", "MIDSWAP",
    "Pattern", "Hook", "ImGui", "Config", "Auth", "SIG-"
]
for pat in key_patterns:
    for off, s in strings:
        if pat.lower() in s.lower():
            print(f"  {off:#08x}: {s}")
            break

print("\nDone with extraction phase.")
