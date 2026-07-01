#!/usr/bin/env python3
"""
LIBERTEA.DLL PE Analyzer
Parses the packed PE file, extracts all headers/sections/resources/imports/relocations,
and documents the packer's modifications (zero-size .text, compressed data in .rsrc).

Requires the LIBERTEA.DLL file path as first argument, or reads from default location.
"""

import struct
import sys
import os
from io import BytesIO

# ---------------------------------------------------------------------------
# Known paths
# ---------------------------------------------------------------------------
DEFAULT_DLL = r"C:\Users\emora\OneDrive\Desktop\LIBERTEA.dll"
DEFAULT_TEXT_BIN = r"C:\Users\emora\OneDrive\Desktop\2\.text_unpacked_mem.bin"


# ---------------------------------------------------------------------------
# PE Constants
# ---------------------------------------------------------------------------
IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x00004550
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x020B
IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x010B

DIRECTORY_NAMES = [
    "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY",
    "BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS",
    "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "CLR", "RESERVED",
]

SECTION_FLAGS = {
    0x00000020: "CNT_CODE",
    0x00000040: "CNT_INIT_DATA",
    0x00000080: "CNT_UNINIT_DATA",
    0x02000000: "MEM_DISCARDABLE",
    0x04000000: "MEM_NOT_CACHED",
    0x08000000: "MEM_NOT_PAGED",
    0x10000000: "MEM_SHARED",
    0x20000000: "MEM_EXECUTE",
    0x40000000: "MEM_READ",
    0x80000000: "MEM_WRITE",
}

RELOCATION_TYPES = {
    0: "ABSOLUTE",
    1: "HIGH",
    2: "LOW",
    3: "HIGHLOW",
    4: "HIGHADJ",
    5: "MIPS_JMPADDR",
    6: "ARM_MOV32",
    7: "THUMB_MOV32",
    8: "RISCV",
    9: "MIPS_JMPADDR16",
    10: "DIR64",
}

# MSVC resource type constants
RESOURCE_TYPE_NAMES = {
    1: "RT_CURSOR",
    2: "RT_BITMAP",
    3: "RT_ICON",
    4: "RT_MENU",
    5: "RT_DIALOG",
    6: "RT_STRING",
    7: "RT_FONTDIR",
    8: "RT_FONT",
    9: "RT_ACCELERATOR",
    10: "RT_RCDATA",
    11: "RT_MESSAGETABLE",
    12: "RT_GROUP_CURSOR",
    14: "RT_GROUP_ICON",
    16: "RT_VERSION",
    24: "RT_MANIFEST",
}

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def read_struct(fmt, data, offset):
    size = struct.calcsize(fmt)
    if offset + size > len(data):
        return None
    return struct.unpack_from(fmt, data, offset)


    def rva_to_offset_raw_raw(sections, rva):
    """Convert RVA to file offset using section headers.
    Returns None if RVA maps past raw data (virtual-only region)."""
    for name, vsize, vrva, rsize, rptr, chars in sections:
        if vrva <= rva < vrva + vsize:
            section_offset = rva - vrva
            if rsize == 0:
                return None  # zero-size on disk, all virtual
            if section_offset >= rsize:
                return None  # past raw data boundary
            return rptr + section_offset
    return None


def offset_to_rva(sections, offset):
    """Convert file offset to RVA using section headers."""
    for name, vsize, vrva, rsize, rptr, chars in sections:
        if rptr <= offset < rptr + rsize:
            return vrva + (offset - rptr)
    return None


def flags_to_str(flags):
    result = []
    for bit, name in sorted(SECTION_FLAGS.items()):
        if flags & bit:
            result.append(name)
    return " | ".join(result) if result else "0"


def get_asciiz(data, offset, maxlen=128):
    end = offset
    while end < offset + maxlen and end < len(data) and data[end] != 0:
        end += 1
    return data[offset:end].decode("ascii", errors="replace"), end + 1


# ---------------------------------------------------------------------------
# PE Parser Class
# ---------------------------------------------------------------------------
class PEAnalyzer:
    def __init__(self, filepath):
        self.filepath = filepath
        with open(filepath, "rb") as f:
            self.data = f.read()
        self.filesize = len(self.data)
        self.sections = []
        self.pe_offset = 0
        self.is_64bit = False
        self.parsed = False

    def parse(self):
        if not self._parse_dos_header():
            return False
        if not self._parse_pe_signature():
            return False
        if not self._parse_coff_header():
            return False
        if not self._parse_optional_header():
            return False
        if not self._parse_sections():
            return False
        self.parsed = True
        return True

    def _parse_dos_header(self):
        if len(self.data) < 64:
            print("[!] File too small for DOS header")
            return False
        e_magic, e_lfanew = struct.unpack_from("<H58xI", self.data, 0)
        if e_magic != IMAGE_DOS_SIGNATURE:
            print(f"[!] Invalid DOS signature: 0x{e_magic:04X}")
            return False
        self.pe_offset = e_lfanew
        self.dos_header = {"e_magic": e_magic, "e_lfanew": e_lfanew}
        return True

    def _parse_pe_signature(self):
        sig = struct.unpack_from("<I", self.data, self.pe_offset)[0]
        if sig != IMAGE_NT_SIGNATURE:
            print(f"[!] Invalid PE signature: 0x{sig:08X}")
            return False
        return True

    def _parse_coff_header(self):
        off = self.pe_offset + 4
        fmt = "<HHIIIHH"
        vals = struct.unpack_from(fmt, self.data, off)
        (self.machine, self.num_sections, self.timedatestamp,
         self.symbol_table, self.num_symbols,
         self.size_opt_header, self.characteristics) = vals

        self.coff_offset = off
        self.coff_size = 20

        machine_names = {
            0x014C: "I386", 0x8664: "AMD64",
            0x0200: "IA64", 0x01C4: "ARMNT",
            0xAA64: "ARM64",
        }

        # Detect 32/64 bit
        self.opt_header_offset = self.coff_offset + self.coff_size
        magic = struct.unpack_from("<H", self.data, self.opt_header_offset)[0]
        self.is_64bit = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)

        char_flags = []
        if self.characteristics & 0x0002: char_flags.append("EXECUTABLE_IMAGE")
        if self.characteristics & 0x0020: char_flags.append("LARGE_ADDRESS_AWARE")
        if self.characteristics & 0x0100: char_flags.append("32BIT_MACHINE")
        if self.characteristics & 0x2000: char_flags.append("DLL")
        self.char_flags_str = " | ".join(char_flags) if char_flags else "0x%04X" % self.characteristics

        return True

    def _parse_optional_header(self):
        off = self.opt_header_offset
        data = self.data

        magic = struct.unpack_from("<H", data, off)[0]
        if self.is_64bit:
            fmt = "<HBB I I I Q Q Q I H H H H H H I Q Q Q"
            keys = [
                "magic", "major_linker", "minor_linker",
                "size_of_code", "size_of_init_data", "size_of_uninit_data",
                "entry_rva", "base_of_code", "image_base",
                "section_alignment", "file_alignment",
                "major_os", "minor_os", "major_image", "minor_image",
                "major_subsys", "minor_subsys", "win32_version",
                "size_of_image", "size_of_headers", "checksum",
            ]
            vals = struct.unpack_from(fmt, data, off)
            self.oh = dict(zip(keys, vals))

            extra_off = off + struct.calcsize(fmt)
            self.subsystem, self.dll_chars = struct.unpack_from("<H H", data, extra_off)
            extra_off += 4
            # size of stack reserve/commit and heap reserve/commit
            self.stack_reserve = struct.unpack_from("<Q", data, extra_off)[0]
            self.stack_commit = struct.unpack_from("<Q", data, extra_off + 8)[0]
            self.heap_reserve = struct.unpack_from("<Q", data, extra_off + 16)[0]
            self.heap_commit = struct.unpack_from("<Q", data, extra_off + 24)[0]
            extra_off += 32
            self.loader_flags, self.num_data_dirs = struct.unpack_from("<I I", data, extra_off)
            self.data_dir_offset = extra_off + 8
        else:
            fmt = "<HBB I I I I I I I H H H H H H I I I"
            keys = [
                "magic", "major_linker", "minor_linker",
                "size_of_code", "size_of_init_data", "size_of_uninit_data",
                "entry_rva", "base_of_code", "base_of_code_dup",
                "section_alignment", "file_alignment",
                "major_os", "minor_os", "major_image", "minor_image",
                "major_subsys", "minor_subsys", "win32_version",
                "size_of_image", "size_of_headers", "checksum",
            ]
            vals = struct.unpack_from(fmt, data, off)
            self.oh = dict(zip(keys, vals))
            extra_off = off + struct.calcsize(fmt)
            self.subsystem, self.dll_chars = struct.unpack_from("<H H", data, extra_off)
            extra_off += 4
            self.stack_reserve = struct.unpack_from("<I", data, extra_off)[0]
            self.stack_commit = struct.unpack_from("<I", data, extra_off + 4)[0]
            self.heap_reserve = struct.unpack_from("<I", data, extra_off + 8)[0]
            self.heap_commit = struct.unpack_from("<I", data, extra_off + 12)[0]
            extra_off += 16
            self.loader_flags, self.num_data_dirs = struct.unpack_from("<I I", data, extra_off)
            self.data_dir_offset = extra_off + 8

        # Parse DLL characteristics
        dll_char_names = []
        if self.dll_chars & 0x0020: dll_char_names.append("HIGH_ENTROPY_VA")
        if self.dll_chars & 0x0040: dll_char_names.append("DYNAMIC_BASE")
        if self.dll_chars & 0x0080: dll_char_names.append("FORCE_INTEGRITY")
        if self.dll_chars & 0x0100: dll_char_names.append("NX_COMPAT")
        if self.dll_chars & 0x0200: dll_char_names.append("NO_ISOLATION")
        if self.dll_chars & 0x0400: dll_char_names.append("NO_SEH")
        if self.dll_chars & 0x0800: dll_char_names.append("NO_BIND")
        if self.dll_chars & 0x1000: dll_char_names.append("APPCONTAINER")
        if self.dll_chars & 0x2000: dll_char_names.append("WDM_DRIVER")
        if self.dll_chars & 0x4000: dll_char_names.append("GUARD_CF")
        if self.dll_chars & 0x8000: dll_char_names.append("TERMINAL_SERVER_AWARE")
        self.dll_chars_str = " | ".join(dll_char_names) if dll_char_names else "0x%04X" % self.dll_chars

        # Parse data directories
        self.data_dirs = []
        for i in range(self.num_data_dirs):
            rva, size = struct.unpack_from("<I I", data, self.data_dir_offset + i * 8)
            self.data_dirs.append((rva, size))

        return True

    def _parse_sections(self):
        section_offset = self.data_dir_offset + self.num_data_dirs * 8
        self.sections = []
        for i in range(self.num_sections):
            off = section_offset + i * 40
            name_raw = self.data[off:off+8]
            name = name_raw.rstrip(b"\x00").decode("ascii", errors="replace")
            vals = struct.unpack_from("<I I I I I I H H I", self.data, off + 8)
            vsize, vrva, rsize, rptr, reloc_rptr, lineno_rptr, num_reloc, num_lineno, chars = vals
            self.sections.append((name, vsize, vrva, rsize, rptr, chars))
        self.section_header_offset = section_offset
        return True

    # -------------------------------------------------------------------
    # Analysis methods
    # -------------------------------------------------------------------
    def analyze_packer_modifications(self):
        """Detect packer-specific anomalies."""
        findings = []

        # Check .text section for zero size on disk
        for name, vsize, vrva, rsize, rptr, chars in self.sections:
            if name == ".text":
                if rsize == 0:
                    findings.append((
                        "CRITICAL",
                        f".text section: VirtualSize=0x{vsize:X} but RawSize=0x0 "
                        f"(zero on disk) - decompressed at runtime\n"
                        f"    RVA: 0x{vrva:X}  FilePtr: 0x{rptr:X}  Flags: {flags_to_str(chars)}\n"
                        f"    Packer: aPLib-custom compressed data stored in .rsrc section"
                    ))
                else:
                    findings.append((
                        "INFO",
                        f".text section appears normal: VS=0x{vsize:X} RS=0x{rsize:X}"
                    ))

        # Check duplicate section names
        name_counts = {}
        for name, vsize, vrva, rsize, rptr, chars in self.sections:
            name_counts[name] = name_counts.get(name, 0) + 1
        for name, count in name_counts.items():
            if count > 1:
                findings.append((
                    "WARNING",
                    f"Duplicate section name '{name}' appears {count} times - packer anomaly"
                ))

        # Check entry point location
        entry_rva = self.oh["entry_rva"]
        for name, vsize, vrva, rsize, rptr, chars in self.sections:
            if vrva <= entry_rva < vrva + vsize:
                if name == ".text":
                    findings.append((
                        "INFO",
                        f"Entry point 0x{entry_rva:X} is in .text section (normal)"
                    ))
                else:
                    findings.append((
                        "CRITICAL",
                        f"Entry point 0x{entry_rva:X} is in '{name}' section, NOT .text "
                        f"(packer stub in resource/overlay section)"
                    ))

        # Check timedatestamp
        if self.timedatestamp == 0:
            findings.append((
                "INFO",
                "TimeDateStamp is 0 (epoch) - commonly zeroed by packers to avoid "
                "compilation timestamp fingerprinting"
            ))

        # Check if .text section has EXECUTE|READ|WRITE (suspicious)
        for name, vsize, vrva, rsize, rptr, chars in self.sections:
            if name == ".text":
                rwx = chars & 0xE0000000
                if rwx == 0xE0000000:  # EXECUTE | READ | WRITE
                    findings.append((
                        "WARNING",
                        f".text section has RWX permissions (0x{chars:08X}) - "
                        f"typical for packed code needing self-modification"
                    ))

        # Check compression ratio
        text_section = None
        rsrc_section = None
        for name, vsize, vrva, rsize, rptr, chars in self.sections:
            if name == ".text":
                text_section = (name, vsize, vrva, rsize, rptr, chars)
            elif name == ".rsrc" and rsrc_section is None:
                rsrc_section = (name, vsize, vrva, rsize, rptr, chars)

        if text_section and text_section[4] > 0 and rsrc_section:
            # Estimate compression: uncompressed .text vs on-disk .text
            comp_size = rsrc_section[3]
            orig_size = text_section[1]
            if comp_size > 0 and orig_size > comp_size:
                ratio = orig_size / comp_size
                findings.append((
                    "INFO",
                    f"Estimated compression ratio: {ratio:.1f}:1 "
                    f"({orig_size} -> ~{comp_size} bytes)"
                ))

        return findings

    def parse_import_table(self):
        """Parse Import Directory Table and enumerate all imported DLLs/functions."""
        imp_rva, imp_size = self.data_dirs[1]
        if imp_rva == 0:
            return "No import table found"

        lines = []
        off = rva_to_offset_raw(self.sections, imp_rva)
        if off is None:
            return f"Cannot resolve import RVA 0x{imp_rva:X} to file offset"

        # Parse import descriptors
        lines.append("")
        dlls = []
        idx = 0
        while True:
            idesc_off = off + idx * 20
            if idesc_off + 20 > len(self.data):
                break
            vals = struct.unpack_from("<I I I I I", self.data, idesc_off)
            orig_first_thunk, timedatestamp, forwarder, name_rva, first_thunk = vals
            if name_rva == 0:
                break

            name_foff = rva_to_offset_raw(self.sections, name_rva)
            dll_name = ""
            if name_foff:
                dll_name, _ = get_asciiz(self.data, name_foff)

            # Enumerate thunks (imported functions)
            imports = []
            thunk_rva = first_thunk if first_thunk != 0 else orig_first_thunk
            thunk_off = rva_to_offset_raw(self.sections, thunk_rva)
            if thunk_off:
                t = 0
                while True:
                    toff = thunk_off + t * 8
                    if toff + 8 > len(self.data):
                        break
                    if self.is_64bit:
                        entry = struct.unpack_from("<Q", self.data, toff)[0]
                    else:
                        entry = struct.unpack_from("<I", self.data, toff)[0]
                    if entry == 0:
                        break

                    if self.is_64bit:
                        is_ordinal = (entry >> 63) & 1
                    else:
                        is_ordinal = (entry >> 31) & 1

                    if is_ordinal:
                        ordinal = entry & 0xFFFF
                        imports.append(f"  Ordinal #{ordinal}")
                    else:
                        hint_name_rva = entry & 0x7FFFFFFF if not self.is_64bit else entry & 0xFFFFFFFF
                        fn_off = rva_to_offset_raw(self.sections, hint_name_rva)
                        if fn_off and fn_off + 4 <= len(self.data):
                            hint = struct.unpack_from("<H", self.data, fn_off)[0]
                            fn_name, _ = get_asciiz(self.data, fn_off + 2)
                            imports.append(f"  {fn_name} (hint={hint})")
                        else:
                            imports.append(f"  <RVA=0x{hint_name_rva:X}>")
                    t += 1

            dlls.append((dll_name, imports))
            idx += 1

        # Format output
        for dll_name, imports in dlls:
            lines.append(f"  [{dll_name}]")
            if not imports:
                lines.append("    (no imports listed)")
            else:
                for imp in imports[:30]:  # limit per DLL for readability
                    lines.append(f"    {imp}")
                if len(imports) > 30:
                    lines.append(f"    ... and {len(imports) - 30} more")
            lines.append("")

        return "\n".join(lines)

    def parse_resource_table(self):
        """Parse the resource directory tree."""
        rsrc_rva, rsrc_size = self.data_dirs[2]
        if rsrc_rva == 0:
            return "No resource table"

        rsrc_off = rva_to_offset_raw(self.sections, rsrc_rva)
        if rsrc_off is None:
            return f"Cannot resolve resource RVA 0x{rsrc_rva:X}"

        lines = []
        lines.append("")

        def parse_dir(dir_off, depth=0):
            prefix = "  " * (depth + 1)
            vals = struct.unpack_from("<I I H H H H", self.data, dir_off)
            characteristics, timedate, major, minor, num_named, num_id = vals
            num_entries = num_named + num_id

            for i in range(num_entries):
                entry_off = dir_off + 16 + i * 8
                name_rva, offset = struct.unpack_from("<I I", self.data, entry_off)
                is_name = (name_rva >> 31) & 1
                is_dir = (offset >> 31) & 1

                # Resolve name or ID
                if is_name:
                    name_str_off = rsrc_off + (name_rva & 0x7FFFFFFF)
                    if name_str_off < len(self.data):
                        name_len = struct.unpack_from("<H", self.data, name_str_off)[0]
                        name_str = self.data[name_str_off + 2:name_str_off + 2 + name_len * 2]
                        try:
                            entry_name = name_str.decode("utf-16-le")
                        except:
                            entry_name = f"<unicode:{name_len}>"
                    else:
                        entry_name = f"?({name_rva:08X})"
                else:
                    tid = name_rva & 0xFFFF
                    entry_name = f"#{tid}"
                    if depth == 0 and tid in RESOURCE_TYPE_NAMES:
                        entry_name += f" ({RESOURCE_TYPE_NAMES[tid]})"

                if is_dir:
                    subdir_off = rsrc_off + (offset & 0x7FFFFFFF)
                    lines.append(f"{prefix}[{entry_name}] -> subdirectory")
                    parse_dir(subdir_off, depth + 1)
                else:
                    data_off = rsrc_off + (offset & 0x7FFFFFFF)
                    data_rva, data_size, codepage, reserved = struct.unpack_from(
                        "<I I I I", self.data, data_off
                    )
                    lines.append(
                        f"{prefix}[{entry_name}] DataEntry: "
                        f"RVA=0x{data_rva:X} Size={data_size}"
                    )

        try:
            parse_dir(rsrc_off)
        except Exception as e:
            lines.append(f"  [!] Error parsing resources: {e}")

        lines.append("")
        lines.append(f"  Total resource tree size: {rsrc_size} bytes")
        return "\n".join(lines)

    def parse_relocations(self):
        """Parse base relocation table."""
        reloc_rva, reloc_size = self.data_dirs[5]
        if reloc_rva == 0:
            return "No relocation table"

        # Handle very small relocation sizes (packed DLLs have minimal relocs)
        if reloc_size <= 0x30:
            return (
                f"\n  Base Relocation Table: RVA=0x{reloc_rva:X} Size={reloc_size}\n"
                f"    [!] MINIMAL relocation table ({reloc_size} bytes) - "
                f"characteristic of packed DLLs\n"
                f"    This is sufficient for loader stub only; real code relocates at runtime"
            )

        reloc_off = rva_to_offset_raw(self.sections, reloc_rva)
        if reloc_off is None:
            return f"Cannot resolve reloc RVA 0x{reloc_rva:X}"

        lines = []
        lines.append("")
        pos = reloc_off
        total_entries = 0
        blocks = 0
        while pos < reloc_off + min(reloc_size, 0x10000):
            page_rva, block_size = struct.unpack_from("<I I", self.data, pos)
            if block_size == 0:
                break
            entries = []
            entry_count = (block_size - 8) // 2
            for i in range(entry_count):
                e_off = pos + 8 + i * 2
                entry = struct.unpack_from("<H", self.data, e_off)[0]
                e_type = (entry >> 12) & 0xF
                e_offset = entry & 0xFFF
                if e_type in RELOCATION_TYPES:
                    entries.append(f"    +{e_offset:03X} {RELOCATION_TYPES[e_type]}")
                else:
                    entries.append(f"    +{e_offset:03X} type={e_type}")
            if blocks < 3:
                lines.append(f"  Block {blocks}: Page=0x{page_rva:X} Size={block_size}")
                for e in entries[:8]:
                    lines.append(e)
                if entry_count > 8:
                    lines.append(f"    ... {entry_count - 8} more entries")
            blocks += 1
            total_entries += entry_count
            pos += block_size

        lines.append(f"  Total: {blocks} blocks, {total_entries} relocation entries")
        return "\n".join(lines)

    def parse_exception_table(self):
        """Parse exception directory (pdata/xdata for x64)."""
        exc_rva, exc_size = self.data_dirs[3]
        if exc_rva == 0:
            return "No exception table"

        lines = []
        lines.append("")
        lines.append(
            f"  Exception Directory: RVA=0x{exc_rva:X} Size={exc_size} "
            f"({exc_size // 12} entries)"
        )

        exc_off = rva_to_offset_raw(self.sections, exc_rva)
        if exc_off:
            lines.append(f"  File offset: 0x{exc_off:X}")

            if self.is_64bit:
                # x64: each entry is 3 DWORDS (RVA + size + unwind)
                num_entries = exc_size // 12
                for i in range(min(num_entries, 5)):
                    e_off = exc_off + i * 12
                    begin, end, unwind = struct.unpack_from("<I I I", self.data, e_off)
                    lines.append(f"    [{i}] Begin=0x{begin:X} End=0x{end:X} Unwind=0x{unwind:X}")
                if num_entries > 5:
                    lines.append(f"    ... {num_entries - 5} more entries")
            else:
                lines.append("    (x86 exception entries, 8 bytes each)")
        return "\n".join(lines)

    def parse_tls(self):
        """Parse TLS directory."""
        tls_rva, tls_size = self.data_dirs[9]
        if tls_rva == 0:
            return "No TLS directory"

        tls_off = rva_to_offset_raw(self.sections, tls_rva)
        if tls_off is None:
            return f"  TLS: RVA=0x{tls_rva:X} Size={tls_size}"

        lines = []
        lines.append("")
        if self.is_64bit:
            if tls_off + 40 <= len(self.data):
                start, end, index, callbacks, zero_fill, chars = struct.unpack_from(
                    "<Q Q Q Q I I", self.data, tls_off
                )
                lines.append(
                    f"  TLS Directory: RVA=0x{tls_rva:X} Size={tls_size}\n"
                    f"    StartVA:       0x{start:X}\n"
                    f"    EndVA:         0x{end:X}\n"
                    f"    Index:         0x{index:X}\n"
                    f"    Callbacks:     RVA=0x{callbacks:X}\n"
                    f"    ZeroFill:      {zero_fill}\n"
                    f"    Flags:         0x{chars:X}"
                )
        else:
            if tls_off + 24 <= len(self.data):
                start, end, index, callbacks, zero_fill, chars = struct.unpack_from(
                    "<I I I I I I", self.data, tls_off
                )
                lines.append(
                    f"  TLS Directory: RVA=0x{tls_rva:X} Size={tls_size}"
                )
        return "\n".join(lines)

    def parse_load_config(self):
        """Parse Load Config directory (important for security flags)."""
        lc_rva, lc_size = self.data_dirs[10]
        if lc_rva == 0:
            return "No Load Config"

        lc_off = rva_to_offset_raw(self.sections, lc_rva)
        if lc_off is None:
            return f"  Load Config: RVA=0x{lc_rva:X} Size={lc_size}"

        lines = []
        lines.append("")
        lines.append(f"  Load Config: RVA=0x{lc_rva:X} Size={lc_size}")

        if self.is_64bit and lc_off + 140 <= len(self.data):
            # Parse key fields
            fmt = "<I I I I I Q Q Q I I I I"
            vals = struct.unpack_from(fmt, self.data, lc_off)
            (size, timedate, major, minor, global_flags_clear,
             global_flags_set, crit_sec_timeout,
             decommit_free, decommit_total) = vals[0:9]

            # Guard CF fields at offset 0x50
            gcf_off = lc_off + 0x50
            if gcf_off + 24 <= len(self.data):
                gcf_check, gcf_dispatch, gcf_ftable, gcf_ftable_count = \
                    struct.unpack_from("<Q Q Q Q", self.data, gcf_off)

                guard_present = (self.dll_chars & 0x4000) != 0
                lines.append(
                    f"    GuardCF Check:    RVA=0x{gcf_check:X}\n"
                    f"    GuardCF Dispatch:  RVA=0x{gcf_dispatch:X}\n"
                    f"    GuardCF FnTable:   RVA=0x{gcf_ftable:X}\n"
                    f"    GuardCF FnCount:   {gcf_ftable_count}\n"
                    f"    CFG Enabled:       {guard_present}"
                )
        return "\n".join(lines)

    def analyze_text_section_content(self):
        """Examine the decompressed .text section content (if .text_unpacked_mem.bin available)."""
        text_bin = DEFAULT_TEXT_BIN
        if not os.path.exists(text_bin):
            return ""

        lines = []
        lines.append("")
        lines.append("=" * 68)
        lines.append("  DECOMPRESSED .TEXT SECTION ANALYSIS")
        lines.append("=" * 68)

        with open(text_bin, "rb") as f:
            text_data = f.read()

        lines.append(f"  File: {text_bin}")
        lines.append(f"  Size: {len(text_data):,} bytes ({len(text_data) / 1024 / 1024:.2f} MB)")

        non_zero = sum(1 for b in text_data if b != 0)
        zero_count = len(text_data) - non_zero
        density = (non_zero / len(text_data)) * 100 if len(text_data) > 0 else 0
        lines.append(f"  Non-zero bytes: {non_zero:,}")
        lines.append(f"  Zero bytes:     {zero_count:,}")
        lines.append(f"  Code density:   {density:.1f}%")

        # Detect byte patterns at known landmarks
        # PE header magic should be at start of .text in a standard DLL
        first_2 = struct.unpack_from("<H", text_data, 0)[0]
        if first_2 == 0x5A4D:
            lines.append(f"  Starts with MZ header (0x{first_2:04X}) - text is an appended PE?")
        else:
            lines.append(f"  First word: 0x{first_2:04X} (not MZ, likely raw code)")

        # Signature scan for common x64 function prologues
        prologue_count = 0
        for i in range(0, len(text_data) - 4, 1):
            if text_data[i] == 0x48 and text_data[i + 1] == 0x83 and text_data[i + 2] == 0xEC:
                # sub rsp, XX
                prologue_count += 1
            elif text_data[i] == 0x48 and text_data[i + 1] == 0x89:
                # mov [rsp+NN], reg
                pass
            elif text_data[i] == 0xC3:
                # ret
                pass
        lines.append(f"  sub rsp,XX prologues found: {prologue_count}")

        # Look for ImGui ## IDs in the text data to estimate ImGui widget count
        imgui_ids = set()
        for i in range(len(text_data) - 6):
            if text_data[i:i + 2] == b"##":
                end = i + 2
                while end < len(text_data) and end < i + 40:
                    if text_data[end] < 32 or text_data[end] > 126:
                        break
                    if text_data[end] == ord(" ") or text_data[end] == ord('"'):
                        break
                    end += 1
                if end > i + 3:
                    try:
                        id_str = text_data[i + 2:end].decode("ascii")
                        imgui_ids.add(id_str)
                    except:
                        pass
        lines.append(f"  Unique ImGui ## IDs in .text: {len(imgui_ids)}")

        # Look for URL/API strings
        for marker in [b"api.live.prod", b"libertea", b"helldiversgame", b"workers.dev"]:
            pos = text_data.find(marker)
            if pos >= 0:
                end = pos
                while end < len(text_data) and end < pos + 120:
                    if text_data[end] < 32:
                        break
                    end += 1
                try:
                    url = text_data[pos:end].decode("ascii", errors="replace")
                    lines.append(f"  Found URL: {url}")
                except:
                    pass

        # Look for crash log format string
        if b"CRASH LOG" in text_data:
            lines.append("  Found '=== LIBERTEA CRASH LOG ===' string")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main analysis report
# ---------------------------------------------------------------------------
def run_analysis(dll_path):
    print("=" * 68)
    print("  LIBERTEA.DLL PE STRUCTURE ANALYSIS")
    print("=" * 68)
    print(f"  DLL File: {dll_path}")

    pe = PEAnalyzer(dll_path)
    if not pe.parse():
        print("[!] Failed to parse PE structure")
        return

    fsize_mb = pe.filesize / 1024.0 / 1024.0
    print(f"  File Size:       {pe.filesize:,} bytes ({fsize_mb:.2f} MB)")
    print(f"  DOS Signature:   0x{pe.dos_header['e_magic']:04X} (MZ)")
    print(f"  PE Offset:       0x{pe.dos_header['e_lfanew']:X}")

    # COFF Header
    print(f"\n{'=' * 68}")
    print("  COFF / FILE HEADER")
    print(f"{'=' * 68}")
    machine_names = {0x8664: "AMD64 (x86-64)", 0x014C: "I386 (x86)"}
    print(f"  Machine:         0x{pe.machine:04X} ({machine_names.get(pe.machine, 'Unknown')})")
    print(f"  Num Sections:    {pe.num_sections}")
    print(f"  TimeDateStamp:   0x{pe.timedatestamp:08X} ({'ZEROED - packer obfuscation' if pe.timedatestamp == 0 else pe.timedatestamp})")
    print(f"  Symbol Table:    @0x{pe.symbol_table:X} ({pe.num_symbols} entries)")
    print(f"  SizeOfOptHdr:    {pe.size_opt_header}")
    print(f"  Characteristics: {pe.char_flags_str}")
    print(f"  Bitness:         {'64-bit (PE32+)' if pe.is_64bit else '32-bit (PE32)'}")

    # Optional Header
    print(f"\n{'=' * 68}")
    print("  OPTIONAL HEADER (PE32+)")
    print(f"{'=' * 68}")
    print(f"  Magic:           0x{pe.oh['magic']:04X}")
    print(f"  Entry Point RVA: 0x{pe.oh['entry_rva']:X}")
    print(f"  ImageBase:       0x{pe.oh['image_base']:X}")
    print(f"  SectionAlign:    {pe.oh['section_alignment']} (0x{pe.oh['section_alignment']:X})")
    print(f"  FileAlign:       {pe.oh['file_alignment']} (0x{pe.oh['file_alignment']:X})")
    print(f"  SizeOfImage:     0x{pe.oh['size_of_image']:X}")
    print(f"  SizeOfHeaders:   0x{pe.oh['size_of_headers']:X}")
    print(f"  Subsystem:       {pe.subsystem} ({'GUI' if pe.subsystem == 2 else 'CONSOLE' if pe.subsystem == 3 else 'Unknown'})")
    print(f"  DLL Flags:       {pe.dll_chars_str}")
    print(f"  BaseOfCode:      0x{pe.oh['base_of_code']:X}")
    print(f"  CheckSum:        0x{pe.oh['checksum']:08X}")
    print(f"  Data Dirs:       {pe.num_data_dirs}")

    # Stack/Heap
    print(f"  Stack Reserve:   {pe.stack_reserve // 1024:,} KB")
    print(f"  Stack Commit:    {pe.stack_commit // 1024:,} KB")
    print(f"  Heap Reserve:    {pe.heap_reserve // 1024:,} KB")
    print(f"  Heap Commit:     {pe.heap_commit // 1024:,} KB")

    # Section table
    print(f"\n{'=' * 68}")
    print("  SECTION TABLE")
    print(f"{'=' * 68}")
    header = f"  {'Name':<10} {'VirtSize':>10} {'RVA':>10} {'RawSize':>10} {'RawPtr':>10} {'Flags':>30}"
    print(header)
    print(f"  {'-'*8} {'-'*10} {'-'*10} {'-'*10} {'-'*10} {'-'*30}")
    for name, vsize, vrva, rsize, rptr, chars in pe.sections:
        flags = flags_to_str(chars)
        print(f"  {name:<10} 0x{vsize:08X} 0x{vrva:08X} 0x{rsize:08X} 0x{rptr:08X} {flags}")

    # Data Directories
    print(f"\n{'=' * 68}")
    print("  DATA DIRECTORIES")
    print(f"{'=' * 68}")
    header = f"  {'#':>2} {'Name':<16} {'RVA':>10} {'Size':>10} {'Status'}"
    print(header)
    print(f"  {'-'*2} {'-'*16} {'-'*10} {'-'*10} {'-----'}")
    for i, (rva, size) in enumerate(pe.data_dirs):
        name = DIRECTORY_NAMES[i] if i < len(DIRECTORY_NAMES) else f"DIR_{i}"
        status = ""
        if rva == 0:
            status = "(empty)"
        else:
            file_off = rva_to_offset_raw(pe.sections, rva)
            if file_off is not None:
                status = f"@0x{file_off:X}"
            else:
                status = f"(unmapped RVA)"
        print(f"  {i:>2} {name:<16} 0x{rva:08X} 0x{size:08X} {status}")

    # Packer modifications
    print(f"\n{'=' * 68}")
    print("  PACKER ANOMALIES & MODIFICATIONS")
    print(f"{'=' * 68}")
    findings = pe.analyze_packer_modifications()
    for severity, msg in findings:
        tag = f"[{severity}]"
        print(f"  {tag:<10} {msg}")

    # Import table
    print(f"\n{'=' * 68}")
    print("  IMPORT TABLE")
    print(f"{'=' * 68}")
    imp_rva, imp_size = pe.data_dirs[1]
    print(f"  Import Directory: RVA=0x{imp_rva:X} Size=0x{imp_size:X}")
    print(pe.parse_import_table())

    # Resource table
    print(f"\n{'=' * 68}")
    print("  RESOURCE TABLE")
    print(f"{'=' * 68}")
    print(pe.parse_resource_table())

    # Exception table
    print(f"\n{'=' * 68}")
    print("  EXCEPTION DIRECTORY (pdata/xdata)")
    print(f"{'=' * 68}")
    print(pe.parse_exception_table())

    # Relocations
    print(f"\n{'=' * 68}")
    print("  BASE RELOCATIONS")
    print(f"{'=' * 68}")
    print(pe.parse_relocations())

    # TLS
    print(f"\n{'=' * 68}")
    print("  THREAD LOCAL STORAGE")
    print(f"{'=' * 68}")
    print(pe.parse_tls())

    # Load Config
    print(f"\n{'=' * 68}")
    print("  LOAD CONFIG")
    print(f"{'=' * 68}")
    print(pe.parse_load_config())

    # Decompressed .text analysis
    print(pe.analyze_text_section_content())

    # Hash / fingerprint
    print(f"\n{'=' * 68}")
    print("  BINARY FINGERPRINTS")
    print(f"{'=' * 68}")
    import hashlib
    md5 = hashlib.md5(pe.data).hexdigest()
    sha256 = hashlib.sha256(pe.data).hexdigest()
    print(f"  MD5:    {md5}")
    print(f"  SHA256: {sha256}")
    print(f"  CRC32:  {binascii.crc32(pe.data) & 0xFFFFFFFF:08X}")

    print(f"\n{'=' * 68}")
    print("  ANALYSIS COMPLETE")
    print(f"{'=' * 68}")


if __name__ == "__main__":
    import binascii

    dll_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DLL
    if not os.path.exists(dll_path):
        print(f"Error: DLL not found at '{dll_path}'")
        print(f"Usage: python pe_analyzer.py [path\\to\\LIBERTEA.DLL]")
        sys.exit(1)
    run_analysis(dll_path)
