#!/usr/bin/env python3
"""
LIBERTEA.DLL - COMPREHENSIVE BYTE-LEVEL RE-SWEEP
Uses pefile for accurate PE parsing + raw byte analysis
"""
import struct, math, sys, os, zlib, re
from collections import Counter
import pefile

DLL_PATH = r"C:\Users\emora\OneDrive\Desktop\2\LIBERTEA.DLL"
TEXT_PATH = r"C:\Users\emora\OneDrive\Desktop\2\.text_unpacked_mem.bin"
OUT_PATH = r"C:\Users\emora\OneDrive\Desktop\2\resweep_pe.txt"

OUT = []
def O(s=""): OUT.append(s)

with open(DLL_PATH, "rb") as f:
    raw = f.read()
with open(TEXT_PATH, "rb") as f:
    text_raw = f.read()

fsize = len(raw)
tsize = len(text_raw)

O("=" * 80)
O("LIBERTEA.DLL - COMPREHENSIVE BYTE-LEVEL RE-SWEEP")
O("=" * 80)
O(f"File size: {fsize} bytes (0x{fsize:X})")
O(f"Unpacked .text size: {tsize} bytes (0x{tsize:X})")
O("")

try:
    pe = pefile.PE(data=raw)
    pe_ok = True
except Exception as e:
    O(f"PEFILE FAILED: {e}")
    pe_ok = False
    pe = None

# ============================================================
# 1. PE HEADERS
# ============================================================
O("=" * 80)
O("1. PE HEADERS - EXHAUSTIVE PARSE")
O("=" * 80)

# DOS
e_magic = struct.unpack_from("<H", raw, 0)[0]
e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
O(f"DOS Header: e_magic=0x{e_magic:04X} ({'MZ' if e_magic == 0x5A4D else 'INVALID'}) e_lfanew=0x{e_lfanew:X}")

# Full DOS header bytes
O("DOS header bytes 0x00-0x3F:")
O("  " + raw[:0x40].hex(' ').upper())

# DOS stub
if e_lfanew > 64:
    stub = raw[64:e_lfanew]
    stub_str = stub.decode('ascii', errors='replace')
    O(f"DOS stub: {len(stub)} bytes")
    if "This program cannot be run in DOS mode" in stub_str:
        O("  Standard 'This program cannot be run in DOS mode' message")
    else:
        O(f"  First 100 chars: {stub_str[:100]}")

# Rich header scan
O("Scanning for Rich header:")
rich_found = False
for i in range(0x80, e_lfanew - 8):
    if struct.unpack_from("<I", raw, i)[0] == 0x68636952:  # "Rich"
        rich_found = True
        xor_key = struct.unpack_from("<I", raw, i + 4)[0]
        O(f"  RICH HEADER at offset 0x{i:X}, XOR key=0x{xor_key:08X}")
        # Decode entries
        j = i - 8
        while j >= 0:
            vid = struct.unpack_from("<I", raw, j)[0] ^ xor_key
            vcnt = struct.unpack_from("<I", raw, j + 4)[0] ^ xor_key
            comp_id = (vid >> 16) & 0xFFFF
            build = vid & 0xFFFF
            if comp_id == 0xFFFF and build == 0xFFFF:
                break
            if comp_id > 0x400:
                break
            O(f"    Tool: 0x{comp_id:04X}, Build: {build}, Use Count: {vcnt}")
            j -= 8
        break
if not rich_found:
    O("  Rich header: NOT FOUND")

# PE signature
pe_off = e_lfanew
pe_sig = struct.unpack_from("<I", raw, pe_off)[0]
O(f"\nPE Signature at 0x{pe_off:X}: 0x{pe_sig:08X} ({'PE\\0\\0' if pe_sig == 0x4550 else 'INVALID'})")

coff_off = pe_off + 4
machine = struct.unpack_from("<H", raw, coff_off)[0]
nsections = struct.unpack_from("<H", raw, coff_off + 2)[0]
timedate = struct.unpack_from("<I", raw, coff_off + 4)[0]
opthdrsize = struct.unpack_from("<H", raw, coff_off + 16)[0]
chars = struct.unpack_from("<H", raw, coff_off + 18)[0]

machine_name = {0x014C: "i386", 0x8664: "AMD64", 0x01C4: "ARM", 0xAA64: "ARM64"}.get(machine, f"0x{machine:04X}")
cflags = []
if chars & 0x0002: cflags.append("EXE")
if chars & 0x0020: cflags.append("LARGE_ADDR")
if chars & 0x2000: cflags.append("DLL")
if chars & 0x0100: cflags.append("32BIT")
if chars & 0x0001: cflags.append("RELOC_STRIP")

import datetime
dt = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=timedate)
O(f"COFF: Machine=0x{machine:04X} ({machine_name}) Sections={nsections} Time={dt} OptHdrSize=0x{opthdrsize:04X} Chars=0x{chars:04X} ({' '.join(cflags)})")

# Parse optional header MANUALLY for correctness
opt_off = coff_off + 20
opt_magic = struct.unpack_from("<H", raw, opt_off)[0]
is_pe64 = opt_magic == 0x20B
mtype = "PE32+" if is_pe64 else "PE32"

# PE32+ offsets:
if is_pe64:
    # ---- offset from opt_off ----
    O_ENTRY = 0x10        # AddressOfEntryPoint (4)
    O_BASEOFCODE = 0x14   # BaseOfCode (4)
    O_IMAGEBASE = 0x18    # ImageBase (8)
    O_SECTIONALIGN = 0x20 # SectionAlignment (4)
    O_FILEALIGN = 0x24    # FileAlignment (4)
    O_MAJOROS = 0x28      # MajorOSVer (2)
    O_MINOROS = 0x2A      # MinorOSVer (2)
    O_MAJORIMG = 0x2C     # MajorImageVer (2)
    O_MINORIMG = 0x2E     # MinorImageVer (2)
    O_MAJORSUB = 0x30     # MajorSubsysVer (2)
    O_MINORSUB = 0x32     # MinorSubsysVer (2)
    O_WIN32VER = 0x34     # Win32Version (4)
    O_SIZEOFIMAGE = 0x38  # SizeOfImage (4)
    O_SIZEOFHEADERS = 0x3C # SizeOfHeaders (4)
    O_CHECKSUM = 0x40     # CheckSum (4)
    O_SUBSYSTEM = 0x44    # Subsystem (2)
    O_DLLCHAR = 0x46      # DllCharacteristics (2)
    O_STACKRESERVE = 0x48 # SizeOfStackReserve (8)
    O_STACKCOMMIT = 0x50  # SizeOfStackCommit (8)
    O_HEAPRESERVE = 0x58  # SizeOfHeapReserve (8)
    O_HEAPCOMMIT = 0x60   # SizeOfHeapCommit (8)
    O_LOADERFLAGS = 0x68  # LoaderFlags (4)
    O_NUMDATADIRS = 0x6C  # NumberOfRvaAndSizes (4)
    O_DATADIRS = 0x70     # Data dirs start
else:
    O_ENTRY = 0x10
    O_BASEOFCODE = 0x14
    O_IMAGEBASE = 0x18    # ImageBase (4)
    O_SECTIONALIGN = 0x1C
    O_FILEALIGN = 0x20
    O_MAJOROS = 0x24
    O_MINOROS = 0x26
    O_MAJORIMG = 0x28
    O_MINORIMG = 0x2A
    O_MAJORSUB = 0x2C
    O_MINORSUB = 0x2E
    O_WIN32VER = 0x30
    O_SIZEOFIMAGE = 0x34
    O_SIZEOFHEADERS = 0x38
    O_CHECKSUM = 0x3C
    O_SUBSYSTEM = 0x40
    O_DLLCHAR = 0x42
    O_STACKRESERVE = 0x44  # SizeOfStackReserve (4)
    O_STACKCOMMIT = 0x48   # SizeOfStackCommit (4)
    O_HEAPRESERVE = 0x4C   # SizeOfHeapReserve (4)
    O_HEAPCOMMIT = 0x50    # SizeOfHeapCommit (4)
    O_LOADERFLAGS = 0x54
    O_NUMDATADIRS = 0x58
    O_DATADIRS = 0x5C

entry = struct.unpack_from("<I", raw, opt_off + O_ENTRY)[0]
base_of_code = struct.unpack_from("<I", raw, opt_off + O_BASEOFCODE)[0]
if is_pe64:
    image_base = struct.unpack_from("<Q", raw, opt_off + O_IMAGEBASE)[0]
else:
    image_base = struct.unpack_from("<I", raw, opt_off + O_IMAGEBASE)[0]
section_align = struct.unpack_from("<I", raw, opt_off + O_SECTIONALIGN)[0]
file_align = struct.unpack_from("<I", raw, opt_off + O_FILEALIGN)[0]
size_of_image = struct.unpack_from("<I", raw, opt_off + O_SIZEOFIMAGE)[0]
size_of_headers = struct.unpack_from("<I", raw, opt_off + O_SIZEOFHEADERS)[0]
checksum = struct.unpack_from("<I", raw, opt_off + O_CHECKSUM)[0]
subsystem = struct.unpack_from("<H", raw, opt_off + O_SUBSYSTEM)[0]
dllchar = struct.unpack_from("<H", raw, opt_off + O_DLLCHAR)[0]
num_dd = struct.unpack_from("<I", raw, opt_off + O_NUMDATADIRS)[0]

if is_pe64:
    stack_reserve = struct.unpack_from("<Q", raw, opt_off + O_STACKRESERVE)[0]
else:
    stack_reserve = struct.unpack_from("<I", raw, opt_off + O_STACKRESERVE)[0]

sname = {2: "WINDOWS_GUI", 3: "WINDOWS_CUI"}.get(subsystem, f"0x{subsystem:04X}")

O("")
O("Optional Header ({0}):".format(mtype))
O(f"  Magic                 = 0x{opt_magic:04X}")
O(f"  EntryPoint            = 0x{entry:X}")
O(f"  BaseOfCode            = 0x{base_of_code:X}")
O(f"  ImageBase             = 0x{image_base:X}")
O(f"  SectionAlignment      = 0x{section_align:X}")
O(f"  FileAlignment         = 0x{file_align:X}")
O(f"  SizeOfImage           = 0x{size_of_image:X}")
O(f"  SizeOfHeaders         = 0x{size_of_headers:X}")
O(f"  CheckSum              = 0x{checksum:08X}")
O(f"  Subsystem             = {sname} (0x{subsystem:X})")
O(f"  DllCharacteristics    = 0x{dllchar:04X}")
O(f"  SizeOfStackReserve    = 0x{stack_reserve:X}")
O(f"  NumberOfRvaAndSizes   = {num_dd}")

dllf = []
if dllchar & 0x0040: dllf.append("DYNAMIC_BASE (ASLR)")
if dllchar & 0x0100: dllf.append("NX_COMPAT")
if dllchar & 0x4000: dllf.append("HIGH_ENTROPY_VA")
if dllchar & 0x1000: dllf.append("APPCONTAINER")
if dllchar & 0x2000: dllf.append("CF_GUARD")
O(f"  DllChar flags: {' '.join(dllf)}")

# Data directories
dd_off = opt_off + O_DATADIRS
dd_names = ["EXPORT","IMPORT","RESOURCE","EXCEPTION","SECURITY","BASERELOC","DEBUG",
            "ARCHITECTURE","GLOBALPTR","TLS","LOAD_CONFIG","BOUND_IMPORT","IAT",
            "DELAY_IMPORT","COM_DESCRIPTOR","RESERVED"]

O("\nDATA DIRECTORIES:")
O(f"{'Name':<20} {'RVA':<12} {'Size':<12}")
data_dirs = []
for i in range(min(num_dd, 16)):
    rva = struct.unpack_from("<I", raw, dd_off + i*8)[0]
    sz = struct.unpack_from("<I", raw, dd_off + i*8 + 4)[0]
    stat = "EMPTY" if (rva == 0 and sz == 0) else ""
    O(f"{dd_names[i]:<20} 0x{rva:<10X} 0x{sz:<10X} {stat}")
    data_dirs.append({"idx": i, "name": dd_names[i], "rva": rva, "size": sz})

# Section headers
sec_hdr_off = dd_off + num_dd * 8
O("\nSECTION HEADERS:")

def rva_to_raw(rva):
    """Convert RVA to raw offset using section table"""
    for s in sections:
        if s['va'] <= rva < s['va'] + s['vsize']:
            return s['raw_ptr'] + (rva - s['va'])
    if sections and rva < sections[0]['va']:
        return rva
    return -1

sections = []
for i in range(nsections):
    so = sec_hdr_off + i * 40
    sname_raw = raw[so:so+8]
    sn = sname_raw.split(b'\x00')[0].decode('ascii', errors='replace')
    svs = struct.unpack_from("<I", raw, so + 8)[0]
    sva = struct.unpack_from("<I", raw, so + 12)[0]
    srs = struct.unpack_from("<I", raw, so + 16)[0]
    srp = struct.unpack_from("<I", raw, so + 20)[0]
    srp2 = struct.unpack_from("<I", raw, so + 24)[0]
    sch = struct.unpack_from("<I", raw, so + 36)[0]
    sf = ""
    sf += "X" if sch & 0x20000000 else "-"
    sf += "R" if sch & 0x40000000 else "-"
    sf += "W" if sch & 0x80000000 else "-"
    sec = {'name':sn, 'vsize':svs, 'va':sva, 'raw_size':srs, 'raw_ptr':srp, 'chars':sch}
    sections.append(sec)
    O(f"  [{sn:<10}] VS=0x{svs:08X} VA=0x{sva:08X} RS=0x{srs:08X} RP=0x{srp:08X} {sf}")
    O(f"            VA range: 0x{sva:X}-0x{sva+svs-1:X}  Raw: 0x{srp:X}-0x{srp+srs-1:X}")

# ============================================================
# 2. RELOCATIONS
# ============================================================
O("\n" + "=" * 80)
O("2. RELOCATIONS")
O("=" * 80)
rd = data_dirs[5]
O(f"BASERELOC: RVA=0x{rd['rva']:X} Size=0x{rd['size']:X}")
if rd['rva'] == 0 or rd['size'] == 0:
    O("  NO RELOCATIONS! ASLR requires manual fixup by unpacker.")
    O(f"  ImageBase=0x{image_base:X}")
else:
    rr = rva_to_raw(rd['rva'])
    tb = te = 0
    ro = rr
    while ro + 8 <= rr + rd['size']:
        pr = struct.unpack_from("<I", raw, ro)[0]
        bs = struct.unpack_from("<I", raw, ro + 4)[0]
        if bs == 0: break
        tb += 1; te += (bs - 8) // 2
        if tb <= 5:
            O(f"  Block: page=0x{pr:X} size={bs} entries={(bs-8)//2}")
        ro += bs
    O(f"  Total: {tb} blocks, {te} entries")

# ============================================================
# 3. RESOURCES
# ============================================================
O("\n" + "=" * 80)
O("3. RESOURCE DIRECTORY")
O("=" * 80)
rsd = data_dirs[2]
O(f"RESOURCE: RVA=0x{rsd['rva']:X} Size=0x{rsd['size']:X}")

# Find .rsrc section
rsrc_sec = None
for s in sections:
    if s['name'] == '.rsrc':
        rsrc_sec = s
        break

rsrc_entropy = 0
if rsrc_sec and rsrc_sec['raw_size'] > 0:
    rsdata = raw[rsrc_sec['raw_ptr']:rsrc_sec['raw_ptr'] + min(rsrc_sec['raw_size'], 0x10000)]
    cnt = Counter(rsdata)
    total = len(rsdata)
    for c in cnt.values():
        p = c / total
        if p > 0: rsrc_entropy += -p * math.log2(p)
    O(f".rsrc section: VA=0x{rsrc_sec['va']:X} VS=0x{rsrc_sec['vsize']:X} "
      f"RP=0x{rsrc_sec['raw_ptr']:X} RS=0x{rsrc_sec['raw_size']:X}")
    O(f"  Entropy: {rsrc_entropy:.2f} bits/byte")
    if rsrc_entropy > 7.0:
        O("  !! HIGH ENTROPY - likely compressed/encrypted, not standard resources!")

# Try to parse resource directory manually
if rsd['rva'] != 0 and rsd['size'] != 0:
    rr = rva_to_raw(rsd['rva'])
    if rr >= 0 and rr + 16 <= fsize:
        known_types = {1:"CURSOR",2:"BITMAP",3:"ICON",4:"MENU",5:"DIALOG",6:"STRING",
                       7:"FONTDIR",8:"FONT",9:"ACCEL",10:"RCDATA",12:"GRP_CURSOR",
                       14:"GRP_ICON",16:"VERSION",24:"MANIFEST"}
        
        def parse_rd(brva, db_rva, rb, lv, path):
            ro = rb + (brva - db_rva)
            if ro + 16 > fsize: return
            nc = struct.unpack_from("<H", raw, ro + 12)[0]
            ic = struct.unpack_from("<H", raw, ro + 14)[0]
            for j in range(nc + ic):
                eo = ro + 16 + j * 8
                if eo + 8 > fsize: break
                nr = struct.unpack_from("<I", raw, eo)[0]
                dr = struct.unpack_from("<I", raw, eo + 4)[0]
                is_leaf = (dr & 0x80000000) != 0
                nv = nr & 0x7FFFFFFF
                if is_leaf:
                    deo = rb + ((dr & 0x7FFFFFFF) - db_rva)
                    if deo + 16 > fsize: continue
                    data_rva = struct.unpack_from("<I", raw, deo)[0]
                    data_size = struct.unpack_from("<I", raw, deo + 4)[0]
                    tn = f" [{known_types.get(nv,'')}]" if lv == 0 and nv in known_types else ""
                    O(f"  {path}\\{nv}{tn}: DataRVA=0x{data_rva:X} Size=0x{data_size:X}")
                    # If version/manifest, extract text
                    if lv == 0 and nv in (16, 24) and data_size > 0 and data_size < 0x10000:
                        drw = rva_to_raw(data_rva)
                        if drw >= 0 and drw + data_size <= fsize:
                            try:
                                rstr = raw[drw:drw+min(data_size, 0x2000)].decode('utf-8', errors='replace')
                                for line in rstr.split('\n'):
                                    if line.strip():
                                        O(f"      {line.rstrip()}")
                            except:
                                pass
                else:
                    np = f"{path}\\{nv}"
                    if lv == 0 and nv in known_types:
                        np += f"({known_types[nv]})"
                    parse_rd(dr & 0x7FFFFFFF, db_rva, rb, lv+1, np)
        
        try:
            parse_rd(rsd['rva'], rsd['rva'], rr, 0, "")
        except Exception as e:
            O(f"  Resource parse error: {e}")

# Also scan for resource strings in raw sections
O("\nScanning sections for 'VS_VERSION_INFO', '<assembly', '<?xml':")
for s in sections:
    if s['raw_size'] == 0: continue
    sd = raw[s['raw_ptr']:s['raw_ptr'] + min(s['raw_size'], 0x100000)]
    for pat in [b'VS_VERSION_INFO', b'<assembly', b'<?xml', b'supportedOS', b'dpiAware']:
        idx = sd.find(pat)
        if idx >= 0:
            try:
                ctx = sd[max(0,idx-10):idx+80].decode('ascii', errors='replace').replace('\n',' ').replace('\r','')
                O(f"  [{s['name']}] '{pat.decode('ascii')}' at raw 0x{s['raw_ptr']+idx:X}: ...{ctx}...")
            except:
                pass

# ============================================================
# 4. IMPORTS
# ============================================================
O("\n" + "=" * 80)
O("4. IMPORT DIRECTORY")
O("=" * 80)
idd = data_dirs[1]
O(f"IMPORT: RVA=0x{idd['rva']:X} Size=0x{idd['size']:X}")

if idd['rva'] == 0 or idd['size'] == 0:
    O("  EMPTY import directory - packed DLL, runtime import resolution")
else:
    ir = rva_to_raw(idd['rva'])
    if ir >= 0:
        io = ir; ic = 0
        while io + 20 <= fsize:
            oft = struct.unpack_from("<I", raw, io)[0]
            nr = struct.unpack_from("<I", raw, io + 12)[0]
            ft = struct.unpack_from("<I", raw, io + 16)[0]
            if oft == 0 and nr == 0 and ft == 0: break
            dn = ""
            if nr > 0:
                nr2 = rva_to_raw(nr)
                if nr2 >= 0:
                    dn = raw[nr2:nr2+256].split(b'\x00')[0].decode('ascii', errors='replace')
            O(f"  DLL: {dn}")
            tr = rva_to_raw(oft if oft != 0 else ft)
            if tr and tr >= 0:
                fc = 0
                while True:
                    if is_pe64:
                        e = struct.unpack_from("<Q", raw, tr)[0]
                        mask = 0x8000000000000000
                        inc = 8
                    else:
                        e = struct.unpack_from("<I", raw, tr)[0]
                        mask = 0x80000000
                        inc = 4
                    if e == 0: break
                    if e & mask:
                        O(f"      Ordinal: {e & 0xFFFF}")
                    else:
                        hr = rva_to_raw(int(e & 0x7FFFFFFF))
                        if hr and hr >= 0 and hr + 2 <= fsize:
                            fn = raw[hr+2:hr+256].split(b'\x00')[0].decode('ascii', errors='replace')
                            O(f"      {fn}")
                    tr += inc; fc += 1
                    if fc > 500: break
            io += 20; ic += 1
        O(f"  Total imported DLLs: {ic}")

# Scan compressed data for DLL names
O("\nScanning compressed region (0x400+) for DLL strings:")
comp_region = raw[0x400:min(fsize, 0x400+0x100000)]
for dlln in [b'kernel32.dll', b'user32.dll', b'ntdll.dll', b'advapi32.dll', b'ws2_32.dll',
             b'shell32.dll', b'gdi32.dll', b'ole32.dll', b'KERNEL32', b'USER32']:
    idx = comp_region.find(dlln)
    if idx >= 0:
        O(f"  Found '{dlln.decode('ascii')}' at raw 0x{0x400+idx:X}")
    idx = comp_region.find(dlln.upper())
    if idx >= 0:
        O(f"  Found '{dlln.upper().decode('ascii')}' at raw 0x{0x400+idx:X}")

# ============================================================
# 5. EXPORTS
# ============================================================
O("\n" + "=" * 80)
O("5. EXPORT DIRECTORY")
O("=" * 80)
ed = data_dirs[0]
O(f"EXPORT: RVA=0x{ed['rva']:X} Size=0x{ed['size']:X}")
if ed['rva'] == 0:
    O("  NO EXPORTS")
else:
    er = rva_to_raw(ed['rva'])
    if er >= 0:
        enr = struct.unpack_from("<I", raw, er + 12)[0]
        enb = struct.unpack_from("<I", raw, er + 16)[0]
        enf = struct.unpack_from("<I", raw, er + 20)[0]
        enn = struct.unpack_from("<I", raw, er + 24)[0]
        dlle = ""
        if enr > 0:
            ex = rva_to_raw(enr)
            if ex >= 0: dlle = raw[ex:ex+256].split(b'\x00')[0].decode('ascii', errors='replace')
        O(f"  DLL={dlle} Funcs={enf} Names={enn} Base={enb}")
        if 0 < enn < 1000:
            ear = rva_to_raw(struct.unpack_from("<I", raw, er + 28)[0])
            enr2 = rva_to_raw(struct.unpack_from("<I", raw, er + 32)[0])
            eor = rva_to_raw(struct.unpack_from("<I", raw, er + 36)[0])
            for k in range(enn):
                fnr = struct.unpack_from("<I", raw, enr2 + k*4)[0]
                ord = struct.unpack_from("<H", raw, eor + k*2)[0]
                addr = struct.unpack_from("<I", raw, ear + ord*4)[0]
                try:
                    fname = raw[rva_to_raw(fnr):rva_to_raw(fnr)+256].split(b'\x00')[0].decode('ascii', errors='replace')
                except:
                    fname = "???"
                O(f"  {fname} RVA=0x{addr:X} Ord={enb+ord}")

# ============================================================
# 6. TLS
# ============================================================
O("\n" + "=" * 80)
O("6. TLS DIRECTORY")
O("=" * 80)
td = data_dirs[9]
O(f"TLS: RVA=0x{td['rva']:X} Size=0x{td['size']:X}")
if td['rva'] == 0:
    O("  NO TLS DIRECTORY. No TLS callbacks.")
else:
    tr = rva_to_raw(td['rva'])
    if tr >= 0:
        if is_pe64:
            tcb = struct.unpack_from("<Q", raw, tr + 24)[0]
        else:
            tcb = struct.unpack_from("<I", raw, tr + 12)[0]
        O(f"  TLS Callbacks VA: 0x{tcb:X}")
        if tcb != 0:
            O("  !! TLS CALLBACKS PRESENT !!")
            cbr = rva_to_raw(int(tcb - image_base))
            if cbr and cbr >= 0:
                for cb in range(10):
                    if is_pe64:
                        ca = struct.unpack_from("<Q", raw, cbr + cb * 8)[0]
                    else:
                        ca = struct.unpack_from("<I", raw, cbr + cb * 4)[0]
                    if ca == 0: break
                    O(f"    Callback[{cb}]: RVA=0x{ca - image_base:X}")

# ============================================================
# 7. EXCEPTIONS
# ============================================================
O("\n" + "=" * 80)
O("7. EXCEPTIONS (.pdata)")
O("=" * 80)
exc = data_dirs[3]
O(f"EXCEPTION: RVA=0x{exc['rva']:X} Size=0x{exc['size']:X}")
if exc['rva'] == 0:
    O("  NO exception table")
else:
    esize = 12 if is_pe64 else 8
    O(f"  Exception entries: {exc['size'] // esize}")

# ============================================================
# 8. CERTIFICATE
# ============================================================
O("\n" + "=" * 80)
O("8. CERTIFICATE")
O("=" * 80)
sc = data_dirs[4]
O(f"SECURITY: RVA=0x{sc['rva']:X} Size=0x{sc['size']:X}")
if sc['rva'] == 0:
    O("  NOT SIGNED. No digital certificate.")
else:
    sr = rva_to_raw(sc['rva'])
    if sr >= 0:
        clen = struct.unpack_from("<I", raw, sr)[0]
        ctype = struct.unpack_from("<H", raw, sr + 6)[0]
        O(f"  Cert length: 0x{clen:X} Type: 0x{ctype:04X}")

# ============================================================
# 9. OVERLAY
# ============================================================
O("\n" + "=" * 80)
O("9. OVERLAY DATA")
O("=" * 80)
lre = 0
for s in sections:
    e = s['raw_ptr'] + s['raw_size']
    if e > lre: lre = e
ovs = fsize - lre
O(f"Last section raw end: 0x{lre:X}  File end: 0x{fsize:X}  Overlay: {ovs} bytes")
if ovs > 0:
    ov_first = raw[lre:lre+64]
    O(f"Overlay first 64 bytes: {ov_first.hex(' ').upper()}")
    if struct.unpack_from("<H", raw, lre)[0] == 0x5A4D:
        O("  !! MZ signature - embedded executable!")
    # Entropy
    ov_sample = raw[lre:min(fsize, lre+0x8000)]
    ovcnt = Counter(ov_sample)
    otot = len(ov_sample)
    oent = 0.0
    for c in ovcnt.values():
        p = c / otot
        if p > 0: oent += -p * math.log2(p)
    O(f"Overlay entropy: {oent:.2f} bits/byte")

# ============================================================
# 10. RICH HEADER: see Section 1 (already parsed)
# ============================================================

# ============================================================
# 11. LOAD CONFIG
# ============================================================
O("\n" + "=" * 80)
O("11. LOAD CONFIG")
O("=" * 80)
ld = data_dirs[10]
O(f"LOAD_CONFIG: RVA=0x{ld['rva']:X} Size=0x{ld['size']:X}")
if ld['rva'] != 0:
    lr = rva_to_raw(ld['rva'])
    if lr and lr >= 0:
        lsize = struct.unpack_from("<I", raw, lr)[0]
        if is_pe64:
            gf = struct.unpack_from("<Q", raw, lr + 96)[0]
            gfc = struct.unpack_from("<Q", raw, lr + 104)[0]
            scookie = struct.unpack_from("<Q", raw, lr + 64)[0]
        else:
            gf = struct.unpack_from("<I", raw, lr + 84)[0]
            gfc = struct.unpack_from("<I", raw, lr + 88)[0]
            scookie = struct.unpack_from("<I", raw, lr + 72)[0]
        O(f"  Size: 0x{lsize:X}  GF Check: 0x{gf:X}  GF Count: {gfc}")
        O(f"  Security Cookie: 0x{scookie:X}")
        if gfc > 0: O("  !! Control Flow Guard ENABLED")

# ============================================================
# 12. DEBUG DIRECTORY
# ============================================================
O("\n" + "=" * 80)
O("12. DEBUG DIRECTORY")
O("=" * 80)
ddg = data_dirs[6]
O(f"DEBUG: RVA=0x{ddg['rva']:X} Size=0x{ddg['size']:X}")
if ddg['rva'] != 0 and ddg['size'] >= 28:
    dr = rva_to_raw(ddg['rva'])
    nde = ddg['size'] // 28
    for k in range(nde):
        deo = dr + k * 28
        dt = struct.unpack_from("<I", raw, deo + 12)[0]
        ds = struct.unpack_from("<I", raw, deo + 16)[0]
        dfp = struct.unpack_from("<I", raw, deo + 24)[0]
        O(f"  Entry[{k}]: Type={dt} Size=0x{ds:X} FilePtr=0x{dfp:X}")
        if dt == 2 and dfp > 0 and ds > 24:  # CODEVIEW
            sig = struct.unpack_from("<I", raw, dfp)[0]
            if sig == 0x53445352:  # RSDS
                age = struct.unpack_from("<I", raw, dfp + 20)[0]
                pdb = raw[dfp+24:dfp+ds].split(b'\x00')[0].decode('ascii', errors='replace')
                O(f"    RSDS PDB: {pdb} Age: {age}")

# ============================================================
# 13. BOUND IMPORT
# ============================================================
O("\n" + "=" * 80)
O("13. BOUND IMPORT")
O("=" * 80)
bd = data_dirs[11]
O(f"BOUND_IMPORT: RVA=0x{bd['rva']:X} Size=0x{bd['size']:X}")
if bd['rva'] != 0:
    br = rva_to_raw(bd['rva'])
    for bc in range(50):
        bts = struct.unpack_from("<I", raw, br + bc*8)[0]
        if bts == 0: break
        bno = struct.unpack_from("<H", raw, br + bc*8 + 4)[0]
        bdn = raw[br+bno:br+bno+256].split(b'\x00')[0].decode('ascii', errors='replace')
        O(f"  {bdn} (ts=0x{bts:X})")

# ============================================================
# 14. DELAY IMPORT
# ============================================================
O("\n" + "=" * 80)
O("14. DELAY IMPORT")
O("=" * 80)
di = data_dirs[13]
O(f"DELAY_IMPORT: RVA=0x{di['rva']:X} Size=0x{di['size']:X}")
if di['rva'] != 0:
    dir = rva_to_raw(di['rva'])
    do = dir; dc = 0
    while dc < 50:
        dnr = struct.unpack_from("<I", raw, do + 4)[0]
        if dnr == 0: break
        dn2 = rva_to_raw(dnr)
        if dn2 >= 0:
            O(f"  {raw[dn2:dn2+256].split(b'\x00')[0].decode('ascii', errors='replace')}")
        do += 32; dc += 1

# ============================================================
# 15. SECTION ANOMALIES
# ============================================================
O("\n" + "=" * 80)
O("15. SECTION ANOMALIES")
O("=" * 80)

for s in sections:
    diff = s['vsize'] - s['raw_size']
    O(f"\n[{s['name']}] VS=0x{s['vsize']:X} RS=0x{s['raw_size']:X} Diff={diff}")
    if s['raw_size'] == 0 and s['vsize'] > 0:
        O("  !! ZERO RAW SIZE - decompressed at load time from compressed payload")
    if s['raw_size'] > s['vsize']:
        O(f"  !! RAW > VIRT by {diff} bytes - hidden data in section tail")

# Raw gaps
O("\nINTER-SECTION RAW GAPS:")
for i in range(len(sections)-1):
    er = sections[i]['raw_ptr'] + sections[i]['raw_size']
    nr = sections[i+1]['raw_ptr']
    g = nr - er
    if g > 0:
        O(f"  [{sections[i]['name']} -> {sections[i+1]['name']}] Gap: {g} bytes at raw 0x{er:X}")
        if g <= 64:
            O(f"    Data: {raw[er:er+g].hex(' ').upper()}")
    elif g < 0:
        O(f"  [{sections[i]['name']} -> {sections[i+1]['name']}] OVERLAP: {-g} bytes!")

# Virtual gaps
O("\nVIRTUAL GAPS:")
for i in range(len(sections)-1):
    ev = sections[i]['va'] + sections[i]['vsize']
    nv = sections[i+1]['va']
    if nv > ev:
        O(f"  [{sections[i]['name']} -> {sections[i+1]['name']}] Virtual gap: 0x{nv-ev:X} bytes")

# Check for hidden data dirs
O("\nHIDDEN DATA IN STANDARD DIRECTORY SLOTS:")
for dd in data_dirs:
    if dd['rva'] == 0: continue
    r = rva_to_raw(dd['rva'])
    if r >= 0:
        for s in sections:
            if s['raw_ptr'] <= r < s['raw_ptr'] + s['raw_size']:
                O(f"  {dd['name']}: RVA=0x{dd['rva']:X} -> [{s['name']}] raw 0x{r:X}")
                break
        else:
            O(f"  {dd['name']}: RVA=0x{dd['rva']:X} -> NOT IN ANY SECTION (will be allocated at load)")
    else:
        for s in sections:
            if s['va'] <= dd['rva'] < s['va'] + s['vsize']:
                O(f"  {dd['name']}: RVA=0x{dd['rva']:X} -> [{s['name']}] VIRTUAL ONLY (decompressed)")
                break
        else:
            O(f"  {dd['name']}: RVA=0x{dd['rva']:X} -> OUTSIDE ALL SECTIONS")

# Section tails
O("\nSECTION TAILS (last 32 bytes):")
for s in sections:
    if s['raw_size'] == 0: continue
    to = s['raw_ptr'] + s['raw_size'] - 32
    if to < s['raw_ptr']: to = s['raw_ptr']
    tl = min(32, s['raw_size'])
    O(f"  [{s['name']}] 0x{to:X}: {raw[to:to+tl].hex(' ').upper()}")

# ============================================================
# 16. COMPRESSED DATA ANALYSIS
# ============================================================
O("\n" + "=" * 80)
O("16. COMPRESSED DATA ANALYSIS")
O("=" * 80)

co = 0x400
O(f"Data at offset 0x{co:X}, first 64 bytes:")
for i in range(0, 64, 16):
    O(f"  {co+i:03X}: {raw[co+i:co+i+16].hex(' ').upper()}")

first4 = struct.unpack_from("<I", raw, co)[0]
O(f"First UInt32: 0x{first4:08X} ({first4})")

# Signature detection
sig = ""
if raw[co:co+2] == b'\x78\xDA': sig = "zlib (default compression)"
elif raw[co:co+2] == b'\x78\x5E': sig = "zlib (best compression)"
elif raw[co:co+2] == b'\x78\x9C': sig = "zlib (default level)"
elif raw[co:co+2] == b'\x78\x01': sig = "zlib (no compression)"
elif raw[co:co+4] == b'Rar!': sig = "Rar!"
elif raw[co:co+4] == b'\x28\xB5\x2F\xFD': sig = "Zstandard"
elif raw[co:co+2] == b'MZ': sig = "MZ (EXE/DLL stub)"
elif raw[co:co+2] == b'\x18\x4D': sig = "LZ4"
elif raw[co:co+2] == b'BZ': sig = "bzip2"
elif raw[co:co+2] == b'\xFD\x37': sig = "lz4 frame"
elif raw[co] == 0x5D: sig = "LZMA/LZMA2"
elif raw[co] == 0x1F: sig = "gzip"
if sig:
    O(f"Compression signature: {sig}")
else:
    O(f"No standard compression magic detected. First 8 bytes: {raw[co:co+8].hex(' ').upper()}")

# Full 256 bytes
O("First 256 bytes:")
for i in range(0, 256, 16):
    O(f"  {co+i:03X}: {raw[co+i:co+i+16].hex(' ').upper()}")

# Entropy
cs = min(fsize - co, 0x20000)
cdata = raw[co:co+cs]
ccnt = Counter(cdata)
ctot = len(cdata)
cent = sum(-(c/ctot) * math.log2(c/ctot) for c in ccnt.values() if c > 0)
O(f"\nCompressed data entropy: {cent:.2f} bits/byte")
if cent > 7.5:
    O("  HIGH ENTROPY - likely encrypted or strongly compressed")
elif cent > 5:
    O("  MODERATE ENTROPY - typical compression")

# Block boundary analysis
O("\nBlock boundary analysis:")
prev = first4
sc = 0; trans = []
for ci in range(co+4, min(co+0x10000, fsize), 4):
    curr = struct.unpack_from("<I", raw, ci)[0]
    if curr != prev:
        if sc >= 8:
            trans.append((ci, sc+1, prev))
        sc = 0
    else:
        sc += 1
    prev = curr
if trans:
    O(f"  {len(trans)} repeated dword patterns (blocks):")
    for t in trans[:10]:
        O(f"    0x{t[0]:X}: {t[1]} dwords of 0x{t[2]:08X}")

# Compression summary
O("\nCompression summary:")
tc_size = fsize - co
tdc_size = 0
for s in sections:
    if s['raw_size'] == 0 and s['vsize'] > 0:
        tdc_size += s['vsize']
        O(f"  Virtual-only section [{s['name']}]: decompresses to 0x{s['vsize']:X} bytes")
if tdc_size > 0:
    O(f"  Compressed: 0x{tc_size:X} -> Decompressed: 0x{tdc_size:X} (ratio {tdc_size/tc_size:.2f}:1)")

# Try decompression
O("\nAttempting decompression of 0x400 data:")
# Try zlib
try:
    decomp = zlib.decompress(raw[co:min(fsize, co+0xB0000)])
    O(f"  zlib SUCCESS: {len(decomp)} bytes decompressed")
    O(f"  First 64 bytes: {decomp[:64].hex(' ').upper()}")
except Exception as e:
    O(f"  zlib failed: {e}")

# Try raw deflate
try:
    decomp = zlib.decompress(raw[co:min(fsize, co+0xB0000)], -15)
    O(f"  raw deflate SUCCESS: {len(decomp)} bytes")
    O(f"  First 64 bytes: {decomp[:64].hex(' ').upper()}")
except Exception as e:
    O(f"  raw deflate failed: {e}")

# Try with wbits=47 (gzip)
try:
    decomp = zlib.decompress(raw[co:min(fsize, co+0xB0000)], 16 + 15)
    O(f"  gzip SUCCESS: {len(decomp)} bytes")
    O(f"  First 64 bytes: {decomp[:64].hex(' ').upper()}")
except Exception as e:
    O(f"  gzip failed: {e}")

# ============================================================
# UNPACKED .TEXT ANALYSIS
# ============================================================
O("\n" + "=" * 80)
O("UNPACKED .TEXT ANALYSIS")
O("=" * 80)
O(f"Size: {tsize} bytes (0x{tsize:X})")

tm = struct.unpack_from("<H", text_raw, 0)[0]
tm_str = "MZ (COMPLETE PE?)" if tm == 0x5A4D else f"NOT MZ (raw x64 code, 0x{tm:04X})"
O(f"First 2 bytes: 0x{tm:04X} = {tm_str}")

# First 256 bytes
O("First 256 bytes:")
for i in range(0, min(256, tsize), 16):
    h = text_raw[i:i+16].hex(' ').upper()
    asc = ''.join(chr(b) if 0x20 <= b <= 0x7E else '.' for b in text_raw[i:i+16])
    O(f"  {i:08X}: {h:<50}{asc}")

# Last 256 bytes
O("Last 256 bytes:")
to = max(0, tsize - 256)
for i in range(to, min(to+256, tsize), 16):
    h = text_raw[i:i+16].hex(' ').upper()
    asc = ''.join(chr(b) if 0x20 <= b <= 0x7E else '.' for b in text_raw[i:i+16])
    O(f"  {i:08X}: {h:<50}{asc}")

# String scanning
O("\nString scanning in unpacked .text:")
scan_len = min(0x200000, tsize)
text_str = text_raw[:scan_len].decode('ascii', errors='replace')

patterns = [
    r'kernel32\.dll', r'user32\.dll', r'ntdll\.dll', r'advapi32\.dll',
    r'ws2_32\.dll', r'shell32\.dll', r'gdi32\.dll',
    r'GameAssembly\.dll', r'UnityPlayer\.dll', r'mono', r'il2cpp',
    r'Aimbot', r'ESP\b', r'Wallhack', r'God[Mm]ode', r'NoRecoil', r'NoSpread',
    r'SpeedHack', r'SuperCredits?', r'Requisition',
    r'CreateFile', r'ReadProcessMemory', r'WriteProcessMemory',
    r'VirtualAlloc', r'VirtualProtect', r'LoadLibrary', r'GetProcAddress',
    r'SwapChain', r'Present', r'D3D11', r'D3D12', r'DXGI',
    r'AntiCheat', r'BattlEye', r'EAC', r'VAC', r'GameGuard',
    r'CreateRemoteThread', r'IDI_ICON1', r'MAINICON',
    r'steamapps', r'Helldivers',
    r'WeaponEditor', r'WeaponOvr', r'AllGuns', r'SpawnSwapper',
    r'NtProtectVirtualMemory', r'INF_STAMINA', r'SC_Farming',
    r'helios', r'ht?(tps?)://', r'MachineGuid',
    r'SCLoop', r'Medal', r'LIBERTEA', r'HELLDIVERS'
]
for pat in patterns:
    for m in re.finditer(pat, text_str, re.IGNORECASE):
        s = max(0, m.start()-10)
        e = min(len(text_str), m.end()+60)
        ctx = text_str[s:e].replace('\n',' ').replace('\r','')
        O(f"  '{m.group()}' at 0x{m.start():X}: ...{ctx}...")

# x64 function prologue scan
O("\nFunction prologue scan (x64, first 1MB):")
prologues = []
scan_end = min(0x100000, tsize - 8)
i = 0
while i < scan_end:
    # sub rsp, XX
    if text_raw[i] == 0x48 and text_raw[i+1] == 0x83 and text_raw[i+2] == 0xEC:
        prologues.append(('sub rsp', i))
        i += 4; continue
    # push rbp; mov rbp, rsp
    if text_raw[i] == 0x55 and text_raw[i+1] == 0x48 and text_raw[i+2] == 0x89 and text_raw[i+3] == 0xE5:
        prologues.append(('push rbp', i))
        i += 4; continue
    # mov [rsp+xx], rbx (prologue)
    if text_raw[i] == 0x48 and text_raw[i+1] == 0x89 and text_raw[i+2] == 0x5C and text_raw[i+3] == 0x24:
        prologues.append(('mov [rsp], rbx', i))
        i += 4; continue
    # push rbx (prologue start)
    if text_raw[i] == 0x40 and text_raw[i+1] == 0x53:
        prologues.append(('push rbx', i))
        i += 2; continue
    # CC CC CC CC (alignment padding between functions)
    if text_raw[i] == 0xCC and text_raw[i+1] == 0xCC and text_raw[i+2] == 0xCC and text_raw[i+3] == 0xCC:
        if prologues and prologues[-1][1] + 4 < i:
            pass  # alignment
    i += 1

O(f"  Total x64 prologues found: {len(prologues)}")
for p in prologues[:10]:
    O(f"    {p[0]} at 0x{p[1]:X}")

# Check for INT3 / CC padding density (gives hint about code density)
cc_count = text_raw[:scan_end].count(0xCC)
O(f"  INT3 (0xCC) padding bytes in first 1MB: {cc_count} ({100*cc_count/scan_end:.1f}%)")

# Compressed header cross-reference
O("\nCross-reference: compressed header in unpacked .text:")
comp_hdr = raw[co:co+64]
idx = text_raw[:min(0x100000, tsize)].find(comp_hdr)
if idx >= 0:
    O(f"  FOUND at 0x{idx:X}")
else:
    O("  NOT found (expected).")

# ============================================================
# FINAL SUMMARY
# ============================================================
O("\n" + "=" * 80)
O("FINAL ANOMALIES SUMMARY")
O("=" * 80)

anoms = []
if data_dirs[5]['rva'] == 0: anoms.append("NO BASE RELOCATIONS - ASLR requires unpacker to handle manually")
if data_dirs[1]['rva'] == 0: anoms.append("NO IMPORTS IN PE - Runtime import resolution by unpacker")
if data_dirs[0]['rva'] == 0: anoms.append("NO EXPORTS - DLL has no exported entry points")
if data_dirs[4]['rva'] == 0: anoms.append("NO CODE SIGNING - Not digitally signed")
if ovs > 0: anoms.append(f"OVERLAY DATA: {ovs} bytes after last section")
if data_dirs[9]['rva'] == 0: anoms.append("NO TLS DIRECTORY")
if rsrc_entropy > 7.0: anoms.append(f"HIGH ENTROPY .rsrc ({rsrc_entropy:.2f} bits/byte) - compressed, not standard resources")
if cent > 7.5: anoms.append(f"HIGH ENTROPY compressed data ({cent:.2f} bits/byte) - encrypted or strongly compressed")

for s in sections:
    if s['raw_size'] == 0 and s['vsize'] > 0:
        anoms.append(f"SECTION [{s['name']}] ZERO RAW - decompressed at load (0x{s['vsize']:X} bytes)")
    if s['raw_size'] > s['vsize']:
        anoms.append(f"SECTION [{s['name']}] RAWSIZE > VIRTSIZE by {s['raw_size']-s['vsize']} bytes - hidden data!")

O("")
for a in anoms:
    O(f"  !! {a}")

# Key decompression findings
if tdc_size > 0:
    O(f"\nCOMPRESSION: {tc_size:,} bytes compressed -> ~{tdc_size:,} bytes decompressed")

# Specific observations from the analysis
O("\nKEY OBSERVATIONS:")
O(f"  Machine: {machine_name} ({'64-bit' if is_pe64 else '32-bit'})")
O(f"  ImageBase: 0x{image_base:X}")
O(f"  EntryPoint: 0x{entry:X}")
O(f"  Sections: {nsections}")

# Check if compressed data maps to virtual section
for s in sections:
    if s['raw_size'] == 0 and s['vsize'] > 0:
        O(f"  [{s['name']}] stored in compressed payload at 0x400, decompresses to VA 0x{s['va']:X} (size 0x{s['vsize']:X})")

O("")
O("=" * 80)
O("END OF ANALYSIS")
O("=" * 80)

# Write output
with open(OUT_PATH, "w", encoding="utf-8") as f:
    f.write("\n".join(OUT))

print(f"Written {len(OUT)} lines to {OUT_PATH}")
