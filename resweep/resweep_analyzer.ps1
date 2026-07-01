$ErrorActionPreference = "Continue"

$dllPath = "C:\Users\emora\OneDrive\Desktop\2\LIBERTEA.DLL"
$textPath = "C:\Users\emora\OneDrive\Desktop\2\.text_unpacked_mem.bin"
$outPath = "C:\Users\emora\OneDrive\Desktop\2\resweep_pe.txt"

$bytes = [System.IO.File]::ReadAllBytes($dllPath)
$fsize = $bytes.Length
$textDll = [System.IO.File]::ReadAllBytes($textPath)
$textSize = $textDll.Length

$sb = New-Object System.Text.StringBuilder
function O($s) { [void]$sb.AppendLine($s) }

function G16($off) {
    if ($off -lt 0 -or $off + 2 -gt $script:bytes.Length) { return 0 }
    [BitConverter]::ToUInt16($script:bytes, $off)
}
function G32($off) {
    if ($off -lt 0 -or $off + 4 -gt $script:bytes.Length) { return 0 }
    [BitConverter]::ToUInt32($script:bytes, $off)
}
function G64($off) {
    if ($off -lt 0 -or $off + 8 -gt $script:bytes.Length) { return 0 }
    [BitConverter]::ToUInt64($script:bytes, $off)
}
function GB($off, $len) {
    if ($off + $len -gt $script:bytes.Length) { $len = $script:bytes.Length - $off }
    if ($len -le 0) { return @() }
    $r = New-Object byte[] $len
    [Array]::Copy($script:bytes, $off, $r, 0, $len)
    return $r
}
function FH($arr) {
    if (-not $arr -or $arr.Count -eq 0) { return "(empty)" }
    return [BitConverter]::ToString($arr).Replace("-"," ")
}
function T16($off) {
    if ($off -lt 0 -or $off + 2 -gt $script:textDll.Length) { return 0 }
    [BitConverter]::ToUInt16($script:textDll, $off)
}
function T32($off) {
    if ($off -lt 0 -or $off + 4 -gt $script:textDll.Length) { return 0 }
    [BitConverter]::ToUInt32($script:textDll, $off)
}
function R2R($rva) {
    for ($si = 0; $si -lt $script:sections.Count; $si++) {
        $sr = $script:sections[$si].VirtualAddress
        $ss = $script:sections[$si].VirtualSize
        if ($rva -ge $sr -and $rva -lt $sr + $ss) {
            return $script:sections[$si].PointerToRawData + ($rva - $sr)
        }
    }
    if ($script:sections.Count -gt 0 -and $rva -lt $script:sections[0].VirtualAddress) { return $rva }
    return -1
}

$sections = @()

O("=" * 80)
O("LIBERTEA.DLL - COMPREHENSIVE BYTE-LEVEL RE-SWEEP")
O("=" * 80)
O("File size: $fsize bytes (0x{0:X})" -f $fsize)
O("Unpacked .text size: $textSize bytes (0x{0:X})" -f $textSize)
O("")

# ============================================================
# 1. PE HEADERS
# ============================================================
O("=" * 80)
O("1. PE HEADERS")
O("=" * 80)

$e_magic = G16 0
$e_lfanew = G32 60
$mzok = if ($e_magic -eq 0x5A4D) { "MZ" } else { "INVALID" }
O("DOS: e_magic=0x{0:X4} ({1}) e_lfanew=0x{2:X}" -f $e_magic, $mzok, $e_lfanew)
O("DOS header bytes 0x00-0x3F:")
O("  " + (FH (GB 0 64)))

# Rich header
$richFound = $false; $richOff = 0; $xorKey = 0
for ($i = 0x80; $i -lt $e_lfanew - 8; $i++) {
    if ((G32 $i) -eq 0x68636952) {
        $richOff = $i; $xorKey = G32 ($richOff + 4); $richFound = $true; break
    }
}
if ($richFound) {
    O("RICH HEADER at 0x{0:X} XOR=0x{1:X8}" -f $richOff, $xorKey)
    for ($j = $richOff - 8; $j -ge 0; $j -= 8) {
        $id = (G32 $j) -bxor $xorKey
        $count = (G32 ($j + 4)) -bxor $xorKey
        $compId = ($id -shr 16) -band 0xFFFF
        $build = $id -band 0xFFFF
        if ($compId -eq 0xFFFF -and $build -eq 0xFFFF) { break }
        if ($compId -gt 0x200) { break }
        O("  ToolID=0x{0:X4} Build={1} UseCount={2}" -f $compId, $build, $count)
    }
} else {
    O("Rich header: NOT FOUND")
}

# PE signature + COFF
$peOff = $e_lfanew
$peSig = G32 $peOff
$peok = if ($peSig -eq 0x4550) { "PE" } else { "INVALID" }
O("PE sig at 0x{0:X}: 0x{1:X8} ({2})" -f $peOff, $peSig, $peok)

$coffOff = $peOff + 4
$machine = G16 $coffOff
$numSections = G16 ($coffOff + 2)
$timeDate = G32 ($coffOff + 4)
$optHdrSize = G16 ($coffOff + 16)
$characteristics = G16 ($coffOff + 18)

$mname = switch ($machine) { 0x014C { "i386" } 0x8664 { "AMD64" } default { "0x"+$machine.ToString("X4") } }
$dts = [DateTime]::new(1970,1,1,0,0,0,0).AddSeconds($timeDate)
$cflags = @()
if ($characteristics -band 0x0002) { $cflags += "EXE" }
if ($characteristics -band 0x0020) { $cflags += "LARGE_ADDR" }
if ($characteristics -band 0x2000) { $cflags += "DLL" }
if ($characteristics -band 0x0100) { $cflags += "32BIT" }
if ($characteristics -band 0x0001) { $cflags += "RELOC_STRIP" }

O("COFF: Machine=0x{0:X4} ({1}) Sections={2} Time={3} OptHdrSize=0x{4:X4} Chars=0x{5:X4} ({6})" -f `
    $machine, $mname, $numSections, $dts.ToString("yyyy-MM-dd HH:mm:ss"), $optHdrSize, $characteristics, ($cflags -join " "))

# Optional header
$optOff = $coffOff + 20
$optMagic = G16 $optOff
$isPE64 = ($optMagic -eq 0x20B)
$pep = if ($isPE64) { 16 } else { 0 }

$entryRva = G32 ($optOff + 18)
$imageBase = if ($isPE64) { G64 ($optOff + 26) } else { [uint64](G32 ($optOff + 26)) }
$sectionAlign = G32 ($optOff + 34 - $pep)
$fileAlign = G32 ($optOff + 38 - $pep)
$sizeOfImage = G32 ($optOff + 58 - $pep)
$sizeOfHeaders = G32 ($optOff + 62 - $pep)
$checksum = G32 ($optOff + 66 - $pep)
$subsystem = G16 ($optOff + 70 - $pep)
$dllChar = G16 ($optOff + 72 - $pep)
$numDataDirs = G32 ($optOff + 110 - $pep)
$stackReserve = if ($isPE64) { G64 ($optOff + 74 - $pep) } else { [uint64](G32 ($optOff + 74 - $pep)) }

$mtype = if ($isPE64) { "PE32+" } else { "PE32" }
$sname = switch ($subsystem) { 2 { "WINDOWS_GUI" } 3 { "WINDOWS_CUI" } default { "0x"+$subsystem.ToString("X4") } }

O("OptHdr: Magic={0} ({1}) EntryPoint=0x{2:X} ImageBase=0x{3:X} SectionAlign=0x{4:X} FileAlign=0x{5:X}" -f `
    $optMagic.ToString("X4"), $mtype, $entryRva, $imageBase, $sectionAlign, $fileAlign)
O("  SizeOfImage=0x{0:X} SizeOfHeaders=0x{1:X} CheckSum=0x{2:X8} Subsystem={3}" -f $sizeOfImage, $sizeOfHeaders, $checksum, $sname)
O("  StackReserve=0x{0:X} DllChar=0x{1:X4} NumDataDirs={2}" -f $stackReserve, $dllChar, $numDataDirs)

$dllf = @()
if ($dllChar -band 0x0040) { $dllf += "DYNAMIC_BASE" }
if ($dllChar -band 0x0100) { $dllf += "NX_COMPAT" }
if ($dllChar -band 0x4000) { $dllf += "HIGH_ENTROPY_VA" }
if ($dllChar -band 0x2000) { $dllf += "CF_GUARD" }
O("  DllChar flags: " + ($dllf -join " "))

# Data directories
$ddOff = $optOff + 114 - $pep
$ddNames = @("EXPORT","IMPORT","RESOURCE","EXCEPTION","SECURITY","BASERELOC","DEBUG","ARCHITECTURE",
    "GLOBALPTR","TLS","LOAD_CONFIG","BOUND_IMPORT","IAT","DELAY_IMPORT","COM_DESCRIPTOR","RESERVED")

O("")
O("DATA DIRECTORIES:")
$dataDirs = @()
for ($i = 0; $i -lt [Math]::Min($numDataDirs, 16); $i++) {
    $ddr = $ddOff + $i * 8
    $rva = G32 $ddr; $size = G32 ($ddr + 4)
    $stat = if ($rva -eq 0 -and $size -eq 0) { "EMPTY" } else { "PRESENT" }
    O("{0,-18} RVA=0x{1,-8:X} Size=0x{2,-8:X} {3}" -f $ddNames[$i], $rva, $size, $stat)
    $dataDirs += @{ Index=$i; Name=$ddNames[$i]; RVA=$rva; Size=$size }
}

# Section headers
$secHdrOff = $ddOff + $numDataDirs * 8
O("")
O("SECTION HEADERS (Name VirtSize VirtAddr RawSize RawPtr Chars):")
$script:sections = @()
for ($i = 0; $i -lt $numSections; $i++) {
    $soff = $secHdrOff + $i * 40
    $sn = [System.Text.Encoding]::ASCII.GetString($bytes, $soff, 8) -replace '\0.*'
    $svs = G32 ($soff + 8); $sva = G32 ($soff + 12)
    $srs = G32 ($soff + 16); $srp = G32 ($soff + 20)
    $sch = G32 ($soff + 36)
    $sf = @()
    if ($sch -band 0x20000000) { $sf += "X" } else { $sf += "-" }
    if ($sch -band 0x40000000) { $sf += "R" } else { $sf += "-" }
    if ($sch -band 0x80000000) { $sf += "W" } else { $sf += "-" }
    $script:sections += @{ Name=$sn; VirtualSize=$svs; VirtualAddress=$sva; SizeOfRawData=$srs; PointerToRawData=$srp; Characteristics=$sch }
    O("{0,-10} {1,-8} @0x{2,-8:X} rawSz=0x{3,-8:X} rawPtr=0x{4,-8:X} {5}" -f $sn, "vs=0x"+$svs.ToString("X"), $sva, $srs, $srp, ($sf -join ""))
    O("  VA range: 0x{0:X}-0x{1:X}  Raw: 0x{2:X}-0x{3:X}" -f $sva, ($sva+$svs-1), $srp, ($srp+$srs-1))
}

# ============================================================
# 2. RELOCATIONS
# ============================================================
O("")
O("=" * 80)
O("2. RELOCATIONS")
O("=" * 80)
$rd = $dataDirs | Where-Object { $_.Index -eq 5 } | Select-Object -First 1
O("BASERELOC: RVA=0x{0:X} Size=0x{1:X}" -f $rd.RVA, $rd.Size)
if ($rd.RVA -eq 0) {
    O("  NO RELOCATIONS! ASLR requires manual fixup by unpacker at ImageBase=0x{0:X}" -f $imageBase)
} else {
    $rr = R2R $rd.RVA; $tb = 0; $te = 0; $roff = $rr
    while ($roff + 8 -le $rr + $rd.Size) {
        $pr = G32 $roff; $bs = G32 ($roff + 4)
        if ($bs -eq 0) { break }
        $tb++; $te += ($bs - 8) / 2
        if ($tb -le 3) { O("  Block page=0x{0:X} size={1} entries={2}" -f $pr, $bs, ($bs - 8)/2) }
        $roff += $bs
    }
    O("  Total: {0} blocks, {1} entries" -f $tb, $te)
}

# ============================================================
# 3. RESOURCES
# ============================================================
O("")
O("=" * 80)
O("3. RESOURCES")
O("=" * 80)
$rsd = $dataDirs | Where-Object { $_.Index -eq 2 } | Select-Object -First 1
O("RESOURCE: RVA=0x{0:X} Size=0x{1:X}" -f $rsd.RVA, $rsd.Size)

$rsrcSec = $script:sections | Where-Object { $_.Name -eq ".rsrc" }
$rsrcEntropy = 0
if ($rsrcSec) {
    $rsSample = GB $rsrcSec.PointerToRawData ([Math]::Min($rsrcSec.SizeOfRawData, 0x10000))
    $rcnt = @{}; $rtot = 0
    foreach ($b in $rsSample) { if (-not $rcnt.ContainsKey($b)) { $rcnt[$b]=0 }; $rcnt[$b]++; $rtot++ }
    foreach ($v in $rcnt.Values) { $p = $v / $rtot; if ($p -gt 0) { $rsrcEntropy += -$p * [Math]::Log($p, 2) } }
    O(".rsrc section: VA=0x{0:X} VS=0x{1:X} Raw=0x{2:X} RS=0x{3:X} Entropy={4:F2}" -f `
        $rsrcSec.VirtualAddress, $rsrcSec.VirtualSize, $rsrcSec.PointerToRawData, $rsrcSec.SizeOfRawData, $rsrcEntropy)
    if ($rsrcEntropy -gt 7.0) { O("  !! HIGH ENTROPY - likely compressed/crypto, not standard resources!") }
}

if ($rsd.RVA -ne 0 -and $rsd.Size -ne 0) {
    $rr = R2R $rsd.RVA
    # Quick depth-first resource parse
    $knownTypes = @{1="CURSOR";2="BITMAP";3="ICON";4="MENU";5="DIALOG";6="STRING";7="FONTDIR";8="FONT";
        9="ACCEL";10="RCDATA";12="GRP_CURSOR";14="GRP_ICON";16="VERSION";24="MANIFEST"}
    
    function PD($br, $db, $rb, $lv, $p) {
        $ro = $rb + ($br - $db)
        $nc = G16 ($ro + 12); $ic = G16 ($ro + 14)
        for ($j = 0; $j -lt ($nc + $ic); $j++) {
            $eo = $ro + 16 + $j * 8
            $nr = G32 $eo; $dr = G32 ($eo + 4)
            $isLeaf = ($dr -band 0x80000000) -ne 0
            $nv = $nr -band 0x7FFFFFFF
            $isNamed = ($nr -band 0x80000000) -eq 0
            if ($isLeaf) {
                $deo = $rb + (($dr -band 0x7FFFFFFF) - $db)
                $dataRva = G32 $deo; $dataSize = G32 ($deo + 4)
                $tn = if ($knownTypes.ContainsKey($nv) -and $lv -eq 0) { " [" + $knownTypes[$nv] + "]" } else { "" }
                O("  {0}\{1}{2}: DataRVA=0x{3:X} Size=0x{4:X}" -f $p, $nv, $tn, $dataRva, $dataSize)
                # Read version/manifest data
                if ($tn -match "VERSION|MANIFEST") {
                    $drw = R2R $dataRva
                    if ($drw -ge 0 -and $dataSize -gt 0 -and $dataSize -le 0x10000) {
                        $rstr = [System.Text.Encoding]::UTF8.GetString((GB $drw ([Math]::Min($dataSize, 0x2000))))
                        foreach ($l in ($rstr -split "`n")) { $lt = $l.Trim(); if ($lt) { O("      " + $lt) } }
                    }
                }
            } else {
                $np = $p + "\" + $nv
                if ($knownTypes.ContainsKey($nv) -and $lv -eq 0) { $np += "(" + $knownTypes[$nv] + ")" }
                PD -br ($dr -band 0x7FFFFFFF) -db $db -rb $rb -lv ($lv+1) -p $np
            }
        }
    }
    if ($rr -ge 0) { PD -br $rsd.RVA -db $rsd.RVA -rb $rr -lv 0 -p "" }
}

# Also check other sections for "version info" strings (sometimes hidden)
O("")
O("Scanning sections for ASCII strings 'VS_VERSION_INFO', '<assembly', '<?xml':")
foreach ($s in $script:sections) {
    if ($s.SizeOfRawData -eq 0) { continue }
    $ss = $s.SizeOfRawData
    if ($ss -gt 0x100000) { $ss = 0x100000 }
    $sd = GB $s.PointerToRawData $ss
    $sStr = [System.Text.Encoding]::ASCII.GetString($sd)
    foreach ($pk in @("VS_VERSION_INFO", "<assembly", "<?xml", "supportedOS", "dpiAware")) {
        $ix = $sStr.IndexOf($pk)
        if ($ix -ge 0) {
            $ctx = $sStr.Substring([Math]::Max(0,$ix-10), [Math]::Min(80,$sStr.Length-[Math]::Max(0,$ix-10))) -replace "[\r\n]"," "
            O("  [{0}] '{1}' at offset 0x{2:X}: ...{3}..." -f $s.Name, $pk, ($s.PointerToRawData+$ix), $ctx)
        }
    }
}

# ============================================================
# 4. IMPORTS
# ============================================================
O("")
O("=" * 80)
O("4. IMPORTS")
O("=" * 80)
$id = $dataDirs | Where-Object { $_.Index -eq 1 } | Select-Object -First 1
O("IMPORT: RVA=0x{0:X} Size=0x{1:X}" -f $id.RVA, $id.Size)
if ($id.RVA -eq 0) {
    O("  EMPTY import directory - packed DLL, runtime import resolution")
} else {
    $ir = R2R $id.RVA
    $ic = 0; $io = $ir
    while ($true) {
        $oft = G32 $io; $nr = G32 ($io + 12); $ft = G32 ($io + 16)
        if ($oft -eq 0 -and $nr -eq 0 -and $ft -eq 0) { break }
        $dn = ""; if ($nr -gt 0) { $nr2 = R2R $nr; if ($nr2 -gt 0) { $dn = [System.Text.Encoding]::ASCII.GetString($bytes,$nr2,256) -split "`0" | Select -First 1 } }
        O("  DLL: " + $dn)
        $tr = R2R (if ($oft -ne 0) { $oft } else { $ft })
        if ($tr -gt 0) {
            $fc = 0
            while ($true) {
                $e = if ($isPE64) { G64 $tr } else { [uint64](G32 $tr) }
                if ($e -eq 0) { break }
                $mask = if ($isPE64) { [uint64]0x8000000000000000 } else { [uint64]0x80000000 }
                if (($e -band $mask) -ne 0) {
                    O("      Ordinal: " + ([uint16]($e -band 0xFFFF)))
                } else {
                    $hr = R2R ([uint32]($e -band 0x7FFFFFFF))
                    if ($hr -gt 0) {
                        $fn = [System.Text.Encoding]::ASCII.GetString($bytes,$hr+2,256) -split "`0" | Select -First 1
                        O("      " + $fn)
                    }
                }
                $tr += if ($isPE64) { 8 } else { 4 }; $fc++
                if ($fc -gt 5000) { break }
            }
        }
        $io += 20; $ic++
    }
    O("  DLLs imported: " + $ic)
}

# Also scan compressed data area for potential DLL names / API hashes
O("")
O("Scanning compressed region for DLL names as ASCII:")
$compBytes = GB 0x400 ([Math]::Min($fsize - 0x400, 0x100000))
$compStr = [System.Text.Encoding]::ASCII.GetString($compBytes)
foreach ($dllP in @("kernel32.dll", "user32.dll", "ntdll.dll", "advapi32.dll", "KERNEL32", "USER32", "ws2_32", "shell32", "gdi32")) {
    $ix = $compStr.IndexOf($dllP, [StringComparison]::InvariantCultureIgnoreCase)
    if ($ix -ge 0) {
        O("  Found '" + $dllP + "' in compressed data at raw 0x" + (0x400+$ix).ToString("X"))
    }
}

# ============================================================
# 5. EXPORTS
# ============================================================
O("")
O("=" * 80)
O("5. EXPORTS")
O("=" * 80)
$ed = $dataDirs | Where-Object { $_.Index -eq 0 } | Select-Object -First 1
O("EXPORT: RVA=0x{0:X} Size=0x{1:X}" -f $ed.RVA, $ed.Size)
if ($ed.RVA -eq 0) { O("  NO EXPORTS") } else {
    $er = R2R $ed.RVA
    $enr = G32 ($er + 12); $enb = G32 ($er + 16); $enf = G32 ($er + 20); $enn = G32 ($er + 24)
    $dllE = if ($enr -gt 0) { $ex = R2R $enr; if ($ex -gt 0) { [System.Text.Encoding]::ASCII.GetString($bytes,$ex,256) -split "`0" | Select -First 1 } else { "" } } else { "" }
    O("  DLL={0} Funcs={1} Names={2} Base={3}" -f $dllE, $enf, $enn, $enb)
    if ($enn -gt 0 -and $enn -lt 500) {
        $ear = R2R (G32 ($er + 28)); $enr2 = R2R (G32 ($er + 32)); $eor = R2R (G32 ($er + 36))
        for ($k=0; $k -lt $enn; $k++) {
            $fnr = G32 ($enr2 + $k*4); $ord = G16 ($eor + $k*2); $addr = G32 ($ear + $ord*4)
            $fnN = [System.Text.Encoding]::ASCII.GetString($bytes,(R2R $fnr),256) -split "`0" | Select -First 1
            O("  {0} RVA=0x{1:X} Ord={2}" -f $fnN, $addr, ($enb+$ord))
        }
    }
}

# ============================================================
# 6. TLS
# ============================================================
O("")
O("=" * 80)
O("6. TLS")
O("=" * 80)
$td = $dataDirs | Where-Object { $_.Index -eq 9 } | Select-Object -First 1
O("TLS: RVA=0x{0:X} Size=0x{1:X}" -f $td.RVA, $td.Size)
if ($td.RVA -eq 0) { O("  NO TLS DIRECTORY") } else {
    $tr = R2R $td.RVA
    $tc = if ($isPE64) { G64 ($tr + 24) } else { [uint64](G32 ($tr + 12)) }
    O("  TLS Callbacks VA: 0x{0:X}" -f $tc)
    if ($tc -ne 0) {
        $cbr = R2R ([uint32]($tc - $imageBase))
        for ($cb=0; $cb -lt 10; $cb++) {
            $ca = if ($isPE64) { G64 ($cbr + $cb*8) } else { [uint64](G32 ($cbr + $cb*4)) }
            if ($ca -eq 0) { break }
            O("  Callback[{0}]: RVA=0x{1:X}" -f $cb, ($ca - $imageBase))
        }
    }
}

# ============================================================
# 7. EXCEPTIONS
# ============================================================
O("")
O("=" * 80)
O("7. EXCEPTIONS (.pdata)")
O("=" * 80)
$exc = $dataDirs | Where-Object { $_.Index -eq 3 } | Select-Object -First 1
O("EXCEPTION: RVA=0x{0:X} Size=0x{1:X}" -f $exc.RVA, $exc.Size)
$pdSec = $script:sections | Where-Object { $_.Name -eq ".pdata" }
if ($exc.RVA -eq 0) {
    O("  NO exception directory")
    if ($pdSec) { O("  .pdata section exists: VA=0x{0:X} VS=0x{1:X}" -f $pdSec.VirtualAddress, $pdSec.VirtualSize) }
} else {
    $es = if ($isPE64) { 12 } else { 8 }
    O("  Exception entries: " + ($exc.Size / $es))
}

# ============================================================
# 8-14. CERT, OVERLAY, DEBUG, BOUND, DELAY, LOAD_CONFIG
# ============================================================
O("")
O("=" * 80)
O("8. CERTIFICATE")
O("=" * 80)
$sec = $dataDirs | Where-Object { $_.Index -eq 4 } | Select-Object -First 1
O("SECURITY: RVA=0x{0:X} Size=0x{1:X}" -f $sec.RVA, $sec.Size)
O(if ($sec.RVA -eq 0) { "  NOT SIGNED" } else { "  Certificate present, size=0x{0:X}" -f $sec.Size })

O("")
O("=" * 80)
O("9. OVERLAY")
O("=" * 80)
$lre = 0
foreach ($s in $script:sections) { $e = $s.PointerToRawData + $s.SizeOfRawData; if ($e -gt $lre) { $lre = $e } }
$ovs = $fsize - $lre
O("Last section raw end: 0x{0:X}  File end: 0x{1:X}  Overlay: {2} bytes" -f $lre, $fsize, $ovs)
if ($ovs -gt 0) {
    O("Overlay first 64 bytes: " + (FH (GB $lre 64)))
    if ((G16 $lre) -eq 0x5A4D) { O("  !! MZ signature - embedded executable!") }
    # Check entropy
    $ovb = GB $lre ([Math]::Min($ovs, 0x8000))
    $ocnt = @{}; $otot = 0
    foreach ($b in $ovb) { if (-not $ocnt.ContainsKey($b)) { $ocnt[$b]=0 }; $ocnt[$b]++; $otot++ }
    $oent = 0.0
    foreach ($v in $ocnt.Values) { $p = $v / $otot; if ($p -gt 0) { $oent += -$p * [Math]::Log($p,2) } }
    O("Overlay entropy: {0:F2} bits/byte" -f $oent)
}

O("")
O("=" * 80)
O("10. RICH HEADER: see Section 1")

O("")
O("=" * 80)
O("11. LOAD CONFIG")
O("=" * 80)
$ld = $dataDirs | Where-Object { $_.Index -eq 10 } | Select-Object -First 1
O("LOAD_CONFIG: RVA=0x{0:X} Size=0x{1:X}" -f $ld.RVA, $ld.Size)
if ($ld.RVA -ne 0) {
    $lr = R2R $ld.RVA
    $gfc = if ($isPE64) { G64 ($lr + 104) } else { [uint64](G32 ($lr + 88)) }
    O("  Guard CF Func Count: " + $gfc)
    if ($gfc -gt 0) { O("  !! CFG ENABLED") }
}

O("")
O("=" * 80)
O("12. DEBUG DIRECTORY")
O("=" * 80)
$dd = $dataDirs | Where-Object { $_.Index -eq 6 } | Select-Object -First 1
O("DEBUG: RVA=0x{0:X} Size=0x{1:X}" -f $dd.RVA, $dd.Size)
if ($dd.RVA -ne 0) {
    $dr = R2R $dd.RVA
    $nde = $dd.Size / 28
    for ($k=0; $k -lt $nde; $k++) {
        $deo = $dr + $k*28
        $dt = G32 ($deo + 12); $ds = G32 ($deo + 16); $dfp = G32 ($deo + 24)
        O("  Entry[{0}]: Type={1} Size=0x{2:X} FilePtr=0x{3:X}" -f $k, $dt, $ds, $dfp)
        if ($dt -eq 2 -and $dfp -gt 0 -and $ds -gt 24 -and $dfp+$ds -le $bytes.Length) {
            if ((G32 $dfp) -eq 0x53445352) {
                $pdb = [System.Text.Encoding]::ASCII.GetString($bytes,$dfp+24,$ds-24) -split "`0" | Select -First 1
                O("    RSDS PDB: " + $pdb)
            }
        }
    }
}

O("")
O("=" * 80)
O("13. BOUND IMPORT")
O("=" * 80)
$bd = $dataDirs | Where-Object { $_.Index -eq 11 } | Select-Object -First 1
O("BOUND_IMPORT: RVA=0x{0:X} Size=0x{1:X}" -f $bd.RVA, $bd.Size)
if ($bd.RVA -ne 0) {
    $br = R2R $bd.RVA; $bc = 0
    while ($bc -lt 50) {
        $bts = G32 ($br + $bc*8)
        if ($bts -eq 0) { break }
        $bno = G16 ($br + $bc*8 + 4)
        $bdn = [System.Text.Encoding]::ASCII.GetString($bytes,$br+$bno,256) -split "`0" | Select -First 1
        O("  " + $bdn)
        $bc++
    }
}

O("")
O("=" * 80)
O("14. DELAY IMPORT")
O("=" * 80)
$di = $dataDirs | Where-Object { $_.Index -eq 13 } | Select-Object -First 1
O("DELAY_IMPORT: RVA=0x{0:X} Size=0x{1:X}" -f $di.RVA, $di.Size)
if ($di.RVA -ne 0) {
    $dir = R2R $di.RVA; $doff = $dir; $dc = 0
    while ($dc -lt 50) {
        $dnr = G32 ($doff + 4)
        if ($dnr -eq 0) { break }
        $dn2 = R2R $dnr
        if ($dn2 -gt 0) { O("  " + ([System.Text.Encoding]::ASCII.GetString($bytes,$dn2,256) -split "`0" | Select -First 1)) }
        $doff += 32; $dc++
    }
}

# ============================================================
# 15. SECTION ANOMALIES
# ============================================================
O("")
O("=" * 80)
O("15. SECTION ANOMALIES")
O("=" * 80)

foreach ($s in $script:sections) {
    $diff = [int64]$s.VirtualSize - [int64]$s.SizeOfRawData
    O("[{0}] Raw: 0x{1:X}-0x{2:X} ({3})  Virt: 0x{4:X}-0x{5:X} ({6})  Diff: {7}" -f `
        $s.Name, $s.PointerToRawData, ($s.PointerToRawData+$s.SizeOfRawData-1), $s.SizeOfRawData, `
        $s.VirtualAddress, ($s.VirtualAddress+$s.VirtualSize-1), $s.VirtualSize, $diff)
    if ($s.SizeOfRawData -eq 0 -and $s.VirtualSize -gt 0) {
        O("  !! ZERO RAW - decompressed at load")
    }
    if ($s.SizeOfRawData -gt $s.VirtualSize) {
        $excess = $s.SizeOfRawData - $s.VirtualSize
        O("  !! RAW > VIRT by " + $excess + " bytes - trailing hidden data!")
    }
}

# Raw gaps
O("")
O("INTER-SECTION RAW GAPS:")
for ($i=0; $i -lt ($script:sections.Count-1); $i++) {
    $er = $script:sections[$i].PointerToRawData + $script:sections[$i].SizeOfRawData
    $nr = $script:sections[$i+1].PointerToRawData
    $g = $nr - $er
    if ($g -gt 0) {
        O("  [{0} -> {1}] Gap: {2} bytes at raw 0x{3:X}" -f $script:sections[$i].Name, $script:sections[$i+1].Name, $g, $er)
        if ($g -le 64) { O("    " + (FH (GB $er $g))) }
    } elseif ($g -lt 0) {
        O("  [{0} -> {1}] OVERLAP: {2} bytes" -f $script:sections[$i].Name, $script:sections[$i+1].Name, (-$g))
    }
}

# Virtual gaps
O("")
O("VIRTUAL GAPS:")
for ($i=0; $i -lt ($script:sections.Count-1); $i++) {
    $ev = $script:sections[$i].VirtualAddress + $script:sections[$i].VirtualSize
    $nv = $script:sections[$i+1].VirtualAddress
    $vg = $nv - $ev
    if ($vg -gt 0) {
        O("  [{0} -> {1}] Virtual gap: 0x{2:X} bytes" -f $script:sections[$i].Name, $script:sections[$i+1].Name, $vg)
    }
}

# Section tail bytes
O("")
O("SECTION TAILS (last 32 bytes):")
foreach ($s in $script:sections) {
    if ($s.SizeOfRawData -eq 0) { continue }
    $to = $s.PointerToRawData + $s.SizeOfRawData - 32
    if ($to -lt $s.PointerToRawData) { $to = $s.PointerToRawData }
    $tl = [Math]::Min(32, $s.SizeOfRawData)
    O("  [{0}] 0x{1:X}: {2}" -f $s.Name, $to, (FH (GB $to $tl)))
}

# ============================================================
# 16. COMPRESSED DATA ANALYSIS
# ============================================================
O("")
O("=" * 80)
O("16. COMPRESSED DATA ANALYSIS")
O("=" * 80)

$co = 0x400
$first4 = G32 $co
$first8 = FH (GB $co 8)
O("Offset 0x400: first 8 bytes = " + $first8)
O("First UInt32: 0x{0:X8} ({0})" -f $first4)

# Signature check
if ((G16 $co) -eq 0xDA78) { O("SIGNATURE: zlib (default compression)") }
elseif ((G16 $co) -eq 0x5E78) { O("SIGNATURE: zlib (best compression)") }
elseif ((G32 $co) -eq 0x21726152) { O("SIGNATURE: Rar!") }
elseif ((G32 $co) -eq 0x28B52FFD) { O("SIGNATURE: Zstandard") }
elseif ((G16 $co) -eq 0x5A4D) { O("SIGNATURE: MZ (EXE/DLL stub)") }
elseif ((G16 $co) -eq 0x184D) { O("SIGNATURE: LZ4") }
elseif ((G16 $co) -eq 0x425A) { O("SIGNATURE: bzip2") }
elseif ((G16 $co) -eq 0xFD37) { O("SIGNATURE: lz4 frame") }
elseif (($first4 -band 0xFFFFFF00) -eq 0x6C7A7800) { O("SIGNATURE: zlib stream") }
else { O("No standard compression magic detected.") }

# First 256 bytes for pattern analysis
O("First 256 bytes of compressed data:")
for ($i=0; $i -lt 256; $i+=16) {
    O("  {0:X3}: {1}" -f ($co+$i), (FH (GB ($co+$i) 16)))
}

# Entropy
$cs = [Math]::Min($fsize - $co, 0x20000)
$cData = GB $co $cs
$cc = @{}; $ct = 0
foreach ($b in $cData) { if (-not $cc.ContainsKey($b)) { $cc[$b]=0 }; $cc[$b]++; $ct++ }
$ce = 0.0
foreach ($v in $cc.Values) { $p = $v / $ct; if ($p -gt 0) { $ce += -$p * [Math]::Log($p,2) } }
O("")
O("Compressed data entropy: {0:F2} bits/byte (first {1} bytes)" -f $ce, $cs)
if ($ce -gt 7.5) { O("  HIGH ENTROPY - encrypted or strongly compressed") }
elseif ($ce -gt 5) { O("  MODERATE ENTROPY - typical compression") }
else { O("  LOW ENTROPY") }

# Look for structured block boundaries
O("")
O("Block boundary analysis (repeated dword patterns):")
$prev = $first4
$sameC = 0; $trans = @()
for ($ci = $co + 4; $ci -lt [Math]::Min($co + 0x10000, $fsize); $ci += 4) {
    $curr = G32 $ci
    if ($curr -ne $prev) {
        if ($sameC -ge 8) { $trans += @{O=$ci; C=$sameC; V=$prev} }
        $sameC = 0
    } else { $sameC++ }
    $prev = $curr
}
if ($trans.Count -gt 0) {
    O("  {0} repeated dword patterns (potential block delimiters):" -f $trans.Count)
    foreach ($t in $trans | Select -First 10) {
        O("    0x{0:X}: {1} dwords of 0x{2:X8}" -f $t.O, $t.C+1, $t.V)
    }
}

# Compression ratio estimate
O("")
O("Compression summary:")
$tcSize = $fsize - $co
$tdcSize = 0
foreach ($s in $script:sections) {
    if ($s.SizeOfRawData -eq 0 -and $s.VirtualSize -gt 0) {
        $tdcSize += $s.VirtualSize
        O("  Virtual-only section [{0}]: decompresses to 0x{1:X} bytes" -f $s.Name, $s.VirtualSize)
    }
}
if ($tdcSize -gt 0) {
    O("  Compressed: 0x{0:X} -> Decompressed: 0x{1:X} (ratio {2:F2}:1)" -f $tcSize, $tdcSize, ($tdcSize / $tcSize))
}

# ============================================================
# UNPACKED .TEXT ANALYSIS
# ============================================================
O("")
O("=" * 80)
O("UNPACKED .TEXT ANALYSIS")
O("=" * 80)
O("Size: {0} bytes (0x{0:X})" -f $textSize)

$tMagic = T16 0
$tm = if ($tMagic -eq 0x5A4D) { "MZ (COMPLETE PE?)" } else { "NOT MZ (raw code/memory dump)" }
O("First 2 bytes: 0x{0:X4} = {1}" -f $tMagic, $tm)

if ($tMagic -eq 0x5A4D) {
    $tLfa = T32 60
    O("  e_lfanew = 0x{0:X}" -f $tLfa)
    if ($tLfa + 4 -le $textDll.Length) {
        $tp = T32 $tLfa
        O("  PE sig = 0x{0:X8}" -f $tp)
    }
}

O("First 256 bytes:")
for ($i=0; $i -lt [Math]::Min(256,$textSize); $i+=16) {
    $hex = ""; $asc = ""
    $end = [Math]::Min($i+15,$textSize-1)
    for ($j=$i; $j -le $end; $j++) {
        $hex += ("{0:X2} " -f $textDll[$j])
        if ($textDll[$j] -ge 0x20 -and $textDll[$j] -le 0x7E) { $asc += [char]$textDll[$j] } else { $asc += "." }
    }
    O("  {0:X8}: {1,-50}{2}" -f $i, $hex, $asc)
}

O("Last 256 bytes of unpacked .text:")
$tailOff2 = [Math]::Max(0, $textSize - 256)
for ($i=$tailOff2; $i -lt [Math]::Min($tailOff2+256,$textSize); $i+=16) {
    $hex = ""; $asc = ""
    $end = [Math]::Min($i+15,$textSize-1)
    for ($j=$i; $j -le $end; $j++) {
        $hex += ("{0:X2} " -f $textDll[$j])
        if ($textDll[$j] -ge 0x20 -and $textDll[$j] -le 0x7E) { $asc += [char]$textDll[$j] } else { $asc += "." }
    }
    O("  {0:X8}: {1,-50}{2}" -f $i, $hex, $asc)
}

# String scanning in unpacked text (using .NET IndexOf)
O("")
O("String scanning in unpacked .text (first 2MB):")
$scanLen = [Math]::Min(0x200000, $textSize)
$textStr = [System.Text.Encoding]::ASCII.GetString($textDll, 0, $scanLen)

$patterns = @(
    "kernel32.dll","user32.dll","ntdll.dll","advapi32.dll","ws2_32.dll","shell32.dll","gdi32.dll",
    "GameAssembly.dll","UnityPlayer.dll","mono","il2cpp",
    "Aimbot","ESP ","Wallhack","Godmode","NoRecoil","NoSpread",
    "SpeedHack","SuperCredits","Requisition",
    "CreateFile","ReadProcessMemory","WriteProcessMemory",
    "VirtualAlloc","VirtualProtect","LoadLibrary","GetProcAddress",
    "SwapChain","Present","D3D11","D3D12","DXGI",
    "AntiCheat","BattlEye","EAC","VAC","GameGuard",
    "CreateRemoteThread","IDI_ICON1","MAINICON",
    "steamapps","common","Helldivers",
    "PlayerController","Weapon","Sample","SC_Farming"
)
foreach ($pat in $patterns) {
    $rem = $textStr
    $pos = 0
    while ($true) {
        $ix = $rem.IndexOf($pat, [StringComparison]::InvariantCultureIgnoreCase)
        if ($ix -lt 0) { break }
        $absIx = $pos + $ix
        $start = [Math]::Max(0, $absIx - 10)
        $len = [Math]::Min(120, $textStr.Length - $start)
        $ctx = $textStr.Substring($start, $len) -replace "[\r\n]", " "
        O("  '{0}' at 0x{1:X}: ...{2}..." -f $pat, $absIx, $ctx.Trim())
        $pos = $absIx + 1
        $rem = $textStr.Substring([Math]::Min($pos, $textStr.Length))
        if ([string]::IsNullOrEmpty($rem)) { break }
    }
}

# Function prologue count (fast scan using Array.IndexOf)
O("")
O("Function prologue scan (limited to first 128KB of unpacked .text):")
$scanEnd = [Math]::Min(0x20000, $textSize - 4)
$pc = 0
for ($ioff = 0; $ioff -lt $scanEnd; $ioff++) {
    if ($textDll[$ioff] -eq 0x55 -and $textDll[$ioff+1] -eq 0x8B -and $textDll[$ioff+2] -eq 0xEC) {
        if ($pc -lt 5) { O("  x86 prologue (55 8B EC) at 0x{0:X}" -f $ioff) }
        $pc++
    }
}
O("  Total x86 push ebp/mov ebp,esp: " + $pc)

# Compressed data header cross-reference
O("")
O("Cross-reference: compressed header in unpacked .text:")
$compHead = GB $co 64
$found = $false
$srEnd = [Math]::Min(0x100000, $textSize - 64)
for ($si = 0; $si -lt $srEnd - 64; $si++) {
    $m = $true
    for ($sj = 0; $sj -lt 64; $sj++) {
        if ($compHead[$sj] -ne $textDll[$si+$sj]) { $m = $false; break }
    }
    if ($m) { O("  FOUND at 0x{0:X}" -f $si); $found = $true; break }
}
if (-not $found) { O("  NOT found in first 1MB (expected - decompressed data shouldn't contain compressed header)") }

# ============================================================
# FINAL SUMMARY
# ============================================================
O("")
O("=" * 80)
O("FINAL ANOMALIES SUMMARY")
O("=" * 80)

$anoms = @()

# Which data directories point into which sections?
O("")
O("Data Directory -> Section mapping:")
foreach ($d in $dataDirs) {
    if ($d.RVA -eq 0) { O("  " + $d.Name + ": EMPTY"); continue }
    $r = R2R $d.RVA
    if ($r -ge 0) {
        foreach ($s in $script:sections) {
            $se = $s.PointerToRawData + $s.SizeOfRawData
            if ($s.SizeOfRawData -gt 0 -and $r -ge $s.PointerToRawData -and $r -lt $se) {
                O("  " + $d.Name + " (0x" + $d.RVA.ToString("X") + ") -> [" + $s.Name + "] raw 0x" + $r.ToString("X"))
                break
            }
        }
        # Check if RVA maps to a section with zero raw size (decompressed)
        foreach ($s in $script:sections) {
            if ($d.RVA -ge $s.VirtualAddress -and $d.RVA -lt $s.VirtualAddress + $s.VirtualSize) {
                if ($s.SizeOfRawData -eq 0) {
                    O("  " + $d.Name + " (0x" + $d.RVA.ToString("X") + ") -> [" + $s.Name + "] DECOMPRESSED at load")
                }
                break
            }
        }
    } else {
        O("  " + $d.Name + " (0x" + $d.RVA.ToString("X") + ") -> OUTSIDE FILE BOUNDS")
    }
}

# Generate anomalies
if ($rd.RVA -eq 0) { $anoms += "NO BASE RELOCATIONS - Standard ASLR impossible; unpacker must handle" }
if ($id.RVA -eq 0) { $anoms += "NO IMPORTS IN PE HEADERS - Runtime import resolution (packed DLL)" }
if ($ed.RVA -eq 0) { $anoms += "NO EXPORTS - DLL has no exported entry points" }
if ($sec.RVA -eq 0) { $anoms += "NO CODE SIGNING - Not digitally signed" }
if ($ovs -gt 0) { $anoms += "OVERLAY DATA: " + $ovs + " bytes after last section" }
if ($td.RVA -eq 0) { $anoms += "NO TLS DIRECTORY" }
if ($rsrcEntropy -gt 7.0) { $anoms += "HIGH ENTROPY .rsrc (" + $rsrcEntropy.ToString("F2") + " bits/byte) - compressed/encrypted payload, NOT standard resources" }

foreach ($s in $script:sections) {
    if ($s.SizeOfRawData -eq 0 -and $s.VirtualSize -gt 0) {
        $anoms += "Section [" + $s.Name + "] ZERO RAW SIZE (0x" + $s.VirtualSize.ToString("X") + " virtual) - stored in compressed payload"
    }
    if ($s.SizeOfRawData -gt $s.VirtualSize) {
        $ex = $s.SizeOfRawData - $s.VirtualSize
        $anoms += "Section [" + $s.Name + "] RAWSIZE > VIRTSIZE by " + $ex + " bytes - extra hidden data"
    }
}

O("")
foreach ($a in $anoms) { O("  !! " + $a) }
O("")
O("=" * 80)
O("END OF ANALYSIS")
O("=" * 80)

# Write
$out = $sb.ToString()
[System.IO.File]::WriteAllText($outPath, $out, [System.Text.Encoding]::UTF8)
Write-Output "Written $($out.Length) chars to $outPath"
