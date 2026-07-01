# LiberTea — Helldivers 2 Internal Cheat Reverse Engineering

Complete reverse engineering of **LIBERTEA.DLL v414**, a Helldivers 2 internal cheat/trainer by "TheOGcup". Every byte, every pattern, every hook, every protocol detail — fully documented.

## Quick Facts

| Field | Value |
|---|---|
| **Target** | Helldivers 2 (Steam) |
| **Cheat DLL** | LIBERTEA.DLL (732 KB packed, 3.49 MB unpacked) |
| **Injector** | LIBERTEA_Bypass.exe |
| **Version** | v414 |
| **Author** | TheOGcup |
| **Language** | C++17, MSVC 2022, static CRT |
| **GUI** | Dear ImGui 1.91.5, OpenGL overlay |
| **Anti-cheat bypassed** | nProtect GameGuard |
| **Distribution** | Discord + Cloudflare Workers CDN |
| **Auth** | Username/password or key, subscription tiers |

## Directory Structure

```
2/
├── README.md
├── MASTER_INDEX.txt
├── LIBERTEA.DLL
├── .text_decompressed.bin
│
├── docs/
│   ├── 01_binary_identity/
│   │   ├── libertea_analysis.txt          # Pointers, offsets, IDs, ImGui toggles
│   │   ├── libertea_tech_breakdown.txt    # Build architecture, aPLib spec, build strategy
│   │   ├── libertea_complete.txt          # Full disassembly, call graph, entropy, anti-debug
│   │   └── resweep_pe.txt                 # PE headers, relocations, TLS, exceptions, compression
│   ├── 02_code_analysis/
│   │   ├── libertea_deep_dive.txt         # Memory map, function map, strings, C++ RTTI, features
│   │   ├── libertea_niche.txt             # Format strings, HTTP headers, enums, FP constants
│   │   └── resweep_code.txt               # ImGui version, pattern scanner, HTTP stack, JSON parser
│   ├── 03_game_data/
│   │   ├── resweep_game_data.txt          # 130 weapons, 68 armor, 37 stratagems, pointer chains
│   │   └── resweep_strings.txt            # Base64, crypto, proxy detection, AOB signatures, HWID
│   ├── 04_hook_system/
│   │   └── hook_system_analysis.txt       # 73 patterns, 6 hook types, 4-phase install
│   ├── 05_network_protocol/
│   │   └── sc_farming_analysis.txt        # State machine, replay capture, hash table NOP, VEH
│   ├── 06_architecture/
│   │   └── architecture_recreation.txt    # 15 components, data flow, recreation strategy
│   └── 07_sanitized/
│       └── FULL_BREAKDOWN_SANITIZED.txt   # Sanitized full breakdown
│
├── scripts/
│   ├── extractors/
│   │   ├── pattern_extractor.py           # Extract 73+ IDA patterns → JSON
│   │   ├── deep_dive.py                   # Generate deep dive document
│   │   ├── niche_details.py               # Generate niche details document
│   │   ├── extract_analysis.py            # Generate analysis document
│   │   ├── full_extract.py                # Generate complete document
│   │   └── libertea_tech_breakdown.py     # Generate tech breakdown document
│   ├── analysis/
│   │   ├── sc_protocol_analysis.py        # SC farming state machine with data classes
│   │   ├── _analyze.py                    # aPLib decompressor (partial)
│   │   ├── analyze_re.py                  # Reverse analysis script
│   │   ├── deep_analyze.py                # Deep analysis script
│   │   └── supplement_analyze.py          # Supplement analysis script
│   ├── decompressor/
│   │   ├── unpack.py                      # Decompressor attempt 1
│   │   └── unpack2.py                     # Decompressor attempt 2
│   └── build/
│       └── (empty — pe_analyzer.py kept in build_scripts/)
│
├── data/
│   ├── .text_unpacked_mem.bin             # 3.49 MB — ground-truth unpacked .text
│   ├── compressed.bin                     # 458 KB — aPLib compressed payload
│   ├── payload_compressed.bin             # Earlier extraction variant
│   ├── patterns_extracted.json            # 18 KB — all 73 patterns in JSON
│   ├── all_strings.txt                    # Extracted strings (filtered)
│   ├── all_strings_raw.txt                # All raw strings
│   └── strings_utf16le.txt                # UTF-16LE strings dump
│
├── resweep/
│   ├── resweep_analyzer.ps1               # PowerShell resweep analysis runner
│   ├── resweep_analyzer.py                # Python resweep analysis runner
│   ├── resweep_supplement.py              # Supplement analysis generator
│   └── resweep_supplement.txt             # Supplement analysis output
│
├── build_scripts/
│   └── pe_analyzer.py                     # Full PE parsing + packer anomaly detection
│
└── .git/
```

## Architecture Overview

```
LIBERTEA_Bypass.exe
  │
  ├─ Enable SeDebugPrivilege
  ├─ Remove/block GameMon.des / GameMon64.des
  ├─ Inject LIBERTEA.DLL → helldivers2.exe
  │
  └─ LIBERTEA.DLL (DllMain)
       │
       ├─ Phase 1: Decompress .text (custom aPLib)
       ├─ Phase 2: Resolve imports (IAT)
       ├─ Phase 3: Find game.dll → pattern scan → install 73 hooks
       ├─ Phase 4: Create ImGui overlay → hook wglSwapIntervalEXT → render loop
       │
       └─ Runtime Features:
            ├─ FARMING: Reward multipliers, sample injection, instant shuttle
            ├─ SUPER CREDITS: Auto-replay captured API calls, 58s cooldown batches
            ├─ WEAPON XP: Override primary weapon, cycle all 51 guns
            ├─ PLAYER: God mode, speed, no recoil, no ragdoll
            ├─ COMBAT: Infinite stratagems, turret mods, kill counter
            ├─ VISUAL: FOV, map hack, no laser overheat
            └─ ARMORY: Unlock all, weapon/armor stat editors
```

## Custom aPLib Decompression Specification

The DLL entry point (RVA 0x3C4F30) contains a packing stub that decompresses the .text section:

```
Source: RVA 0x355000 (raw offset 0x400) — 458,544 compressed bytes
Dest:   RVA 0x001000 (.text base) — 3,489,792 uncompressed bytes

Bit Reader:  add ebx,ebx / adc ebx,ebx (carry propagated through refills)
Main Loop:   GETBIT → jb(CF=1)=LITERAL, jae(CF=0)=MATCH

Gamma Offset: eax = prev_len+1 → first pass: 1 bit + stop
              subsequent: dec eax + 2 bits + stop → eax -= 3

Long Match:   eax = (eax<<8)|dl → src++ → XOR 0xFFFFFFFF → sar eax,1 → offset
              LSB determines COPY_SETUP_A vs alt path

Match Copy:   len <= 5 or offset >= -4: byte copy
              else: dword copy loop with sub ecx,4 / jae / add ecx,4 remainder
```

## Hook System

**73 IDA-style byte patterns** across 4 DLLs with 6 hook types:

| Hook Type | Count | Description |
|---|---|---|
| NOP_PATCH | 27 | Replace instructions with NOPs |
| CODE_PATCH | 30 | Write opcode bytes |
| FUNCTION_PROLOGUE | 5 | Detour at function entry |
| POINTER_RESOLVE | 5 | Read/write pointer values |
| FUNCTION_RETURN | 4 | Hook at function epilogue |
| CONDITIONAL_INVERT | 2 | JE→JMP or JNE→JMP |

**Syscall stubs:** 9 instances of `syscall` instruction, SSN resolved dynamically from ntdll.dll at runtime. Stub constructed as: `lea rcx,[name]; load SSN; mov eax,SSN; syscall`.

## SC/Medal Farming Protocol

```
State Machine:
  IDLE → PROBING → CAPTURED → FIRING_SC/FIRING_MEDAL → COOLDOWN → IDLE

Capture: libcurl write callback hook intercepts Mission/end POST
         12 JSON fields stored → C:\libertea_replay_cap.json

Replay:   9 API calls at 500ms intervals → 58s cooldown → repeat
           Alternates SC/Medal batches
           Hash table NOP (2 INSERT sites) prevents duplicate detection
           MIDSWAP replaces missionId mid-flight to cycle captures

Recovery: Vectored Exception Handler catches crashes, restores state
           Auto-sync distributes SC to all lobby players
```

## Pattern Scanner

**404 IDA-style patterns** found. Scalar byte-by-byte comparison (no SIMD). `??` bytes treated as wildcards. Patterns stored as null-terminated strings with name and type tag. Missing patterns trigger warning: `"WARNING: Game may have updated ... %d/%d patterns found"`.

## Key Discoveries from Resweep

- **ImGui version:** 1.91.5 (confirmed via embedded version string at RVA 0x104DAD)
- **HTTP stack:** Triple backend — WinHTTP, WinINet, and libcurl
- **Anti-debug:** IsDebuggerPresent, CheckRemoteDebuggerPresent, 34x RDTSC timing checks
- **Proxy detection:** Checks for Fiddler, Burp Suite, Charles, mitmproxy + 8 other tools
- **HWID system:** MachineGuid-based hardware fingerprint
- **Cheat Engine detection:** 4 string variants checked
- **Crypto:** bcrypt.dll with SHA256 and ChainingModeCBC (AES-CBC), base64 embedded
- **Custom protocol:** "f2s7" — nonce capture, body XOR, key-waiting for HTTP encryption
- **CRC-32 table:** IEEE 802.3 (0xEDB88320) embedded but no hardware CRC32 instructions
- **No TLS callbacks** — entry is purely via DllMain
- **2,466 exception handlers** registered (.pdata entries)
- **66% zero-filled** — large reserved allocation space (2.3 MB padding)

## Features Complete Matrix (28+ toggles)

| Category | Features |
|---|---|
| **Farming** | Max reward multiplier, force difficulty 1-10, add samples instantly, samples over limit, instant shuttle/complete |
| **Super Credits** | SC loop (auto batch fire), SC goal, medal batch, medals only, auto sync |
| **Weapon XP** | Primary override, all guns rotation, selected guns list |
| **Player** | God mode, movement speed, no ragdoll, no recoil |
| **Combat** | Infinite stratagems, instant call-in, turret overheat/duration, kill counter, infinite horde |
| **Visual** | FOV editor, map hack, no laser overheat, instant charge, dark fluid pack, no boundary, longer hover |
| **Armory** | Unlock all, weapon stats editor, armor passive editor |
| **Ammo** | Inf ammo, no reload, inf grenades, inf stims |

## Detection Vectors (9 attack surfaces identified)

1. GameGuard driver file modification (GameMon.des / GameMon64.des)
2. wglSwapIntervalEXT hook (detectable by anti-cheat overlay scan)
3. Non-standard API call patterns (batch-fire to Mission/end)
4. NtProtectVirtualMemory on game.dll pages
5. Public Discord server (intelligence gathering)
6. Workers.dev DNS (Cloudflare abuse reporting)
7. DLL hash: SHA256 `95C0E0A655906BDE0AB24E70CC72F382B49B14E6AC833BC06A60FCE07ABE5287`
8. Bypass.exe hash: SHA256 `3DE503976D6E5EB6E079F086AFF116864F148BC06367268F9660983013CE2B18`
9. SeDebugPrivilege elevation + GameMon targeting memory pattern

## Recreating the .text Unpack

The decompressed .text was obtained by loading the DLL and letting DllMain run:
```python
handle = ctypes.windll.kernel32.LoadLibraryW(dll_path)
# DllMain runs → decompresses .text → resolves imports
ctypes.memmove(buf, handle + 0x1000, 0x354000)
# .text section is now unpacked in memory
```

A static Python decompressor is partially implemented in `_analyze.py` and `unpack.py`.

---

*28 files · 5.2 MB · Every byte owned*
