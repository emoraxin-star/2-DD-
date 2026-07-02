# LiberTea — Helldivers 2 Internal Cheat Reverse Engineering

![Language](https://img.shields.io/badge/language-C++17-blue)
![Compiler](https://img.shields.io/badge/compiler-MSVC%202022-purple)
![GUI](https://img.shields.io/badge/gui-Dear%20ImGui%201.91.5-green)
![Status](https://img.shields.io/badge/status-Complete%20Reverse%20Engineering-brightgreen)
![Files](https://img.shields.io/badge/files-100%2B-orange)
![Docs](https://img.shields.io/badge/docs-2.5%20MB-red)

> **Complete reverse engineering of LIBERTEA.DLL v414** — a Helldivers 2 internal cheat/trainer by "TheOGcup".
> Every byte, every pattern, every hook, every protocol detail — fully documented, verified, and cross-referenced.

---

## Quick Facts

| Field | Value |
|---|---|
| **Target Game** | Helldivers 2 (Steam) |
| **Cheat DLL** | LIBERTEA.DLL (732 KB packed, 3.49 MB unpacked) |
| **Injector** | LIBERTEA_Bypass.exe |
| **Version** | v414 |
| **Author** | TheOGcup (with Legend, HotPocket) |
| **Language** | C++17, MSVC 2022, static CRT |
| **GUI** | Dear ImGui 1.91.5, OpenGL overlay |
| **Anti-cheat bypassed** | nProtect GameGuard |
| **Distribution** | Discord + Cloudflare Workers CDN |
| **Auth** | Username/password or key, subscription tiers |
| **Package** | 100+ files, ~16 MB across docs, scripts, binaries |

---

## Directory Structure

```
2/
├── README.md                           # This file
├── MASTER_INDEX.txt                    # Team deliverables & quick reference
├── LIBERTEA.DLL                        # Original packed DLL (732 KB)
├── .text_decompressed.bin              # Metadata snippet
│
├── docs/                               # === ANALYSIS DOCUMENTS (7 categories) ===
│   ├── 01_binary_identity/             # PE headers, build info, compression
│   │   ├── libertea_analysis.txt       # Pointers, offsets, ImGui toggles, weapon list
│   │   ├── libertea_tech_breakdown.txt # Build architecture, aPLib spec, detection vectors
│   │   ├── libertea_complete.txt       # Full disassembly, call graph, entropy, anti-debug
│   │   └── resweep_pe.txt              # PE headers, relocations, TLS, exceptions, packer
│   ├── 02_code_analysis/               # Memory map, functions, strings, patterns
│   │   ├── libertea_deep_dive.txt      # 680+ functions, C++ RTTI, 30+ feature matrix
│   │   ├── libertea_niche.txt          # Format strings, HTTP headers, enums, FP constants
│   │   └── resweep_code.txt            # ImGui version, pattern scanner, HTTP/JSON stack
│   ├── 03_game_data/                   # Weapons, armor, stratagems, pointer chains
│   │   ├── resweep_game_data.txt       # 130 weapons, 68 armor, 37 stratagems
│   │   └── resweep_strings.txt         # Base64, crypto, proxy detection, AOB sigs, HWID
│   ├── 04_hook_system/                 # Hook architecture & pattern scanner
│   │   └── hook_system_analysis.txt    # 73 patterns, 6 hook types, 4-phase install
│   ├── 05_network_protocol/            # SC/Medal farming protocol
│   │   └── sc_farming_analysis.txt     # State machine, replay capture, hash table NOP, VEH
│   ├── 06_architecture/                # Architecture recreation & data flow
│   │   └── architecture_recreation.txt # 15 components, data flow, recreation strategy
│   └── 07_sanitized/                   # Sanitized full breakdown
│       └── FULL_BREAKDOWN_SANITIZED.txt
│
├── scripts/                            # === ANALYSIS SCRIPTS ===
│   ├── extractors/                     # Document generation from binary data
│   │   ├── pattern_extractor.py        # Extract 73+ IDA patterns to JSON
│   │   ├── deep_dive.py                # Generate deep dive document
│   │   ├── niche_details.py            # Generate niche details document
│   │   ├── extract_analysis.py         # Generate analysis document
│   │   ├── full_extract.py             # Generate complete document
│   │   └── libertea_tech_breakdown.py  # Generate tech breakdown
│   ├── analysis/                       # In-depth protocol/function analysis
│   │   ├── sc_protocol_analysis.py     # SC farming state machine (data classes)
│   │   ├── _analyze.py                 # aPLib decompressor (partial)
│   │   ├── analyze_re.py               # Reverse analysis script
│   │   ├── deep_analyze.py             # Deep analysis script
│   │   ├── supplement_analyze.py       # Supplement analysis script
│   │   └── pattern_scanner.py          # Pattern scanning utilities
│   ├── decompressor/                   # aPLib decompression attempts
│   │   ├── unpack.py                   # Decompressor attempt 1
│   │   └── unpack2.py                  # Decompressor attempt 2
│   ├── scratch/                        # Agent work scripts (historical)
│   │   ├── agentB_analyze.py           # Function catalog v1
│   │   ├── agentB_analyze_v2.py        # Function catalog v2
│   │   ├── agentB_analyze_v3.py        # Function catalog v3
│   │   ├── agentB_v4.py                # Function catalog v4 (final)
│   │   ├── build_string_map.py         # String map builder
│   │   ├── extract_strings.py          # String extraction utility
│   │   ├── fix_unknown.py              # Unknown string re-categorization
│   │   └── temp_scan.py                # Temporary string scanner
│   ├── agent1_scan.ps1                 # Initial integrity scan
│   ├── agent1_expand.ps1               # Expanded scan
│   ├── agent1_final.ps1                # Final integrity scan
│   ├── hyper1_analysis.py              # Byte differential analysis
│   ├── hyper1_append.py                # Append analysis data
│   ├── hyper1_expanded.py              # Expanded byte analysis
│   ├── hyper2_analyze.py               # Semantic decompile
│   └── hyper3/                         # Data structure extraction
│       ├── extract_structures.py
│       └── extract_structures2.py
│
├── data/                               # === BINARY DATA & STRINGS ===
│   ├── .text_unpacked_mem.bin          # 3.49 MB — ground-truth unpacked .text
│   ├── compressed.bin                  # 458 KB — aPLib compressed payload
│   ├── payload_compressed.bin          # Earlier extraction variant
│   ├── patterns_extracted.json         # 18 KB — all 73 patterns in JSON
│   ├── all_strings.txt                 # Extracted strings (filtered)
│   ├── all_strings_raw.txt             # All raw strings
│   ├── strings_utf16le.txt             # UTF-16LE strings dump
│   ├── agentE_all_strings.txt          # Agent E string extraction
│   ├── agentE_full_strings_sorted.txt  # Agent E sorted strings
│   └── extras/                         # Additional data files
│
├── logs/                               # === AGENT ANALYSIS LOGS (21 files) ===
│   ├── agent1_integrity_scan.txt       # Integrity scan
│   ├── agent2_deep_reanalysis.txt      # Deep reanalysis
│   ├── agent3_crossref_validation.txt  # Cross-reference validation
│   ├── agentB_function_catalog.txt     # Function catalog
│   ├── agentC_import_map.txt           # Import mapping
│   ├── agentD_string_map.txt           # String map
│   ├── agentE_game_data.txt            # Game data (part 1)
│   ├── agentE_game_data_part2.txt      # Game data (part 2)
│   ├── agentF_crypto_keys.txt          # Crypto key extraction
│   ├── agentG_f2s7_spec.txt            # f2s7 protocol spec
│   ├── agentH_imgui_tree.txt           # ImGui widget tree
│   ├── agentI_syscall_infra.txt        # Syscall infrastructure
│   ├── agentJ_pattern_scanner.txt      # Pattern scanner analysis
│   ├── DISCREPANCY_FIXES.txt           # Discrepancy fixes log
│   ├── extracted_ascii.txt             # ASCII string extraction
│   ├── extracted_utf16le.txt           # UTF-16LE string extraction
│   ├── hyper1_byte_differential.txt    # Byte differential
│   ├── hyper2_semantic_decompile.txt   # Semantic decompile
│   ├── hyper3_data_structures.txt      # Data structures
│   ├── hyper4_protocol_crypto.txt      # Protocol & crypto
│   └── hyper5_anti_analysis.txt        # Anti-analysis techniques
│
├── resweep/                            # === RESWEEP RE-ANALYSIS ===
│   ├── resweep_analyzer.ps1            # PowerShell runner
│   ├── resweep_analyzer.py             # Python runner
│   ├── resweep_supplement.py           # Supplement generator
│   └── resweep_supplement.txt          # Supplement output
│
└── build_scripts/                      # === BUILD & PE ANALYSIS ===
    └── pe_analyzer.py                  # Full PE parsing + packer anomaly detection
```

---

## Getting Started

### What is this project?

This is a complete reverse engineering package for **LIBERTEA.DLL**, a Helldivers 2 internal cheat/trainer. It documents every aspect of the binary: how it's packed, how it injects, how it hooks the game, how it farms Super Credits, and how it renders the cheat menu.

### How to use these analysis files

1. **Quick overview**: Read `MASTER_INDEX.txt` — it summarizes every team's deliverables and key findings.
2. **Architecture first**: Start with `docs/06_architecture/architecture_recreation.txt` for the big picture.
3. **Binary identity**: Read `docs/01_binary_identity/` for PE headers, packer specs, and build details.
4. **Hook system**: Read `docs/04_hook_system/hook_system_analysis.txt` to understand how the cheat intercepts the game.
5. **Network protocol**: Read `docs/05_network_protocol/sc_farming_analysis.txt` for the SC farming state machine.
6. **Feature deep dive**: Read `docs/02_code_analysis/libertea_deep_dive.txt` for per-feature analysis.
7. **Pattern reference**: See `data/patterns_extracted.json` for all 73 IDA-style byte patterns.

### Requirements for scripts

Most Python scripts require:
- Python 3.8+
- `capstone` (disassembly engine): `pip install capstone`
- `pefile` (PE parsing): `pip install pefile`

---

## Key Findings Summary

| # | Finding | Detail |
|---|---|---|
| 1 | **Custom aPLib packer** | Unique bit-inverted variant with gamma decoding, XOR/SAR offset calculation |
| 2 | **73 hook patterns** | Across 4 DLLs (game.dll, winhttp.dll, bcrypt.dll, game_current.dll) |
| 3 | **6 hook types** | NOP_PATCH (27), CODE_PATCH (30), FUNCTION_PROLOGUE (5), POINTER_RESOLVE (5), FUNCTION_RETURN (4), CONDITIONAL_INVERT (2) |
| 4 | **SC Farming Protocol** | 9-call batches at 500ms intervals, 58s cooldown, alternating SC/Medal |
| 5 | **HTTP capture replay** | libcurl write callback hook intercepts Mission/end POST, replays via `libertea_replay_cap.json` |
| 6 | **Hash table NOP** | 2 INSERT sites NOP'd in memory to prevent server-side duplicate detection |
| 7 | **VEV recovery** | Vectored Exception Handler catches crashes, auto-restores state |
| 8 | **9 syscall stubs** | Dynamic SSN resolution from ntdll.dll, runtime stub construction |
| 9 | **Triple HTTP backend** | WinHTTP, WinINet, and libcurl — fallback chain for HTTP operations |
| 10 | **ImGui 1.91.5 overlay** | OpenGL rendering via wglSwapIntervalEXT hook, window subclassing with WM_SC_DISPATCH |
| 11 | **2,466 exception handlers** | .pdata entries for structured exception handling coverage |
| 12 | **34 RDTSC checks** | Timing-based anti-debug detection |
| 13 | **Proxy detection** | Checks for Fiddler, Burp Suite, Charles, mitmproxy + 8 more tools |
| 14 | **bcrypt crypto** | SHA256 + AES-CBC (ChainingModeCBC), base64 encoding |
| 15 | **f2s7 protocol** | Custom nonce-based encryption with XOR body obfuscation and key-waiting |
| 16 | **HWID fingerprinting** | MachineGuid-based unique hardware identification |
| 17 | **GameGuard bypass** | GameMon.des/GameMon64.des file blocking + SeDebugPrivilege elevation |
| 18 | **15 architecture components** | Mapped by RVA ranges with full data flow diagram |
| 19 | **130+ weapons documented** | With pointer chains and stat offsets |
| 20 | **28+ feature toggles** | Across 8 categories: Farming, SC, Weapon XP, Player, Combat, Visual, Armory, Ammo |

---

## Agent Analysis Rounds

This project was analyzed by **18 specialized agents** across 5 hyper-analysis phases. Each agent produced a detailed log or script.

| Agent | Type | Output | Description |
|---|---|---|---|
| **agent1** | Integrity Scan | `agent1_integrity_scan.txt` | Initial binary integrity verification, hash checks |
| **agent2** | Deep Reanalysis | `agent2_deep_reanalysis.txt` | Second-pass deep structural reanalysis |
| **agent3** | Cross-Ref Validation | `agent3_crossref_validation.txt` | Cross-reference validation across all findings |
| **agentB v1** | Function Catalog | `agentB_analyze.py` | Initial function prologue scan + disassembly |
| **agentB v2** | Function Catalog v2 | `agentB_analyze_v2.py` | Improved function detection with embedded string analysis |
| **agentB v3** | Function Catalog v3 | `agentB_analyze_v3.py` | Call-graph propagation, richer heuristics |
| **agentB v4** | Function Catalog v4 | `agentB_v4.py` | Final version: propagation + CRT detection |
| **agentC** | Import Map | `agentC_import_map.txt` | Complete IAT/import dependency mapping |
| **agentD** | String Map | `agentD_string_map.txt` | Comprehensive string categorization and mapping |
| **agentE** | Game Data | `agentE_game_data.txt`, `.part2` | Weapon, armor, stratagem data extraction |
| **agentF** | Crypto Keys | `agentF_crypto_keys.txt` | bcrypt keys, base64 strings, crypto constants |
| **agentG** | f2s7 Protocol | `agentG_f2s7_spec.txt` | Custom f2s7 protocol specification |
| **agentH** | ImGui Tree | `agentH_imgui_tree.txt` | ImGui widget hierarchy and overlay structure |
| **agentI** | Syscall Infra | `agentI_syscall_infra.txt` | Syscall stub analysis, SSN resolution, direct calls |
| **agentJ** | Pattern Scanner | `agentJ_pattern_scanner.txt` | Pattern scanner reverse engineering |
| **hyper1** | Byte Differential | `hyper1_byte_differential.txt` | Byte-level differential analysis vs clean game |
| **hyper2** | Semantic Decompile | `hyper2_semantic_decompile.txt` | Semantic decompilation of key functions |
| **hyper3** | Data Structures | `hyper3_data_structures.txt` | C++ class structure recovery from memory |
| **hyper4** | Protocol Crypto | `hyper4_protocol_crypto.txt` | Network protocol cryptography analysis |
| **hyper5** | Anti-Analysis | `hyper5_anti_analysis.txt` | Anti-debug, anti-VM, anti-reversing techniques |

---

## Documentation Map

### I want to understand...

| Question | Read this |
|---|---|
| How is the DLL packed? | `docs/01_binary_identity/libertea_tech_breakdown.txt` |
| What is the aPLib algorithm? | `docs/01_binary_identity/libertea_tech_breakdown.txt` (Custom aPLib section) |
| How does injection work? | `docs/06_architecture/architecture_recreation.txt` |
| What hooks are installed? | `docs/04_hook_system/hook_system_analysis.txt` |
| How does SC farming work? | `docs/05_network_protocol/sc_farming_analysis.txt` |
| What does each feature do? | `docs/02_code_analysis/libertea_deep_dive.txt` |
| What are the pattern signatures? | `data/patterns_extracted.json` |
| How is GameGuard bypassed? | `docs/01_binary_identity/libertea_analysis.txt` |
| What crypto is used? | `docs/03_game_data/resweep_strings.txt` |
| How does the overlay render? | `docs/02_code_analysis/resweep_code.txt` |
| What API endpoints are called? | `docs/02_code_analysis/libertea_niche.txt` |
| How are weapons/armor structured? | `docs/03_game_data/resweep_game_data.txt` |
| What's the full feature list? | `docs/02_code_analysis/libertea_deep_dive.txt` (Feature Matrix) |
| Where are detection vectors documented? | `docs/01_binary_identity/libertea_tech_breakdown.txt` |
| What did each agent produce? | `logs/` directory + this README (Agent Analysis Rounds table) |

---

## Architecture Overview

```
LIBERTEA_Bypass.exe
  |
  +-- Enable SeDebugPrivilege
  +-- Remove/block GameMon.des / GameMon64.des
  +-- Inject LIBERTEA.DLL into helldivers2.exe
  |
  +-- LIBERTEA.DLL (DllMain)
       |
       +-- Phase 1: Decompress .text (custom aPLib packer)
       +-- Phase 2: Resolve imports (IAT fixup)
       +-- Phase 3: Pattern scan game.dll -> install 73 hooks
       +-- Phase 4: Create ImGui overlay -> hook wglSwapIntervalEXT -> render loop
       |
       +-- Runtime Features:
            |
            +-- FARMING: Reward multipliers, sample injection, instant shuttle
            +-- SUPER CREDITS: Auto-replay captured API calls, 58s cooldown batches
            +-- WEAPON XP: Override primary weapon, cycle all 51 guns
            +-- PLAYER: God mode, speed, no recoil, no ragdoll
            +-- COMBAT: Infinite stratagems, turret mods, kill counter
            +-- VISUAL: FOV, map hack, no laser overheat
            +-- ARMORY: Unlock all, weapon/armor stat editors
            +-- AMMO: Infinite ammo, no reload, infinite grenades, infinite stims
```

---

## Custom aPLib Decompression Specification

The DLL entry point (RVA 0x3C4F30) contains a packing stub that decompresses the .text section:

```
Source: RVA 0x355000 (raw offset 0x400) — 458,544 compressed bytes
Dest:   RVA 0x001000 (.text base) — 3,489,792 uncompressed bytes

Bit Reader:  add ebx,ebx / adc ebx,ebx (carry propagated through refills)
Main Loop:   GETBIT -> jb(CF=1)=LITERAL, jae(CF=0)=MATCH

Gamma Offset: eax = prev_len+1 -> first pass: 1 bit + stop
              subsequent: dec eax + 2 bits + stop -> eax -= 3

Long Match:   eax = (eax<<8)|dl -> src++ -> XOR 0xFFFFFFFF -> sar eax,1 -> offset
              LSB determines COPY_SETUP_A vs alt path

Match Copy:   len <= 5 or offset >= -4: byte copy
              else: dword copy loop with sub ecx,4 / jae / add ecx,4 remainder
```

**How we obtained the unpacked .text:**
```python
handle = ctypes.windll.kernel32.LoadLibraryW(dll_path)
# DllMain runs -> decompresses .text -> resolves imports
ctypes.memmove(buf, handle + 0x1000, 0x354000)
# .text section is now unpacked in memory
```

A static Python decompressor is partially implemented in `scripts/analysis/_analyze.py` and `scripts/decompressor/unpack.py`.

---

## Hook System

**73 IDA-style byte patterns** across 4 DLLs with 6 hook types:

| Hook Type | Count | Description |
|---|---|---|
| NOP_PATCH | 27 | Replace instructions with NOPs |
| CODE_PATCH | 30 | Write opcode bytes |
| FUNCTION_PROLOGUE | 5 | Detour at function entry |
| POINTER_RESOLVE | 5 | Read/write pointer values |
| FUNCTION_RETURN | 4 | Hook at function epilogue |
| CONDITIONAL_INVERT | 2 | JE->JMP or JNE->JMP |

**Syscall stubs:** 9 instances of `syscall` instruction, SSN resolved dynamically from ntdll.dll at runtime. Stub constructed as: `lea rcx,[name]; load SSN; mov eax,SSN; syscall`.

---

## SC/Medal Farming Protocol

```
State Machine:
  IDLE -> PROBING -> CAPTURED -> FIRING_SC/FIRING_MEDAL -> COOLDOWN -> IDLE

Capture: libcurl write callback hook intercepts Mission/end POST
         12 JSON fields stored -> C:\libertea_replay_cap.json

Replay:   9 API calls at 500ms intervals -> 58s cooldown -> repeat
           Alternates SC/Medal batches
           Hash table NOP (2 INSERT sites) prevents duplicate detection
           MIDSWAP replaces missionId mid-flight to cycle captures

Recovery: Vectored Exception Handler catches crashes, restores state
           Auto-sync distributes SC to all lobby players
```

---

## Feature Matrix (28+ Toggles)

| Category | Features |
|---|---|
| **Farming** | Max reward multiplier, force difficulty 1-10, add samples instantly, samples over limit, instant shuttle/complete |
| **Super Credits** | SC loop (auto batch fire), SC goal, medal batch, medals only, auto sync |
| **Weapon XP** | Primary override, all guns rotation, selected guns list |
| **Player** | God mode, movement speed, no ragdoll, no recoil |
| **Combat** | Infinite stratagems, instant call-in, turret overheat/duration, kill counter, infinite horde |
| **Visual** | FOV editor, map hack, no laser overheat, instant charge, dark fluid pack, no boundary, longer hover |
| **Armory** | Unlock all, weapon stats editor, armor passive editor |
| **Ammo** | Infinite ammo, no reload, infinite grenades, infinite stims |

---

## Detection Vectors

| # | Attack Surface | Description |
|---|---|---|
| 1 | GameGuard driver files | GameMon.des / GameMon64.des modification/blocking |
| 2 | wglSwapIntervalEXT hook | Detectable by anti-cheat overlay scan |
| 3 | Abnormal API patterns | Batch-fire POST to Mission/end endpoint |
| 4 | NtProtectVirtualMemory | Memory protection changes on game.dll pages |
| 5 | Public Discord server | Community intelligence gathering point |
| 6 | Workers.dev DNS | Cloudflare abuse reporting vector |
| 7 | DLL hash | SHA256: `95C0E0A655906BDE0AB24E70CC72F382B49B14E6AC833BC06A60FCE07ABE5287` |
| 8 | Bypass.exe hash | SHA256: `3DE503976D6E5EB6E079F086AFF116864F148BC06367268F9660983013CE2B18` |
| 9 | SeDebugPrivilege + pattern | Privilege elevation + GameMon targeting memory pattern |

---

## For Researchers

### Why this is significant

LiberTea represents a sophisticated, production-grade game cheat with:
- A **custom compression algorithm** (modified aPLib) to evade signature detection
- A **multi-phase injection architecture** that defeats kernel-level anti-cheat (GameGuard)
- A **network protocol replay system** that farms premium currency by intercepting and replaying API calls
- **Direct syscall invocation** to bypass user-mode API hooks
- **Vectored Exception Handling** for crash recovery and anti-detection resilience

### Research Value

| Area | Research Interest |
|---|---|
| **Packer design** | Custom aPLib variant with bit-inversion, gamma decoding offset calculation |
| **Anti-cheat evasion** | Direct syscalls, GameGuard driver blocking, memory protection bypass |
| **Network protocol abuse** | HTTP replay attacks on live-service game APIs |
| **Rendering hook** | OpenGL overlay injection via wglSwapIntervalEXT with window subclassing |
| **Runtime protection** | VEH crash recovery, proxy detection, anti-debug timing checks |

### Methodology

All analysis was performed via:
1. **Static analysis**: PE parsing, pattern extraction, string mining, entropy analysis
2. **Dynamic analysis**: LoadLibrary execution, memory dumping, inline hook observation
3. **Pattern scanning**: 73 IDA-style signatures matched across game DLLs
4. **Cross-referencing**: Multi-agent validation, resweep verification passes

### Key Documents for Researchers

- `docs/01_binary_identity/libertea_complete.txt` — Full disassembly, call graph, entropy
- `docs/06_architecture/architecture_recreation.txt` — Component map, data flow, recreation strategy
- `docs/04_hook_system/hook_system_analysis.txt` — Complete hook catalog with RVA offsets
- `docs/05_network_protocol/sc_farming_analysis.txt` — Protocol state machine and replay format
- `docs/03_game_data/resweep_game_data.txt` — In-game data structures and pointer chains

---

## Project Statistics

| Statistic | Value |
|---|---|
| **Total files** | 100+ |
| **Total documentation size** | ~2.5 MB across all .txt docs |
| **Analysis scripts** | 25+ Python/PowerShell scripts |
| **Binary data files** | 9 files, ~4 MB total |
| **Analysis documents** | 17 structured analysis docs |
| **Agents deployed** | 18 agents + 5 hyper-analysis phases |
| **Hook patterns documented** | 73 |
| **Features documented** | 28+ |
| **Game items cataloged** | 130 weapons, 68 armor, 37 stratagems |
| **Functions cataloged** | 680+ |
| **ImGui widgets identified** | 162 |

---

## Related Files

- **[ULTIMATE_GUIDE_FOR_DUMMIES.txt](docs/ULTIMATE_GUIDE_FOR_DUMMIES.txt)** — Complete beginner's guide explaining everything in simple terms
- **[NON-COMMIT.txt](NON-COMMIT.txt)** — Alternative language analysis: could LiberTea be written in Rust, Go, C#, Python, Zig, or pure assembly?
- **[MASTER_INDEX.txt](MASTER_INDEX.txt)** — Quick-reference index of all team deliverables and findings

---

## License

This repository contains reverse engineering analysis for educational and research purposes only. The original LIBERTEA.DLL binary is included for analysis purposes. No source code from the original authors is reproduced. All analysis documents are original research.

---

*100+ files · ~16 MB · Complete reverse engineering coverage · 18 analysis agents · Every byte documented*
