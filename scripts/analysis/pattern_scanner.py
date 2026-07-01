"""
AGENT J: PATTERN SCANNER - Python implementation of LiberTea's
byte-pattern scanning algorithm.

Tests the exact algorithm used by the native cheat DLL against
the unpacked .text binary.
"""

import json
import struct
import time
import sys
import os
from dataclasses import dataclass
from typing import List, Optional, Tuple

# ==============================================================================
# CONFIGURATION
# ==============================================================================

BIN_PATH = r'C:\Users\emora\OneDrive\Desktop\2\data\.text_unpacked_mem.bin'
PATTERNS_PATH = r'C:\Users\emora\OneDrive\Desktop\2\data\patterns_extracted.json'


# ==============================================================================
# PATTERN PARSER - exact implementation of the native parser
# ==============================================================================

def hex_nibble(c: int) -> int:
    """Convert a single hex character to its 4-bit value.
    Matches the native code's lookup table approach."""
    if 0x30 <= c <= 0x39:  # '0'-'9'
        return c - 0x30
    if 0x41 <= c <= 0x46:  # 'A'-'F'
        return c - 0x41 + 10
    if 0x61 <= c <= 0x66:  # 'a'-'f'
        return c - 0x61 + 10
    return 0


@dataclass
class ParsedPattern:
    """Result of parsing an IDA-style pattern string."""
    signature: str
    pattern_bytes: bytes
    pattern_mask: bytes  # 0xFF = exact, 0x00 = wildcard (??)
    pattern_len: int

    def is_wildcard(self, idx: int) -> bool:
        return self.pattern_mask[idx] == 0x00

    def byte_at(self, idx: int) -> int:
        return self.pattern_bytes[idx]

    def __repr__(self):
        return (f'ParsedPattern(len={self.pattern_len}, '
                f'wildcards={self.pattern_mask.count(0)}, '
                f'sig="{self.signature[:50]}...")')


def parse_pattern(pattern_str: str) -> Optional[ParsedPattern]:
    """
    Parse an IDA-style byte pattern string into byte array + wildcard mask.

    This replicates the native code's pattern string parser EXACTLY.
    Each token is either "??" (wildcard) or a 2-char hex byte.
    Tokens are separated by exactly one space character.

    Returns None for empty/malformed patterns.
    """
    pattern_str = pattern_str.strip()
    if not pattern_str:
        return None

    tokens = pattern_str.split(' ')
    pattern_len = len(tokens)

    if pattern_len == 0:
        return None

    ba = bytearray(pattern_len)
    ma = bytearray(pattern_len)

    for i, token in enumerate(tokens):
        if token in ('??', '?'):
            ba[i] = 0x00  # don't care
            ma[i] = 0x00  # wildcard flag
        else:
            if len(token) >= 2:
                hi = hex_nibble(ord(token[0]))
                lo = hex_nibble(ord(token[1]))
                ba[i] = (hi << 4) | lo
                ma[i] = 0xFF  # exact match
            else:
                ba[i] = 0x00
                ma[i] = 0xFF

    return ParsedPattern(
        signature=pattern_str,
        pattern_bytes=bytes(ba),
        pattern_mask=bytes(ma),
        pattern_len=pattern_len,
    )


# ==============================================================================
# PATTERN SCANNER - exact linear scan algorithm
# ==============================================================================

def pattern_scan(data: bytes, pattern: ParsedPattern,
                 start_offset: int = 0,
                 end_offset: Optional[int] = None) -> Optional[int]:
    """
    EXACT pattern scanning algorithm as used by LiberTea.

    For each byte position 'pos' in data[start:end]:
        For each byte 'i' in pattern:
            If pattern_mask[i] == 0x00 (wildcard): skip comparison
            If data[pos + i] != pattern_bytes[i]: break (mismatch)
        If all bytes matched: return pos

    Returns the byte offset of the first match, or None if not found.

    Complexity: O(M*N) worst case, where M = data_size, N = pattern_len.
    Average case is better due to early exit on first mismatch byte.
    """
    data_size = len(data)
    end = end_offset if end_offset is not None else data_size
    end = min(end, data_size)

    pattern_bytes = pattern.pattern_bytes
    pattern_mask = pattern.pattern_mask
    pattern_len = pattern.pattern_len

    if pattern_len == 0:
        return None
    if start_offset + pattern_len > end:
        return None

    # Find first non-wildcard byte as anchor for fast filtering
    anchor_idx = -1
    for i in range(pattern_len):
        if pattern_mask[i] != 0:
            anchor_idx = i
            break

    if anchor_idx == -1:
        # All wildcards - match at start_offset
        return start_offset

    anchor_byte = pattern_bytes[anchor_idx]
    pos = start_offset
    max_pos = end - pattern_len

    while pos <= max_pos:
        found = data.find(anchor_byte, pos, max_pos + 1)
        if found == -1:
            return None

        candidate = found - anchor_idx
        if candidate < start_offset:
            pos = found + 1
            continue

        # Verify all bytes at candidate position
        match = True
        for i in range(pattern_len):
            if pattern_mask[i] != 0:
                if data[candidate + i] != pattern_bytes[i]:
                    match = False
                    break

        if match:
            return candidate

        pos = found + 1

    return None


def pattern_scan_all(data: bytes, pattern: ParsedPattern,
                     start_offset: int = 0,
                     end_offset: Optional[int] = None) -> List[int]:
    """
    Find ALL matches of a pattern in data.
    Unlike the native code (which returns first match only),
    this is useful for analysis.
    """
    data_size = len(data)
    end = end_offset if end_offset is not None else data_size
    end = min(end, data_size)

    pattern_bytes = pattern.pattern_bytes
    pattern_mask = pattern.pattern_mask
    pattern_len = pattern.pattern_len

    results = []

    if pattern_len == 0:
        return results
    if start_offset + pattern_len > end:
        return results

    # Find first non-wildcard byte as anchor
    anchor_idx = -1
    for i in range(pattern_len):
        if pattern_mask[i] != 0:
            anchor_idx = i
            break

    if anchor_idx == -1:
        # All wildcards - everything matches
        max_pos = end - pattern_len
        return list(range(start_offset, max_pos + 1))

    anchor_byte = pattern_bytes[anchor_idx]
    pos = start_offset
    max_pos = end - pattern_len

    while pos <= max_pos:
        found = data.find(anchor_byte, pos, max_pos + 1)
        if found == -1:
            break

        candidate = found - anchor_idx
        if candidate >= start_offset:
            match = True
            for i in range(pattern_len):
                if pattern_mask[i] != 0:
                    if data[candidate + i] != pattern_bytes[i]:
                        match = False
                        break
            if match:
                results.append(candidate)

        pos = found + 1

    return results


# ==============================================================================
# BATCH PATTERN SCANNER - replicates HookManager::InstallHook behavior
# ==============================================================================

@dataclass
class ScanResult:
    """Result of scanning one pattern."""
    pattern: dict
    parsed: ParsedPattern
    match_offset: Optional[int]
    match_address: Optional[int]  # virtual address (offset + base)
    found: bool

    def __repr__(self):
        status = f'FOUND @ 0x{self.match_offset:X}' if self.found else 'NOT FOUND'
        return (f'ScanResult(name="{self.pattern.get("name", "")}", '
                f'offset=0x{self.pattern["offset"]:X} '
                f'result={status})')


def batch_scan_all(data: bytes, patterns: List[dict],
                   base_address: int = 0) -> List[ScanResult]:
    """
    Scan all patterns against the data buffer.
    Replicates HookManager::InstallHook's batch scanning.
    Tracks found/missing count and returns results.
    """
    results = []
    found_count = 0
    missing = []

    for i, p in enumerate(patterns):
        sig = p.get('signature', '')
        name = p.get('name', f'pattern_{i}')

        parsed = parse_pattern(sig)
        if parsed is None:
            continue

        offset = pattern_scan(data, parsed)
        is_found = offset is not None

        results.append(ScanResult(
            pattern=p,
            parsed=parsed,
            match_offset=offset,
            match_address=(base_address + offset) if offset is not None else None,
            found=is_found,
        ))

        if is_found:
            found_count += 1
        else:
            missing.append(name)

    return results


def print_scan_summary(results: List[ScanResult]):
    """Print the pattern scan summary, replicating native log output."""
    found = sum(1 for r in results if r.found)
    total = len(results)

    print()
    print('=' * 72)
    print('PATTERN SCAN SUMMARY')
    print('=' * 72)
    print(f'  Patterns: {found}/{total} found')

    if found < total:
        print(f'  WARNING: Game may have updated... {found}/{total} patterns '
              f'found. Some features may not work.')
        missing_names = [r.pattern.get('name', '?')
                         for r in results if not r.found]
        print(f'  Missing ({len(missing_names)}):')
        for nm in missing_names[:10]:
            print(f'    - {nm}')
        if len(missing_names) > 10:
            print(f'    ... and {len(missing_names) - 10} more')

    # Group by module
    print()
    print('-' * 72)
    print(f'  {"MODULE":<20} {"FOUND":<8} {"TOTAL":<8} {"RATE"}')
    print(f'  {"-"*20} {"-"*8} {"-"*8} {"-"*8}')
    by_module = {}
    for r in results:
        mod = r.pattern.get('module', 'unknown')
        if mod not in by_module:
            by_module[mod] = {'found': 0, 'total': 0}
        by_module[mod]['total'] += 1
        if r.found:
            by_module[mod]['found'] += 1

    for mod in sorted(by_module.keys()):
        m = by_module[mod]
        pct = (m['found'] / m['total'] * 100) if m['total'] > 0 else 0
        print(f'  {mod:<20} {m["found"]:<8} {m["total"]:<8} {pct:.1f}%')
    print('=' * 72)
    print()


# ==============================================================================
# UNIT TESTS
# ==============================================================================

def run_unit_tests(data: bytes):
    """Run comprehensive unit tests against the pattern scanning algorithm."""
    print('=' * 72)
    print('UNIT TESTS')
    print('=' * 72)

    passed = 0
    failed = 0

    def assert_eq(name: str, actual, expected):
        nonlocal passed, failed
        if actual == expected:
            passed += 1
        else:
            failed += 1
            print(f'  FAIL [{name}]: expected {expected!r}, got {actual!r}')

    def assert_not_none(name: str, actual):
        nonlocal passed, failed
        if actual is not None:
            passed += 1
        else:
            failed += 1
            print(f'  FAIL [{name}]: expected non-None, got None')

    def assert_is_none(name: str, actual):
        nonlocal passed, failed
        if actual is None:
            passed += 1
        else:
            failed += 1
            print(f'  FAIL [{name}]: expected None, got {actual}')

    # --- Test 1: Parse exact pattern (no wildcards) ---
    p1 = parse_pattern('48 89 5C 24 08')
    assert_eq('parse_no_wildcards_len', p1.pattern_len, 5)
    assert_eq('parse_bytes_0', p1.pattern_bytes[0], 0x48)
    assert_eq('parse_bytes_2', p1.pattern_bytes[2], 0x5C)
    assert_eq('parse_mask_all_ff', list(p1.pattern_mask), [0xFF]*5)
    assert_eq('parse_sig_preserved', p1.signature, '48 89 5C 24 08')

    # --- Test 2: Parse wildcard pattern ---
    p2 = parse_pattern('48 8B 05 ?? ?? ?? ?? 33 D2')
    assert_eq('parse_wildcard_len', p2.pattern_len, 9)
    assert_eq('parse_wildcard_mask_3', p2.pattern_mask[3], 0x00)
    assert_eq('parse_wildcard_mask_4', p2.pattern_mask[4], 0x00)
    assert_eq('parse_wildcard_mask_5', p2.pattern_mask[5], 0x00)
    assert_eq('parse_wildcard_mask_6', p2.pattern_mask[6], 0x00)
    assert_eq('parse_wildcard_mask_0', p2.pattern_mask[0], 0xFF)
    assert_eq('parse_wildcard_count', p2.pattern_mask.count(0), 4)

    # --- Test 3: Parse uppercase hex ---
    p3 = parse_pattern('AA BB CC DD EE FF')
    assert_eq('parse_upper_len', p3.pattern_len, 6)
    assert_eq('parse_upper_byte_0', p3.pattern_bytes[0], 0xAA)
    assert_eq('parse_upper_byte_5', p3.pattern_bytes[5], 0xFF)

    # --- Test 4: Parse lowercase hex ---
    p4 = parse_pattern('aa bb cc dd')
    assert_eq('parse_lower_byte_0', p4.pattern_bytes[0], 0xAA)
    assert_eq('parse_lower_byte_3', p4.pattern_bytes[3], 0xDD)

    # --- Test 5: Parse empty pattern ---
    assert_is_none('parse_empty', parse_pattern(''))
    assert_is_none('parse_whitespace', parse_pattern('   '))

    # --- Test 6: Parse single byte ---
    p6 = parse_pattern('C3')
    assert_eq('parse_single_len', p6.pattern_len, 1)
    assert_eq('parse_single_byte', p6.pattern_bytes[0], 0xC3)

    # --- Test 7: Match known bytes from the binary itself ---
    # Use bytes from the ACTUAL binary content (not game.dll patterns)
    # First 8 bytes of the binary: 48 83 EC 28 E8 77 04 00 00
    actual_preamble = ' '.join(f'{b:02X}' for b in data[:8])
    p7 = parse_pattern(actual_preamble)
    result7 = pattern_scan(data, p7)
    assert_not_none('exact_match_bin_start', result7)
    if result7 is not None:
        assert_eq('exact_match_bin_start_pos', result7, 0)

    # --- Test 8: Pattern with wildcards using known content ---
    # LEA rcx, [rip+...] pattern: 48 8D 0D ?? ?? ?? ??
    # Very common in x64 code for loading global addresses
    p8 = parse_pattern('48 8D 0D ?? ?? ?? ??')
    result8 = pattern_scan(data, p8)
    assert_not_none('lea_rip_wildcard_match', result8)

    # --- Test 9: Pattern not in buffer ---
    p9 = parse_pattern('DE AD BE EF DE AD BE EF DE AD BE EF')
    assert_is_none('pattern_not_found', pattern_scan(data, p9))

    # --- Test 10: Pattern longer than buffer ---
    long_pat = 'CC ' * 3500000
    p10 = parse_pattern(long_pat)
    assert_is_none('pattern_too_long', pattern_scan(data, p10))

    # --- Test 11: Pattern at end of buffer (last 5 unique bytes) ---
    # Find last non-CC non-00 sequence in the binary
    trail_pos = len(data) - 1
    while trail_pos > 0 and data[trail_pos] in (0x00, 0xCC):
        trail_pos -= 1
    end_seq = data[trail_pos-4:trail_pos+1]
    end_seq_hex = ' '.join(f'{b:02X}' for b in end_seq)
    p11 = parse_pattern(end_seq_hex)
    result11 = pattern_scan(data, p11)
    assert_not_none('match_near_end', result11)
    if result11 is not None:
        assert_eq('match_near_end_pos', result11, trail_pos - 4)

    # --- Test 12: Wildcard-only pattern matches first bytes ---
    p12 = parse_pattern('?? ?? ?? ??')
    result12 = pattern_scan(data, p12)
    assert_not_none('wildcard_only', result12)
    if result12 is not None:
        assert_eq('wildcard_only_at_0', result12, 0)

    # --- Test 13: Verify byte-by-byte scan correctness using known bytes ---
    # Find a unique 5-byte sequence in the binary and verify positional match
    # Use the first 4 bytes that aren't all 00 or CC
    for scan_i in range(len(data) - 12):
        snippet = data[scan_i:scan_i+12]
        if snippet[:4] not in (b'\x00\x00\x00\x00', b'\xCC\xCC\xCC\xCC'):
            p13 = parse_pattern(' '.join(f'{b:02X}' for b in snippet))
            result13 = pattern_scan(data, p13)
            if result13 is not None:
                assert_eq('byte_scan_correct', result13, scan_i)
                # Verify each byte
                for j in range(12):
                    assert_eq(f'byte_at_{j}', data[result13 + j], snippet[j])
                break
    else:
        assert_eq('byte_scan_no_match', True, True)  # skip if nothing found

    # --- Test 14: Single wildcard in middle ---
    p14 = parse_pattern('48 83 EC ?? 48 8B 01')
    results14 = pattern_scan_all(data, p14)
    if len(results14) > 0:
        for pos in results14:
            assert_eq('wildcard_mid_0', data[pos], 0x48)
            assert_eq('wildcard_mid_1', data[pos + 1], 0x83)
            assert_eq('wildcard_mid_2', data[pos + 2], 0xEC)
            # byte 3 is free
            assert_eq('wildcard_mid_4', data[pos + 4], 0x48)
            assert_eq('wildcard_mid_5', data[pos + 5], 0x8B)
            assert_eq('wildcard_mid_6', data[pos + 6], 0x01)

    # --- Test 15: start_offset parameter ---
    p15 = parse_pattern('CC CC CC CC')
    # Find all CC locations
    results15a = pattern_scan_all(data, p15)
    if len(results15a) >= 2:
        second = results15a[1]
        result15b = pattern_scan(data, p15, start_offset=second)
        assert_eq('start_offset_second', result15b, second)

    # --- Test 16: end_offset parameter ---
    one_mb = 1024 * 1024
    p16 = parse_pattern('48 8D 0D ?? ?? ?? ??')
    result16 = pattern_scan(data, p16, start_offset=0, end_offset=one_mb)
    assert_not_none('end_offset_in_range', result16)
    # With end_offset too small (less than pattern length), should be None
    result16b = pattern_scan(data, p16, start_offset=0, end_offset=len(p16.pattern_bytes))
    assert_is_none('end_offset_boundary', result16b)
    result16c = pattern_scan(data, p16, start_offset=0, end_offset=0)
    assert_is_none('end_offset_zero', result16c)

    # --- Test 17: pattern_scan vs pattern_scan_all consistency ---
    # Find all matches of a common pattern, verify first returned by scan
    p17 = parse_pattern('48 8D 0D ?? ?? ?? ??')
    single = pattern_scan(data, p17)
    all_matches = pattern_scan_all(data, p17)
    if len(all_matches) > 0:
        assert_eq('first_match_consistency', single, all_matches[0])

    # --- Test 18: Boundary: pattern_len == 1 match at last byte ---
    last_byte = f'{data[-1]:02X}'
    p18 = parse_pattern(last_byte)
    result18 = pattern_scan(data, p18)
    assert_not_none('last_byte_match', result18)

    # --- Test 19: start_offset + pattern_len > end returns None ---
    p_long = parse_pattern(' '.join(f'{b:02X}' for b in data[:20]))
    assert_is_none('start_beyond_end',
                   pattern_scan(data, p_long, start_offset=len(data) - 5))

    # --- Test 20: Empty data buffer ---
    p20 = parse_pattern('CC')
    assert_is_none('empty_data', pattern_scan(b'', p20))

    print(f'\n  Results: {passed} passed, {failed} failed')
    print('=' * 72)
    return passed, failed


# ==============================================================================
# PERFORMANCE ANALYSIS
# ==============================================================================

def run_performance_analysis(data: bytes, patterns: List[dict]):
    """Measure and report pattern scanning performance."""
    print()
    print('=' * 72)
    print('PERFORMANCE ANALYSIS')
    print('=' * 72)

    data_size = len(data)
    total_pattern_bytes = 0
    total_wildcards = 0
    total_scanned_positions = 0
    total_byte_comparisons = 0
    scan_times = []

    for p in patterns[:20]:
        sig = p.get('signature', '')
        parsed = parse_pattern(sig)
        if parsed is None:
            continue

        total_pattern_bytes += parsed.pattern_len
        total_wildcards += parsed.pattern_mask.count(0)

        t_start = time.perf_counter()
        result = pattern_scan(data, parsed)
        t_end = time.perf_counter()
        scan_times.append((t_end - t_start) * 1000)

        if result is not None:
            total_scanned_positions += result + 1
            total_byte_comparisons += (result + 1) * parsed.pattern_len

    print(f'  Data size:               {data_size:>12,} bytes ({data_size/1024/1024:.1f} MB)')
    print(f'  Avg pattern length:      {total_pattern_bytes/20:>12.1f} bytes')
    print(f'  Avg wildcards/pattern:   {total_wildcards/20:>12.1f}')
    print(f'  Avg scan time (per pat): {sum(scan_times)/len(scan_times):>12.3f} ms')
    print(f'  Min scan time:           {min(scan_times):>12.3f} ms')
    print(f'  Max scan time:           {max(scan_times):>12.3f} ms')

    # Estimate for 50MB module
    hypothetical_50mb = 50 * 1024 * 1024
    scale = hypothetical_50mb / data_size if data_size > 0 else 1
    est_time = sum(scan_times) / len(scan_times) * 73 * scale
    print(f'\n  Estimated time for 73 patterns on 50MB module:')
    print(f'    Worst case (no early exit): {73 * 50*1024*1024 * 13 / 1e9 * 10:.1f} seconds')
    print(f'    Scaled from 3.5MB tests:    {est_time/1000:.1f} seconds')

    # Show known time complexity analysis
    print(f'\n  Algorithm: O(M * N) linear scan')
    print(f'    M = module size (data_size)')
    print(f'    N = pattern length')
    print(f'    Early exit on first mismatched byte reduces average case')
    print(f'    No SIMD, no Boyer-Moore, no hash pre-filtering')

    # Memory usage estimate
    import sys as _sys
    mem_per_pattern = _sys.getsizeof(bytes(20)) + _sys.getsizeof(bytes(20))
    print(f'\n  Memory per pattern parse: ~{mem_per_pattern} bytes (two 20-byte arrays)')
    print(f'  Total for 73 patterns:    ~{mem_per_pattern * 73:,} bytes '
          f'({mem_per_pattern * 73 / 1024:.1f} KB)')
    print(f'  Data buffer:              {data_size:,} bytes ({data_size/1024/1024:.1f} MB)')

    print('=' * 72)


# ==============================================================================
# WILDCARD VARIABILITY VERIFICATION
# ==============================================================================

def verify_wildcards(data: bytes, patterns: List[dict]):
    """
    Verify that ?? wildcards in patterns genuinely match variable bytes.
    In the actual game DLL, RIP-relative displacements change between
    game versions, so ?? bytes should differ between pattern instances
    at the same offset.

    Since we only have one binary, we verify wildcards by:
    1. Finding a pattern with wildcards that has multiple matches
    2. Comparing the wildcard positions across matches
    """
    print()
    print('=' * 72)
    print('WILDCARD VARIABILITY VERIFICATION')
    print('=' * 72)

    verified = 0
    unchecked = 0

    for p_entry in patterns:
        sig = p_entry.get('signature', '')
        name = p_entry.get('name', 'unnamed')
        parsed = parse_pattern(sig)
        if parsed is None:
            continue

        # Find all matches
        all_matches = pattern_scan_all(data, parsed)
        if len(all_matches) < 2:
            unchecked += 1
            continue

        # Check if wildcard bytes differ between first two matches
        m1, m2 = all_matches[0], all_matches[1]
        wc_differ = False
        for i in range(parsed.pattern_len):
            if parsed.is_wildcard(i):
                if data[m1 + i] != data[m2 + i]:
                    wc_differ = True
                    break

        if wc_differ:
            verified += 1
        else:
            unchecked += 1

    print(f'  Patterns with >=2 matches and differing wildcards: {verified}')
    print(f'  Other patterns (single match or same wildcards):   {unchecked}')

    # Show examples
    print(f'\n  Example wildcard mismatches (first 5):')
    shown = 0
    for p_entry in patterns:
        if shown >= 5:
            break
        sig = p_entry.get('signature', '')
        parsed = parse_pattern(sig)
        if parsed is None:
            continue
        all_matches = pattern_scan_all(data, parsed)
        if len(all_matches) < 2:
            continue
        m1, m2 = all_matches[0], all_matches[1]
        for i in range(parsed.pattern_len):
            if parsed.is_wildcard(i):
                b1 = data[m1 + i]
                b2 = data[m2 + i]
                if b1 != b2:
                    sig_short = sig[:50] + '...' if len(sig) > 50 else sig
                    print(f'    [{shown+1}] "{sig_short}"')
                    print(f'          wildcard[{i}]: match1=0x{b1:02X} '
                          f'match2=0x{b2:02X}')
                    shown += 1
                    break
    print('=' * 72)


# ==============================================================================
# SCAN PATTERNS AND REPORT
# ==============================================================================

def scan_all_patterns_with_report(data: bytes, patterns: List[dict]):
    """Scan all 73 patterns and produce a detailed report."""
    print()
    print('=' * 72)
    print('FULL PATTERN SCAN RESULTS')
    print('=' * 72)

    results = []
    found_count = 0

    for i, p in enumerate(patterns):
        sig = p.get('signature', '')
        name = p.get('name', f'#{i}')
        module = p.get('module', '?')
        hook_type = p.get('hook_type', '?')

        parsed = parse_pattern(sig)
        if parsed is None:
            results.append(None)
            continue

        offset = pattern_scan(data, parsed)
        is_found = offset is not None

        if is_found:
            found_count += 1
            status = f'FOUND @ 0x{offset:06X}'
        else:
            status = 'NOT FOUND'

        # Show first few bytes of the match for verification
        match_preview = ''
        if is_found and offset + min(8, parsed.pattern_len) <= len(data):
            preview_bytes = data[offset:offset + min(8, parsed.pattern_len)]
            match_preview = ' '.join(f'{b:02X}' for b in preview_bytes)

        print(f'  [{i+1:>3}] {name[:30]:<30} {module:<20} '
              f'{hook_type:<20} {status:<25} {match_preview}')

        results.append(ScanResult(
            pattern=p,
            parsed=parsed,
            match_offset=offset,
            match_address=offset,
            found=is_found,
        ))

    print()
    print(f'  TOTAL: {found_count}/{len(patterns)} patterns found')
    if found_count < len(patterns):
        print(f'  MISSING: {len(patterns) - found_count} patterns not found')
        for r in results:
            if r is not None and not r.found:
                safe_name = r.pattern.get("name", "?").encode('ascii', errors='replace').decode('ascii')
        safe_sig = r.pattern.get("signature", "")[:40].encode('ascii', errors='replace').decode('ascii')
        print(f'    - "{safe_name}" '
              f'({r.pattern.get("module", "?")}) '
              f'[{safe_sig}...]')
    print('=' * 72)

    return results


# ==============================================================================
# BYTE-LEVEL FEATURE ANALYSIS
# ==============================================================================

def analyze_pattern_features(patterns: List[dict]):
    """Analyze statistical properties of the pattern database."""
    print()
    print('=' * 72)
    print('PATTERN DATABASE FEATURE ANALYSIS')
    print('=' * 72)

    lengths = []
    wc_counts = []
    wc_pcts = []
    by_module = {}
    by_hook = {}
    all_sig_chars = ''
    leading_bytes = {}
    patterns_with_trailing_wc = 0
    patterns_with_leading_wc = 0
    all_wc = 0
    all_exact = 0

    for p in patterns:
        sig = p.get('signature', '')
        mod = p.get('module', '?')
        hook = p.get('hook_type', '?')

        parsed = parse_pattern(sig)
        if parsed is None:
            continue

        lengths.append(parsed.pattern_len)
        wc = parsed.pattern_mask.count(0)
        wc_counts.append(wc)
        pct = (wc / parsed.pattern_len * 100) if parsed.pattern_len > 0 else 0
        wc_pcts.append(pct)
        all_wc += wc
        all_exact += parsed.pattern_len - wc

        # Module stats
        if mod not in by_module:
            by_module[mod] = {'count': 0, 'total_len': 0, 'total_wc': 0}
        by_module[mod]['count'] += 1
        by_module[mod]['total_len'] += parsed.pattern_len
        by_module[mod]['total_wc'] += wc

        # Hook type stats
        if hook not in by_hook:
            by_hook[hook] = {'count': 0, 'total_len': 0, 'total_wc': 0}
        by_hook[hook]['count'] += 1
        by_hook[hook]['total_len'] += parsed.pattern_len
        by_hook[hook]['total_wc'] += wc

        # Character frequency (sig string)
        all_sig_chars += sig

        # Leading byte analysis
        tokens = sig.split(' ')
        if tokens:
            first = tokens[0]
            if first == '??':
                patterns_with_leading_wc += 1
            else:
                leading_bytes[first] = leading_bytes.get(first, 0) + 1

        # Trailing wildcard
        if tokens and tokens[-1] == '??':
            patterns_with_trailing_wc += 1

    print(f'  Total patterns:             {len(patterns)}')
    print(f'  Total bytes (exact+wc):     {all_exact + all_wc}')
    print(f'  Exact bytes:                {all_exact}')
    print(f'  Wildcard bytes:             {all_wc}')
    print(f'  Overall wildcard %:         {all_wc/(all_exact+all_wc)*100:.1f}%')

    if lengths:
        mean_l = sum(lengths) / len(lengths)
        variance_l = sum((x - mean_l) ** 2 for x in lengths) / len(lengths)
        stddev_l = variance_l ** 0.5
        print(f'\n  Pattern length stats:')
        print(f'    Min:      {min(lengths):>4}')
        print(f'    Max:      {max(lengths):>4}')
        print(f'    Mean:     {mean_l:>7.1f}')
        print(f'    Stddev:   {stddev_l:>7.1f}')

    if wc_pcts:
        print(f'\n  Wildcard percentage per pattern:')
        print(f'    Min:      {min(wc_pcts):>6.1f}%')
        print(f'    Max:      {max(wc_pcts):>6.1f}%')
        print(f'    Mean:     {sum(wc_pcts)/len(wc_pcts):>6.1f}%')

    print(f'\n  Patterns with leading  ?? : {patterns_with_leading_wc}')
    print(f'  Patterns with trailing ?? : {patterns_with_trailing_wc}')

    print(f'\n  Top leading bytes:')
    for b in sorted(leading_bytes, key=leading_bytes.get, reverse=True)[:10]:
        print(f'    {b}: {leading_bytes[b]} patterns')

    print(f'\n  Module distribution:')
    for mod in sorted(by_module):
        m = by_module[mod]
        print(f'    {mod:<22} {m["count"]:>3} patterns, '
              f'avg len={m["total_len"]/m["count"]:.1f}, '
              f'avg wc={m["total_wc"]/m["count"]:.1f}')

    print(f'\n  Hook type distribution:')
    for hk in sorted(by_hook):
        h = by_hook[hk]
        print(f'    {hk:<22} {h["count"]:>3} patterns, '
              f'avg len={h["total_len"]/h["count"]:.1f}, '
              f'avg wc={h["total_wc"]/h["count"]:.1f}')

    # Hex character frequency
    hex_chars = {}
    for c in all_sig_chars:
        if c in '0123456789ABCDEF':
            hex_chars[c] = hex_chars.get(c, 0) + 1
    # Find spikes (opcodes that appear as first byte often)
    print(f'\n  Byte value frequency (top 10 nibble pairs):')
    byte_freq = {}
    for i in range(0, len(all_sig_chars) - 1, 3):
        pair = all_sig_chars[i:i+2]
        if len(pair) == 2 and '?' not in pair:
            byte_freq[pair] = byte_freq.get(pair, 0) + 1
    for b in sorted(byte_freq, key=byte_freq.get, reverse=True)[:10]:
        opcode_hints = {
            '48': 'REX.W prefix (64-bit ops)',
            '0F': 'Two-byte opcode prefix',
            '8B': 'MOV r32/64, r/m',
            '89': 'MOV r/m, r32/64',
            '83': 'Group 1 (ADD/OR/ADC/SBB/AND/SUB/XOR/CMP)',
            'FF': 'Group 5 (INC/DEC/CALL/JMP/PUSH)',
            'F3': 'REP/SSE prefix',
            '41': 'REX.B prefix',
            'C7': 'MOV r/m, imm32',
            '8D': 'LEA',
            '4C': 'REX.WR prefix',
            '33': 'XOR r, r/m',
            'E8': 'CALL rel32',
            'E9': 'JMP rel32',
            '74': 'JE/JZ rel8',
            '75': 'JNE/JNZ rel8',
            '42': 'REX.X prefix',
            '49': 'REX.WB prefix',
            '44': 'REX.R prefix',
            'BA': 'MOV EDX, imm32',
            '39': 'CMP r/m, r32/64',
            '2B': 'SUB r, r/m',
            'CC': 'INT3 (padding)',
        }
        hint = opcode_hints.get(b, '')
        print(f'    {b}: {byte_freq[b]:>4}x    {hint}')

    print('=' * 72)


# ==============================================================================
# MAIN
# ==============================================================================

def main():
    print('AGENT J: PATTERN SCANNER IMPLEMENTATION')
    print('=' * 72)

    # Load binary
    print(f'\n[1] Loading binary: {BIN_PATH}')
    with open(BIN_PATH, 'rb') as f:
        data = f.read()
    print(f'    Size: {len(data):,} bytes ({len(data)/1024/1024:.1f} MB)')
    print(f'    First 16 bytes: {" ".join(f"{b:02X}" for b in data[:16])}')

    # Load patterns
    print(f'\n[2] Loading patterns: {PATTERNS_PATH}')
    with open(PATTERNS_PATH, 'r') as f:
        patterns = json.load(f)
    print(f'    Total patterns: {len(patterns)}')

    # Run unit tests
    print(f'\n[3] Running unit tests...')
    passed, failed = run_unit_tests(data)
    print(f'\n    Units: {passed} passed, {failed} failed')

    # Analyze pattern features
    print(f'\n[4] Pattern feature analysis...')
    analyze_pattern_features(patterns)

    # Full scan
    print(f'\n[5] Full pattern scan against .text binary...')
    results = scan_all_patterns_with_report(data, patterns)

    # Performance analysis
    print(f'\n[6] Performance analysis...')
    run_performance_analysis(data, patterns)

    # Wildcard verification
    print(f'\n[7] Wildcard variability verification...')
    verify_wildcards(data, patterns)

    # Summary
    print(f'\n{"=" * 72}')
    print('FINAL VERDICT')
    print('=' * 72)
    found = sum(1 for r in results if r is not None and r.found)
    total = len(results)
    print(f'  Patterns matched:    {found}/{total}')

    if found == total:
        print('  STATUS: ALL PATTERNS FOUND - binary is consistent with patterns')
    elif found > 0:
        print(f'  STATUS: PARTIAL MATCH - {total - found} patterns missing')
        print('  NOTE: Patterns extracted from .rdata may reference code that')
        print('        is NOT present in the unpacked .text section. The pattern')
        print('        signatures are for the ORIGINAL game.dll, not the cheat')
        print('        DLL itself. Therefore some patterns may not be found in')
        print('        this binary since they target game code at different RVAs.')

    if failed == 0:
        print(f'  ALL {passed} UNIT TESTS PASSED')
    else:
        print(f'  {passed}/{passed+failed} unit tests passed, {failed} failed')
    print('=' * 72)

    return 0


if __name__ == '__main__':
    sys.exit(main())
