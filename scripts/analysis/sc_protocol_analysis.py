#!/usr/bin/env python3
"""
SC (Super Credits) & Medal Farming Protocol Analysis
LIBERTEA Helldivers 2 Trainer (v1.91.5 / v414)
============================================================

This script documents the reverse-engineered SC farming protocol
from the unpacked .text section of the LIBERTEA Helldivers 2 cheat DLL.

Author: Static analysis of .text_unpacked_mem.bin (3,489,792 bytes)
Binary base: 0x00000000 (RVAs as offsets from image base)
"""

import json
import struct
import time
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import IntEnum


# ============================================================================
# SECTION 1: KEY OFFSETS AND STRING LOCATIONS
# ============================================================================

class StringOffsets:
    """RVA offsets of critical strings in the .text section."""
    
    # === SC Farming Strings ===
    SCLOOP_FMT           = 0x100750  # "SCLoop[%d]: actObj=%p missionId=%s actId32=0x%08X objId=0x%08X pids=%d (retry=%d)"
    SCLOOP_STATUS        = 0x1007F0  # "SCLoop[%d]: %s"
    SC_MIDSWAP           = 0x1007A8  # "[SC] MIDSWAP call %d/%d: str=%d bin=%d"
    SC_MIDSWAP_ID        = 0x1007D2  # " mid=%s"
    SC_MEDAL             = 0x100810  # "MEDAL"
    SC_BATCH_DONE        = 0x100820  # "[SC] %s batch done"
    COOLDOWN_START       = 0x100836  # " cooldown starting"
    SC_COOLDOWN_58S      = 0x100850  # "SC cooldown 58s"
    SC_GOAL_REACHED      = 0x1006F8  # "SC goal reached"
    SC_NO_DATA           = 0x100718  # "[SC] No data"
    SC_SKIP_NO_SESSION   = 0x100610  # "SC skip: no session"
    SC_SESSION_INFO      = 0x1005E8  # "  GetActiveSession() = 0x%llX "
    SC_HAS_SESSION       = 0x1005C8  # "HAS SESSION"
    SC_NULL_SESSION      = 0x1005D8  # "NULL SESSION"
    
    # === Batch Firing ===
    FIRING_MEDAL_BATCH   = 0x0FEA80  # "Firing MEDAL batch (9 calls x 500ms)..."
    FIRING_SC_BATCH      = 0x0FEAA8  # "Firing SC batch (9 calls x 500ms)..."
    CALLS_SENT           = 0x0FEAD0  # "Calls sent: %d"
    SKIPPED_REPLAY       = 0x0FEAE0  # "  |  Skipped (replay): %d"
    REWARDED             = 0x0FEB00  # "Rewarded: %d"
    EMPTY                = 0x0FEB10  # "  Empty: %d"
    TOTAL                = 0x0FEB20  # "  Total: %d"
    RECOVERED            = 0x0FEB30  # "Recovered: %d"
    FAILED               = 0x0FEB40  # "  Failed: %d"
    SC_TRACKER           = 0x0FEB60  # "%d calls sent  |  %d SC earned  |  %d x100 bonus"
    SC_TRACKER_SIMPLE    = 0x0FEB98  # "%d calls sent  |  %d SC earned"
    
    # === SC Loop States ===
    MEDAL_BATCH_FIRING   = 0x100728  # "Medal Batch Firing"
    SC_BATCH_FIRING      = 0x100740  # "SC Batch Firing"
    SC_ACTFN_CALLED      = 0x1006D0  # "[SC] actFn called"
    MONITORING_10S       = 0x1006E5  # " monitoring 10s"
    
    # === VEH / Crash Recovery ===
    VEH_RECOVERED_CRASH  = 0x100660  # "[SC] VEH recovered crash"
    AFTER_FMT            = 0x100680  # "  AFTER(0s): ctr=0x%X flag=0x%X ring=%u rax=0x%llX url="%.40s" qDelta=%d"
    BEFORE_FMT           = 0x100628  # "  BEFORE: ctr=0x%X flag=0x%X ring=%u url="%.40s""
    BAIL_NO_SERVERINFO   = 0x1008B8  # "BAIL: no serverInfo"
    BAIL_RING_UNREADABLE = 0x1008D0  # "BAIL: ring index unreadable"
    
    # === Auto Sync ===
    SC_AUTOSYNC          = 0x100860  # "[SC AutoSync] %d player(s) synced"
    SC_SYNCNOW           = 0x100B68  # "[SC] SyncNow: %d player(s) synced on inject"
    
    # === Replay System ===
    REPLAY_CAP_FILE      = 0x0C5C78  # "libertea_replay_cap.json"
    CAPTURED_WARTIME     = 0x0C5CC0  # "capturedWarTime"
    CAPTURED_MISSION_ID  = 0x101CE8  # " CAPTURED missionId=%s"
    NEXT_POST_MISSION_ID = 0x101DAC  # " next POST will use missionId=%s"
    GOLDEN_CAPTURE       = 0x101EE0  # "[HTTP-RESP] Golden capture: hi2=%p rawPostLen=%d"
    CAPTURED_POST_BODY   = 0x102128  # "Captured Mission/end POST body: %d bytes"
    HTTP_SETOPT_POST     = 0x102158  # "[HTTP] SETOPT POSTFIELDS h=%p len=%d (%s)"
    
    # === Replay Capture JSON Fields (at 0x1012F8-0x1013E0) ===
    CAP_FIELD_WARTIME     = 0x1012F8  # '  "capturedWarTime": %u,'
    CAP_FIELD_URL         = 0x101318  # '  "url": "%s",'
    CAP_FIELD_SEROBJ      = 0x101328  # '  "serObjOrigAddr": %llu,'
    CAP_FIELD_MD          = 0x101348  # '  "md": "%s",'
    CAP_FIELD_SEROBJ_VAL  = 0x101358  # '  "serObj": "%s",'
    CAP_FIELD_SLOTDATA    = 0x101370  # '  "slotData": "%s",'
    CAP_FIELD_ENTITYDEEP  = 0x101388  # '  "entityDeep": "%s",'
    CAP_FIELD_ENTITYDATA  = 0x1013A0  # '  "entityDataDeep": "%s",'
    CAP_FIELD_AC          = 0x1013C0  # '  "ac": %d,'
    CAP_FIELD_OI          = 0x1013D0  # '  "oi": %u,'
    CAP_FIELD_GS          = 0x1013E0  # '  "gs": "%s"'
    
    # === Hash Table NOP ===
    HASH_TABLE_NOP       = 0x1034D0  # "NOP both hash table INSERT calls that mark SC entities as collected"
    HASH_PATTERN_BYTES   = 0x103480  # Pattern bytes for locating INSERT calls
    RESOURCE_NOP         = 0x103550  # "NOP resource value read (freezes resources)"
    
    # === API Endpoint ===
    API_ENDPOINT_1       = 0x0C624C  # "https://api.live.prod.thehelldiversgame.com/api/Operation/Mission/end"
    API_ENDPOINT_2       = 0x0C6ED0
    # (multiple duplicate references exist at various offsets)
    
    # === HTTP / Header Strings ===
    HTTP_HEADERS_START   = 0x1020A0
    X_SIGNATURE          = 0x1020A0  # "X-Signature:"
    AUTHORIZATION        = 0x1020B0  # "Authorization:"
    COOKIE               = 0x1020C0  # "Cookie:"
    X_SESSION            = 0x1020C8  # "X-Session"
    X_AUTH               = 0x1020D4  # "X-Auth"
    X_TOKEN              = 0x1020E0  # "X-Token"
    CONTENT_TYPE         = 0x1020E8  # "Content-Type:"
    ACCEPT               = 0x1020F8  # "Accept:"
    API_PREFIX           = 0x102100  # "/api/"
    HTTP_RESP_POST       = 0x101EC0  # "[HTTP-RESP] POST missionId=%s"
    
    # === Replay Burst ===
    BURST_START          = 0x100B30  # "[Burst] Starting %d staggered replays (5s apart)..."
    BURST_DONE           = 0x100AE8  # "[Burst] Done"
    BURST_DISPATCHED     = 0x100AF8  # " %d replays dispatched"
    BURST_SENT           = 0x100AB8  # "[Burst] Sent %d/%d"
    BURST_FAILED         = 0x100AD0  # "[Burst] %d/%d failed"
    
    # === Signature Capture (libcurl write callback hook) ===
    SIG_CAPTURE_INIT     = 0x102238  # "[SIG-CAPTURE] SINGLE #%d bufLen=%lu bodyXorLen=%lu nonce=%s"
    SIG_CHUNK_F2S7       = 0x10229A  # " got f2s7"
    SIG_CHUNK_NONCE      = 0x1022CA  # " got f2s7+nonce (%lu bytes)"
    SIG_CHUNK_PARTIAL    = 0x1022F0  # " got f2s7+partial (%lu bytes)"
    SIG_NONCE_CAPTURED   = 0x102349  # " nonce captured (%lu bytes)"
    SIG_CHUNK_BODY       = 0x102389  # " body chunk %lu bytes (waiting for key)"
    SIG_CHUNK_UNEXPECTED = 0x1023D1  # " unexpected chunk idx=%d size=%lu"
    
    # === libcurl Integration ===
    LIBCURL_FOUND        = 0x1026C0  # "[HTTP] Found libcurl at %p"
    CURL_SETOPT          = 0x1026E0  # "curl_easy_setopt"
    CURL_PERFORM         = 0x1026F8  # "curl_easy_perform"
    CURL_GETINFO         = 0x102710  # "curl_easy_getinfo"
    CURL_CLEANUP         = 0x102728  # "curl_easy_cleanup"
    CURL_INIT            = 0x102780  # "curl_easy_init"
    CURL_SLIST_APPEND    = 0x102790  # "curl_slist_append"
    CURL_SLIST_FREE      = 0x1027A8  # "curl_slist_free_all"
    CURL_RESOLVED        = 0x102740  # "[HTTP] Resolved: setopt=%p perform=%p getinfo=%p cleanup=%p"
    
    # === Window Message Dispatch ===
    QUEUE_SC             = 0x103FB8  # "QueueSC: PostMessage(hwnd=%p, actObj=%p) = %d, LastErr=%u"
    WM_SC_DISPATCH       = 0x103ED1  # "WndProc: WM_SC_DISPATCH received, actObj=%p, TID=%u"
    SC_ACTIVITY_APC      = 0x1005A4  # "=== ScActivityAPC === actObj=%p TID=%u"


# ============================================================================
# SECTION 2: SC FARMING STATE MACHINE
# ============================================================================

class SCLoopState(IntEnum):
    """States of the SC farming state machine."""
    IDLE              = 0  # Not running
    ACTFN_CALLED      = 1  # Entry: ScActivityAPC received via APC/Window message
    CHECK_SESSION     = 2  # Validate GetActiveSession() != NULL
    MONITORING        = 3  # "monitoring 10s" - waiting for ring buffer data
    FIRING_SC         = 4  # "SC Batch Firing" - sending 9 SC calls
    FIRING_MEDAL      = 5  # "Medal Batch Firing" - sending 9 Medal calls
    MIDSWAP           = 6  # Replacing missionId in POST body
    COOLDOWN          = 7  # 58-second cooldown between batches
    GOAL_REACHED      = 8  # Target SC count reached
    CRASH_RECOVERY    = 9  # VEH recovered a crash


@dataclass
class SCLoopContext:
    """Context passed through the SC farming loop."""
    act_obj: int          # Pointer to game's Activity object
    mission_id: str       # Current mission UUID
    act_id32: int         # Activity ID (32-bit hash)
    obj_id: int           # Object ID
    player_count: int     # Number of players in lobby
    retry_count: int      # Current retry attempt
    batch_type: str       # "SC" or "MEDAL"
    batch_num: int        # Which call in the batch (1-9)
    midswap_count_str: int # Number of STR-based MID swaps
    midswap_count_bin: int # Number of BIN-based MID swaps
    sc_earned: int        # Total SC earned this session
    calls_sent: int       # Total API calls sent
    skipped_replay: int   # Calls skipped because replay detected
    rewarded: int         # Calls that returned SC reward
    empty: int            # Calls that returned no data
    recovered: int        # Calls recovered after VEH crash
    failed: int           # Failed calls
    goal_sc: int          # Target SC goal (0 = unlimited)
    cooldown_remaining: float  # Seconds remaining in cooldown
    crashes_absorbed: int # Total VEH-recovered crashes


class SCFarmingStateMachine:
    """
    SC Farming State Machine - inferred from SCLoop string references
    and code flow analysis.
    
    The SC farming loop fires batches of 9 HTTP POST requests to the
    Mission/end API endpoint, alternating between SC and Medal batches,
    with a 58-second cooldown between batches.
    
    Flow:
    1. Game activity triggers -> ScActivityAPC entry point
    2. Check for active session -> BAIL if no session
    3. Read ring buffer (circular) for queued requests
    4. For each request in batch (9 per batch):
       a. Read raw POST request from ring buffer
       b. Execute MIDSWAP: replace missionId in JSON body
       c. Fire via CRUL library (libcurl clone/embedded)
       d. Count response: Rewarded, Empty, Skipped, Failed
    5. After batch complete, enter 58s cooldown
    6. Toggle batch type (SC <-> Medal) for next cycle
    7. Loop until SC goal reached or stopped
    """
    
    API_ENDPOINT = "https://api.live.prod.thehelldiversgame.com/api/Operation/Mission/end"
    BATCH_SIZE = 9
    CALL_INTERVAL_MS = 500       # 500ms between calls in batch
    COOLDOWN_SECONDS = 58        # Cooldown between batches
    RING_BUFFER_SIZE = 256       # Inferred from ring=%u pattern
    MONITORING_WINDOW_S = 10     # "monitoring 10s"
    RETRY_MAX = 3                # Inferred from retry patterns
    
    def describe_flow(self) -> str:
        return """
    SC FARMING STATE MACHINE FLOW:
    ===============================
    
    [IDLE] --(WM_SC_DISPATCH/APC)--> [CHECK_SESSION]
      |
      +-> "SC skip: no session" (BAIL if GetActiveSession()==NULL)
      |
      v
    [MONITORING] -- "monitoring 10s"
      |  Reads ring buffer for queued API calls from game
      |  BEFORE log: ctr, flag, ring index, URL (partial)
      |
      v
    [SC_BATCH_FIRING] or [MEDAL_BATCH_FIRING]
      |  "Firing SC/MEDAL batch (9 calls x 500ms)..."
      |  Loop i=0..8:
      |    - Read POST body from ring buffer slot
      |    - [MIDSWAP] Replace missionId in JSON body
      |    - CURLOPT_POSTFIELDS set modified body
      |    - curl_easy_perform() fire request
      |    - Parse response for "amount" field
      |    - Count: Calls sent, Skipped (replay), Rewarded, Empty
      |  AFTER log: qDelta (queue delta from monitoring)
      |
      v
    [COOLDOWN] -- "SC cooldown 58s" / "cooldown starting"
      |  Sleep(58000) or timer-based wait
      |  Crash during cooldown -> VEH recovers, restarts
      |
      v
    [TOGGLE BATCH TYPE]
      |  SC -> MEDAL -> SC -> MEDAL (alternating)
      |  Unless "Medals Only" mode is set
      |
      v
    [CHECK GOAL]
      |  "SC goal reached - stopping" if earned >= target
      |  Otherwise loop back to MONITORING
      |
      v
    [CRASH RECOVERY] -- VEH handler
      "  [SC] VEH recovered crash"
      Records crash, increments crasher counter, resumes loop
    """


# ============================================================================
# SECTION 3: HTTP REQUEST CONSTRUCTION
# ============================================================================

class HTTPRequestBuilder:
    """
    Constructs the HTTP POST request to the Mission/end API endpoint.
    
    The cheat does NOT construct requests from scratch. Instead, it:
    1. CAPTURES a real Mission/end POST from the game's native libcurl call
    2. Stores raw JSON body, headers, and signatures
    3. REPLAYS the captured request, modifying the missionId field
    """
    
    ENDPOINT = "https://api.live.prod.thehelldiversgame.com/api/Operation/Mission/end"
    
    @staticmethod
    def construct_request_body() -> dict:
        """
        Reconstructed JSON structure sent to the Mission/end endpoint.
        
        This is the body that the game sends when a mission completes.
        The cheat captures and replays this body, only modifying missionId.
        """
        return {
            # Mission identification
            "missionId": "",           # UUID/GUID string - REPLACED by MIDSWAP
            "capturedWarTime": 0,      # uint32 - war timestamp from capture
            
            # Serialized game objects (hex-encoded binary data)
            "url": "",                 # Encoded request URL/endpoint
            "serObjOrigAddr": 0,       # uint64 - original address of serialized object
            "serObj": "",              # Hex string - serialized mission result object
            "md": "",                  # Hex string - mission data (md)
            "slotData": "",            # Hex string - slot/loadout data
            "entityDeep": "",          # Hex string - deep entity state
            "entityDataDeep": "",      # Hex string - deep entity data
            
            # Counts / flags
            "ac": 0,                   # int - activity/action count
            "oi": 0,                   # uint - operation/objective index
            
            # Game state (hex-encoded binary)
            "gs": "",                  # Hex string - game state snapshot
            
            # Additionally, the server may parse:
            # "amount" - the actual SC/Medal reward amount (parsed from response)
        }
    
    @staticmethod
    def get_http_headers() -> dict:
        """HTTP headers sent with the POST request."""
        return {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": "",       # Bearer/JWT token from session
            "X-Session": "",           # Session identifier
            "X-Auth": "",              # Alternative auth token
            "X-Token": "",             # Token for verification
            "X-Signature": "",         # Request signature (anti-tamper)
            "Cookie": "",              # Session cookie
        }


# ============================================================================
# SECTION 4: MIDSWAP - Mission ID Swapping
# ============================================================================

class MIDSWAPEngine:
    """
    MIDSWAP mechanism: replaces the missionId in the POST body before replay.
    
    Why: The server detects duplicate missionId values and rejects them.
    By replacing the missionId with a new one, the cheat bypasses
    server-side duplicate detection.
    
    Two swap modes:
    1. STR swap: Replace missionId string in JSON at text level
    2. BIN swap: Replace missionId in the binary-serialized object data
    
    From log format: "[SC] MIDSWAP call %d/%d: str=%d bin=%d"
    """
    
    @staticmethod
    def str_swap(body: bytes, old_mission_id: str, new_mission_id: str) -> bytes:
        """Replace missionId text in the JSON body."""
        # Find "missionId":"<old>" pattern
        pattern = f'"missionId":"{old_mission_id}"'.encode()
        replacement = f'"missionId":"{new_mission_id}"'.encode()
        return body.replace(pattern, replacement)
    
    @staticmethod
    def bin_swap(body: bytes, old_mission_id: str, new_mission_id: str) -> bytes:
        """Replace missionId in binary-serialized game objects."""
        old_bytes = old_mission_id.encode()
        new_bytes = new_mission_id.encode()
        # Pad/truncate to same length
        if len(new_bytes) < len(old_bytes):
            new_bytes = new_bytes.ljust(len(old_bytes), b'\x00')
        elif len(new_bytes) > len(old_bytes):
            new_bytes = new_bytes[:len(old_bytes)]
        return body.replace(old_bytes, new_bytes)


# ============================================================================
# SECTION 5: REPLAY CAPTURE SYSTEM
# ============================================================================

class ReplayCaptureSystem:
    """
    How the cheat captures and replays Mission/end API calls.
    
    Capture Mechanism:
    - Hooks libcurl's CURLOPT_WRITEFUNCTION callback
    - Intercepts the raw POST body as game sends Mission/end
    - Stores to C:\libertea_replay_cap.json
    - Also hooks response to capture signatures/nonces
    
    Capture File Format (C:\libertea_replay_cap.json):
    {
      "capturedWarTime": <uint32>,
      "url": "<endpoint_url>",
      "serObjOrigAddr": <uint64_pointer>,
      "md": "<hex_encoded_mission_data>",
      "serObj": "<hex_encoded_serialized_object>",
      "slotData": "<hex_encoded_slot_data>",
      "entityDeep": "<hex_encoded_entity_state>",
      "entityDataDeep": "<hex_encoded_entity_data>",
      "ac": <activity_count>,
      "oi": <objective_index>,
      "gs": "<hex_encoded_game_state>"
    }
    
    The capture also records:
    - Authorization headers (tokens, session cookies)
    - X-Signature header for request verification
    - Nonce values from response chunks
    """
    
    CAPTURE_FILE = r"C:\libertea_replay_cap.json"
    BAKED_CAPTURE_MSG = "[+] Baked capture loaded"  # 0x0C5D58
    
    CAPTURE_STATES = {
        "WAITING":    "  Waiting for mission to capture...",    # 0x0FE3F0
        "CAPTURED":   "  Session captured",                     # 0x0FE418
        "PROBE_ON":   "  Probe ON - will overwrite on next mission",  # 0x0FE440
        "PROBE_WAIT": "Probe: ON - waiting for mission",        # 0x0FE470
        "PROBE_SAVED":"Probe: OFF - %d player%s saved",         # 0x0FE498
        "PROBE_OFF":  "Probe: OFF",                             # 0x0FE4B8
    }
    
    @staticmethod
    def describe_capture_flow() -> str:
        return """
    REPLAY CAPTURE FLOW:
    =====================
    
    1. [PROBE] User enables probe -> hooks libcurl write callback
       - Installs hook on CURLOPT_WRITEFUNCTION
       - Monitors for POSTs to /api/Operation/Mission/end
    
    2. [INTERCEPT] Game sends Mission/end POST
       - Hook captures full request: URL, headers, POST body
       - Also captures libcurl easy handle and internal state
    
    3. [SERIALIZE] Raw data serialized to JSON
       - missionId, capturedWarTime extracted
       - Binary game objects hex-encoded
       - Saved to C:\libertea_replay_cap.json
    
    4. [REPLAY] User triggers replay (manual, auto, or burst)
       - Loads capture from JSON file
       - Constructs new libcurl request with captured data
       - MIDSWAP replaces missionId
       - Request sent to same endpoint
    
    5. [RESPONSE] Server response parsed
       - SC reward extracted from "amount" field
       - Success/failure logged
       - Crash recovery via VEH if request crashes game
    """


# ============================================================================
# SECTION 6: HASH TABLE NOP MECHANISM
# ============================================================================

class HashTableNOP:
    """
    The game uses a hash table to track which SC (Super Credit) entities
    have been collected by the player. When an SC pickup is collected,
    the game inserts the entity ID into a hash table and reports it to
    the server. This prevents duplicate collection.
    
    THE NOP: The cheat patches both INSERT call sites with NOP (0x90)
    instructions, so the hash table is NEVER updated. This means:
    - The game thinks no SC entities have been collected
    - The server never receives collection notifications
    - Entities can be "collected" repeatedly
    
    PATTERN BYTES (at 0x103480):
        83 F8 10             cmp eax, 10h         ; Check hash bucket index
        0F 82 XX XX XX XX    jb  <skip_insert>     ; Jump if below threshold
        41 8B 4E 08          mov ecx, [r14+08h]    ; Load hash table pointer
        41 B9 FF FF FF FF    mov r9d, FFFFFFFFh    ; Size param (-1 = auto)
        41 B8 70 00 00 00    mov r8d, 70h           ; Element size = 0x70
        ; ... followed by virtual call to INSERT method
        
    PATCHING:
    - Pattern scanned in game_live.dll (or game_current.dll)
    - Both occurrences located via byte pattern match
    - VirtualProtect to make .text writable
    - Instructions overwritten with 0x90 (NOP) bytes
    - Protection restored
    
    EFFECT:
    - SC entities: Never marked as "collected" client-side
    - Server: Sees mission results without SC entities recorded
    - Reward: Server grants SC based on uncollected entities in mission
    """
    
    PATTERN_BYTES = bytes([
        0x83, 0xF8, 0x10,           # cmp eax, 10h
        0x0F, 0x82,                 # jb (6 bytes: 0F 82 xx xx xx xx)
        0x41, 0x8B, 0x4E, 0x08,    # mov ecx, [r14+08h]
        0x41, 0xB9, 0xFF, 0xFF, 0xFF, 0xFF,  # mov r9d, FFFFFFFFh
        0x41, 0xB8, 0x70, 0x00, 0x00, 0x00,  # mov r8d, 70h
    ])
    
    ELEMENT_SIZE = 0x70  # 112 bytes per hash table entry
    BUCKET_THRESHOLD = 0x10  # 16 buckets
    PATCH_SIZE = 0x1A       # 26 bytes to NOP (estimated)
    
    @staticmethod
    def find_insert_calls(data: bytes) -> List[int]:
        """
        Find the two INSERT call sites in the game DLL.
        Returns list of offsets where the pattern matches.
        """
        import re
        # Pattern with wildcards for the jump displacement
        pattern = re.compile(
            b'\x83\xF8\x10'           # cmp eax, 10h
            b'\x0F\x82....'           # jb rel32 (6 bytes)
            b'\x41\x8B\x4E\x08'       # mov ecx, [r14+08h]
            b'\x41\xB9\xFF\xFF\xFF\xFF'  # mov r9d, -1
            b'\x41\xB8\x70\x00\x00\x00',  # mov r8d, 70h
            re.DOTALL
        )
        matches = []
        for m in pattern.finditer(data):
            matches.append(m.start())
        return matches  # Should return exactly 2 matches
    
    @staticmethod
    def nop_insert_calls(code_section: bytearray, offsets: List[int]) -> None:
        """NOP out the INSERT call setup instructions."""
        for off in offsets:
            for i in range(off, off + 28):  # ~28 bytes to NOP
                code_section[i] = 0x90


# ============================================================================
# SECTION 7: VEH CRASH RECOVERY
# ============================================================================

class VEHCrashRecovery:
    """
    Vectored Exception Handler (VEH) for SC farming crash recovery.
    
    VEH is registered via AddVectoredExceptionHandler(1, handler)
    (Windows API, first-chance handler). When the SC farming loop
    causes a crash (e.g., accessing invalid memory in the ring buffer,
    or a libcurl crash), the VEH handler:
    
    1. Catches the exception (first-chance)
    2. Logs: "[SC] VEH recovered crash"
    3. Records crash counter: "Crashes absorbed: %d"
    4. Updates the CrashLog: "=== LIBERTEA CRASH LOG ==="
    5. Resets relevant SC loop state
    6. Returns EXCEPTION_CONTINUE_EXECUTION (resume at safe point)
    7. Resumes the SC farm loop from a safe continuation point
    
    The logs show the state before/after recovery:
    - BEFORE: ctr, flag, ring index, URL (what was being processed)
    - AFTER:  Same data plus rax register value and qDelta
    """
    
    CRASH_LOG_HEADER = "=== LIBERTEA CRASH LOG ==="  # 0x0C6010
    CRASHES_ABSORBED  = "Crashes absorbed: %d"        # 0x0FEC00
    
    @staticmethod
    def describe_veh_flow() -> str:
        return """
    VEH CRASH RECOVERY FLOW:
    =========================
    
    1. [REGISTRATION]
       - AddVectoredExceptionHandler(1, &VEHHandler) called at init
       - First-chance handler (parameter 1 = CALL_FIRST)
    
    2. [EXCEPTION OCCURS]
       - Crash during SC farming (ring buffer access, libcurl, etc.)
       - Exception record captured: address, code, context
    
    3. [VEH HANDLER EXECUTES]
       - Checks if crash is in SC farming code region
       - If not: returns EXCEPTION_CONTINUE_SEARCH (let other handlers try)
       - If yes:
         a. Log crash: "[SC] VEH recovered crash"
         b. Log BEFORE state: current ring index, counter, flag, URL
         c. Modify exception context:
            - Set RIP/EIP to safe continuation point
            - Fix up stack if needed
            - Clear error state
         d. Increment crash counter
         e. Return EXCEPTION_CONTINUE_EXECUTION
    
    4. [RESUMPTION]
       - SC loop resumes from safe point
       - AFter log shows: rax value, qDelta (queue delta)
       - Current batch retried (up to max retries)
       - Failed count incremented for the crashed request
    
    5. [AFTERMATH]
       - Failed count displayed: "  Failed: %d"
       - Cooldown may be reduced or skipped after crash
       - Next batch proceeds normally
    """


# ============================================================================
# SECTION 8: AUTO-SYNC MECHANISM
# ============================================================================

class AutoSyncMechanism:
    """
    Distributes SC earnings to all lobby players.
    
    The AutoSync feature ensures that when SC are farmed,
    all players in the current lobby receive the rewards.
    This makes it appear as if everyone earned SC legitimately
    from the mission.
    
    How it works:
    1. When SC loop fires, it checks lobby state
       - "(%d/4 players)" - 0x0FE430
    2. For each lobby player, constructs/modifies the POST body
       to include their player ID
    3. All players receive the SC credit
    
    Log: "[SC AutoSync] %d player(s) synced"
    On inject: "[SC] SyncNow: %d player(s) synced on inject"
    """
    
    MAX_LOBBY_PLAYERS = 4
    
    @staticmethod
    def describe_sync_flow() -> str:
        return """
    AUTO-SYNC FLOW:
    ================
    
    1. [LOBBY DETECTION]
       - Enumerate lobby players via game's internal structures
       - Get player count and IDs
       - "  (%d/4 players)" shown in UI
    
    2. [SYNC ON INJECT]
       - On cheat DLL injection, immediately sync current players
       - Log: "[SC] SyncNow: %d player(s) synced on inject"
    
    3. [PER-BATCH SYNC]
       - Before firing each batch (SC or Medal), sync players
       - Log: "[SC AutoSync] %d player(s) synced"
       - If "No lobby found" -> skip, only host gets SC
    
    4. [SC DISTRIBUTION]
       - SC farming amount split/distributed across all synced players
       - %d player%s added to SC   (0x0FE960)
    """


# ============================================================================
# SECTION 9: SC FARMING REQUEST/RESPONSE FLOW
# ============================================================================

class SCRequestResponseFlow:
    """
    Complete request/response flow for SC farming.
    
    INITIAL SETUP:
    --------------
    1. Cheat DLL loaded -> pattern scanning -> install hooks
    2. VEH registered for crash recovery
    3. libcurl (or CRUL clone) initialized
    4. Hash table INSERT calls NOP'd (prevents server duplicate detection)
    5. libcurl write callback hooked (for replay capture)
    
    CAPTURE PHASE:
    --------------
    6. Player completes a real mission in-game
    7. Game sends POST to /api/Operation/Mission/end
    8. Hook intercepts: captures URL, headers, POST body, response
    9. Data saved to C:\libertea_replay_cap.json
    
    FARMING LOOP:
    -------------
    10. User enables "SC Loop: ON" in LIBERTEA overlay
    11. APC/Window message triggers ScActivityAPC
    12. Session validated (GetActiveSession())
    13. Ring buffer monitored for 10 seconds
        - BEFORE logged: ctr, flag, ring index, URL
    14. Loop starts:
        a. Read next request from ring buffer
        b. Clone libcurl handle from capture
        c. MIDSWAP: replace missionId in POST body
        d. Set CURLOPT_POSTFIELDS with modified body
        e. Set authorization headers (token, session, signature)
        f. curl_easy_perform() -> send POST
        g. Parse response for "amount" (SC/Medal value)
        h. Log result: Calls sent/Skipped/Rewarded/Empty
        i. Sleep 500ms
        j. Repeat 9 times (one batch)
    15. AFTER logged: qDelta (queue delta since monitoring started)
    16. Toggle batch type: SC -> MEDAL -> SC ...
    17. Enter 58-second cooldown
    18. Check SC goal. If reached: "SC goal reached - stopping"
    19. If not reached: go to step 13
    
    RESPONSE PARSING:
    -----------------
    Server response to Mission/end is JSON:
    {
      "amount": <int>,        // SC or Medals awarded
      "missionId": "<uuid>",  // Confirmed mission ID
      ... other fields ...
    }
    
    The cheat counts:
    - "Rewarded": response contains "amount" with non-zero value
    - "Empty": response has no "amount" or zero value
    - "Skipped (replay)": server detected duplicate -> rejected
    """
    
    @staticmethod
    def describe_curl_integration() -> str:
        return """
    LIBCURL / CRUL INTEGRATION:
    ============================
    
    The DLL dynamically loads libcurl (tries: libcurl.dll, libcurl-x64.dll, curl.dll)
    and resolves functions:
    - curl_easy_init()      -> Create new easy handle
    - curl_easy_setopt()    -> Configure handle (URL, POST fields, headers, etc.)
    - curl_slist_append()   -> Build header list
    - curl_easy_perform()   -> Execute the request
    - curl_easy_cleanup()   -> Cleanup handle
    - curl_slist_free_all() -> Free header list
    
    Each replay creates a new easy handle, copies headers and
    configuration from the captured request, then fires.
    
    The "CRUL" reference ([HTTP] Clone curl: ...) indicates the DLL
    may clone/reimplement part of libcurl for the replay system.
    
    WRITE CALLBACK HOOK:
    --------------------
    The cheat hooks CURLOPT_WRITEFUNCTION to intercept:
    - The raw POST body being sent (capture)
    - The server response body (parse SC amount)
    - Nonces and signatures from response chunks
    """
    
    @staticmethod
    def describe_signature_capture() -> str:
        return """
    SIGNATURE / NONCE CAPTURE:
    ===========================
    
    The game's Mission/end requests include cryptographic signatures
    to prevent tampering. The cheat captures these during a real
    mission to replay them later.
    
    Capture sequence (from [SIG-CAPTURE] logs):
    1. [SIG-CAPTURE] SINGLE #N bufLen=X bodyXorLen=Y nonce=Z
       - Initial capture of request buffer, body XOR length, and nonce
    
    2. [SIG-CHUNK] Tracking handle X ... got f2s7
       - Frame 2, section 7 of the signature chain captured
    
    3. [SIG-CHUNK] Tracking handle X ... got f2s7+nonce (N bytes)
       - Nonce appended to f2s7 signature block
    
    4. [SIG-CHUNK] Tracking handle X ... got f2s7+partial (N bytes)
       - Partial/non-final signature chunk
    
    5. [SIG-CHUNK] handle X ... nonce captured (N bytes)
       - Standalone nonce capture
    
    6. [SIG-CHUNK] handle X ... body chunk N bytes (waiting for key)
       - Body chunk captured, waiting for encryption key
    
    Call site tracking (frame9_outer, frame8, frame7, frame6, frame5,
    frame4_lobby, frame4_oper):
    - Tracks which call site in the game's code triggered the API call
    - Used to reconstruct the full request context for replay
    """


# ============================================================================
# SECTION 10: DISASSEMBLY OF CRITICAL CODE REGIONS
# ============================================================================

class CriticalCodeRegions:
    """
    Xrefs from code to key string references (RIP-relative LEA instructions).
    These show where the string format functions are called from.
    """
    
    XREFS = {
        # SC Loop function references
        0x015BD5: "SCLoop[%d] format -> SC farming state log function",
        0x015C63: "MIDSWAP format -> Mission ID swapping code",
        0x016055: "MEDAL format -> Medal batch toggle code",
        0x0160B0: "SC cooldown 58s -> Cooldown timer start",
        0x0156D6: "SC goal reached -> Goal check and stop condition",
        0x0164C0: "SC AutoSync -> Player sync at batch boundary",
        
        # Session checks
        0x015103: "SC skip: no session -> Session validation gate",
        
        # VEH recovery
        0x0152A5: "VEH recovered crash -> Exception handler log point",
        0x01524A: "BEFORE fmt -> Pre-crash state logging",
        0x01547A: "AFTER fmt -> Post-recovery state logging",
        0x0172B5: "BAIL ring unreadable -> Ring buffer access failure",
        0x017346: "BAIL no serverInfo -> Server info global read failure",
        
        # Batch firing
        0x0091CE: "Firing MEDAL batch -> Medal batch entry point",
        0x0091D5: "Firing SC batch -> SC batch entry point",
        0x009232: "Calls sent -> Batch results display",
        0x009305: "Rewarded -> SC reward counter display",
        
        # Capture file references
        0x001101: "libertea_replay_cap.json -> Capture file open/write",
        0x018650: "libertea_replay_cap.json -> Capture file read",
    }


# ============================================================================
# SECTION 11: COMPLETE API REQUEST/RESPONSE SCHEMA
# ============================================================================

class APIRequestResponseSchema:
    """
    Reconstructed schema from string references and code analysis.
    """
    
    REQUEST = {
        "method": "POST",
        "url": "https://api.live.prod.thehelldiversgame.com/api/Operation/Mission/end",
        "headers": {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": "<bearer_token_or_jwt>",
            "X-Session": "<session_id>",
            "X-Signature": "<cryptographic_signature>",
            "X-Auth": "<auth_token>",
            "X-Token": "<verification_token>",
            "Cookie": "<session_cookie>",
        },
        "body": {
            "missionId": "<uuid_string>",          # Primary key - MIDSWAP target
            "capturedWarTime": 0,                  # uint32 war timestamp
            "amount": 0,                           # May be in response, not request
            "serObjOrigAddr": 0,                   # uint64 - original game object address
            "serObj": "<hex_encoded_binary>",      # Serialized mission result
            "md": "<hex_encoded_binary>",          # Mission data
            "slotData": "<hex_encoded_binary>",    # Player slot/loadout data
            "entityDeep": "<hex_encoded_binary>",  # Entity state snapshot
            "entityDataDeep": "<hex_encoded_binary>", # Entity data snapshot
            "ac": 0,                               # Activity count
            "oi": 0,                               # Operation index
            "gs": "<hex_encoded_binary>",          # Game state
            "url": "<encoded_url_data>",           # Request URL encoding
        }
    }
    
    RESPONSE = {
        "status": "200 OK (expected)",
        "body": {
            "amount": 0,          # SC or Medal count awarded by server
            "missionId": "<uuid>",# Echoed mission ID
            # Additional fields parsed by the game but not by the cheat
        }
    }
    
    SC_BATCH_RESULTS = {
        "calls_sent": 0,       # "Calls sent: %d"
        "skipped_replay": 0,   # "Skipped (replay): %d" - server duplicate detection
        "rewarded": 0,         # "Rewarded: %d" - non-zero amount in response
        "empty": 0,            # "Empty: %d" - zero or missing amount
        "recovered": 0,        # "Recovered: %d" - VEH-recovered from crash
        "failed": 0,           # "Failed: %d" - unrecoverable errors
        "total": 0,            # "Total: %d"
    }


# ============================================================================
# SECTION 12: ALTERNATIVE PATHS (MEDALS, WEAPON XP)
# ============================================================================

class AlternativeFarming:
    """
    The same replay mechanism is used for:
    - Medals (Warbond Medals): same API endpoint, different reward type
    - Weapon XP: per-weapon tracking, uses weapon ID patching in POST body
    - Requisition Slips: mission reward multipliers
    - Samples: sample collection and sample reward override
    
    Medals mode options:
    - "Include Medals": Alternates SC / Medal batches (default)
    - "Medals Only": Every batch fires medals (no SC)
    """
    
    MEDAL_BATCH_MODE = {
        "alternating": "Alternates SC / Medal batches",  # 0x0FEC28
        "medals_only": "Every batch fires medals",        # 0x0FEC58
    }
    
    WEAPON_XP_MODES = {
        "all_guns": "All Guns ON - cycles through all 51 weapons",
        "selected_guns": "Selected Guns ON - only checked weapons",
        "per_gun_replays": "Replays/gun configurable",  # 0x0FEED8
    }


# ============================================================================
# SECTION 13: SUMMARY AND FINDINGS
# ============================================================================

def print_analysis_summary():
    """Print comprehensive analysis summary."""
    print("=" * 70)
    print("  LIBERTEA Helldivers 2 - SC Farming Protocol Analysis")
    print("  Binary: .text_unpacked_mem.bin (3,489,792 bytes / ~3.3 MB)")
    print("=" * 70)
    
    print("\n[1] SC FARMING STATE MACHINE")
    print("-" * 40)
    print("  Entry:        ScActivityAPC via APC/Window message (WM_SC_DISPATCH)")
    print("  Session gate: GetActiveSession() != NULL check")
    print("  Monitoring:   10-second ring buffer watch window")
    print("  Batch size:   9 calls per batch")
    print("  Interval:     500ms between calls within batch")
    print("  Cooldown:     58 seconds between batches")
    print("  Alternating:  SC batch -> Medal batch -> SC batch -> ...")
    print("  Goal:         Configurable SC target (0 = unlimited)")
    
    print("\n[2] HTTP REQUEST CONSTRUCTION")
    print("-" * 40)
    print("  Endpoint:  POST https://api.live.prod.thehelldiversgame.com/api/Operation/Mission/end")
    print("  Method:    Captured-and-replay (not constructed from scratch)")
    print("  Headers:   Authorization, X-Session, X-Signature, X-Auth, X-Token, Cookie")
    print("  Body:      JSON with missionId, capturedWarTime, serObj, md, slotData,")
    print("             entityDeep, entityDataDeep, ac, oi, gs, url")
    print("  Transport: libcurl (libcurl.dll / libcurl-x64.dll / curl.dll)")
    
    print("\n[3] REPLAY CAPTURE SYSTEM")
    print("-" * 40)
    print("  File:      C:\\libertea_replay_cap.json")
    print("  Hook:      libcurl CURLOPT_WRITEFUNCTION callback")
    print("  Intercept: POST requests to /api/Operation/Mission/end")
    print("  Stores:    URL, headers, POST body, signatures, nonces")
    print("  Replay:    Baked capture + MIDSWAP (missionId replacement)")
    print("  Modes:     Single, Auto (2-min interval), Burst (staggered 5s)")
    
    print("\n[4] MIDSWAP (MISSION ID SWAP)")
    print("-" * 40)
    print("  Purpose:  Bypass server-side duplicate missionId detection")
    print("  Modes:    STR swap (JSON text level), BIN swap (binary data level)")
    print("  Log:      [SC] MIDSWAP call %d/%d: str=%d bin=%d")
    print("  Source:   New missionId from ring buffer or auto-generated")
    
    print("\n[5] HASH TABLE NOP")
    print("-" * 40)
    print("  Target:   2 INSERT calls in game_live.dll hash table insert function")
    print("  Pattern:  cmp eax,10h; jb; mov ecx,[r14+8]; mov r9d,-1; mov r8d,70h")
    print("  Size:     0x70 (112 bytes) per hash table entry")
    print("  Purpose:  Prevents game from marking SC entities as 'collected'")
    print("  Effect:   Server sees no collected SC -> grants them on Mission/end")
    print("  Method:   NOP (0x90) overwrites 26-28 bytes at each INSERT call site")
    
    print("\n[6] VEH CRASH RECOVERY")
    print("-" * 40)
    print("  Handler:  AddVectoredExceptionHandler(1, &handler) - first chance")
    print("  Log:      [SC] VEH recovered crash")
    print("  State:    BEFORE/AFTER logs with ctr, flag, ring, rax, url, qDelta")
    print("  Resume:   Fixups RIP/stack to safe continuation point")
    print("  Counter:  Crashes absorbed: %d")
    print("  Log file: === LIBERTEA CRASH LOG ===")
    
    print("\n[7] AUTO-SYNC")
    print("-" * 40)
    print("  Purpose:  Distribute SC to all lobby players")
    print("  Max:      4 players (full lobby)")
    print("  On inject: %d player(s) synced on inject")
    print("  Per batch: [SC AutoSync] %d player(s) synced")
    
    print("\n[8] CODE LOCATIONS (RVAs in .text)")
    print("-" * 40)
    for addr, desc in sorted(CriticalCodeRegions.XREFS.items()):
        print(f"  0x{addr:06X}: {desc}")
    
    print("\n[9] STRING REFERENCES")
    print("-" * 40)
    print(f"  SCLoop format:         0x{StringOffsets.SCLOOP_FMT:06X}")
    print(f"  MIDSWAP log:           0x{StringOffsets.SC_MIDSWAP:06X}")
    print(f"  Firing SC batch:       0x{StringOffsets.FIRING_SC_BATCH:06X}")
    print(f"  Firing MEDAL batch:    0x{StringOffsets.FIRING_MEDAL_BATCH:06X}")
    print(f"  SC cooldown 58s:       0x{StringOffsets.SC_COOLDOWN_58S:06X}")
    print(f"  VEH recovered crash:   0x{StringOffsets.VEH_RECOVERED_CRASH:06X}")
    print(f"  Bail no serverInfo:    0x{StringOffsets.BAIL_NO_SERVERINFO:06X}")
    print(f"  Bail ring unreadable:  0x{StringOffsets.BAIL_RING_UNREADABLE:06X}")
    print(f"  SC AutoSync:           0x{StringOffsets.SC_AUTOSYNC:06X}")
    print(f"  Hash table NOP:        0x{StringOffsets.HASH_TABLE_NOP:06X}")
    print(f"  API Endpoint:          0x{StringOffsets.API_ENDPOINT_1:06X}")
    print(f"  Capture file:          0x{StringOffsets.REPLAY_CAP_FILE:06X}")
    print(f"  Calls sent:            0x{StringOffsets.CALLS_SENT:06X}")
    print(f"  Rewarded:              0x{StringOffsets.REWARDED:06X}")
    
    print()
    print("=" * 70)
    print("  ANALYSIS COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    print_analysis_summary()
