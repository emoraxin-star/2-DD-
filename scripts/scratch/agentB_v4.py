#!/usr/bin/env python3
"""Agent B v4 - Function Catalog with propagation and CRT detection."""

import struct, os, re
from collections import defaultdict, Counter, deque

try:
    from capstone import *; from capstone.x86 import *
except ImportError:
    print("pip install capstone"); exit(1)

BIN = r"C:\Users\emora\OneDrive\Desktop\2\data\.text_unpacked_mem.bin"
OUT = r"C:\Users\emora\OneDrive\Desktop\2\logs\agentB_function_catalog.txt"

with open(BIN, "rb") as f: binary = bytearray(f.read())
SZ = len(binary)
print(f"Binary: {SZ} bytes")

# -- strings --
EMB = {}
for i in range(SZ-4):
    if binary[i]==0: continue
    e=i
    while e<SZ and 32<=binary[e]<127: e+=1
    if e<SZ and binary[e]==0 and e-i>=3:
        EMB[i]=binary[i:e].decode('ascii','replace')
        i=e
print(f"Strings: {len(EMB)}")

# -- prologues --
def prologue(d,o):
    if o+8>len(d): return False
    b=d[o:o+8]
    if b[0]==0x48 and b[1]==0x83 and b[2]==0xEC and b[3]>=8: return True
    if b[0]==0x48 and b[1]==0x81 and b[2]==0xEC: return True
    if b[0]==0x55 and b[1]==0x48 and b[2] in (0x8B,0x89): return True
    if b[0]==0x48 and b[1]==0x89 and b[2] in (0x4C,0x54,0x5C,0x6C,0x7C) and b[3]==0x24:
        if len(b)>4 and b[4] in (8,0x10,0x18,0x20): return True
    if b[0]==0x40 and b[1]==0x53 and b[2] in (0x48,0x55,0x56,0x57): return True
    if b[0]==0x40 and b[1]==0x53 and b[2]==0x55 and b[3]==0x56 and b[4]==0x57: return True
    if b[0]==0x40 and b[1]==0x57 and b[2]==0x48: return True
    if b[0]==0x41 and b[1]==0x56 and b[2]==0x41 and b[3]==0x57: return True
    if b[0]==0x40 and b[1]==0x53 and b[2]==0x56: return True
    if b[0]==0x55 and b[1]==0x48 and b[2]==0x83 and b[3]==0xEC: return True
    if b[0]==0x48 and b[1]==0x89 and b[2]==0x54 and b[3]==0x24: return True
    if b[0]==0x41 and b[1]==0x56 and b[2] in (0x41,0x48): return True
    # push rbp only
    if b[0]==0x40 and b[1]==0x55 and b[2]==0x57: return True
    return False

ENTS=set()
for o in range(SZ-16):
    if prologue(binary,o): ENTS.add(o)
print(f"Entries: {len(ENTS)}")

# -- disasm --
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
SEEN=set(); FNS={}

def dis(rv,mx=3000):
    if rv in SEEN: return []
    R=[]; off=rv
    for _ in range(mx):
        if off>=SZ: break
        if off in SEEN and off!=rv: break
        try:
            for i in md.disasm(binary[off:off+15],off):
                SEEN.add(i.address); R.append(i)
                if i.mnemonic in ('ret','retf','retn'):
                    if i.address not in ENTS: return R
                if i.mnemonic=='jmp':
                    try:
                        if int(i.op_str,0) in ENTS and len(R)>3: return R
                    except: pass
                if i.mnemonic in ('int3','int','ud2'): return R
                off=i.address+i.size; break
            else: off+=1
        except: off+=1
    return R

L=sorted(ENTS); print(f"Pass1: {len(L)}")
for i,r in enumerate(L):
    if i%400==0: print(f"  {i}/{len(L)}")
    ins=dis(r)
    if not ins or len(ins)<2: continue
    sz=ins[-1].address-r+ins[-1].size
    cl=[];rf=[]
    for ii in ins:
        if ii.mnemonic=='call':
            try:
                t=int(ii.op_str,0)
                if 0<=t<SZ: cl.append(t); ENTS.add(t)
            except: pass
        elif ii.mnemonic=='lea' and 'rip' in ii.op_str.lower():
            rp=ii.address+ii.size+struct.unpack('<i',bytes(ii.bytes[-4:]))[0]
            if 0<=rp<SZ: rf.append(rp)
    FNS[r]={'sz':sz,'ins':ins,'cl':cl,'rf':rf}

for pn in range(2,5):
    nw=ENTS-set(FNS.keys())
    if not nw: break
    print(f"Pass{pn}: {len(nw)}")
    for i,r in enumerate(sorted(nw)):
        if i%500==0: print(f"  {i}/{len(nw)}")
        ins=dis(r)
        if not ins or len(ins)<2: continue
        sz=ins[-1].address-r+ins[-1].size
        cl=[];rf=[]
        for ii in ins:
            if ii.mnemonic=='call':
                try:
                    t=int(ii.op_str,0)
                    if 0<=t<SZ: cl.append(t); ENTS.add(t)
                except: pass
            elif ii.mnemonic=='lea' and 'rip' in ii.op_str.lower():
                rp=ii.address+ii.size+struct.unpack('<i',bytes(ii.bytes[-4:]))[0]
                if 0<=rp<SZ: rf.append(rp)
        FNS[r]={'sz':sz,'ins':ins,'cl':cl,'rf':rf}

print(f"Functions: {len(FNS)}")

# -- call graph --
CG=defaultdict(set); CGR=defaultdict(set)
for r,fn in FNS.items():
    for c in fn['cl']:
        CG[r].add(c); CGR[c].add(r)
print(f"Edges: {sum(len(v) for v in CG.values())}")

# -- features --
print("Features...")
for r,fn in FNS.items():
    ss=[]
    for ref in fn['rf']:
        if ref in EMB: ss.append(EMB[ref])
    fn['ss']=list(dict.fromkeys(ss))
    mn=Counter()
    for ii in fn['ins']: mn[ii.mnemonic]+=1
    fn['mn']=mn; fn['ic']=len(fn['ins'])

# -- SEEDS --
print("Seeds...")
SEEDS={}

MATCH=[
('SC_FARMING',['scactivityapc','scloop','sc]','super credits','super_credit','sc tracker','sc refresh','sc goal','medal batch','sc batch','req.slips','add samples instantly','samples over','max mission reward','reward multiplier','force apply difficulty','sc timer','auto sync','sc earned','sc earned','earning']),
('NETWORK_R',['replay_cap','replay capture','auto-replay','burst repl','golden-capt','golden capture','probe on','probe off','session captured','replay sent','replay queued','[replay]','[r] ','waiting for mission','burst loop','build payload','[probe]','[burst]','watchdog','weaponstats sent','weaponstats: crash','allgun','selectedgun','weaponovr','replay\n','>> next']),
('NETWORK_H',['http]','recon-','mission/end','winhttp','curl','missionid','golden capture','libcurl','curl_easy_setopt','curl_easy_perform','recon-body','recon-hdr','recon-url','recon-auth','recon-resp','http:','missionid','golden','call-site]','sig-capture','sig-chunk']),
('WEAPON_XP',['weapon','primary weapon','allgun','selectedgun','xp tracker','weaponovr','weapon xp']),
('AUTH',['auth','lock screen','enter your access key','login with your account','subscription active','lifetime access','invalid key','access revoked','session expired','network error. check','invalid username','join our discord','made by theogcup','subscription','liber\n','tool  v','checking...','acct:','verify','validat']),
('HOOK_SYSTEM',['hook installed','hook mismatch','call-site','code cave','aob not found','handler install','function prologue mismatch','prologue read','cave alloc failed','hook verified','bp cleared','setup failed','instant complete: gamebase']),
('PLAYER_CHEATS',['god mode','godmode','inf stamina','movement speed','no ragdoll','no recoil','speed hack','player only']),
('COMBAT_CHEATS',['infinite strat','instant strat','mass strat','no turret overheat','inf turret','expire all','inf ammo','no reload','inf grenades','inf stims','no laser overheat','map hack','hoverpack','instant shuttle','instant complete','freeze mission timer','instant hellbomb','skip launch code','instant railgun','grenade fuse','fast landing','no boundary','longer hover','shield cooldown','takeoff force','dark fluid','instant arrows','instant coordinates','instant pipes','arcade combo','correct combo','killstreak','instant charge','fov editor','reduce aggro','zero perception','remove sc limit','instant arcade','turret overheat','turret duration','stratagem count','nop stim','nop grenade','bypass strat','bypass boundary','nop landing','nop hover','nop arrow','nop coordinate','nop pipe','nop fuse','nop combo','nop round','nop killstreak','nop shield','nop hellbomb','nop turret','nop railgun','nop resource','nop unlock','no laser','laser overheat','nop stamina','stratagem','turret','grenade','hover pack','jump pack','combat']),
('ARMORY',['unlock all armory','armor passive editor','weapon stats editor','weapon editor','armor base','weapon stats','armor passive','scan armor']),
('IMGUI_RENDER',['dear imgui','imgui.ini','imgui_log','libertea hud','liberteaoverlay','##libertea_main','##content_area','##farming_scroll','##replay_subtabs','##sc_scroll','##replay_scroll','##log_scroll','##misc_scroll','##inbox_scroll','##lock_screen','l i b e r t e a','tool  v414','farming']),
('PATTERN_SCAN',['pattern','signature','aob','found @','not found','byte pattern']),
('CRASH_HANDLER',['=== libertea crash log ===','crashes absorbed','crash log']),
('CRYPTO',['machineguid','hwid','bcrypthashdata','nonce','encrypt','decrypt','base64']),
('CONFIG',['imgui.ini','libertea_replay_cap.json','.json']),
('MEMORY',['virtualprotect','ntprotectvirtualmemory','syscall stub','protection layer','all layers failed']),
('INIT',['dllmain','helldivers 2','getmoduleinformation','all paths failed','dumped','game.dll not loaded','ntdll.dll handle','[init]','scpresent::install','wndproc','[p] hook installed']),
('UPDATE',['updates','inbox','letter from']),
]

for r,fn in FNS.items():
    st=' '.join(fn['ss']).lower()
    for mod,keys in MATCH:
        if any(k in st for k in keys):
            SEEDS[r]=mod
            break

# -- CRT/STL detection --
CRT=['memcpy','memset','memmove','memcmp','memchr','strlen','strcmp','strncmp','strcpy','strncpy','strcat','strncat','strchr','strrchr','strstr','strtok','malloc','free','realloc','calloc','operator new','operator delete','vector','string','throw','bad_alloc','type_info','vftable','vtable','tootable','dynamic initializer','dynamic atexit','copy constructor','type descriptor','base class descriptor','complete object locator','class hierarchy descriptor','local static thread guard','anonymous namespace','nan(','sn)','log10','logf','unknown exception','string too long','vector too long','map/set','invalid string position','bad array new','CorExitProcess','FlsAlloc','FlsFree','FlsGetValue','FlsSetValue','InitializeCriticalSectionEx','CompareStringEx','GetDateFormatEx','GetTimeFormatEx','LCMapStringEx','LocaleNameToLCID','RoInitialize','RoUninitialize','AppPolicy','operator co_await','operator<=>','utf-8','utf-16le','unicode','sunday','monday','tuesday','wednesday','thursday','friday','january','february','Mm/dd/yy','HH:mm:ss']
for r,fn in FNS.items():
    if r in SEEDS: continue
    st=' '.join(fn['ss']).lower()
    if any(c in st for c in CRT):
        SEEDS[r]='CRT_STL'; continue
    mn=fn['mn']
    if 'rep' in mn and ('movsb' in mn or 'stosb' in mn or 'scasb' in mn):
        SEEDS[r]='CRT_STL'; continue
    if fn['ic']<=4 and fn['cl']:
        SEEDS[r]='CRT_STL'; continue
    if fn['ic']<=2:
        SEEDS[r]='CRT_STL'; continue

print(f"  Seeds: {len(SEEDS)}")
from collections import Counter as _Ct
sc=_Ct(SEEDS.values())
for m,c in sc.most_common(): print(f"    {m}: {c}")

# -- Propagation --
print("Propagation...")
VOTES=defaultdict(lambda: defaultdict(float))
for r,mod in SEEDS.items(): VOTES[r][mod]=100.0

Q=deque()
for r in SEEDS: Q.append((r,0))
DEPTH={}
MAX_D=6; DEC=0.50; THR=4.0
cnt=0
while Q:
    r,d=Q.popleft()
    if d>=MAX_D: continue
    v=VOTES.get(r,{})
    if not v: continue
    main=max(v,key=v.get)
    w=v[main]
    if w<THR: continue
    wp=w*(DEC**d)
    for nb in list(CGR.get(r,set()))+list(CG.get(r,set())):
        nv=VOTES[nb]
        if nv.get(main,0)<wp*0.4:
            nv[main]=wp*0.4
            if nb not in DEPTH:
                DEPTH[nb]=d+1; Q.append((nb,d+1)); cnt+=1

print(f"  Propagated: {cnt}")

# -- remaining --
for r,fn in FNS.items():
    if VOTES[r]: continue
    cl=fn['cl']; img_c=0
    for c in cl:
        v=VOTES.get(c,{})
        if v and max(v,key=v.get)=='IMGUI_RENDER': img_c+=1
    if img_c>=2 and len(cl)>=2: VOTES[r]['IMGUI_RENDER']=30.0
    else: VOTES[r]['UNKNOWN']=1.0

def mod_of(r):
    v=VOTES.get(r,{})
    if not v: return 'UNKNOWN'
    return max(v,key=v.get)

# -- naming --
def name_of(r,fn):
    m=mod_of(r); st=' '.join(fn['ss']).lower()
    ic=fn['ic']; cl=fn['cl']; ca=len(CGR.get(r,set()))
    
    # SC_FARMING
    if 'scactivityapc' in st: return "ScActivityAPC::ActivityCallback"
    if 'scloop' in st: return "ScActivityAPC::ScLoop"
    if 'midswap' in st: return "ScActivityAPC::MissionIdSwap"
    if ('batch' in st or 'firing' in st) and 'medal' in st: return "ScActivityAPC::FireMedalBatch"
    if ('batch' in st or 'firing' in st) and 'sc' in st: return "ScActivityAPC::FireSCBatch"
    if 'sync' in st and 'player' in st: return "ScActivityAPC::SyncPlayers"
    if 'cooldown' in st: return "ScActivityAPC::CooldownTimer"
    if 'goal' in st and 'sc' in st: return "ScActivityAPC::GoalChecker"
    if 'sc tracker' in st: return "ScActivityAPC::RenderSCTracker"
    if 'sc loop' in st: return "ScActivityAPC::RenderSCLoop"
    if 'sc goal' in st: return "ScActivityAPC::RenderSCGoal"
    if 'super credit' in st: return "ScActivityAPC::SuperCreditsUI"
    if 'add sample' in st: return "ScActivityAPC::AddSamplesUI"
    if 'sample' in st and 'reward' in st: return "ScActivityAPC::SampleRewardUI"
    if 'medal' in st: return "ScActivityAPC::MedalUI"
    if 'reduce aggro' in st: return "ScActivityAPC::ReduceAggroToggle"
    if 'zero perception' in st: return "ScActivityAPC::ZeroPerceptionToggle"
    if 'instant arrow' in st: return "ScActivityAPC::InstantArrowsToggle"
    if 'remove sc limit' in st: return "ScActivityAPC::RemoveSCLimitToggle"
    if 'queue' in st: return "ScActivityAPC::QueueSCCallback"
    if 'farming' in st and 'multiplier' in st: return "ScActivityAPC::RewardMultiplierUI"
    if 'farming' in st: return "ScActivityAPC::FarmingUI"
    if 'sc timer' in st: return "ScActivityAPC::SCTimerUI"
    if 'sc: ' in st: return "ScActivityAPC::SCLog"
    if 'mission reward' in st: return "ScActivityAPC::MissionRewardUI"
    if 'auto sync' in st: return "ScActivityAPC::AutoSync"
    if m=='SC_FARMING': return f"ScHelper_{r:06X}"
    
    # NETWORK
    if 'replay' in st and 'queued' in st: return "ReplayCapture::LogEntry"
    if 'replay' in st and 'log' in st: return "ReplayCapture::MissionLogRenderer"
    if 'storemission' in st: return "ReplayCapture::StoreMissionData"
    if 'buildpayload' in st: return "ReplayCapture::BuildPayload"
    if 'dispatch' in st: return "ReplayCapture::DispatchReplay"
    if 'golden' in st: return "ReplayCapture::GoldenCapture"
    if 'probe' in st and 'capture' in st: return "ReplayCapture::ProbeThread"
    if 'auto-replay' in st: return "ReplayCapture::AutoReplayLoop"
    if 'burst loop' in st and 'fire' in st: return "ReplayCapture::BurstLoopFire"
    if 'burst' in st and 'send' in st: return "ReplayCapture::BurstDispatch"
    if 'burst' in st and 'loop' in st: return "ReplayCapture::BurstLoop"
    if 'burst' in st and 'repl' in st: return "ReplayCapture::BurstHandler"
    if 'burst' in st: return "ReplayCapture::BurstUI"
    if 'watchdog' in st: return "ReplayCapture::Watchdog"
    if 'weaponstats' in st: return "ReplayCapture::SendWeaponStats"
    if 'weaponovr' in st: return "ReplayCapture::WeaponOverride"
    if 'allgun' in st: return "ReplayCapture::AllGunsCycle"
    if 'selectedgun' in st: return "ReplayCapture::SelectedGunsCycle"
    if 'replay' in st: return "ReplayCapture::ReplayUtil"
    if 'http' in st and 'swap' in st: return "HttpClient::MissionIdSwap"
    if 'http' in st and 'inject' in st: return "HttpClient::RequestInjector"
    if 'http' in st and 'setopt' in st: return "HttpClient::SetCurlOption"
    if 'http' in st and 'perform' in st: return "HttpClient::PerformRequest"
    if 'http' in st and 'body' in st: return "HttpClient::ReconBody"
    if 'http' in st and 'header' in st: return "HttpClient::ReconHeader"
    if 'http' in st and 'resp' in st: return "HttpClient::ReconResponse"
    if 'http' in st and 'found' in st: return "HttpClient::FindLibcurl"
    if 'http' in st and 'resolved' in st: return "HttpClient::ResolveCurl"
    if 'http' in st and 'clone' in st: return "HttpClient::CloneCurl"
    if 'http' in st: return "HttpClient::HttpHelper"
    if 'recon-' in st: return "HttpClient::ReconLogger"
    if 'mission/end' in st: return "HttpClient::MissionEndPost"
    if 'sig-capture' in st: return "HttpClient::SignatureCapture"
    if 'sig-chunk' in st: return "HttpClient::ChunkTracker"
    if 'call-site' in st: return "HttpClient::CallSiteAnalyzer"
    if m.startswith('NETWORK'): return f"NetHelper_{r:06X}"
    
    # WEAPON_XP
    if 'override' in st: return "WeaponXP::OverrideWeapon"
    if 'allgun' in st: return "WeaponXP::AllGunsRenderer"
    if 'selectedgun' in st: return "WeaponXP::SelectedGunsRenderer"
    if 'patch' in st: return "WeaponXP::PatchWeaponSlots"
    if 'rotate' in st or 'next weapon' in st: return "WeaponXP::RotateToNextWeapon"
    if 'xp tracker' in st: return "WeaponXP::XPTrackerRenderer"
    if m=='WEAPON_XP': return f"WeaponHelper_{r:06X}"
    
    # AUTH
    if 'lock screen' in st: return "AuthClient::RenderLockScreen"
    if 'login with' in st: return "AuthClient::RenderLoginForm"
    if 'enter your access key' in st: return "AuthClient::RenderKeyInput"
    if 'subscription active' in st: return "AuthClient::RenderSubscriptionInfo"
    if 'lifetime access' in st: return "AuthClient::CheckLifetimeAccess"
    if 'remaining' in st: return "AuthClient::FormatRemainingTime"
    if 'checking' in st: return "AuthClient::ValidateCredentials"
    if 'network error' in st: return "AuthClient::NetworkErrorHandler"
    if 'invalid key' in st: return "AuthClient::AccessDeniedHandler"
    if 'invalid username' in st: return "AuthClient::InvalidCredentialsHandler"
    if 'session expired' in st: return "AuthClient::SessionExpiredHandler"
    if 'hwid' in st: return "AuthClient::HardwareIdCollector"
    if 'discord' in st: return "AuthClient::DiscordLink"
    if 'credits' in st: return "AuthClient::CreditsRenderer"
    if m=='AUTH': return f"AuthHelper_{r:06X}"
    
    # HOOK_SYSTEM
    if 'install' in st: return "HookManager::InstallHook"
    if 'verify' in st: return "HookManager::VerifyHooks"
    if 'mismatch' in st: return "HookManager::DetectMismatch"
    if 'code cave' in st: return "HookManager::AllocateCodeCave"
    if 'call-site' in st: return "HookManager::AnalyzeCallSite"
    if 'function prologue' in st: return "HookManager::ValidatePrologue"
    if 'aob not found' in st: return "HookManager::ReportMissingAOB"
    if 'cave alloc' in st: return "HookManager::CaveAllocFailure"
    if 'handler install' in st: return "HookManager::HandlerFailure"
    if 'setup failed' in st: return "HookManager::SetupFailure"
    if '[features]' in st and 'found' in st: return "HookManager::FeatureFound"
    if '[features]' in st and 'not found' in st: return "HookManager::FeatureNotFound"
    if '[features]' in st and 'toggle' in st: return "HookManager::ToggleFeature"
    if '[features]' in st and 'layer' in st: return "HookManager::ProtectionLayer"
    if '[features]' in st and 'ntdll' in st: return "HookManager::NtdllHandle"
    if '[features]' in st: return "HookManager::FeatureLogger"
    if 'hook installed' in st: return "HookManager::InstallConfirmation"
    if m=='HOOK_SYSTEM': return f"HookHelper_{r:06X}"
    
    # PLAYER_CHEATS
    if 'god mode' in st: return "PlayerCheats::GodMode"
    if 'godmode' in st: return "PlayerCheats::GodModeRenderer"
    if 'stamina' in st: return "PlayerCheats::InfiniteStamina"
    if 'movement speed' in st: return "PlayerCheats::SpeedHackRenderer"
    if 'speed' in st: return "PlayerCheats::SpeedHack"
    if 'ragdoll' in st: return "PlayerCheats::NoRagdoll"
    if 'recoil' in st: return "PlayerCheats::NoRecoil"
    if 'player' in st: return "PlayerCheats::PlayerOptions"
    if m=='PLAYER_CHEATS': return f"PlayerHelper_{r:06X}"
    
    # COMBAT_CHEATS
    if 'infinite strat' in st: return "CombatCheats::InfiniteStratagems"
    if 'instant strat callin' in st: return "CombatCheats::InstantStratCallin"
    if 'mass strat' in st: return "CombatCheats::MassStratDrop"
    if 'turret overheat' in st: return "CombatCheats::NoTurretOverheat"
    if 'turret duration' in st: return "CombatCheats::InfTurretDuration"
    if 'expire all turret' in st: return "CombatCheats::ExpireAllTurrets"
    if 'inf ammo' in st: return "CombatCheats::InfiniteAmmo"
    if 'no reload' in st: return "CombatCheats::NoReload"
    if 'inf grenade' in st: return "CombatCheats::InfiniteGrenades"
    if 'inf stim' in st: return "CombatCheats::InfiniteStims"
    if 'instant charge' in st: return "CombatCheats::InstantCharge"
    if 'laser overheat' in st or 'no laser' in st: return "CombatCheats::NoLaserOverheat"
    if 'map hack' in st: return "CombatCheats::MapHack"
    if 'hoverpack' in st: return "CombatCheats::HoverpackControl"
    if 'instant shuttle' in st: return "CombatCheats::InstantShuttle"
    if 'instant complete' in st: return "CombatCheats::InstantComplete"
    if 'freeze mission timer' in st: return "CombatCheats::FreezeMissionTimer"
    if 'instant hellbomb' in st: return "CombatCheats::InstantHellbomb"
    if 'skip launch' in st: return "CombatCheats::SkipLaunchCode"
    if 'instant railgun' in st: return "CombatCheats::InstantRailgun"
    if 'grenade fuse' in st: return "CombatCheats::GrenadeFuseTime"
    if 'fast landing' in st: return "CombatCheats::FastLanding"
    if 'no boundary' in st: return "CombatCheats::NoBoundary"
    if 'longer hover' in st: return "CombatCheats::LongerHover"
    if 'shield cooldown' in st: return "CombatCheats::ShieldCooldown"
    if 'takeoff force' in st: return "CombatCheats::TakeoffForce"
    if 'dark fluid' in st: return "CombatCheats::DarkFluidPack"
    if 'instant arrows' in st: return "CombatCheats::InstantArrows"
    if 'instant coordinates' in st: return "CombatCheats::InstantCoordinates"
    if 'instant pipes' in st: return "CombatCheats::InstantPipes"
    if 'arcade combo' in st: return "CombatCheats::ArcadeCombo"
    if 'arcade round' in st: return "CombatCheats::InstantArcadeRound"
    if 'correct combo' in st: return "CombatCheats::CorrectCombo"
    if 'killstreak' in st: return "CombatCheats::KillstreakHandler"
    if 'eradication' in st: return "CombatCheats::EradicationEditor"
    if 'stratagem' in st: return "CombatCheats::StratagemUI"
    if 'turret' in st: return "CombatCheats::TurretUI"
    if 'grenade' in st: return "CombatCheats::GrenadeUI"
    if 'hover' in st or 'jump pack' in st: return "CombatCheats::HoverPackUI"
    if 'fov editor' in st: return "CombatCheats::FOVEditor"
    if 'combat' in st: return "CombatCheats::CombatOptions"
    if m=='COMBAT_CHEATS': return f"CombatHelper_{r:06X}"
    
    # ARMORY
    if 'unlock all' in st: return "Armory::UnlockAllArmory"
    if 'armor passive' in st: return "Armory::ArmorPassiveEditor"
    if 'weapon stats editor' in st: return "Armory::WeaponStatsEditor"
    if 'weapon editor' in st: return "Armory::WeaponEditorPopulate"
    if 'scan armor' in st: return "Armory::ScanArmor"
    if m=='ARMORY': return f"ArmoryHelper_{r:06X}"
    
    # IMGUI_RENDER
    if 'imgui' in st and '1.91' in st: return "ImGuiRenderer::VersionString"
    if 'overlay' in st: return "ImGuiRenderer::OverlayRenderer"
    if 'farming' in st: return "ImGuiRenderer::FarmingTab"
    if 'weapon' in st and 'xp' in st: return "ImGuiRenderer::WeaponXPTab"
    if 'super credit' in st: return "ImGuiRenderer::SCTab"
    if 'replay' in st: return "ImGuiRenderer::ReplayTab"
    if 'log' in st: return "ImGuiRenderer::LogsTab"
    if 'credit' in st: return "ImGuiRenderer::CreditsTab"
    if 'misc' in st: return "ImGuiRenderer::MiscTab"
    if 'update' in st: return "ImGuiRenderer::UpdatesTab"
    if 'liber' in st: return "ImGuiRenderer::TitleBar"
    if 'boost' in st or 'afk' in st: return "ImGuiRenderer::StatusBar"
    if 'l i b e r t e a' in st: return "ImGuiRenderer::CreditsRenderer"
    if 'feature' in st and 'active' in st: return "ImGuiRenderer::ActiveFeaturesFooter"
    if 'mode' in st: return "ImGuiRenderer::ModeToggle"
    if m=='IMGUI_RENDER': return f"ImGuiHelper_{r:06X}"
    
    # MEMORY
    if 'virtualprotect' in st: return "Memory::VirtualProtect"
    if 'syscall stub' in st: return "Memory::SyscallStubBuilder"
    if 'protection layer' in st: return "Memory::ProtectionLayers"
    if 'all layers failed' in st: return "Memory::AllLayersFailed"
    if m=='MEMORY': return f"MemHelper_{r:06X}"
    
    # PATTERN_SCAN
    if 'found' in st: return "PatternScanner::Found"
    if 'not found' in st: return "PatternScanner::NotFound"
    if m=='PATTERN_SCAN': return f"PatternHelper_{r:06X}"
    
    # CRASH_HANDLER
    if 'crash log' in st: return "CrashHandler::WriteCrashLog"
    if 'crashes absorbed' in st: return "CrashHandler::CrashCounter"
    if m=='CRASH_HANDLER': return f"CrashHelper_{r:06X}"
    
    # CRYPTO
    if 'machineguid' in st: return "Crypto::GetHardwareId"
    if 'bcrypt' in st: return "Crypto::HashData"
    if 'base64' in st: return "Crypto::Base64Codec"
    if m=='CRYPTO': return f"CryptoHelper_{r:06X}"
    
    # CONFIG
    if 'imgui.ini' in st: return "Config::ImGuiConfigLoader"
    if m=='CONFIG': return f"ConfigHelper_{r:06X}"
    
    # INIT
    if 'dllmain' in st: return "Init::DllMain"
    if 'helldivers' in st: return "Init::WaitForGameModule"
    if 'module' in st: return "Init::ModuleHelper"
    if 'wndproc' in st: return "Window::WndProc"
    if 'scpresent' in st: return "Window::ScPresentInstall"
    if 'hook installed' in st and '[p]' in st: return "Init::ProbeHookInstalled"
    if m=='INIT': return f"InitHelper_{r:06X}"
    
    # UPDATE
    if 'inbox' in st: return "UpdateSystem::InboxRenderer"
    if 'letter from' in st: return "UpdateSystem::MessageRenderer"
    if m=='UPDATE': return f"UpdateHelper_{r:06X}"
    
    # CRT_STL
    if m=='CRT_STL':
        if ic<=4: return f"Crt::Thunk_{r:06X}"
        return f"Crt::Func_{r:06X}"
    
    # UNKNOWN
    if ic<=5: return f"Leaf_{r:06X}"
    if ic<=15: return f"SmallUtil_{r:06X}"
    if ca>=10: return f"SharedUtil_{r:06X}"
    if ca>=3: return f"Helper_{r:06X}"
    return f"Func_{r:06X}"

# -- Final names --
for r,fn in FNS.items():
    fn['mod']=mod_of(r)
    fn['name']=name_of(r,fn)

# -- output --
print("Writing catalog...")
MC=Counter(); MS=Counter()
for fn in FNS.values(): MC[fn['mod']]+=1; MS[fn['mod']]+=fn['sz']

SF=sorted(FNS.items(),key=lambda x:(x[1]['mod'],x[1]['name'],x[0]))

with open(OUT,"w",encoding="utf-8") as f:
    f.write("="*100+"\n")
    f.write("  AGENT B: COMPLETE FUNCTION CATALOG\n")
    f.write(f"  Binary: .text_unpacked_mem.bin ({SZ} bytes)\n")
    f.write(f"  Total functions: {len(FNS)}\n")
    f.write("="*100+"\n\n")
    
    f.write("MODULE SUMMARY\n"+"-"*85+"\n")
    for mod in sorted(MC.keys()):
        f.write(f"  {mod:<25} {MC[mod]:>6} fns  ({MS[mod]:>10} bytes)\n")
    f.write("-"*85+"\n")
    f.write(f"  {'TOTAL':<25} {sum(MC.values()):>6} fns  ({sum(MS.values()):>10} bytes)\n")
    f.write(f"  Coverage: {sum(MS.values())*100/SZ:.1f}%\n")
    f.write("="*100+"\n\n")
    
    # Graph stats
    f.write("CALL GRAPH\n"+"-"*85+"\n")
    f.write(f"  Edges: {sum(len(v) for v in CG.values())}\n\n")
    f.write("  Most Called:\n")
    for r,ca in sorted(CGR.items(),key=lambda x:-len(x[1]))[:20]:
        n=FNS[r]['name'] if r in FNS else f"0x{r:06X}"
        f.write(f"    [0x{r:06X}] {len(ca):>4} callers -> {n}\n")
    f.write("\n  Largest:\n")
    for r,fn in sorted(FNS.items(),key=lambda x:-x[1]['sz'])[:20]:
        f.write(f"    [0x{r:06X}] {fn['sz']:>6}b -> [{fn['mod']}] {fn['name']}\n")
    f.write("="*100+"\n\n")
    
    # Detail
    f.write("DETAILED CATALOG\n"+"="*100+"\n\n")
    for r,fn in SF:
        name=fn['name']; mod=fn['mod']; sz=fn['sz']
        cl=fn['cl']; ss=fn['ss']; callers=sorted(CGR.get(r,set()))
        f.write(f"[0x{r:06X}] [{sz:>6}] [{mod}] {name}\n")
        if cl:
            shown=0
            for c in sorted(cl):
                if c in FNS and FNS[c]['mod'] not in ('UNKNOWN','CRT_STL'):
                    f.write(f"  -> [0x{c:06X}] {FNS[c]['name']}\n"); shown+=1
            for c in sorted(cl):
                if shown>=6: break
                if c not in FNS or FNS[c]['mod'] in ('UNKNOWN','CRT_STL'):
                    cn=FNS[c]['name'] if c in FNS else f"0x{c:06X}"
                    f.write(f"  -> [0x{c:06X}] {cn}\n"); shown+=1
            if len(cl)>shown: f.write(f"  ... +{len(cl)-shown} more\n")
        if callers:
            shown=0
            for clr in sorted(callers):
                if clr in FNS and FNS[clr]['mod'] not in ('UNKNOWN','CRT_STL'):
                    f.write(f"  <- [0x{clr:06X}] {FNS[clr]['name']}\n"); shown+=1
            for clr in sorted(callers):
                if shown>=6: break
                if clr not in FNS or FNS[clr]['mod'] in ('UNKNOWN','CRT_STL'):
                    cn=FNS[clr]['name'] if clr in FNS else f"0x{clr:06X}"
                    f.write(f"  <- [0x{clr:06X}] {cn}\n"); shown+=1
            if len(callers)>shown: f.write(f"  ... +{len(callers)-shown} more\n")
        if ss:
            uniq=list(dict.fromkeys(ss))
            f.write(f"  Strings: {', '.join(repr(s[:60]) for s in uniq[:5])}\n")
            if len(uniq)>5: f.write(f"           +{len(uniq)-5} more\n")
        f.write("\n")

print(f"\nDone! {len(FNS)} functions -> {OUT}")
print("\nModule breakdown:")
for mod,cnt in MC.most_common():
    print(f"  {mod:<25} {cnt:>6}")
print(f"  {'TOTAL':<25} {sum(MC.values()):>6}")
