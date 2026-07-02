import struct
BIN=r"C:\Users\emora\OneDrive\Desktop\2\data\.text_unpacked_mem.bin"
with open(BIN,"rb") as f: data=bytearray(f.read())

targets=[
    b"God Mode (Player Only)",
    b"Inf Stamina",
    b"No Ragdoll",
    b"No Recoil",
    b"Infinite Stratagems",
    b"No Turret Overheat",
    b"Inf Turret Duration",
    b"Instant Shuttle",
    b"Freeze Mission Timer",
    b"Map Hack",
    b"No Laser Overheat",
    b"Hoverpack Control",
    b"Infinite Ammo",
    b"No Reload",
    b"Infinite Grenades",
    b"Infinite Stims",
    b"Unlock All Armory",
    b"Armor Passive",
    b"Weapon Stats Editor",
    b"Instant Hellbomb",
    b"No Boundary",
    b"Fast Landing",
    b"Longer Hover",
    b"Correct Combo",
    b"Killstreak Bonus",
    b"Instant Railgun",
    b"Grenade Fuse",
    b"Crash Log",
    b"LIBERTEA CRASH",
    b"MachineGuid",
    b"Base64",
    b"FOV Editor",
    b"Dark Fluid",
    b"Instant Arrows",
    b"Instant Coordinates",
    b"Instant Pipes",
    b"Arcade Combo",
    b"Skip Launch",
    b"Reduce Aggro",
    b"Zero Perception",
    b"Shield Cooldown",
    b"Instant Charge",
    b"Mass Strat",
    b"Instant Arcade",
    b"Correct Combo",
    b"Takeoff Force",
    b"Killstreak",
]

for t in targets:
    found=False
    for idx in range(len(data)-len(t)):
        if data[idx:idx+len(t)]==t:
            if not found:
                print(f"  FOUND \"{t.decode()}\" at offsets:", end=" ")
                found=True
            print(f"0x{idx:06X}", end=" ")
    if found: print()
