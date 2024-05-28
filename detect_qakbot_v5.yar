rule detect_Qakbot_v5
{
    meta:
        description = "just a rule for Qakbot v5"
        author = "Mohamed Ezzat (@ZW01f)"
        hash1  = "af6a9b7e7aefeb903c76417ed2b8399b73657440ad5f8b48a25cfe5e97ff868f"
        hash2  = "59559e97962e40a15adb2237c4d01cfead03623aff1725616caeaa5a8d273a35"
    strings:
        $s1 = "\\u%04X\\u%04X" ascii wide
        $s2 = "%u;%u;%u" ascii wide 
        $s3 = "CfGetPlatformInfo" ascii wide
        $p1 = {45 33 C0 E8 ?? ?? ?? ?? 35 91 CB 35 A2 41 3B C7}
        $p2 = { 0F B6 01 48 FF C1 44 33 C0 41 8B C0 41 C1 E8 04 83 E0 0F 44 33 04 82 41 8B C0 41 C1 E8 04 83 E0 0F 44 33 04 82 49 83 E9 01 75 ?? 41 F7 D041 8B C0 C3}
    condition:
        uint16(0) == 0x5A4D and all of ($p*) and (2 of ($s*)) and filesize < 500KB
} 
