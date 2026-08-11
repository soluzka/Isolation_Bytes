/*
    YARA Rules - RATs and Backdoors Detection
    Author: Anton Marinov (@AntonSMarinov)
    Description: Detection rules for Remote Access Trojans and backdoors including
                 Cobalt Strike, Metasploit, and common RAT families.
*/

rule Cobalt_Strike_Beacon
{
    meta:
        author      = "Anton Marinov"
        description = "Detects Cobalt Strike Beacon payloads"
        category    = "rats_backdoors"
        family      = "Cobalt Strike"
        severity    = "critical"
        date        = "2025-01-01"
        reference   = "https://www.cobaltstrike.com"

    strings:
        // Beacon config patterns
        $beacon1 = { 69 68 69 68 69 6B }
        $beacon2 = "beacon.dll" ascii wide nocase
        $beacon3 = "%s (admin)" ascii
        $beacon4 = "ReflectiveLoader" ascii

        // CS-specific strings
        $cs1 = "cobaltstrike" ascii wide nocase
        $cs2 = "Cobalt Strike" ascii wide
        $cs3 = "sleep_mask" ascii
        $cs4 = "MSSE-" ascii
        $cs5 = "post-ex" ascii

        // Malleable C2 artifacts
        $pipe1 = "\\\\.\\pipe\\MSSE-" ascii wide
        $pipe2 = "\\\\.\\pipe\\msagent_" ascii wide

    condition:
        (2 of ($beacon*)) or
        (2 of ($cs*)) or
        (1 of ($pipe*))
}

rule Metasploit_Meterpreter
{
    meta:
        author      = "Anton Marinov"
        description = "Detects Metasploit Meterpreter payloads"
        category    = "rats_backdoors"
        family      = "Metasploit"
        severity    = "critical"
        date        = "2025-01-01"

    strings:
        $s1 = "metsrv.dll" ascii wide nocase
        $s2 = "meterpreter" ascii wide nocase
        $s3 = "ReflectiveDll" ascii wide
        $s4 = "METERPRETER_TRANSPORT_TCP" ascii wide
        $s5 = "METERPRETER_TRANSPORT_HTTP" ascii wide
        $s6 = "stdapi_" ascii

        // Meterpreter-specific exports
        $exp1 = "Init" ascii
        $exp2 = "DllMain" ascii

        $sig = { 4D 5A 52 45 46 4C 45 43 54 49 56 45 44 4C 4C }

    condition:
        (2 of ($s*)) or ($sig and 1 of ($exp*))
}

rule AsyncRAT
{
    meta:
        author      = "Anton Marinov"
        description = "Detects AsyncRAT remote access trojan"
        category    = "rats_backdoors"
        family      = "AsyncRAT"
        severity    = "high"
        date        = "2025-01-01"

    strings:
        $s1 = "AsyncRAT" ascii wide nocase
        $s2 = "async-rat" ascii wide nocase
        $s3 = "Async-RAT" ascii wide
        $s4 = "Server.exe" ascii wide
        $s5 = "Pastebin" ascii wide nocase

        // AsyncRAT config keys
        $cfg1 = "Ports" ascii wide
        $cfg2 = "Hosts" ascii wide
        $cfg3 = "Version" ascii wide
        $cfg4 = "Install" ascii wide
        $cfg5 = "MTX" ascii wide
        $cfg6 = "Certificate" ascii wide

        // C# artifacts
        $cs1 = "get_Hosts" ascii
        $cs2 = "get_Ports" ascii

    condition:
        (2 of ($s*)) or
        (4 of ($cfg*)) or
        (1 of ($s*) and 3 of ($cfg*)) or
        (2 of ($cs*))
}

rule NjRAT
{
    meta:
        author      = "Anton Marinov"
        description = "Detects njRAT (Bladabindi) remote access trojan"
        category    = "rats_backdoors"
        family      = "njRAT"
        severity    = "high"
        date        = "2025-01-01"

    strings:
        $s1 = "njRAT" ascii wide nocase
        $s2 = "Bladabindi" ascii wide nocase
        $s3 = "|'|'|" ascii wide
        $s4 = "MS-DOS" ascii wide
        $s5 = "nj-q8" ascii wide nocase

        $cmd1 = "proc" ascii wide
        $cmd2 = "kl" ascii wide
        $cmd3 = "CAM" ascii wide
        $cmd4 = "rn" ascii wide

        $reg = "SOFTWARE\\njRAT" ascii wide nocase

    condition:
        (2 of ($s*)) or
        $reg or
        (1 of ($s*) and 3 of ($cmd*))
}

rule Generic_RAT_Indicators
{
    meta:
        author      = "Anton Marinov"
        description = "Detects generic RAT/backdoor behavior patterns"
        category    = "rats_backdoors"
        severity    = "high"
        date        = "2025-01-01"

    strings:
        // Keylogging
        $kl1 = "GetAsyncKeyState" ascii
        $kl2 = "SetWindowsHookEx" ascii
        $kl3 = "WH_KEYBOARD_LL" ascii

        // Screen capture
        $sc1 = "BitBlt" ascii
        $sc2 = "GetDesktopWindow" ascii
        $sc3 = "CreateCompatibleBitmap" ascii

        // Network beaconing
        $net1 = "InternetOpenUrl" ascii
        $net2 = "HttpSendRequest" ascii
        $net3 = "WSAStartup" ascii

        // Webcam
        $cam1 = "capCreateCaptureWindow" ascii
        $cam2 = "VideoCapture" ascii wide nocase

    condition:
        (2 of ($kl*)) or
        (2 of ($sc*) and 1 of ($net*)) or
        (1 of ($cam*) and 1 of ($net*) and 1 of ($kl*))
}

rule Cobalt_Strike_Strict
{
    meta:
        author      = "Patched"
        description = "Detects Cobalt Strike with multiple strong indicators"
        category    = "rats_backdoors"
        family      = "Cobalt Strike"
        severity    = "critical"
        date        = "2026-08-10"

    strings:
        $a = "cobaltstrike" ascii wide nocase
        $b = "beacon.dll" ascii wide
        $c = "ReflectiveLoader" ascii
        $d = "post-ex" ascii
        $e = "%s (admin)" ascii

    condition:
        4 of them
}
