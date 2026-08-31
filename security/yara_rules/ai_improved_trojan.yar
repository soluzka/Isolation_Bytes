/*
    AI-Improved YARA Rule
    Threat: trojan
    Severity: high
    Patterns learned: 3
    Last improved: 2026-08-20T05:41:22
*/

rule ai_improved_trojan : high
{
    strings:
        // Trojan-specific behavior indicators
        $t1 = "CreateRemoteThread" ascii
        $t2 = "VirtualAllocEx" ascii
        $t3 = "WriteProcessMemory" ascii
        $t4 = "NtUnmapViewOfSection" ascii
        $t5 = "SetWindowsHookEx" ascii
        $t6 = "GetAsyncKeyState" ascii
        // Process injection indicators
        $inj1 = "rundll32.exe" ascii wide nocase
        $inj2 = "regsvr32.exe /s" ascii wide nocase
        $inj3 = "powershell -enc" ascii wide nocase

    condition:
        // Require process injection APIs (strong trojan indicator) in a PE file
        ((3 of ($t1, $t2, $t3, $t4)) or
        // Or keylogging plus injection
        ($t5 and $t6 and 1 of ($inj*))) and
        uint16(0) == 0x5A4D
}
