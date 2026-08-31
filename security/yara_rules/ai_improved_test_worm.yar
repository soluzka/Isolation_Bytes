/*
    AI-Improved YARA Rule
    Threat: test_worm
    Severity: high
    Patterns learned: 3
    Last improved: 2026-08-20T05:33:28
*/

rule ai_improved_test_worm : high
{
    strings:
        // Worm propagation indicators
        $w1 = "WNetAddConnection2" ascii
        $w2 = "NetShareEnum" ascii
        $w3 = "CreateService" ascii
        // SMB/network spreading
        $s1 = "\\\\ADMIN$" ascii wide
        $s2 = "\\\\C$" ascii wide
        $s3 = "\\\\IPC$" ascii wide
        // Self-replication
        $r1 = "copy_self" ascii nocase
        $r2 = "spread_network" ascii nocase

    condition:
        // Require network sharing APIs plus SMB paths, in a PE file
        ((1 of ($w*) and 2 of ($s*)) or
        (2 of ($r*) and 1 of ($w*))) and
        uint16(0) == 0x5A4D
}
