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
    $str0 = "spread_network" nocase
    $str1 = "smb_exploit" nocase
    $str2 = "copy_self" nocase

    condition:
        2 of them
}
