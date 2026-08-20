/*
    AI-Improved YARA Rule
    Threat: yara_match
    Severity: medium
    Patterns learned: 5
    Last improved: 2026-08-20T05:41:23
*/

rule ai_improved_yara_match : medium
{
    strings:
    $str0 = "FileSizeAnomaly" nocase
    $str1 = "yara_match" nocase
    $str2 = ".txt" nocase
    $str3 = ".cmd" nocase
    $str4 = ".ps1" nocase

    condition:
        2 of them
}
