/*
    AI-Improved YARA Rule
    Threat: ransomware
    Severity: critical
    Patterns learned: 6
    Last improved: 2026-08-20T05:41:22
*/

rule ai_improved_ransomware : critical
{
    strings:
    $str0 = "ransomware" nocase
    $str1 = "ai_improved_ransomware" nocase
    $str2 = ".toc" nocase
    $str3 = "learned_auto_ransomware" nocase
    $str4 = "Ransomware_Generic" nocase
    $str5 = "LockBit_Ransomware" nocase

    condition:
        2 of them
}
