/*
    AI-Improved YARA Rule
    Threat: ransomware
    Severity: critical
    Patterns learned: 1
    Last improved: 2026-08-20T05:19:36
*/

rule ai_improved_ransomware : critical
{
    strings:
    $str0 = "ransomware" nocase

    condition:
        any of them
}
