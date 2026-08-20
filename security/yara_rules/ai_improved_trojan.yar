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
    $str0 = "learned_auto_trojan" nocase
    $str1 = "trojan" nocase
    $str2 = ".toc" nocase

    condition:
        2 of them
}
