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
        // Suspicious script execution patterns
        $s1 = "powershell -exec bypass" ascii wide nocase
        $s2 = "cmd /c powershell" ascii wide nocase
        $s3 = "certutil -decode" ascii wide nocase
        $s4 = "bitsadmin /transfer" ascii wide nocase

    condition:
        // Require multiple suspicious execution patterns in a small file
        2 of ($s*) and filesize < 500KB
}
