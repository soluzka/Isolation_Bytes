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
        // LockBit-specific indicators
        $lockbit1 = "LockBit" ascii wide nocase
        $lockbit2 = "lockbit_black" ascii nocase
        $lockbit3 = "ABCD1234567890" ascii nocase

        // Ransom note filenames commonly used by LockBit
        $note1 = "Restore-My-Files.txt" ascii wide nocase
        $note2 = "LOCKBIT-README.txt" ascii wide nocase
        $note3 = "Restore-My-Files.htm" ascii wide nocase

        // Encryption-related API calls typical of ransomware
        $crypt1 = "CryptEncrypt" ascii
        $crypt2 = "BCryptEncrypt" ascii
        $crypt3 = "CryptGenKey" ascii

        // Ransom behavior indicators
        $ransom1 = "vssadmin delete shadows" ascii wide nocase
        $ransom2 = "wbadmin delete catalog" ascii wide nocase
        $ransom3 = "bcdedit /default" ascii wide nocase

    condition:
        // Require either LockBit-specific strings OR
        // ransom behavior commands plus encryption APIs
        // All conditions require a PE file
        ((2 of ($lockbit*) and 1 of ($note*)) or
        (2 of ($lockbit*) and 2 of ($crypt*)) or
        (1 of ($ransom*) and 2 of ($crypt*))) and
        uint16(0) == 0x5A4D
}
