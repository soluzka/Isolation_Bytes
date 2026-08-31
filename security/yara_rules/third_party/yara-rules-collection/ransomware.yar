/*
    YARA Rules - Ransomware Detection
    Author: Anton Marinov (@AntonSMarinov)
    Description: Detection rules for ransomware families including file encryption
                 routines, ransom note patterns, and known ransomware indicators.
*/

rule Generic_Ransomware_Indicators
{
    meta:
        author      = "Anton Marinov"
        description = "Detects generic ransomware behavior patterns"
        category    = "ransomware"
        severity    = "critical"
        date        = "2025-01-01"

    strings:
        // Ransom note keywords
        $note1 = "your files have been encrypted" ascii wide nocase
        $note2 = "all your files are encrypted" ascii wide nocase
        $note3 = "to decrypt your files" ascii wide nocase
        $note4 = "bitcoin" ascii wide nocase
        $note5 = "send payment" ascii wide nocase
        $note6 = "unique decryption key" ascii wide nocase
        $note7 = "YOUR_FILES_ARE_ENCRYPTED" ascii wide
        $note8 = "HOW_TO_DECRYPT" ascii wide nocase

        // Crypto API calls
        $crypt1 = "CryptEncrypt" ascii
        $crypt2 = "CryptGenKey" ascii
        $crypt3 = "CryptImportKey" ascii

        // File operations
        $file1 = "FindFirstFile" ascii
        $file2 = "FindNextFile" ascii

    condition:
        (2 of ($note*)) or
        (2 of ($crypt*) and 1 of ($file*))
}

rule LockBit_Ransomware
{
    meta:
        author      = "Anton Marinov"
        description = "Detects LockBit ransomware variants based on known indicators"
        category    = "ransomware"
        family      = "LockBit"
        severity    = "critical"
        date        = "2025-01-01"
        reference   = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a"

    strings:
        $s1 = "LockBit" ascii wide nocase
        $s2 = "Restore-My-Files.txt" ascii wide nocase
        $s3 = "lockbit" ascii wide nocase
        $s4 = ".lockbit" ascii wide

        // LockBit mutex patterns
        $mutex1 = "Global\\{" ascii
        $mutex2 = "AAAAAAAAAAAo" ascii

        // File extension patterns
        $ext1 = ".lockbit" ascii
        $ext2 = ".lock" ascii

    condition:
        2 of them
}

rule Conti_Ransomware
{
    meta:
        author      = "Anton Marinov"
        description = "Detects Conti ransomware based on known string patterns"
        category    = "ransomware"
        family      = "Conti"
        severity    = "critical"
        date        = "2025-01-01"
        reference   = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-265a"

    strings:
        $s1 = "CONTI_LOG.txt" ascii wide
        $s2 = "readme.txt" ascii wide nocase
        $s3 = "conti_v" ascii wide nocase
        $s4 = "www.contirecovery" ascii wide nocase

        // Conti-specific API usage
        $api1 = "EncryptFile" ascii
        $api2 = "GetLogicalDrives" ascii
        $api3 = "NetShareEnum" ascii

        // Shadow copy deletion
        $vss1 = "vssadmin.exe delete shadows" ascii wide nocase
        $vss2 = "wmic shadowcopy delete" ascii wide nocase

    condition:
        (2 of ($s*)) or
        ($vss1 or $vss2) or
        (2 of ($api*))
}

rule REvil_Sodinokibi_Ransomware
{
    meta:
        author      = "Anton Marinov"
        description = "Detects REvil/Sodinokibi ransomware indicators"
        category    = "ransomware"
        family      = "REvil"
        severity    = "critical"
        date        = "2025-01-01"

    strings:
        $s1 = "nssm.exe" ascii wide
        $s2 = "{EXT}-readme.txt" ascii wide
        $s3 = "decryptor.top" ascii wide nocase
        $s4 = "sodinokibi" ascii wide nocase

        $cfg1 = "\"pk\":" ascii
        $cfg2 = "\"pid\":" ascii
        $cfg3 = "\"sub\":" ascii
        $cfg4 = "\"dbg\":" ascii

        $vss = "vssadmin Delete Shadows /All /Quiet" ascii wide nocase

    condition:
        (3 of ($cfg*)) or
        (2 of ($s*)) or
        $vss
}

rule Ransomware_Shadow_Copy_Deletion
{
    meta:
        author      = "Anton Marinov"
        description = "Detects shadow copy deletion commands used by ransomware families"
        category    = "ransomware"
        severity    = "high"
        date        = "2025-01-01"

    strings:
        $s1 = "vssadmin.exe delete shadows" ascii wide nocase
        $s2 = "vssadmin delete shadows /all" ascii wide nocase
        $s3 = "wmic shadowcopy delete" ascii wide nocase
        $s4 = "wbadmin delete catalog" ascii wide nocase
        $s5 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $s6 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $s7 = "Get-WmiObject Win32_Shadowcopy" ascii wide nocase

    condition:
        2 of them
}
