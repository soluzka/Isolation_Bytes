rule Suspicious_PowerShell_Command {
    meta:
        description = "Detects suspicious PowerShell commands"
        author = "Isolation Bytes Fallback Rule Generator"
    strings:
        $s1 = "Invoke-Expression" nocase
        $s2 = "IEX" nocase
        $s3 = "Net.WebClient" nocase
        $s4 = "DownloadString" nocase
        $s5 = "hidden" nocase
        $s6 = "encodedcommand" nocase
        $s7 = "bypass" nocase
    condition:
        3 of them
}

rule Suspicious_System_Dll_Acl_Change {
    meta:
        description = "Detects commands that grant Administrators full control over core Windows DLLs"
        author = "Isolation Bytes"
    strings:
        $icacls = "icacls" nocase
        $advapi = "advapi32.dll" nocase
        $kernel = "kernel32.dll" nocase
        $ntdll = "ntdll.dll" nocase
        $grant = "/grant" nocase
        $admin = "Administrators:(F)" nocase
    condition:
        $icacls and $grant and $admin and 1 of ($advapi, $kernel, $ntdll)
}

rule Suspicious_Lolbin_Download_Or_Registration {
    meta:
        description = "Detects common Windows LOLBin download/registration indicators"
        author = "Isolation Bytes"
    strings:
        $certutil = "certutil" nocase
        $bitsadmin = "bitsadmin" nocase
        $rundll32 = "rundll32" nocase
        $regsvr32 = "regsvr32" nocase
        $mshta = "mshta" nocase
        $wmic = "wmic" nocase
        $url = "http://" nocase
        $https = "https://" nocase
        $urlcache = "/urlcache" nocase
        $transfer = "/transfer" nocase
    condition:
        1 of ($certutil, $bitsadmin, $rundll32, $regsvr32, $mshta, $wmic) and
        1 of ($url, $https, $urlcache, $transfer)
}
