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
