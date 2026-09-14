/*
    YARA Rules - Microsoft Threat Detection
    Author: Security Team
    Description: Detection rules for Microsoft-specific threats including
                 SuspDllOwnship variants and related malware families.
                 Based on Microsoft Defender Intelligence.

    FP-hardening notes (2026-09-14):
    - SuspDllOwnship_ZA now requires ownership-tampering AND multi-API process
      injection AND a privilege-escalation string together — legitimate admin
      tools (unblock/quarantine code, ICacls, takeown.exe) only exercise one of
      these categories at a time so they no longer trigger this rule.
    - SuspDllOwnship_DA_PowerShell now requires a working DLL-manipulation call
      combined with ownership manipulation AND base64-obfuscated execution —
      plain Get-Acl / Set-Acl scripts won't match.
    - DLL_Tampering_Generic requires API + registry + filesystem evidence
      simultaneously; simple file-copy or quarantine moves won't match.
*/

rule SuspDllOwnship_ZA
{
    meta:
        author      = "Security Team"
        description = "Detects Trojan:Win32/SuspDllOwnship.ZA!MTB - Suspicious DLL ownership trojan"
        category    = "trojan"
        family      = "SuspDllOwnship"
        severity    = "critical"
        date        = "2026-09-14"
        reference   = "https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?name=Trojan%3AWin32%2FSuspDllOwnship.ZA%21MTB&threatid=2147967017"

    strings:
        // Ownership/permission modification (rare in legitimate binaries)
        $own1 = "SetSecurityInfo" ascii wide nocase
        $own2 = "SetNamedSecurityInfo" ascii wide nocase
        $own3 = "TakeOwnership" ascii wide nocase
        $own4 = "SeTakeOwnershipPrivilege" ascii wide nocase

        // Process injection — distinguishes malware from admin tools
        $inj1 = "VirtualAllocEx" ascii wide nocase
        $inj2 = "WriteProcessMemory" ascii wide nocase
        $inj3 = "CreateRemoteThread" ascii wide nocase
        $inj4 = "NtCreateThreadEx" ascii wide nocase
        $inj5 = "RtlCreateUserThread" ascii wide nocase

        // Privilege escalation
        $priv1 = "SeDebugPrivilege" ascii wide nocase
        $priv2 = "AdjustTokenPrivileges" ascii wide nocase

        // PE file indicator
        $pe = { 4D 5A }

    condition:
        // Requires PE + ownership tampering + multi-API injection + privilege escalation.
        // Legitimate unblock/quarantine/admin operations only hit one category,
        // so this combination is a strong malware signal.
        $pe and
        (1 of ($own*)) and
        (2 of ($inj*)) and
        (1 of ($priv*))
}

rule SuspDllOwnship_DA_PowerShell
{
    meta:
        author      = "Security Team"
        description = "Detects Trojan:PowerShell/SuspDllOwnship.DA!MTB - PowerShell-based DLL ownership trojan"
        category    = "trojan"
        family      = "SuspDllOwnship"
        severity    = "critical"
        date        = "2026-09-14"
        reference   = "https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:PowerShell/SuspDllOwnship.DA%21MTB"

    strings:
        // Must be a PowerShell context
        $ps1 = "powershell" ascii wide nocase
        $ps2 = "Add-Type" ascii nocase
        $ps3 = "Reflection.Assembly" ascii nocase

        // DLL manipulation via P/Invoke
        $dll_ps1 = "[System.Runtime.InteropServices.Marshal]" ascii nocase
        $dll_ps2 = "LoadLibrary" ascii nocase
        $dll_ps3 = "GetProcAddress" ascii nocase

        // Security/ownership manipulation
        $sec1 = "Set-Acl" ascii nocase
        $sec2 = "SetOwner" ascii nocase

        // Obfuscated execution — distinguishes malicious scripts from admin scripts
        $obf1 = "FromBase64String" ascii nocase
        $obf2 = "Invoke-Expression" ascii nocase
        $obf3 = "IEX" ascii nocase
        $obf4 = "[Convert]::FromBase64String" ascii nocase

    condition:
        // PowerShell context + DLL manipulation + ownership change + obfuscated execution
        (1 of ($ps*)) and
        (1 of ($dll_ps*)) and
        (1 of ($sec*)) and
        (1 of ($obf*))
}

rule DLL_Tampering_Generic
{
    meta:
        author      = "Security Team"
        description = "Detects generic DLL tampering and suspicious ownership modification"
        category    = "trojan"
        severity    = "high"
        date        = "2026-09-14"

    strings:
        // Remote process memory operations (injection-class)
        $api1 = "WriteProcessMemory" ascii wide nocase
        $api2 = "VirtualAllocEx" ascii wide nocase
        $api3 = "CreateRemoteThread" ascii wide nocase

        // Registry manipulation targeting DLL loading keys
        $reg1 = "AppInit_DLLs" ascii wide nocase
        $reg2 = "LoadAppInit_DLLs" ascii wide nocase
        $reg3 = "HKLM\\System\\CurrentControlSet" ascii wide nocase

        // File replacement operations
        $fs1 = "MoveFileEx" ascii wide nocase
        $fs2 = "ReplaceFile" ascii wide nocase
        $fs3 = ".dll" ascii nocase

        // PE header
        $pe = { 4D 5A }

    condition:
        // Requires all three categories: injection APIs + DLL-load registry key + file operations.
        // Simple quarantine/move operations only hit the filesystem category.
        $pe and
        (2 of ($api*)) and
        (1 of ($reg*)) and
        (1 of ($fs*))
}

rule PowerShell_Malware_Generic
{
    meta:
        author      = "Security Team"
        description = "Detects generic PowerShell malware patterns"
        category    = "trojan"
        severity    = "high"
        date        = "2026-09-14"

    strings:
        // Common malicious PowerShell execution patterns
        $mal1 = "Invoke-Expression" ascii nocase
        $mal2 = "IEX" ascii nocase
        $mal3 = "DownloadString" ascii nocase
        $mal4 = "WebClient" ascii nocase

        // Obfuscation techniques
        $obf1 = " -join " ascii nocase
        $obf2 = "([char]" ascii nocase
        $obf3 = "FromBase64String" ascii nocase

        // Execution bypass
        $bypass1 = "ExecutionPolicy" ascii nocase
        $bypass2 = "Bypass" ascii nocase
        $bypass3 = "Hidden" ascii nocase
        $bypass4 = "EncodedCommand" ascii nocase

    condition:
        // Needs both a download/exec pattern AND obfuscation or bypass
        (1 of ($mal*) and 1 of ($obf*)) or
        (1 of ($mal*) and 2 of ($bypass*))
}

rule Microsoft_Threat_Indicators
{
    meta:
        author      = "Security Team"
        description = "General indicators of Microsoft-specific threats"
        category    = "trojan"
        severity    = "medium"
        date        = "2026-09-14"

    strings:
        // Windows APIs commonly abused by malware
        $win1 = "CreateRemoteThread" ascii wide nocase
        $win2 = "OpenProcess" ascii wide nocase
        $win3 = "EnumProcesses" ascii wide nocase
        $win4 = "CreateToolhelp32Snapshot" ascii wide nocase

        // Credential theft patterns
        $cred1 = "CredEnumerate" ascii wide nocase
        $cred2 = "CryptUnprotectData" ascii wide nocase
        $cred3 = "lsass" ascii wide nocase
        $cred4 = "minidump" ascii wide nocase

        // Persistence mechanisms
        $pers1 = "RunOnce" ascii wide nocase
        $pers2 = "ScheduledTasks" ascii wide nocase

        // PE header
        $pe = { 4D 5A }

    condition:
        $pe and
        (
            (2 of ($win*) and 1 of ($cred*)) or
            (1 of ($win*) and 2 of ($pers*)) or
            (3 of ($win*))
        )
}
