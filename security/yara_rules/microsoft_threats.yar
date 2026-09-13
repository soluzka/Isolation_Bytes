/*
    YARA Rules - Microsoft Threat Detection
    Author: Security Team
    Description: Detection rules for Microsoft-specific threats including
                 SuspDllOwnship variants and related malware families
                 Based on Microsoft Defender Intelligence
*/

rule SuspDllOwnship_ZA
{
    meta:
        author      = "Security Team"
        description = "Detects Trojan:Win32/SuspDllOwnship.ZA!MTB - Suspicious DLL ownership trojan"
        category    = "trojan"
        family      = "SuspDllOwnship"
        severity    = "critical"
        date        = "2026-09-13"
        reference   = "https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?name=Trojan%3AWin32%2FSuspDllOwnship.ZA!MTB&threatid=2147967017"

    strings:
        // DLL manipulation patterns
        $dll1 = "LoadLibrary" ascii wide nocase
        $dll2 = "GetProcAddress" ascii wide nocase
        $dll3 = "FreeLibrary" ascii wide nocase
        
        // Ownership/permission modification patterns
        $own1 = "SetSecurityInfo" ascii wide nocase
        $own2 = "SetNamedSecurityInfo" ascii wide nocase
        $own3 = "TakeOwnership" ascii wide nocase
        $own4 = "SetOwner" ascii wide nocase
        
        // Privilege escalation patterns
        $priv1 = "SeDebugPrivilege" ascii wide nocase
        $priv2 = "SeTakeOwnershipPrivilege" ascii wide nocase
        $priv3 = "AdjustTokenPrivileges" ascii wide nocase
        $priv4 = "LookupPrivilegeValue" ascii wide nocase
        
        // Process injection patterns
        $inj1 = "VirtualAllocEx" ascii wide nocase
        $inj2 = "WriteProcessMemory" ascii wide nocase
        $inj3 = "CreateRemoteThread" ascii wide nocase
        
        // PE file indicators
        $pe = { 4D 5A }  // MZ header

    condition:
        $pe and
        (
            (2 of ($dll*) and 2 of ($own*) and 2 of ($priv*)) or
            (2 of ($own*) and 2 of ($priv*) and 2 of ($inj*)) or
            (1 of ($own*) and 2 of ($inj*) and 1 of ($priv*))
        )
}

rule SuspDllOwnship_DA_PowerShell
{
    meta:
        author      = "Security Team"
        description = "Detects Trojan:PowerShell/SuspDllOwnship.DA!MTB - PowerShell-based DLL ownership trojan"
        category    = "trojan"
        family      = "SuspDllOwnship"
        severity    = "critical"
        date        = "2026-09-13"
        reference   = "https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan:PowerShell/SuspDllOwnship.DA!MTB"

    strings:
        // PowerShell indicators
        $ps1 = "# PowerShell" ascii nocase
        $ps2 = "powershell" ascii wide nocase
        $ps3 = "Add-Type" ascii nocase
        $ps4 = "Reflection.Assembly" ascii nocase
        
        // DLL manipulation via PowerShell
        $dll_ps1 = "[System.Runtime.InteropServices.Marshal]" ascii nocase
        $dll_ps2 = "LoadLibrary" ascii nocase
        $dll_ps3 = "GetProcAddress" ascii nocase
        
        // Security/ownership manipulation via PowerShell
        $sec1 = "Get-Acl" ascii nocase
        $sec2 = "Set-Acl" ascii nocase
        $sec3 = "SetOwner" ascii nocase
        $sec4 = "AccessRule" ascii nocase
        
        // WMI for persistence
        $wmi1 = "Get-WmiObject" ascii nocase
        $wmi2 = "Invoke-WmiMethod" ascii nocase
        $wmi3 = "Win32_Process" ascii nocase
        
        // Obfuscation patterns
        $obf1 = "Base64" ascii nocase
        $obf2 = "FromString" ascii nocase
        $obf3 = "ToCharArray" ascii nocase
        $obf4 = "Join-String" ascii nocase

    condition:
        (
            $ps1 or $ps2 or $ps3 or $ps4
        ) and
        (
            (1 of ($dll_ps*) and 1 of ($sec*) and 2 of ($obf*)) or
            (2 of ($sec*) and 1 of ($wmi*) and 2 of ($obf*)) or
            (1 of ($dll_ps*) and 2 of ($obf*) and 1 of ($wmi*))
        )
}

rule DLL_Tampering_Generic
{
    meta:
        author      = "Security Team"
        description = "Detects generic DLL tampering and suspicious ownership modification"
        category    = "trojan"
        severity    = "high"
        date        = "2026-09-13"

    strings:
        // DLL-related API calls
        $api1 = "WriteProcessMemory" ascii wide nocase
        $api2 = "VirtualProtect" ascii wide nocase
        $api3 = "VirtualAlloc" ascii wide nocase
        $api4 = "CreateFileMapping" ascii wide nocase
        $api5 = "MapViewOfFile" ascii wide nocase
        
        // Registry manipulation for DLL hijacking
        $reg1 = "RegSetValueEx" ascii wide nocase
        $reg2 = "RegCreateKey" ascii wide nocase
        $reg3 = "AppInit_DLLs" ascii wide nocase
        $reg4 = "System32" ascii wide nocase
        
        // File system operations
        $fs1 = "MoveFileEx" ascii wide nocase
        $fs2 = "CopyFile" ascii wide nocase
        $fs3 = "ReplaceFile" ascii wide nocase
        $fs4 = ".dll" ascii nocase
        
        // PE header
        $pe = { 4D 5A }

    condition:
        $pe and
        (
            (2 of ($api*) and 1 of ($reg*) and 1 of ($fs*)) or
            (1 of ($api*) and 2 of ($fs*) and 1 of ($reg*)) or
            (2 of ($reg*) and 1 of ($fs*) and 1 of ($api*))
        )
}

rule PowerShell_Malware_Generic
{
    meta:
        author      = "Security Team"
        description = "Detects generic PowerShell malware patterns"
        category    = "trojan"
        severity    = "high"
        date        = "2026-09-13"

    strings:
        // Common malicious PowerShell patterns
        $mal1 = "Invoke-Expression" ascii nocase
        $mal2 = "IEX" ascii nocase
        $mal3 = "DownloadString" ascii nocase
        $mal4 = "WebClient" ascii nocase
        $mal5 = "System.Net.WebClient" ascii nocase
        
        // Obfuscation techniques
        $obf1 = " -join " ascii nocase
        $obf2 = " -replace " ascii nocase
        $obf3 = " -split " ascii nocase
        $obf4 = "([char]" ascii nocase
        $obf5 = "[int]" ascii nocase
        
        // Encoding/decoding
        $enc1 = "FromBase64String" ascii nocase
        $enc2 = "ToBase64String" ascii nocase
        $enc3 = "UTF8.GetString" ascii nocase
        $enc4 = "ASCII.GetString" ascii nocase
        
        // Execution bypass
        $bypass1 = "Bypass" ascii nocase
        $bypass2 = "ExecutionPolicy" ascii nocase
        $bypass3 = "NoProfile" ascii nocase
        $bypass4 = "WindowStyle" ascii nocase
        $bypass5 = "Hidden" ascii nocase

    condition:
        (
            (1 of ($mal*) and 1 of ($obf*)) or
            (1 of ($mal*) and 1 of ($enc*)) or
            (2 of ($bypass*) and 1 of ($mal*))
        )
}

rule Microsoft_Threat_Indicators
{
    meta:
        author      = "Security Team"
        description = "General indicators of Microsoft-specific threats"
        category    = "trojan"
        severity    = "medium"
        date        = "2026-09-13"

    strings:
        // Windows-specific APIs commonly abused
        $win1 = "CreateRemoteThread" ascii wide nocase
        $win2 = "OpenProcess" ascii wide nocase
        $win3 = "EnumProcesses" ascii wide nocase
        $win4 = "CreateToolhelp32Snapshot" ascii wide nocase
        $win5 = "Process32First" ascii wide nocase
        $win6 = "Process32Next" ascii wide nocase
        
        // Credential theft patterns
        $cred1 = "CredEnumerate" ascii wide nocase
        $cred2 = "CredRead" ascii wide nocase
        $cred3 = "CredWrite" ascii wide nocase
        $cred4 = "lsass" ascii wide nocase
        $cred5 = "minidump" ascii wide nocase
        
        // Persistence mechanisms
        $pers1 = "RunOnce" ascii wide nocase
        $pers2 = "RunServices" ascii wide nocase
        $pers3 = "Startup" ascii wide nocase
        $pers4 = "Services" ascii wide nocase
        $pers5 = "ScheduledTasks" ascii wide nocase
        
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