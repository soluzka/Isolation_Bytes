/*
    YARA Rules - DLL Security and Tampering Detection
    Author: Security Team
    Description: Comprehensive detection rules for DLL tampering, suspicious ownership,
                 DLL hijacking, and related security threats
*/

rule DLL_Hijacking_Generic
{
    meta:
        author      = "Security Team"
        description = "Detects generic DLL hijacking and search order hijacking patterns"
        category    = "trojan"
        severity    = "high"
        date        = "2026-09-13"

    strings:
        // DLL loading patterns
        $load1 = "LoadLibrary" ascii wide nocase
        $load2 = "LoadLibraryEx" ascii wide nocase
        $load3 = "GetProcAddress" ascii wide nocase
        
        // Application directory and system directory manipulation
        $dir1 = "SetDllDirectory" ascii wide nocase
        $dir2 = "GetCurrentDirectory" ascii wide nocase
        $dir3 = "SetCurrentDirectory" ascii wide nocase
        $dir4 = "GetSystemDirectory" ascii wide nocase
        $dir5 = "GetWindowsDirectory" ascii wide nocase
        
        // Known DLL hijacking targets
        $target1 = "version.dll" ascii nocase
        $target2 = "shell32.dll" ascii nocase
        $target3 = "user32.dll" ascii nocase
        $target4 = "ntdll.dll" ascii nocase
        $target5 = "kernel32.dll" ascii nocase
        
        // PE file indicator
        $pe = { 4D 5A }

    condition:
        $pe and
        (
            (1 of ($load*) and 1 of ($dir*)) or
            (1 of ($load*) and 1 of ($target*)) or
            (2 of ($dir*) and 1 of ($load*))
        )
}

rule DLL_Sideloading_Attack
{
    meta:
        author      = "Security Team"
        description = "Detects DLL sideloading attacks commonly used by malware"
        category    = "trojan"
        severity    = "critical"
        date        = "2026-09-13"

    strings:
        // Process creation patterns
        $proc1 = "CreateProcess" ascii wide nocase
        $proc2 = "CreateProcessA" ascii wide nocase
        $proc3 = "CreateProcessW" ascii wide nocase
        $proc4 = "WinExec" ascii wide nocase
        
        // Environment manipulation
        $env1 = "SetEnvironmentVariable" ascii wide nocase
        $env2 = "GetEnvironmentVariable" ascii wide nocase
        $env3 = "PATH" ascii wide nocase
        $env4 = "SystemRoot" ascii wide nocase
        
        // Working directory manipulation
        $work1 = "lpCurrentDirectory" ascii wide nocase
        $work2 = "lpCommandLine" ascii wide nocase
        $work3 = "WorkingDirectory" ascii wide nocase
        
        // Common sideloading targets
        $side1 = "microsoft" ascii nocase
        $side2 = "office" ascii nocase
        $side3 = "adobe" ascii nocase
        $side4 = "java" ascii nocase
        $side5 = "chrome" ascii nocase
        
        // PE indicator
        $pe = { 4D 5A }

    condition:
        $pe and
        (
            (1 of ($proc*) and 1 of ($env*)) or
            (1 of ($proc*) and 1 of ($work*)) or
            (1 of ($proc*) and 1 of ($side*))
        )
}

rule DLL_Injection_Techniques
{
    meta:
        author      = "Security Team"
        description = "Detects various DLL injection techniques used by malware"
        category    = "trojan"
        severity    = "critical"
        date        = "2026-09-13"

    strings:
        // Classic DLL injection
        $inj1 = "VirtualAllocEx" ascii wide nocase
        $inj2 = "WriteProcessMemory" ascii wide nocase
        $inj3 = "CreateRemoteThread" ascii wide nocase
        $inj4 = "LoadLibrary" ascii wide nocase
        
        // Advanced injection techniques
        $adv1 = "NtCreateThreadEx" ascii wide nocase
        $adv2 = "RtlCreateUserThread" ascii wide nocase
        $adv3 = "QueueUserAPC" ascii wide nocase
        $adv4 = "NtQueueApcThread" ascii wide nocase
        
        // Reflective DLL injection
        $ref1 = "ReflectiveLoader" ascii wide nocase
        $ref2 = "ReflectiveInjection" ascii wide nocase
        $ref3 = "ManualMap" ascii wide nocase
        $ref4 = "MemoryModule" ascii wide nocase
        
        // Process manipulation
        $proc1 = "OpenProcess" ascii wide nocase
        $proc2 = "VirtualProtectEx" ascii wide nocase
        $proc3 = "GetModuleHandle" ascii wide nocase
        
        // PE indicator
        $pe = { 4D 5A }

    condition:
        $pe and
        (
            (3 of ($inj*)) or
            (1 of ($adv*) and 2 of ($inj*)) or
            (1 of ($ref*) and 2 of ($proc*))
        )
}

rule DLL_Phantom_DLL_Hijacking
{
    meta:
        author      = "Security Team"
        description = "Detects phantom DLL hijacking where malicious DLLs are created for missing dependencies"
        category    = "trojan"
        severity    = "high"
        date        = "2026-09-13"

    strings:
        // File creation patterns
        $file1 = "CreateFile" ascii wide nocase
        $file2 = "CreateFileW" ascii wide nocase
        $file3 = "WriteFile" ascii wide nocase
        $file4 = "CloseHandle" ascii wide nocase
        
        // Missing DLL indicators
        $miss1 = "not found" ascii wide nocase
        $miss2 = "cannot be located" ascii wide nocase
        $miss3 = "missing" ascii wide nocase
        $miss4 = "failed to load" ascii wide nocase
        
        // Error handling patterns
        $err1 = "GetLastError" ascii wide nocase
        $err2 = "SetLastError" ascii wide nocase
        $err3 = "FormatMessage" ascii wide nocase
        
        // System directories
        $sys1 = "System32" ascii wide nocase
        $sys2 = "SysWOW64" ascii wide nocase
        $sys3 = "Windows" ascii wide nocase
        
        // PE indicator
        $pe = { 4D 5A }

    condition:
        $pe and
        (
            (1 of ($file*) and 1 of ($miss*)) or
            (1 of ($file*) and 1 of ($sys*)) or
            (2 of ($file*) and 1 of ($err*))
        )
}

rule DLL_Comodo_Hijacking
{
    meta:
        author      = "Security Team"
        description = "Detects Comodo DLL hijacking attack patterns"
        category    = "trojan"
        severity    = "high"
        date        = "2026-09-13"

    strings:
        // Comodo-specific patterns
        $com1 = "comodo" ascii nocase
        $com2 = "cis" ascii nocase
        $com3 = "defense" ascii nocase
        $com4 = "security" ascii nocase
        
        // Vulnerable Comodo DLLs
        $vuln1 = "sld.dll" ascii nocase
        $vuln2 = "sbie.dll" ascii nocase
        $vuln3 = "sig" ascii nocase
        
        // Process elevation
        $elev1 = "RunAs" ascii wide nocase
        $elev2 = "UAC" ascii wide nocase
        $elev3 = "Administrator" ascii wide nocase
        
        // Registry manipulation
        $reg1 = "RegOpenKey" ascii wide nocase
        $reg2 = "RegSetValue" ascii wide nocase
        $reg3 = "RegCreateKey" ascii wide nocase
        
        // PE indicator
        $pe = { 4D 5A }

    condition:
        $pe and
        (
            (1 of ($com*) and 1 of ($vuln*)) or
            (1 of ($com*) and 1 of ($elev*)) or
            (1 of ($com*) and 1 of ($reg*))
        )
}

rule DLL_Persistence_Mechanisms
{
    meta:
        author      = "Security Team"
        description = "Detects DLL-based persistence mechanisms"
        category    = "trojan"
        severity    = "high"
        date        = "2026-09-13"

    strings:
        // Registry persistence
        $reg1 = "AppInit_DLLs" ascii wide nocase
        $reg2 = "LoadAppInit_DLLs" ascii wide nocase
        $reg3 = "RequireSignedAppInit_DLLs" ascii wide nocase
        $reg4 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" ascii wide nocase
        
        // Service persistence
        $svc1 = "ServiceMain" ascii wide nocase
        $svc2 = "StartServiceCtrlDispatcher" ascii wide nocase
        $svc3 = "RegisterServiceCtrlHandler" ascii wide nocase
        $svc4 = "CreateService" ascii wide nocase
        
        // Startup persistence
        $start1 = "RunOnce" ascii wide nocase
        $start2 = "RunServices" ascii wide nocase
        $start3 = "Startup" ascii wide nocase
        $start4 = "Common Startup" ascii wide nocase
        
        // Task scheduler
        $task1 = "TaskScheduler" ascii wide nocase
        $task2 = "CreateTrigger" ascii wide nocase
        $task3 = "SetActiveTrigger" ascii wide nocase
        
        // PE indicator
        $pe = { 4D 5A }

    condition:
        $pe and
        (
            (1 of ($reg*)) or
            (1 of ($svc*)) or
            (1 of ($start*)) or
            (1 of ($task*))
        )
}

rule DLL_AntiAnalysis_Techniques
{
    meta:
        author      = "Security Team"
        description = "Detects DLL-based anti-analysis and anti-debugging techniques"
        category    = "trojan"
        severity    = "medium"
        date        = "2026-09-13"

    strings:
        // Anti-debugging
        $debug1 = "IsDebuggerPresent" ascii wide nocase
        $debug2 = "CheckRemoteDebuggerPresent" ascii wide nocase
        $debug3 = "OutputDebugString" ascii wide nocase
        $debug4 = "DebugBreak" ascii wide nocase
        
        // Anti-VM
        $vm1 = "VMware" ascii wide nocase
        $vm2 = "VirtualBox" ascii wide nocase
        $vm3 = "QEMU" ascii wide nocase
        $vm4 = "Xen" ascii wide nocase
        $vm5 = "Hyper-V" ascii wide nocase
        
        // Anti-sandbox
        $sand1 = "sandbox" ascii wide nocase
        $sand2 = "analysis" ascii wide nocase
        $sand3 = "malware" ascii wide nocase
        $sand4 = "virustotal" ascii wide nocase
        
        // Timing attacks
        $time1 = "GetTickCount" ascii wide nocase
        $time2 = "QueryPerformanceCounter" ascii wide nocase
        $time3 = "RDTSC" ascii wide nocase
        
        // PE indicator
        $pe = { 4D 5A }

    condition:
        $pe and
        (
            (1 of ($debug*)) or
            (1 of ($vm*)) or
            (1 of ($sand*)) or
            (1 of ($time*))
        )
}

rule DLL_Evasion_Environment_Checks
{
    meta:
        author      = "Security Team"
        description = "Detects DLL-based environment checking for evasion"
        category    = "trojan"
        severity    = "medium"
        date        = "2026-09-13"

    strings:
        // System information gathering
        $sys1 = "GetComputerName" ascii wide nocase
        $sys2 = "GetUserName" ascii wide nocase
        $sys3 = "GetSystemInfo" ascii wide nocase
        $sys4 = "GetVersionEx" ascii wide nocase
        
        // Network checks
        $net1 = "GetAdaptersInfo" ascii wide nocase
        $net2 = "GetNetworkParams" ascii wide nocase
        $net3 = "IsNetworkAlive" ascii wide nocase
        
        // Language/country checks
        $lang1 = "GetLocaleInfo" ascii wide nocase
        $lang2 = "GetUserDefaultLangID" ascii wide nocase
        $lang3 = "GetSystemDefaultLangID" ascii wide nocase
        
        // Registry checks
        $reg1 = "RegQueryValueEx" ascii wide nocase
        $reg2 = "RegOpenKeyEx" ascii wide nocase
        $reg3 = "RegEnumKey" ascii wide nocase
        
        // PE indicator
        $pe = { 4D 5A }

    condition:
        $pe and
        (
            (2 of ($sys*)) or
            (1 of ($net*) and 1 of ($sys*)) or
            (1 of ($lang*) and 1 of ($reg*))
        )
}

rule DLL_Suspicious_Imports
{
    meta:
        author      = "Security Team"
        description = "Detects suspicious API imports commonly used by malicious DLLs"
        category    = "trojan"
        severity    = "high"
        date        = "2026-09-13"

    strings:
        // Network operations
        $net1 = "InternetOpen" ascii wide nocase
        $net2 = "InternetConnect" ascii wide nocase
        $net3 = "HttpSendRequest" ascii wide nocase
        $net4 = "InternetReadFile" ascii wide nocase
        $net5 = "WSAStartup" ascii wide nocase
        $net6 = "socket" ascii wide nocase
        $net7 = "connect" ascii wide nocase
        
        // Credential theft
        $cred1 = "CredEnumerate" ascii wide nocase
        $cred2 = "CredRead" ascii wide nocase
        $cred3 = "CryptUnprotectData" ascii wide nocase
        
        // Keylogging
        $key1 = "GetAsyncKeyState" ascii wide nocase
        $key2 = "GetKeyboardState" ascii wide nocase
        $key3 = "SetWindowsHookEx" ascii wide nocase
        $key4 = "GetKeyState" ascii wide nocase
        
        // Screen capture
        $scr1 = "BitBlt" ascii wide nocase
        $scr2 = "GetDC" ascii wide nocase
        $scr3 = "CreateCompatibleDC" ascii wide nocase
        
        // PE indicator
        $pe = { 4D 5A }

    condition:
        $pe and
        (
            (2 of ($net*)) or
            (1 of ($cred*)) or
            (1 of ($key*)) or
            (1 of ($scr*))
        )
}

rule DLL_Obfuscation_Techniques
{
    meta:
        author      = "Security Team"
        description = "Detects obfuscation techniques commonly used in malicious DLLs"
        category    = "trojan"
        severity    = "medium"
        date        = "2026-09-13"

    strings:
        // String encryption
        $enc1 = "XOR" ascii wide nocase
        $enc2 = "AES" ascii wide nocase
        $enc3 = "RC4" ascii wide nocase
        $enc4 = "CryptDecrypt" ascii wide nocase
        $enc5 = "CryptEncrypt" ascii wide nocase
        
        // Control flow obfuscation
        $flow1 = "JMP" ascii wide nocase
        $flow2 = "CALL" ascii wide nocase
        $flow3 = "RET" ascii wide nocase
        $flow4 = "PUSH" ascii wide nocase
        $flow5 = "POP" ascii wide nocase
        
        // Code packing
        $pack1 = "UPX" ascii wide nocase
        $pack2 = "aPLib" ascii wide nocase
        $pack3 = "PECompact" ascii wide nocase
        $pack4 = "ASPack" ascii wide nocase
        
        // Junk code
        $junk1 = "NOP" ascii wide nocase
        $junk2 = "INT3" ascii wide nocase
        $junk3 = "0xCC" ascii wide nocase
        
        // PE indicator
        $pe = { 4D 5A }

    condition:
        $pe and
        (
            (1 of ($enc*)) or
            (2 of ($flow*)) or
            (1 of ($pack*)) or
            (1 of ($junk*))
        )
}