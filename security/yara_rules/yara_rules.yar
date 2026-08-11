rule SuspiciousExecutable_Strict {
    meta:
        description = "Detects suspicious PE files with advanced and empowered indicators"
        author = "CascadeAI"
        ssdeep = "TODO:replace_with_ssdeep_hash"
        imphash = "TODO:replace_with_imphash"
        fuzzy_note = "Add ssdeep in meta and run external ssdeep comparison to enable fuzzy matching."
    strings:
        // PE header and packers
        $mz = {4D 5A}
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx2 = "UPX2"
        $aspack = "ASPack"
        $fsg = "FSG!"
        $mpress = "MPRESS1"
        $petite = "PEtite"
        $pecompact = "PECompact2"
        $themida = "Themida"
        $molebox = "MoleBox"
        $yoda = "yC"
        $execryptor = "ExeCryptor"
        $nsPack = "NsPack"
        $telock = "tElock"
        $armadillo = "Armadillo"
        $svkp = "SVKP"
        $upack = "Upack"
        $petite2 = "PEtite"
        $section1 = ".text"
        $section2 = ".rdata"
        $section3 = ".data"
        $section4 = ".rsrc"
        $section5 = ".UPX"
        $section6 = ".adata"
        $section7 = ".bss"
        $section8 = ".edata"
        $section9 = ".idata"
        $section10 = ".reloc"
        $section11 = ".tls"
        $section12 = ".pdata"
        $section13 = ".sdata"
        $section14 = ".writable"
        $section15 = ".shared"
        $rich = "Rich"
        $dosmode = "This program cannot be run in DOS mode"
        $padd = "PADDING"
        $mzpad = "MZPADDING"
        // Suspicious extensions
        $dll = ".dll"
        $exe = ".exe"
        $bat = ".bat"
        $scr = ".scr"
        $com = ".com"
        // Anti-debugging/anti-VM
        $antidbg1 = "IsDebuggerPresent"
        $antidbg2 = "CheckRemoteDebuggerPresent"
        $antidbg3 = "FindWindow"
        $antidbg4 = "OutputDebugString"
        $antidbg5 = "NtQueryInformationProcess"
        $antivm1 = "VBoxGuest"
        $antivm2 = "vmtoolsd.exe"
        $antivm3 = "vmware"
        $antivm4 = "qemu"
        $antivm5 = "VirtualBox"
        $antivm6 = "vbox"
        $antivm7 = "Xen"
        $antivm8 = "Parallels"
        $antivm9 = "Sandboxie"
        // Obfuscation and suspicious imports
        $obf1 = "VirtualAlloc"
        $obf2 = "VirtualProtect"
        $obf3 = "LoadLibrary"
        $obf4 = "GetProcAddress"
        $obf5 = "CreateRemoteThread"
        $obf6 = "WriteProcessMemory"
        $obf7 = "SetWindowsHookEx"
        $obf8 = "NtUnmapViewOfSection"
        $obf9 = "ZwUnmapViewOfSection"
        $obf10 = "RtlDecompressBuffer"
        $obf11 = "RtlDecompressMemory"
        $obf12 = "GetTickCount"
        $obf13 = "GetForegroundWindow"
        $obf14 = "GetAsyncKeyState"
        $obf15 = "RegOpenKeyEx"
        $obf16 = "RegSetValueEx"
        $obf17 = "RegCreateKeyEx"
        $obf18 = "RegDeleteKey"
        $obf19 = "NtSetInformationProcess"
        $obf20 = "NtSetInformationThread"
        // Malware-specific and generic suspicious strings
        $mal1 = "This file is packed"
        $mal2 = "malware"
        $mal3 = "trojan"
        $mal4 = "ransom"
        $mal5 = "keylogger"
        $mal6 = "botnet"
        $mal7 = "backdoor"
        $mal8 = "stealer"
        $mal9 = "inject"
        $mal10 = "payload"
        $mal11 = "shellcode"
        $mal12 = "decrypt"
        $mal13 = "encrypt"
        $mal14 = "bitcoin"
        $mal15 = "command and control"
        $mal16 = "C2"
        $mal17 = "exfiltrate"
        $mal18 = "persistence"
        $mal19 = "autorun"
        $mal20 = "startup"
        // More can be added for even greater empowerment
    condition:
        $mz at 0 and
        5 of ($section*, $rich, $dosmode, $dll, $exe, $bat, $scr, $com) and
        (
            (3 of ($antidbg*, $antivm*, $mal*) and (2 of ($antivm*) or 1 of ($antidbg2, $antidbg4, $antidbg5))) or
            (1 of ($upx*, $aspack, $fsg, $mpress, $petite*, $pecompact, $themida, $molebox, $yoda, $execryptor, $nsPack, $telock, $armadillo, $svkp, $upack, $padd, $mzpad) and 2 of ($antidbg*, $antivm*, $obf*, $mal*))
        )
}

// NOTE: this rule's header (rule NAME { ... strings:) was missing in the
// original file -- the block below was a strings:/condition: pair with no
// preceding rule declaration, which failed to compile. Reconstructed with a
// name matching its content (suspicious API imports + executable extensions).
rule Suspicious_PE_API_Imports {
    meta:
        description = "Detects multiple suspicious Windows API imports commonly used by malware"
    strings:
        $mz = {4D 5A}
        $susp1 = "CreateRemoteThread"
        $susp2 = "WriteProcessMemory"
        $susp3 = "SetWindowsHookEx"
        $susp4 = "NtUnmapViewOfSection"
        $susp5 = "ZwUnmapViewOfSection"
        $susp6 = "IsDebuggerPresent"
        $susp7 = "FindWindow"
        $susp8 = "GetAsyncKeyState"
    condition:
        $mz at 0 and 3 of ($susp1, $susp2, $susp3, $susp4, $susp5, $susp6, $susp7, $susp8)
}

rule Suspicious_PowerShell_Strict {
    meta:
        description = "Detects a wide range of suspicious PowerShell commands and obfuscation"
        author = "CascadeAI"
        ssdeep = "TODO:replace_with_ssdeep_hash"
        imphash = "TODO:replace_with_imphash"
        fuzzy_note = "Add ssdeep in meta and run external ssdeep comparison to enable fuzzy matching."
    strings:
        $cmd1 = "Invoke-Expression"
        $cmd2 = "IEX"
        $cmd3 = "DownloadString"
        $cmd4 = "New-Object Net.WebClient"
        $cmd5 = "FromBase64String"
        $cmd6 = "Add-MpPreference"
        $cmd7 = "Set-MpPreference"
        $cmd8 = "Bypass"
        $cmd9 = "Hidden"
        $cmd10 = "Start-BitsTransfer"
        $cmd11 = "Invoke-WebRequest"
        $cmd12 = "Invoke-Shellcode"
        $cmd13 = "System.Reflection.Assembly"
        $cmd14 = "ConvertTo-SecureString"
        $cmd15 = "Unrestricted"
        $cmd16 = "powershell.exe -enc"
        $cmd17 = "powershell.exe -nop"
        $cmd18 = "Set-ExecutionPolicy"
        $cmd19 = "iex (New-Object Net.WebClient).DownloadString"
        $cmd20 = "Invoke-Obfuscation"
        $cmd21 = "Invoke-Mimikatz"
        $cmd22 = "Invoke-ReflectivePEInjection"
        $cmd23 = "Invoke-PSInject"
        $cmd24 = "Invoke-TokenManipulation"
        $cmd25 = "Invoke-BypassUAC"
        $cmd26 = "Invoke-DllInjection"
        $cmd27 = "Invoke-RunAs"
        $cmd28 = "Invoke-WmiMethod"
        $cmd29 = "Invoke-ProcessShellcode"
        $cmd30 = "Invoke-AMSIBypass"
        $cmd31 = "Invoke-EventVwrBypass"
        $cmd32 = "Invoke-PowerShellIcmp"
        $cmd33 = "Invoke-PowerShellTcp"
        $cmd34 = "Invoke-PowerShellUdp"
        $cmd35 = "Invoke-PSRemoting"
        $cmd36 = "Invoke-PSExec"
        $cmd37 = "Invoke-PSReverseShell"
        $cmd38 = "Invoke-PSBindShell"
        $cmd39 = "Invoke-PSDownload"
        $cmd40 = "Invoke-PSUpload"
        $cmd41 = "Invoke-ReflectivePEInjection"
        $cmd42 = "Invoke-Phant0m"
        $cmd43 = "Invoke-TokenManipulation"
        $cmd44 = "Invoke-WScriptBypassUAC"
        $cmd45 = "Invoke-RunAs"
        $cmd46 = "Invoke-PSInject"
        $cmd47 = "Invoke-PSImage"
        $cmd48 = "Invoke-PSGcat"
        $cmd49 = "Invoke-PSJaws"
        $cmd50 = "Invoke-PSPersist"
        $cmd51 = "Invoke-PSRecon"
        $cmd52 = "Invoke-PowerShellTcp"
        $cmd53 = "Invoke-PowerShellUdp"
        $cmd54 = "Invoke-Obfuscation"
        $cmd55 = "Invoke-CredentialInjection"
        $cmd56 = "Invoke-ADSBackdoor"
        $cmd57 = "Invoke-EventVwrBypass"
        $cmd58 = "Invoke-PSRemoting"
        $cmd59 = "Invoke-PSExec"
        $cmd60 = "Invoke-PSReverseShell"
        $cmd61 = "Invoke-PSBindShell"
        $cmd62 = "Invoke-PSDownload"
        $cmd63 = "Invoke-PSUpload"
        $cmd64 = "Invoke-PSGcat"
        $cmd65 = "Invoke-PSJaws"
        $cmd66 = "Invoke-PSPersist"
        $cmd67 = "Invoke-PSRecon"
        $cmd68 = "Invoke-TokenManipulation"
        $cmd69 = "Invoke-WScriptBypassUAC"
        $cmd70 = "Invoke-ReflectivePEInjection"
        $cmd71 = "Invoke-Phant0m"
        $cmd72 = "Invoke-PSImage"
        $cmd73 = "Invoke-CredentialInjection"
        $cmd74 = "Invoke-ADSBackdoor"
        $cmd75 = "Invoke-Obfuscation"
        $cmd76 = "Invoke-EventVwrBypass"
        $cmd77 = "Invoke-PSRemoting"
        $cmd78 = "Invoke-PSExec"
        $cmd79 = "Invoke-PSReverseShell"
        $cmd80 = "Invoke-PSBindShell"
        $cmd81 = "Invoke-PSDownload"
        $cmd82 = "Invoke-PSUpload"
        $cmd83 = "powershell -w hidden"
        $cmd84 = "powershell -nop"
        $cmd85 = "powershell -ep bypass"
        $cmd86 = "powershell -enc"
        $cmd87 = "powershell -e"
        $cmd88 = "powershell -NoP -NonI -W Hidden -Enc"
        $cmd89 = "cmd /c powershell"
        $cmd90 = "cmd.exe /c powershell"
        $cmd91 = "iex (iwr"
        $cmd92 = "[System.Text.Encoding]::UTF8.GetString"
        $cmd93 = "[System.Convert]::FromBase64String"
        $cmd94 = "[System.Reflection.Assembly]::Load"
        $cmd95 = "[System.IO.MemoryStream]"
        $cmd96 = "[System.Management.Automation.PSCredential]"
        $cmd97 = "[System.Diagnostics.Process]"
        $cmd98 = "[System.Net.WebClient]"
        $cmd99 = "[System.Net.ServicePointManager]"
        $cmd100 = "[System.Security.Cryptography]"
    condition:
        8 of them
}

rule EICAR_Test_File_Strict {
    meta:
        description = "Strict detection of the EICAR antivirus test file and variants"
        author = "CascadeAI"
    strings:
        $eicar1 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        $eicar2 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"
        $eicar3 = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        $eicar4 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}"
        $eicar5 = "H+H*"
        $eicar6 = "X5O!P%@AP[4\\PZX54(P^)7CC)7}"
    condition:
        3 of them
}

// Additional empowered rules for generic and fileless malware, droppers, macro exploits, and more can be added below as needed for full coverage.


rule EICAR_Test_File {
    meta:
        description = "Detects the EICAR antivirus test file"
        author = "CascadeAI"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

// === Broad Coverage Expansion ===

rule Emotet_Banking_Trojan {
    meta:
        description = "Detects Emotet banking trojan"
        author = "CascadeAI"
    strings:
        $str1 = "emotet"
        $str2 = "E5B8A8C4"
        $str3 = "client_id="
        $str4 = "POST /load.php"
        $url1 = "hxxp://emotet.xyz"
        $mutex1 = "Global\\Emotet"
        $dll1 = "emotet.dll"
        $exe1 = "emotet.exe"
        $reg1 = "SOFTWARE\\Emotet"
        $c2_1 = "185.62.188.88"
        $c2_2 = "185.234.219.167"
        $c2_3 = "185.234.219.168"
        // ...add dozens more
    condition:
        3 of them
}

rule Trickbot_Banking_Trojan {
    meta:
        description = "Detects Trickbot banking trojan"
        author = "CascadeAI"
    strings:
        $str1 = "trickbot"
        $str2 = "client_id="
        $str3 = "module=injectDll"
        $str4 = "POST /dpost.php"
        $url1 = "hxxp://trickbot.xyz"
        $mutex1 = "Global\\Trickbot"
        $dll1 = "trickbot.dll"
        $exe1 = "trickbot.exe"
        $reg1 = "SOFTWARE\\Trickbot"
        $c2_1 = "91.219.236.179"
        $c2_2 = "185.234.219.191"
        // ...add more
    condition:
        3 of them
}

rule CobaltStrike_Beacon {
    meta:
        description = "Detects Cobalt Strike beacon payloads"
        author = "CascadeAI"
    strings:
        $str1 = "Cobalt Strike"
        $str2 = "Beacon"
        $str3 = "Malleable_C2"
        $str4 = "x86/shikata_ga_nai"
        $str5 = "Process Injection"
        $str6 = "ReflectiveLoader"
        $url1 = "cobaltstrike.com"
        $payload1 = { fc e8 89 00 00 00 60 89 e5 31 c0 64 8b 50 30 }
        // ...add more
    condition:
        3 of them
}

rule LOLBins_Generic {
    meta:
        description = "Detects suspicious use of LOLBins"
        author = "CascadeAI"
    strings:
        $certutil = "certutil.exe"
        $mshta = "mshta.exe"
        $regsvr32 = "regsvr32.exe"
        $rundll32 = "rundll32.exe"
        $wmic = "wmic.exe"
        $bitsadmin = "bitsadmin.exe"
        $schtasks = "schtasks.exe"
        $cmd = "cmd.exe"
        $powershell = "powershell.exe"
        $forfiles = "forfiles.exe"
        $cscript = "cscript.exe"
        $wscript = "wscript.exe"
        $msbuild = "msbuild.exe"
        $installutil = "installutil.exe"
        $mavinject = "mavinject.exe"
        // ...add more
    condition:
        3 of them
}

rule Suspicious_Document_Macros {
    meta:
        description = "Detects suspicious macro-enabled Office documents"
        author = "CascadeAI"
    strings:
        $vba1 = "AutoOpen"
        $vba2 = "Document_Open"
        $vba3 = "Shell("
        $vba4 = "CreateObject"
        $vba5 = "WScript.Shell"
        $vba6 = "PowerShell"
        $vba7 = "GetObject"
        $vba8 = "Environ("
        $vba9 = "Base64String"
        $vba10 = "ThisWorkbook"
        $vba11 = "DDE"
        $vba12 = "cmd.exe"
        $vba13 = "regsvr32"
        $vba14 = "mshta"
        $vba15 = "bitsadmin"
        // ...add more
    condition:
        3 of them
}

rule Process_Injection_Generic {
    meta:
        description = "Detects generic process injection techniques"
        author = "CascadeAI"
    strings:
        $api1 = "VirtualAllocEx"
        $api2 = "WriteProcessMemory"
        $api3 = "CreateRemoteThread"
        $api4 = "NtUnmapViewOfSection"
        $api5 = "ZwUnmapViewOfSection"
        $api6 = "SetThreadContext"
        $api7 = "GetThreadContext"
        $api8 = "ResumeThread"
        $api9 = "QueueUserAPC"
        $api10 = "OpenProcess"
        // ...add more
    condition:
        3 of them
}

rule Credential_Dumping_Generic {
    meta:
        description = "Detects credential dumping techniques"
        author = "CascadeAI"
    strings:
        $lsass = "lsass.exe"
        $sekurlsa = "sekurlsa.dll"
        $mimikatz = "mimikatz"
        $procdump = "procdump"
        $out1 = "sekurlsa::logonpasswords"
        $out2 = "Invoke-Mimikatz"
        $out3 = "DumpCreds"
        $out4 = "MiniDump"
        $out5 = "NTLM"
        $out6 = "WDigest"
        // ...add more
    condition:
        3 of them
}

rule Persistence_Autorun_Generic {
    meta:
        description = "Detects persistence via autorun and registry"
        author = "CascadeAI"
    strings:
        $reg1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $reg2 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $reg3 = "CurrentVersion\\RunOnce"
        $reg4 = "CurrentVersion\\Policies\\Explorer\\Run"
        $reg5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices"
        $reg6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"
        $schtasks = "schtasks.exe"
        $startup = "Startup"
        $taskschd = "taskschd.msc"
        // ...add more
    condition:
        3 of them
}

// ...additional rules for Dridex, QakBot, AgentTesla, LokiBot, AZORult, NanoCore, Remcos, Cobalt Strike, REvil, Ryuk, Dharma, Maze, LockBit, GandCrab, Sodinokibi, etc. can be added in this same format for maximum coverage.


rule Suspicious_PowerShell {
    meta:
        description = "Detects suspicious PowerShell commands"
        severity = "high"
    strings:
        $cmd1 = "Invoke-Expression"
        $cmd2 = "IEX"
        $cmd3 = "DownloadString"
    condition:
        2 of ($cmd*)
}

rule Generic_Malware_Strings {
    meta:
        description = "Detects generic malware-related strings"
    strings:
        $str1 = "cmd.exe"
        $str2 = "powershell.exe"
        $str3 = "vssadmin delete shadows"
        $str4 = "rundll32"
        $str5 = "Mimikatz"
        $str6 = "net user"
        $str7 = "systeminfo"
        $str8 = "schtasks"
        $str9 = "certutil"
        $str10 = "bypass"
    condition:
        3 of ($str*) and filesize < 200KB
}

rule Ransomware_Indicators {
    meta:
        description = "Detects common ransomware extension and note patterns"
    strings:
        $note1 = "Your files have been encrypted"
        $note2 = "How to recover your files"
        $ext1 = ".locked"
        $ext2 = ".encrypted"
        $ext3 = ".crypt"
        $ext4 = ".ransom"
    condition:
        (2 of ($note*) or 2 of ($ext*)) and filesize < 200KB
}

rule Packed_Executable_UPX {
    meta:
        description = "Detects UPX packed executables"
    strings:
        $upx = "UPX!"
    condition:
        $upx
}

rule Exploit_Macro_Documents {
    meta:
        description = "Detects suspicious macro keywords in Office documents"
    strings:
        $macro1 = "AutoOpen"
        $macro2 = "Shell.Application"
        $macro3 = "CreateObject"
        $macro4 = "WScript.Shell"
    condition:
        2 of ($macro*)
}

rule Suspicious_Network_Connections {
    meta:
        description = "Detects suspicious network-related commands"
    strings:
        $net1 = "ftp://"
        $net2 = "http://"
        $net3 = "https://"
        $net4 = "wget"
        $net5 = "curl"
        $net6 = "Invoke-WebRequest"
    condition:
        2 of ($net*)
}

rule Keylogger_Indicators {
    meta:
        description = "Detects common keylogger strings"
    strings:
        $key1 = "GetAsyncKeyState"
        $key2 = "SetWindowsHookEx"
        $key3 = "keylog"
    condition:
        2 of ($key*)
}

rule Reverse_Shell_Indicators {
    meta:
        description = "Detects common reverse shell commands and patterns"
    strings:
        $rev1 = "nc -e"
        $rev2 = "bash -i >& /dev/tcp/"
        $rev3 = "powershell -nop -c"
        $rev4 = "/bin/sh -i"
    condition:
        2 of ($rev*)
}

rule Suspicious_JS_Script {
    meta:
        description = "Detects suspicious JavaScript patterns"
    strings:
        $eval = "eval("
        $unescape = "unescape("
        $fromCharCode = "String.fromCharCode"
        $wscript = "WScript.Shell"
    condition:
        2 of ($*)
}

rule Suspicious_VBS_Script {
    meta:
        description = "Detects suspicious VBScript patterns"
    strings:
        $shell = "CreateObject(\"WScript.Shell\")"
        $run = "Shell.Run"
        $base64 = "base64decode"
    condition:
        2 of ($*)
}

rule Suspicious_Batch_File {
    meta:
        description = "Detects suspicious batch file commands"
    strings:
        $del = "del /F /Q"
        $attrib = "attrib +h +s"
        $reg = "reg add"
        $schtasks = "schtasks /create"
        $powershell = "powershell -"
    condition:
        2 of ($*)
}

rule PDF_Exploit_Indicators {
    meta:
        description = "Detects common PDF exploit patterns"
    strings:
        $js = "/JavaScript"
        $openaction = "/OpenAction"
        $launch = "/Launch"
        $aa = "/AA"
        $embedded = "/EmbeddedFile"
    condition:
        2 of ($*)
}

rule Office_Macro_Malware {
    meta:
        description = "Detects Office macro malware keywords"
    strings:
        $autoopen = "AutoOpen"
        $autorun = "Auto_Run"
        $powershell = "powershell"
        $cmd = "cmd.exe"
        $wscript = "WScript.Shell"
        $createobject = "CreateObject"
    condition:
        not uint16(0) == 0x5A4D and 2 of ($*) and filesize < 500KB
}

rule PE_Suspicious_Imports {
    meta:
        description = "Detects PE files with suspicious imports"
    strings:
        $virtualalloc = "VirtualAlloc"
        $writeprocess = "WriteProcessMemory"
        $createremotethread = "CreateRemoteThread"
        $getprocaddress = "GetProcAddress"
        $loadlibrary = "LoadLibraryA"
        $wsasocket = "WSASocketA"
    condition:
        2 of ($*)
}

rule Packed_Obfuscated_Executable {
    meta:
        description = "Detects packed or obfuscated executables (UPX, ASPack, etc)"
    strings:
        $upx = "UPX0"
        $aspack = ".aspack"
        $petite = ".petite"
        $fsg = ".FSG!"
    condition:
        2 of ($*)
}

rule Credential_Dumper_Indicators {
    meta:
        description = "Detects credential dumping tools and techniques"
    strings:
        $mimikatz = "mimikatz"
        $lsass = "lsass.exe"
        $sekurlsa = "sekurlsa::logonpasswords"
        $procdump = "procdump"
    condition:
        2 of ($*)
}

rule Dropper_Indicators {
    meta:
        description = "Detects dropper malware behaviors"
    strings:
        $drop1 = "WriteFile"
        $drop2 = "CreateFile"
        $drop3 = "URLDownloadToFile"
        $drop4 = "WinExec"
    condition:
        2 of ($*)
}

rule Exploit_Payloads {
    meta:
        description = "Detects common exploit payload patterns (Meterpreter, shellcode)"
    strings:
        $met1 = "Meterpreter"
        $met2 = "reverse_tcp"
        $buf = "\x90\x90\x90\x90"
        $cmd = "cmd.exe /c"
    condition:
        2 of ($*)
}

rule Emotet_Malware {
    meta:
        description = "Detects Emotet banking trojan"
    strings:
        $str1 = "E5D7A7F6"
        $str2 = "client_hello"
        $str3 = "emotet"
        $str4 = "outlook.exe"
    condition:
        2 of ($*)
}

rule TrickBot_Malware {
    meta:
        description = "Detects TrickBot banking trojan"
    strings:
        $str1 = "tabDll32"
        $str2 = "client_id"
        $str3 = "group_tag"
        $str4 = "TrickBot"
    condition:
        2 of ($*)
}

rule Ryuk_Ransomware {
    meta:
        description = "Detects Ryuk ransomware"
    strings:
        $note1 = "RyukReadMe.html"
        $note2 = "RyukReadMe.txt"
        $ext1 = ".RYK"
        $ext2 = ".RYUK"
        $proc1 = "kill.bat"
    condition:
        2 of ($note*) or 2 of ($ext*) or $proc1
}

rule WannaCry_Ransomware {
    meta:
        description = "Detects WannaCry ransomware"
    strings:
        $note1 = "@Please_Read_Me@.txt"
        $ext1 = ".WNCRY"
        $mutex = "Global\\MsWinZonesCacheCounterMutexA0"
        $url = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
    condition:
        2 of ($note*) or $ext1 or $mutex or $url
}

rule XMRig_Miner_Strict {
    meta:
        description = "Strict detection of XMRig cryptocurrency miner and variants"
        author = "CascadeAI"
    strings:
        $str1 = "XMRig"
        $str2 = "donate.v2.xmrig.com"
        $str3 = "stratum+tcp://"
        $str4 = "xmrig.exe"
        $str5 = "xmrig-cuda"
        $str6 = "xmrig-amd"
        $str7 = "mining pool"
        $str8 = "donate-level"
        $str9 = "randomx"
        $str10 = "cpu-priority"
        $str11 = "api-port"
        $str12 = "NiceHash"
        $str13 = "cryptonight"
        $str14 = "monero"
        $str15 = "pool.minexmr.com"
        $str16 = "supportxmr.com"
        $str17 = "xmrpool.eu"
        $str18 = "xmr.nanopool.org"
        $str19 = "xmr-eu1.nanopool.org"
        $str20 = "xmr-us-east1.nanopool.org"
        // ...add more for full coverage
    condition:
        3 of them
}

rule LokiBot_Stealer_Strict {
    meta:
        description = "Strict detection of LokiBot stealer malware"
        author = "CascadeAI"
    strings:
        $str1 = "lokibot"
        $str2 = "client/build.php"
        $str3 = "gate.php"
        $str4 = "Mozilla/4.08 (Charon; Inferno)"
        $str5 = "Loki"
        $str6 = "lokibot.exe"
        $str7 = "LokiBot Panel"
        $str8 = "LokiBot Loader"
        $str9 = "LokiBot Stealer"
        $str10 = "LokiMutex"
        $str11 = "SOFTWARE\\LokiBot"
        $str12 = "SYSTEM\\CurrentControlSet\\Services\\LokiBot"
        $str13 = "X-LokiBot-ID"
        $str14 = "X-LokiBot-Token"
        $str15 = "X-LokiBot-Data"
        $url1 = "hxxp://lokibotpanel.top"
        $url2 = "hxxp://lokibot.top"
        $url3 = "hxxp://lokigate.top"
        // ...add more for full coverage
    condition:
        3 of them
}

rule CONTI_Ransomware {
    meta:
        description = "Detects CONTI ransomware"
        author = "CascadeAI"
    strings:
        $note1 = "CONTI_README.txt"
        $ext1 = ".CONTI"
        $proc1 = "vssadmin delete shadows"
    condition:
        2 of ($note*) or $ext1 or $proc1
}

rule REvil_Ransomware {
    meta:
        description = "Detects REvil/Sodinokibi ransomware"
    strings:
        $note1 = "-README-.txt"
        $ext1 = ".REvil"
        $ext2 = ".sodinokibi"
        $url1 = "decryptor.top"
    condition:
        2 of ($note*) or 2 of ($ext*) or $url1
}

rule Maze_Ransomware {
    meta:
        description = "Detects Maze ransomware"
    strings:
        $note1 = "DECRYPT-FILES.txt"
        $ext1 = ".maze"
        $maze = "maze ransomware"
    condition:
        2 of ($note*) or $ext1 or $maze
}

rule AgentTesla_Stealer {
    meta:
        description = "Detects AgentTesla info stealer"
    strings:
        $str1 = "AgentTesla"
        $str2 = "smtp.gmail.com"
        $str3 = "password recovery"
    condition:
        2 of ($*)
}

rule RedLine_Stealer {
    meta:
        description = "Detects RedLine info stealer"
    strings:
        $str1 = "RedLine"
        $str2 = "TelegramAPI"
        $str3 = "PasswordRecovery"
    condition:
        2 of ($*)
}

rule njRAT_Trojan {
    meta:
        description = "Detects njRAT remote access trojan"
    strings:
        $str1 = "njRAT"
        $str2 = "NJRAT"
        $str3 = "njw0rm"
        $str4 = "cmd.exe /c"
    condition:
        2 of ($*)
}

rule Remcos_RAT {
    meta:
        description = "Detects Remcos RAT"
    strings:
        $str1 = "Remcos"
        $str2 = "remcos.exe"
        $str3 = "Remcos Client"
    condition:
        2 of ($*)
}

rule CobaltKitty_APT {
    meta:
        description = "Detects Cobalt Kitty APT tools"
    strings:
        $str1 = "kitty.exe"
        $str2 = "Cobalt Kitty"
        $str3 = "apt32"
    condition:
        2 of ($*)
}

rule Turla_APT_Tool {
    meta:
        description = "Detects Turla APT tools"
    strings:
        $str1 = "Turla"
        $str2 = "Snake"
        $str3 = "Carbon"
    condition:
        2 of ($*)
}

rule Dridex_Banking_Trojan {
    meta:
        description = "Detects Dridex banking trojan"
    strings:
        $str1 = "dridex"
        $str2 = "Dridex"
        $str3 = "botnet_id"
        $str4 = "dridex_config"
    condition:
        2 of ($*)
}

rule Zeus_Banking_Trojan {
    meta:
        description = "Detects Zeus/Zbot banking trojan"
    strings:
        $str1 = "Zeus"
        $str2 = "Zbot"
        $str3 = "botnet"
        $str4 = "zeus_config"
    condition:
        2 of ($*)
}

rule QakBot_Banking_Trojan {
    meta:
        description = "Detects QakBot (Qbot) banking trojan"
    strings:
        $str1 = "QakBot"
        $str2 = "Qbot"
        $str3 = "qakbot_config"
        $str4 = "qbot_id"
    condition:
        2 of ($*)
}

rule DarkSide_Ransomware {
    meta:
        description = "Detects DarkSide ransomware"
    strings:
        $note1 = "README_FOR_RESTORE"
        $ext1 = ".darkside"
        $proc1 = "vssadmin delete shadows"
    condition:
        2 of ($note*) or $ext1 or $proc1
}

rule GandCrab_Ransomware {
    meta:
        description = "Detects GandCrab ransomware"
    strings:
        $note1 = "GDCB-DECRYPT.txt"
        $ext1 = ".GDCB"
        $ext2 = ".KRAB"
        $url1 = "gandcrab"
    condition:
        2 of ($note*) or 2 of ($ext*) or $url1
}

rule LockBit_Ransomware {
    meta:
        description = "Detects LockBit ransomware"
    strings:
        $note1 = "Restore-My-Files.txt"
        $ext1 = ".lockbit"
        $proc1 = "vssadmin delete shadows"
    condition:
        2 of ($note*) or $ext1 or $proc1
}

rule Netwalker_Ransomware_Strict {
    meta:
        description = "Strict detection of Netwalker ransomware"
        threat_family = "Netwalker"
        author = "CascadeAI"
    strings:
        $note1 = "NETWALKER_README.txt"
        $note2 = "ReadMe.txt"
        $note3 = "YOUR_FILES_ARE_ENCRYPTED.txt"
        $note4 = "YOUR_FILES_ARE_LOCKED.txt"
        $ext1 = ".nwkr"
        $ext2 = ".encrypted"
        $ext3 = ".walker"
        $proc1 = "vssadmin delete shadows"
        $proc2 = "bcdedit /set {default} recoveryenabled No"
        $proc3 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures"
        $proc4 = "wbadmin delete catalog"
        $proc5 = "wmic shadowcopy delete"
        $url1 = "hxxp://netwalkerdecryptor.top"
        $url2 = "hxxp://decryptor.top"
        $url3 = "hxxp://netwalker.top"
        $mutex1 = "Global\\Netwalker"
        $mutex2 = "Global\\NWKR"
        $reg1 = "SOFTWARE\\Netwalker"
        $reg2 = "SYSTEM\\CurrentControlSet\\Services\\Netwalker"
        $str1 = "netwalker"
        $str2 = "decryptor"
        $str3 = "torproject.org"
        $str4 = "public key"
        $str5 = "private key"
        $str6 = "RSA-2048"
        $str7 = "AES-256"
        $str8 = "All your files have been encrypted"
        $str9 = "Your network is locked"
        $str10 = "Contact us to get the decryption tool"
        $str11 = "Personal ID:"
        $str12 = "Your files are encrypted with RSA-2048 and AES-256"
        $str13 = "To decrypt your files, you need to buy our decryptor"
        $str14 = "Send us your ID and 1 encrypted file"
        $str15 = "Do not rename encrypted files"
        $str16 = "Do not try to decrypt files yourself"
        $str17 = "Do not use third party software"
        $str18 = "If you do not contact us within 3 days, your data will be published"
        $str19 = "netwalker support"
        $str20 = "netwalker decryptor"
        // ... (add more indicators as needed for strictness)
    condition:
        3 of them
}

rule FormBook_Stealer_Strict {
    meta:
        description = "Strict detection of FormBook info stealer"
        threat_family = "FormBook"
        author = "CascadeAI"
    strings:
        $str1 = "FormBook"
        $str2 = "formgrabber"
        $str3 = "keylogger"
        $str4 = "GetAsyncKeyState"
        $str5 = "user32.dll"
        $str6 = "kernel32.dll"
        $str7 = "POST /gate.php"
        $str8 = "Mozilla/5.0 (Windows NT"
        $str9 = "X-FormBook-ID"
        $str10 = "X-FormBook-Data"
        $str11 = "FormBook Panel"
        $str12 = "FormBook Loader"
        $str13 = "FormBook Stealer"
        $str14 = "FormBook Stub"
        $str15 = "FormBook Bot"
        $str16 = "FormBook Campaign"
        $str17 = "FormBook Task"
        $str18 = "FormBook Key"
        $str19 = "FormBook Mutex"
        $str20 = "FormBook Registry"
        $mutex1 = "Global\\FormBook"
        $mutex2 = "FormBookMutex"
        $reg1 = "SOFTWARE\\FormBook"
        $reg2 = "SYSTEM\\CurrentControlSet\\Services\\FormBook"
        $url1 = "hxxp://formbookpanel.top"
        $url2 = "hxxp://formbook.top"
        $url3 = "hxxp://formbookgate.top"
        // ... (add more indicators as needed for strictness)
    condition:
        3 of them
}


rule AZORult_Stealer {
    meta:
        description = "Detects AZORult info stealer"
    strings:
        $str1 = "AZORult"
        $str2 = "azorult"
        $str3 = "passwords.txt"
    condition:
        2 of ($*)
}

rule Nanocore_RAT {
    meta:
        description = "Detects Nanocore remote access trojan"
    strings:
        $str1 = "NanoCore"
        $str2 = "nanocore"
        $str3 = "nanocore_config"
    condition:
        2 of ($*)
}

rule PlugX_RAT {
    meta:
        description = "Detects PlugX remote access trojan"
    strings:
        $str1 = "PlugX"
        $str2 = "plugx"
        $str3 = "plugx_config"
    condition:
        2 of ($*)
}

rule FIN7_Carbanak_APT {
    meta:
        description = "Detects FIN7/Carbanak APT tools"
    strings:
        $str1 = "Carbanak"
        $str2 = "carbanak"
        $str3 = "fin7"
        $str4 = "Anunak"
    condition:
        2 of ($*)
}

rule Trickbot_Malware {
    meta:
        description = "Detects Trickbot banking trojan"
        author = "YARA-Rules"
    strings:
        $a = "trickbot"
        $b = "tabDll32"
        $c = "client_id"
    condition:
        2 of them
}

rule Suspicious_Macro_Doc {
    meta:
        description = "Detects suspicious macro-enabled Office documents"
        author = "CascadeAI"
    strings:
        $a = "AutoOpen"
        $b = "Shell"
        $c = "CreateObject"
        $d = "WScript.Shell"
    condition:
        2 of them
}

rule Ransomware_Generic {
    meta:
        description = "Detects generic ransomware strings"
        author = "CascadeAI"
    strings:
        $a = "All your files have been encrypted"
        $b = "decrypt"
        $c = "bitcoin"
        $d = "ransom"
    condition:
        3 of them
}

// This rule detects files that begin with the ASCII string 'CC8UPTDOGVX1HPJK', which is the start of the user's Pollux cipher binary output. This can be used to flag or ignore files encrypted or encoded with the user's custom Pollux cipher.
rule Pollux_Cipher_File {
    meta:
        description = "Detects files containing the user's Pollux cipher binary pattern (ASCII: CC8UPTDOGVX1HPJK)"
        author = "CascadeAI"
    strings:
        $header = { 43 43 38 55 50 54 44 4F 47 56 58 31 48 50 4A 4B }
    condition:
        $header at 0
}

rule Fernet_Encrypted_File {
    meta:
        description = "Detects files encrypted with the user's Fernet file_crypto.py utility (44-byte Base64 Fernet key header)"
        author = "CascadeAI"
    strings:
        $key_header = /^Z0FBQUFB.{36}==/
    condition:
        $key_header at 0
}


