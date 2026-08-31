/*
    Minimal YARA Rules Index
    Created on 2025-05-11
    Updated to fix loading issues
    
    This index only includes rules that are confirmed to load properly.
*/

// Import the PE module which is needed for certain rules
import "pe"

// Comment out includes that cause problems or reference files that don't exist
// include "./pe_module.yar"  // Uncomment if issues are fixed

// We're skipping generic_anomalies.yar due to known loading issues
// include "./generic_anomalies.yar"

// Basic malware detection rules
rule SuspiciousFile {
    meta:
        description = "Basic detection for potentially suspicious files"
        author = "Windows Defender Clone"
        reference = "Internal"
        date = "2025-05-11"
        severity = "medium"
    
    strings:
        $s1 = "CreateRemoteThread" ascii
        $s2 = "VirtualAllocEx" ascii
        $s3 = "WriteProcessMemory" ascii
        $s4 = "mimikatz" ascii wide nocase
        $s5 = "lsass.dmp" ascii wide nocase
        $s6 = "sekurlsa::logonpasswords" ascii wide nocase
    
    condition:
        3 of them and uint16(0) == 0x5A4D
}

rule AntiDebugCheck {
    meta:
        description = "Detect anti-debugging code"
        author = "Windows Defender Clone"
        date = "2025-05-11"
    
    strings:
        $a1 = "IsDebuggerPresent" ascii
        $a2 = "CheckRemoteDebuggerPresent" ascii
        $a3 = "NtSetInformationThread" ascii
        $a4 = "DbgUiRemoteBreakin" ascii
        $a5 = "NtQueryInformationProcess" ascii
    
    condition:
        3 of them and uint16(0) == 0x5A4D
}

rule AntiVMCheck {
    meta:
        description = "Detect anti-VM code"
        author = "Windows Defender Clone"
        date = "2025-05-11"
    
    strings:
        $vm1 = "vmware" nocase
        $vm2 = "virtualbox" nocase
        $vm3 = "qemu" nocase
    
    condition:
        2 of them
}
