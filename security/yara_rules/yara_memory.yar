rule MemoryDisclosure {
    meta:
        description = "Detects memory disclosure attempts"
        severity = "high"
        
    strings:
        $read_mem = "ReadProcessMemory" wide ascii fullword
        $virtual_query = "VirtualQueryEx" wide ascii fullword
        $mem_pattern = { 8B 45 ?? 8B 00 }
        $heap_walk = "HeapWalk" wide ascii fullword
        
    condition:
        all of them and filesize < 20KB
}

rule KernelPoolOverflow {
    meta:
        description = "Detects kernel pool overflow attempts"
        severity = "critical"
        
    strings:
        $pool_tag = "kern" wide ascii fullword
        $pool_alloc = "ExAllocatePool" wide ascii fullword
        $pool_overflow = { F3 A5 }  // REP MOVSD
        $pool_spray = { B9 ?? ?? 00 00 F3 }  // MOV ECX, X; REP
        
    condition:
        all of them and filesize < 20KB
}

rule HeapFungibility {
    meta:
        description = "Detects heap manipulation techniques"
        severity = "critical"
        
    strings:
        $heap_chunk = { 8B 47 F8 8B 4F FC }
        $unlink_pattern = { 8B 4B F8 89 43 FC }
        $coalesce = { 8B 4B F8 8B 43 FC }
        $heap_cookie = { 8B 4D FC 33 4D F8 }
        
    condition:
        all of them and filesize < 20KB
}

rule StackCookieBypasses {
    meta:
        description = "Detects stack cookie bypass attempts"
        severity = "critical"
        
    strings:
        $cookie_check = { 33 C5 89 45 FC }
        $cookie_override = { C7 45 FC }
        $frame_pointer = { 55 8B EC 81 EC }
        $exception_handler = "SetUnhandledExceptionFilter" wide ascii fullword
        
    condition:
        all of them and filesize < 20KB
}

rule PageTableManipulation {
    meta:
        description = "Detects page table manipulation"
        severity = "critical"
        
    strings:
        $pte_mod = { 0F 20 ?? 0F 22 }
        $page_walk = { 8B 45 ?? C1 E8 0C }
        $tlb_flush = { 0F 01 F8 }
        $page_fault = { CD 0E }
        
    condition:
        all of them and filesize < 20KB
}

rule MemoryMappingExploit {
    meta:
        description = "Detects memory mapping exploitation"
        severity = "critical"
        
    strings:
        $map_view = "MapViewOfFile" wide ascii fullword
        $create_section = "NtCreateSection" wide ascii fullword
        $physical_mem = "\\\\.\\PhysicalMemory" wide ascii fullword
        $mem_device = "\\\\.\\MemoryDevice" wide ascii fullword
        
    condition:
        all of them and filesize < 20KB
}

rule AdvancedHeapExploit {
    meta:
        description = "Detects advanced heap exploitation techniques"
        severity = "critical"
        
    strings:
        $metadata_corrupt = { 8B 4D F8 83 C1 08 }
        $fastbin_dup = { 8B 45 F8 89 45 FC }
        $tcache_poison = { 48 89 45 ?? 48 8B 45 }
        $house_of_force = { 8B 15 ?? ?? ?? ?? 81 C2 }
        
    condition:
        all of them and filesize < 20KB
}

rule KernelMemoryDisclosure {
    meta:
        description = "Detects kernel memory disclosure attempts"
        severity = "critical"
        
    strings:
        $kdebug_read = "DbgkReadVirtualMemory" wide ascii fullword
        $kernel_read = { 0F 01 F8 8B 45 }
        $mdl_mapping = "MmMapLockedPages" wide ascii fullword
        $probe_read = { 0F B6 ?? ?? ?? ?? ?? }
        
    condition:
        all of them and filesize < 20KB
}

rule ThreadContextManipulation {
    meta:
        description = "Detects thread context manipulation"
        severity = "critical"
        
    strings:
        $context_get = "GetThreadContext" wide ascii fullword
        $context_set = "SetThreadContext" wide ascii fullword
        $suspend_thread = "SuspendThread" wide ascii fullword
        $resume_thread = "ResumeThread" wide ascii fullword
        
    condition:
        all of them and filesize < 20KB
}

rule StackCanaryBypass {
    meta:
        description = "Detects stack canary bypass techniques"
        severity = "critical"
        
    strings:
        $canary_read = { 64 A1 18 00 00 00 }
        $canary_override = { 89 45 FC 33 C5 }
        $cookie_init = "__security_init_cookie" wide ascii fullword
        $fail_handler = "__security_check_fail" wide ascii fullword
        
    condition:
        all of them and filesize < 20KB
}


