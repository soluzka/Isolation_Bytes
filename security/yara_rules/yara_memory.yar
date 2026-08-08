rule HeapSprayPattern {
    meta:
        description = "Detects heap spray attack patterns"
        severity = "critical"
        
    strings:
        $nop_sled = { 90 90 90 90 90 90 }
        $spray_alloc = "VirtualAlloc" wide ascii
        $heap_create = "HeapCreate" wide ascii
        $large_alloc = { 68 00 00 10 00 }  // PUSH 0x100000
        
    condition:
        2 of them
}

rule StackPivotDetection {
    meta:
        description = "Detects stack pivot techniques"
        severity = "critical"
        
    strings:
        $xchg_esp = { 94 }  // XCHG ESP,EAX
        $mov_esp = { 8B ?? 24 }  // MOV ESP,[REG]
        $lea_esp = { 8D ?? 24 }  // LEA ESP,[REG]
        $add_esp = { 83 C4 }     // ADD ESP,imm8
        
    condition:
        2 of them
}

rule MemoryDisclosure {
    meta:
        description = "Detects memory disclosure attempts"
        severity = "high"
        
    strings:
        $read_mem = "ReadProcessMemory" wide ascii
        $virtual_query = "VirtualQueryEx" wide ascii
        $mem_pattern = { 8B 45 ?? 8B 00 }
        $heap_walk = "HeapWalk" wide ascii
        
    condition:
        2 of them
}

rule UseAfterFreePattern {
    meta:
        description = "Detects use-after-free exploitation patterns"
        severity = "critical"
        
    strings:
        $double_free = { FF 15 ?? ?? ?? ?? FF 15 }
        $heap_free = "HeapFree" wide ascii
        $dangling_ref = { 8B 06 85 C0 }
        $realloc_pattern = "HeapReAlloc" wide ascii
        
    condition:
        2 of them
}

rule KernelPoolOverflow {
    meta:
        description = "Detects kernel pool overflow attempts"
        severity = "critical"
        
    strings:
        $pool_tag = { 'k' 'e' 'r' 'n' }
        $pool_alloc = "ExAllocatePool" wide ascii
        $pool_overflow = { F3 A5 }  // REP MOVSD
        $pool_spray = { B9 ?? ?? 00 00 F3 }  // MOV ECX, X; REP
        
    condition:
        2 of them
}

rule ReturnOrientedProgramming {
    meta:
        description = "Detects ROP chain construction"
        severity = "critical"
        
    strings:
        $gadget_chain = { C3 ?? ?? ?? ?? C3 }
        $pop_ret = { 5? C3 }
        $push_ret = { 68 ?? ?? ?? ?? C3 }
        $move_esp = { 8B ?? 24 ?? ?? ?? ?? C3 }
        
    condition:
        2 of them
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
        2 of them
}

rule StackCookieBypasses {
    meta:
        description = "Detects stack cookie bypass attempts"
        severity = "critical"
        
    strings:
        $cookie_check = { 33 C5 89 45 FC }
        $cookie_override = { C7 45 FC }
        $frame_pointer = { 55 8B EC 81 EC }
        $exception_handler = "SetUnhandledExceptionFilter" wide ascii
        
    condition:
        2 of them
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
        2 of them
}

rule MemoryMappingExploit {
    meta:
        description = "Detects memory mapping exploitation"
        severity = "critical"
        
    strings:
        $map_view = "MapViewOfFile" wide ascii
        $create_section = "NtCreateSection" wide ascii
        $physical_mem = "\\\\.\\PhysicalMemory" wide ascii
        $mem_device = "\\\\.\\MemoryDevice" wide ascii
        
    condition:
        2 of them
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
        2 of them
}

rule KernelMemoryDisclosure {
    meta:
        description = "Detects kernel memory disclosure attempts"
        severity = "critical"
        
    strings:
        $kdebug_read = "DbgkReadVirtualMemory" wide ascii
        $kernel_read = { 0F 01 F8 8B 45 }
        $mdl_mapping = "MmMapLockedPages" wide ascii
        $probe_read = { 0F B6 ?? ?? ?? ?? ?? }
        
    condition:
        2 of them
}

rule ThreadContextManipulation {
    meta:
        description = "Detects thread context manipulation"
        severity = "critical"
        
    strings:
        $context_get = "GetThreadContext" wide ascii
        $context_set = "SetThreadContext" wide ascii
        $suspend_thread = "SuspendThread" wide ascii
        $resume_thread = "ResumeThread" wide ascii
        
    condition:
        2 of them
}

rule StackCanaryBypass {
    meta:
        description = "Detects stack canary bypass techniques"
        severity = "critical"
        
    strings:
        $canary_read = { 64 A1 18 00 00 00 }
        $canary_override = { 89 45 FC 33 C5 }
        $cookie_init = "__security_init_cookie" wide ascii
        $fail_handler = "__security_check_fail" wide ascii
        
    condition:
        2 of them
}

rule MemoryDebuggingAbuse {
    meta:
        description = "Detects memory debugging mechanism abuse"
        severity = "high"
        
    strings:
        $debug_heap = "PageHeap" wide ascii
        $heap_validate = "HeapValidate" wide ascii
        $debug_break = { CC CC CC CC }
        $memory_bp = { 0F 0B }  // UD2 instruction
        
    condition:
        2 of them
}
