rule AntiDebugCheck {
    meta:
        description = "Detects common anti-debugging techniques"
        author = "CascadeAI"
    strings:
        $check_debugger = {83 3D ?? ?? ?? ?? 00}
        $check_debug_port = {64 8B 0D 30 00 00 00}
        $check_peb = {64 8B 0D 18 00 00 00}
    condition:
        any of ($check_debugger, $check_debug_port, $check_peb)
}

rule AntiVMCheck {
    meta:
        description = "Detects common anti-VM techniques"
        author = "CascadeAI"
    strings:
        $check_vmware = {56 57 50 53 55 56 57}
        $check_virtualbox = {55 8B EC 83 EC 1C 53 56 57}
        $check_hypervisor = {0F 01 10}
    condition:
        any of ($check_vmware, $check_virtualbox, $check_hypervisor)
}
