rule SuspiciousExecutable_Strict {
    meta:
        description = "Detects suspicious PE files with advanced and empowered indicators"
        author = "CascadeAI"
    strings:
        // PE header and packers
        $mz = {4D 5A}
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx2 = "UPX2"
        $aspack = "ASPack"
        
        // Common packers
        $packer = {55 8B EC 83 EC 10 53 56 57 8B F9 33 C0 89 45 FC}
        
        // Common encryption patterns
        $xor = {8B 45 08 33 C0 89 45 FC 8B 45 10 33 C0 89 45 F8}
        
        // Common shellcode patterns
        $shellcode = {31 C0 50 68 00 00 00 00 68 00 00 00 00 68 00 00 00 00 8B}
    
    condition:
        all of ($mz, $packer, $xor, $shellcode)
}

rule FileSizeAnomaly {
    meta:
        description = "Detects unusually large or small executable files"
        author = "CascadeAI"
    condition:
        filesize > 10MB or filesize < 1KB
}

rule EntropyAnomaly {
    meta:
        description = "Detects files with unusually high entropy (potential encryption/packing)"
        author = "CascadeAI"
    condition:
        pe.entropy > 7.0
}
