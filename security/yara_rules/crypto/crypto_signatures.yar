rule CryptoSignature {
    meta:
        description = "Detects common cryptographic signatures"
        author = "CascadeAI"
    strings:
        $rsa = {30 82 ?? ?? 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01}
        $aes = {30 82 ?? ?? 30 0D 06 09 2A 86 48 86 F7 0D 01 01 04}
        $sha256 = {30 82 ?? ?? 30 0D 06 09 60 86 48 01 65 03 04 02 01}
    condition:
        any of ($rsa, $aes, $sha256)
}

rule MalwareCryptoUse {
    meta:
        description = "Detects suspicious use of cryptography in malware"
        author = "CascadeAI"
    strings:
        $xor_key = {31 C0 88 0C 07 40 88 0C 07}
        $rc4_init = {33 C0 89 45 FC 8B 45 FC 83 E0 0F}
        $aes_init = {33 C0 89 45 FC 8B 45 FC 83 E0 10}
    condition:
        any of ($xor_key, $rc4_init, $aes_init)
}
