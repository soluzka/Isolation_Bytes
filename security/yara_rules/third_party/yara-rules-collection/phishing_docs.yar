/*
    YARA Rules - Phishing Document Detection
    Author: Anton Marinov (@AntonSMarinov)
    Description: Detection rules for malicious documents used in phishing campaigns
                 including Office macros, PDF exploits, and document-based droppers.
*/

rule Malicious_Office_Macro
{
    meta:
        author      = "Anton Marinov"
        description = "Detects Office documents with suspicious VBA macro indicators"
        category    = "phishing"
        severity    = "high"
        date        = "2025-01-01"

    strings:
        // VBA execution sinks
        $vba1 = "Shell" ascii wide nocase
        $vba2 = "WScript.Shell" ascii wide nocase
        $vba3 = "CreateObject" ascii wide nocase
        $vba4 = "PowerShell" ascii wide nocase
        $vba5 = "cmd.exe" ascii wide nocase
        $vba6 = "mshta.exe" ascii wide nocase
        $vba7 = "wscript.exe" ascii wide nocase
        $vba8 = "certutil" ascii wide nocase

        // Download indicators
        $dl1 = "XMLHTTP" ascii wide nocase
        $dl2 = "WinHttp" ascii wide nocase
        $dl3 = "URLDownloadToFile" ascii wide nocase
        $dl4 = "Environ" ascii wide nocase

        // Obfuscation patterns
        $ob1 = "Chr(" ascii wide nocase
        $ob2 = "ChrW(" ascii wide nocase
        $ob3 = "String(" ascii wide nocase

        // OLE/VBA stream marker
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $vba_marker = "VBA" ascii

    condition:
        ($ole at 0 or $vba_marker) and
        (
            (2 of ($vba*) and 1 of ($dl*)) or
            (1 of ($vba*) and 3 of ($ob*))
        )
}

rule ClickFix_Social_Engineering
{
    meta:
        author      = "Anton Marinov"
        description = "Detects ClickFix-style social engineering lures that trick users into running malicious commands"
        category    = "phishing"
        severity    = "high"
        date        = "2025-01-01"
        reference   = "https://www.proofpoint.com/us/blog/threat-insight/clipboard-hijacking"

    strings:
        // ClickFix lure text patterns
        $lure1 = "Press Win + R" ascii wide nocase
        $lure2 = "Press Windows + R" ascii wide nocase
        $lure3 = "Copy and paste" ascii wide nocase
        $lure4 = "CTRL+V" ascii wide nocase
        $lure5 = "I am not a robot" ascii wide nocase
        $lure6 = "Human Verification" ascii wide nocase
        $lure7 = "Verify you are human" ascii wide nocase
        $lure8 = "Click Allow to confirm" ascii wide nocase

        // Clipboard-delivered payloads
        $cmd1 = "powershell" ascii wide nocase
        $cmd2 = "mshta" ascii wide nocase
        $cmd3 = "rundll32" ascii wide nocase
        $cmd4 = "regsvr32" ascii wide nocase

    condition:
        (1 of ($lure*)) and (1 of ($cmd*))
}

rule Malicious_PDF_JavaScript
{
    meta:
        author      = "Anton Marinov"
        description = "Detects malicious PDF files with embedded JavaScript"
        category    = "phishing"
        severity    = "high"
        date        = "2025-01-01"

    strings:
        $pdf_header = "%PDF-" ascii
        $js1 = "/JavaScript" ascii
        $js2 = "/JS" ascii
        $js3 = "eval(" ascii nocase
        $js4 = "unescape(" ascii nocase
        $js5 = "String.fromCharCode" ascii nocase

        // Exploit patterns
        $exp1 = "util.printf" ascii
        $exp2 = "getAnnots" ascii
        $exp3 = "spell.customDictionaryOpen" ascii
        $exp4 = "media.newPlayer" ascii

        // Launch action
        $launch = "/Launch" ascii
        $openaction = "/OpenAction" ascii

    condition:
        $pdf_header at 0 and
        (
            (1 of ($js*) and 2 of ($exp*)) or
            ($launch and 1 of ($js*)) or
            ($openaction and 2 of ($js*))
        )
}

rule RTF_Exploit_Indicators
{
    meta:
        author      = "Anton Marinov"
        description = "Detects RTF files with exploit indicators (CVE-2017-11882 and similar)"
        category    = "phishing"
        severity    = "critical"
        date        = "2025-01-01"

    strings:
        $rtf_header = "{\\rtf" ascii
        $ole_obj = "\\object" ascii nocase
        $ole_data = "\\objdata" ascii nocase

        // Equation editor exploit
        $eq1 = { 45 71 75 61 74 69 6F 6E 2E 33 }
        $eq2 = "Equation.3" ascii
        $eq3 = "Microsoft Equation" ascii wide nocase

        // CVE-2017-11882 pattern
        $cve = { 0C 00 00 00 00 00 00 00 00 00 00 00 }

        // Shellcode delivery
        $sc1 = "cmd" ascii nocase
        $sc2 = "powershell" ascii nocase
        $sc3 = "mshta" ascii nocase

    condition:
        $rtf_header at 0 and
        (
            ($ole_obj and ($eq1 or $eq2 or $eq3)) or
            ($cve and $ole_data) or
            (2 of ($sc*) and $ole_obj)
        )
}

rule Phishing_Credential_Harvester
{
    meta:
        author      = "Anton Marinov"
        description = "Detects HTML/web-based credential harvesting pages"
        category    = "phishing"
        severity    = "high"
        date        = "2025-01-01"

    strings:
        // Fake login form indicators
        $form1 = "<form" ascii nocase
        $pass1 = "type=\"password\"" ascii nocase
        $pass2 = "type='password'" ascii nocase
        $user1 = "type=\"email\"" ascii nocase

        // Data exfiltration
        $exfil1 = "XMLHttpRequest" ascii
        $exfil2 = "fetch(" ascii
        $exfil3 = "$.post(" ascii
        $exfil4 = "$.ajax(" ascii

        // Obfuscation
        $ob1 = "eval(atob(" ascii nocase
        $ob2 = "eval(unescape(" ascii nocase
        $ob3 = "document.write(unescape" ascii nocase
        $ob4 = "String.fromCharCode" ascii

        // Suspicious domains / keywords
        $spoof1 = "microsoft-login" ascii nocase
        $spoof2 = "secure-login" ascii nocase
        $spoof3 = "account-verify" ascii nocase

    condition:
        ($form1 and $user1 and ($pass1 or $pass2) and 1 of ($exfil*)) or
        (2 of ($ob*)) or
        (1 of ($spoof*) and $form1 and $user1 and ($pass1 or $pass2))
}

rule Phishing_Credential_Harvester_Strict
{
    meta:
        author      = "Patched"
        description = "Detects credential harvesting pages with all required indicators"
        category    = "phishing"
        severity    = "critical"
        date        = "2026-08-10"

    strings:
        $form  = "<form" ascii nocase
        $email = "type=\"email\"" ascii nocase
        $pass  = "type=\"password\"" ascii nocase
        $exfil = "XMLHttpRequest" ascii
        $spoof = "microsoft-login" ascii nocase

    condition:
        all of them
}
