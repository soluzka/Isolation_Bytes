/*
    YARA Rules - Web Shell Detection
    Author: Anton Marinov (@AntonSMarinov)
    Description: Detection rules for web shells across multiple languages
                 including PHP, ASP, JSP, and generic obfuscated shells.
*/

rule Generic_PHP_Webshell
{
    meta:
        author      = "Anton Marinov"
        description = "Detects generic PHP web shells based on common execution patterns"
        category    = "webshells"
        severity    = "critical"
        date        = "2025-01-01"

    strings:
        $php = "<?php" ascii nocase

        // Execution functions
        $exec1 = "eval(" ascii nocase
        $exec2 = "system(" ascii nocase
        $exec3 = "exec(" ascii nocase
        $exec4 = "passthru(" ascii nocase
        $exec5 = "shell_exec(" ascii nocase
        $exec6 = "popen(" ascii nocase
        $exec7 = "proc_open(" ascii nocase
        $exec8 = "assert(" ascii nocase

        // Input sources
        $input1 = "$_GET" ascii
        $input2 = "$_POST" ascii
        $input3 = "$_REQUEST" ascii
        $input4 = "$_COOKIE" ascii
        $input5 = "$_SERVER" ascii

        // Obfuscation patterns
        $ob1 = "base64_decode(" ascii nocase
        $ob2 = "str_rot13(" ascii nocase
        $ob3 = "gzinflate(" ascii nocase
        $ob4 = "gzuncompress(" ascii nocase
        $ob5 = "str_replace(" ascii nocase

    condition:
        $php and
        (
            (1 of ($exec*) and 1 of ($input*)) or
            (2 of ($ob*) and 1 of ($exec*))
        )
}

rule China_Chopper_Webshell
{
    meta:
        author      = "Anton Marinov"
        description = "Detects China Chopper web shell variants"
        category    = "webshells"
        family      = "China Chopper"
        severity    = "critical"
        date        = "2025-01-01"
        reference   = "https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html"

    strings:
        // Classic China Chopper one-liner
        $cc1 = "eval(Request[" ascii nocase
        $cc2 = "eval(Request.Item[" ascii nocase
        $cc3 = "eval($_POST[" ascii nocase

        // PHP variant
        $php_cc = { 3C 3F 70 68 70 20 40 65 76 61 6C 28 24 5F 50 4F 53 54 5B }

        // ASP variant
        $asp_cc = "<%eval request(" ascii nocase
        $asp_cc2 = "<%execute request(" ascii nocase

        // Known C2 commands
        $cmd1 = "shell" ascii nocase
        $cmd2 = "fileManager" ascii nocase
        $cmd3 = "database" ascii nocase

    condition:
        (1 of ($cc*)) or
        $php_cc or
        ($asp_cc or $asp_cc2) or
        (2 of ($cmd*))
}

rule ASP_Webshell
{
    meta:
        author      = "Anton Marinov"
        description = "Detects ASP/ASPX web shells"
        category    = "webshells"
        severity    = "critical"
        date        = "2025-01-01"

    strings:
        $asp1 = "<%@" ascii nocase
        $asp2 = "<%" ascii

        // Execution
        $exec1 = "cmd.exe" ascii wide nocase
        $exec2 = "Shell.Application" ascii wide nocase
        $exec3 = "WScript.Shell" ascii wide nocase
        $exec4 = "CreateObject" ascii wide nocase
        $exec5 = "Process.Start" ascii wide nocase
        $exec6 = "Runtime.exec" ascii wide nocase

        // Input
        $input1 = "Request(" ascii nocase
        $input2 = "Request.Form(" ascii nocase
        $input3 = "Request.QueryString(" ascii nocase

        // File operations
        $file1 = "FileSystemObject" ascii wide nocase
        $file2 = "OpenTextFile" ascii wide nocase

    condition:
        ($asp1 or $asp2) and
        (
            (1 of ($exec*) and 1 of ($input*)) or
            (1 of ($file*) and 1 of ($input*) and 1 of ($exec*))
        )
}

rule JSP_Webshell
{
    meta:
        author      = "Anton Marinov"
        description = "Detects JSP web shells"
        category    = "webshells"
        severity    = "critical"
        date        = "2025-01-01"

    strings:
        $jsp_tag = "<%@" ascii
        $jsp_tag2 = "<jsp:" ascii nocase

        $exec1 = "Runtime.getRuntime().exec(" ascii
        $exec2 = "ProcessBuilder" ascii
        $exec3 = "new ProcessBuilder" ascii

        $input1 = "request.getParameter(" ascii
        $input2 = "request.getInputStream(" ascii

        $java_io = "java.io" ascii
        $java_lang = "java.lang.Runtime" ascii

    condition:
        ($jsp_tag or $jsp_tag2) and
        (1 of ($exec*) or 1 of ($java*)) and
        (1 of ($input*))
}

rule Obfuscated_Webshell
{
    meta:
        author      = "Anton Marinov"
        description = "Detects heavily obfuscated web shells using encoding/encryption"
        category    = "webshells"
        severity    = "high"
        date        = "2025-01-01"

    strings:
        // Chained obfuscation
        $chain1 = "eval(base64_decode(" ascii nocase
        $chain2 = "eval(gzinflate(base64_decode(" ascii nocase
        $chain3 = "eval(str_rot13(" ascii nocase
        $chain4 = "assert(base64_decode(" ascii nocase
        $chain5 = "preg_replace('/.*/e'" ascii nocase

        // Hex/char obfuscation
        $hex1 = /\$[a-zA-Z_]+\s*=\s*(['"]([\\x][0-9a-fA-F]{2}){10,}['"])/
        $hex2 = "chr(ord(" ascii nocase

        // Long base64 strings (common in shells)
        $b64_long = /['"](([A-Za-z0-9+\/]{4}){50,}={0,2})['"]/

        // Variable function calls
        $var_func = /\$[a-zA-Z_]+\s*\(\s*\$[a-zA-Z_]+\s*\[/

    condition:
        (1 of ($chain*)) or
        ($b64_long and $var_func) or
        (2 of ($hex*))
}

rule PHP_Webshell_Strict
{
    meta:
        author      = "Patched"
        description = "Detects PHP webshell with input and obfuscation"
        category    = "webshells"
        severity    = "critical"
        date        = "2026-08-10"

    strings:
        $php   = "<?php" ascii nocase
        $input = "$_POST" ascii
        $exec  = "eval(" ascii nocase
        $ob    = "base64_decode(" ascii nocase

    condition:
        all of them
}
