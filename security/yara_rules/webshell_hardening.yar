/*
    Web-shell hardening rules
    Purpose: high-confidence detection of server-side command shells and
             obfuscated request-driven execution. These rules are deliberately
             composite so ordinary PHP/ASP/JSP application code is not treated
             as a web shell merely because it uses one sensitive API.
*/

rule WebShell_PHP_Request_Execution
{
    meta:
        author = "Isolation Bytes Security"
        category = "webshell"
        severity = "critical"
        description = "PHP server-side command execution driven by HTTP input"

    strings:
        $tag1 = "<?php" ascii nocase
        $tag2 = "<?=" ascii nocase
        $in1 = "$_GET" ascii
        $in2 = "$_POST" ascii
        $in3 = "$_REQUEST" ascii
        $in4 = "$_COOKIE" ascii
        $ex1 = "system(" ascii nocase
        $ex2 = "shell_exec(" ascii nocase
        $ex3 = "passthru(" ascii nocase
        $ex4 = "exec(" ascii nocase
        $ex5 = "proc_open(" ascii nocase
        $ex6 = "popen(" ascii nocase
        $ob1 = "base64_decode(" ascii nocase
        $ob2 = "gzinflate(" ascii nocase
        $ob3 = "str_rot13(" ascii nocase
        $ob4 = "eval(" ascii nocase

    condition:
        (1 of ($tag*) and 1 of ($in*) and 1 of ($ex*)) or
        (1 of ($tag*) and 1 of ($in*) and 1 of ($ob*) and 1 of ($ex*))
}

rule WebShell_PHP_File_Management
{
    meta:
        author = "Isolation Bytes Security"
        category = "webshell"
        severity = "critical"
        description = "PHP request-controlled file management consistent with a web shell"

    strings:
        $tag1 = "<?php" ascii nocase
        $tag2 = "<?=" ascii nocase
        $in1 = "$_GET" ascii
        $in2 = "$_POST" ascii
        $in3 = "$_REQUEST" ascii
        $f1 = "file_put_contents(" ascii nocase
        $f2 = "move_uploaded_file(" ascii nocase
        $f3 = "unlink(" ascii nocase
        $f4 = "copy(" ascii nocase
        $f5 = "rename(" ascii nocase
        $f6 = "file_get_contents(" ascii nocase
        $e1 = "eval(" ascii nocase
        $e2 = "system(" ascii nocase
        $e3 = "shell_exec(" ascii nocase

    condition:
        1 of ($tag*) and 1 of ($in*) and 1 of ($f*) and (1 of ($e*) or 2 of ($f*))
}

rule WebShell_ASPNET_Request_Execution
{
    meta:
        author = "Isolation Bytes Security"
        category = "webshell"
        severity = "critical"
        description = "ASP.NET request data combined with process or command execution"

    strings:
        $tag1 = "<%@" ascii nocase
        $tag2 = "<%=" ascii nocase
        $req1 = "Request[" ascii nocase
        $req2 = "Request.Form" ascii nocase
        $req3 = "Request.QueryString" ascii nocase
        $req4 = "Request.InputStream" ascii nocase
        $ex1 = "System.Diagnostics.Process" ascii nocase
        $ex2 = "Process.Start(" ascii nocase
        $ex3 = "cmd.exe" ascii wide nocase
        $ex4 = "powershell" ascii wide nocase
        $load1 = "Assembly.Load" ascii nocase
        $load2 = "Activator.CreateInstance" ascii nocase

    condition:
        1 of ($tag*) and 1 of ($req*) and (1 of ($ex*) or 1 of ($load*))
}

rule WebShell_JSP_Request_Execution
{
    meta:
        author = "Isolation Bytes Security"
        category = "webshell"
        severity = "critical"
        description = "JSP request data combined with Java process execution"

    strings:
        $tag1 = "<jsp:" ascii nocase
        $tag2 = "<%@" ascii
        $req1 = "request.getParameter(" ascii nocase
        $req2 = "request.getInputStream(" ascii nocase
        $req3 = "request.getReader(" ascii nocase
        $ex1 = "Runtime.getRuntime().exec(" ascii nocase
        $ex2 = "Runtime.exec(" ascii nocase
        $ex3 = "ProcessBuilder" ascii nocase
        $ex4 = "new ProcessBuilder" ascii nocase
        $load1 = "Class.forName(" ascii nocase
        $load2 = "Method.invoke(" ascii nocase

    condition:
        1 of ($tag*) and 1 of ($req*) and (1 of ($ex*) or (1 of ($load*) and 1 of ($ex*)))
}

rule WebShell_Obfuscated_Request_Execution
{
    meta:
        author = "Isolation Bytes Security"
        category = "webshell"
        severity = "critical"
        description = "Obfuscated request-driven command execution"

    strings:
        $in1 = "$_GET" ascii
        $in2 = "$_POST" ascii
        $in3 = "$_REQUEST" ascii
        $in4 = "$_SERVER" ascii
        $ob1 = "base64_decode(" ascii nocase
        $ob2 = "gzinflate(" ascii nocase
        $ob3 = "gzuncompress(" ascii nocase
        $ob4 = "str_rot13(" ascii nocase
        $ob5 = "convert_uudecode(" ascii nocase
        $ob6 = "chr(" ascii nocase
        $ex1 = "eval(" ascii nocase
        $ex2 = "assert(" ascii nocase
        $ex3 = "system(" ascii nocase
        $ex4 = "shell_exec(" ascii nocase
        $ex5 = "passthru(" ascii nocase

    condition:
        1 of ($in*) and 1 of ($ob*) and 1 of ($ex*)
}

rule WebShell_Reverse_Channel
{
    meta:
        author = "Isolation Bytes Security"
        category = "webshell"
        severity = "critical"
        description = "Server-side shell execution combined with an outbound socket channel"

    strings:
        $php = "<?php" ascii nocase
        $net1 = "fsockopen(" ascii nocase
        $net2 = "socket_create(" ascii nocase
        $net3 = "socket_connect(" ascii nocase
        $net4 = "stream_socket_client(" ascii nocase
        $sh1 = "shell_exec(" ascii nocase
        $sh2 = "system(" ascii nocase
        $sh3 = "exec(" ascii nocase
        $sh4 = "passthru(" ascii nocase
        $proc1 = "proc_open(" ascii nocase
        $proc2 = "popen(" ascii nocase
        $cmd1 = "/bin/sh" ascii
        $cmd2 = "/bin/bash" ascii
        $cmd3 = "cmd.exe" ascii wide nocase

    condition:
        1 of ($php*) and 1 of ($net*) and (1 of ($sh*) or 1 of ($proc*) or 1 of ($cmd*))
}

rule WebShell_Dropper_Execution
{
    meta:
        author = "Isolation Bytes Security"
        category = "webshell"
        severity = "critical"
        description = "Web-facing script that writes a file and then executes code"

    strings:
        $php = "<?php" ascii nocase
        $in1 = "$_POST" ascii
        $in2 = "$_REQUEST" ascii
        $write1 = "file_put_contents(" ascii nocase
        $write2 = "move_uploaded_file(" ascii nocase
        $write3 = "fwrite(" ascii nocase
        $exec1 = "include(" ascii nocase
        $exec2 = "require(" ascii nocase
        $exec3 = "eval(" ascii nocase
        $exec4 = "system(" ascii nocase
        $exec5 = "shell_exec(" ascii nocase

    condition:
        1 of ($php*) and 1 of ($in*) and 1 of ($write*) and 1 of ($exec*)
}
