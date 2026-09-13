/*
    YARA Rules - Enhanced Web Shell Detection
    Author: Security Team
    Description: Advanced detection rules for web shells across multiple platforms
                 including PHP, ASP.NET, JSP, and emerging threats
*/

rule PHP_Webshell_Advanced
{
    meta:
        author      = "Security Team"
        description = "Detects advanced PHP web shells with encryption and obfuscation"
        category    = "webshell"
        severity    = "critical"
        date        = "2026-09-13"

    strings:
        // PHP tags
        $php1 = "<?php" ascii nocase
        $php2 = "<?=" ascii nocase
        $php3 = "<%" ascii nocase
        
        // Advanced execution patterns
        $exec1 = "eval(" ascii nocase
        $exec2 = "assert(" ascii nocase
        $exec3 = "preg_replace" ascii nocase
        $exec4 = "create_function" ascii nocase
        $exec5 = "call_user_func" ascii nocase
        
        // Multi-layer obfuscation
        $obf1 = "base64_decode" ascii nocase
        $obf2 = "gzinflate" ascii nocase
        $obf3 = "gzuncompress" ascii nocase
        $obf4 = "str_rot13" ascii nocase
        $obf5 = "strrev" ascii nocase
        $obf6 = "convert_uudecode" ascii nocase
        
        // Variable functions
        $var1 = "$_GET" ascii
        $var2 = "$_POST" ascii
        $var3 = "$_REQUEST" ascii
        $var4 = "$_COOKIE" ascii
        $var5 = "$_SERVER" ascii
        
        // Chained obfuscation
        $chain1 = "eval(gzinflate(base64_decode(" ascii nocase
        $chain2 = "eval(base64_decode(gzinflate(" ascii nocase
        $chain3 = "assert(base64_decode(" ascii nocase
        
        // Hex encoding patterns
        $hex1 = "\\x" ascii
        $hex2 = "chr(" ascii nocase
        $hex3 = "ord(" ascii nocase

    condition:
        (
            ($php1 or $php2 or $php3) and
            (
                (1 of ($exec*) and 1 of ($var*)) or
                (2 of ($obf*) and 1 of ($exec*)) or
                (1 of ($chain*)) or
                (1 of ($exec*) and 2 of ($hex*))
            )
        )
}

rule ASPNET_Webshell_Advanced
{
    meta:
        author      = "Security Team"
        description = "Detects advanced ASP.NET web shells and C# backdoors"
        category    = "webshell"
        severity    = "critical"
        date        = "2026-09-13"

    strings:
        // ASP.NET indicators
        $asp1 = "<%@" ascii nocase
        $asp2 = "<%=" ascii nocase
        $asp3 = "<%" ascii
        $asp4 = "using System" ascii nocase
        $asp5 = "System.Diagnostics" ascii nocase
        
        // C# execution patterns
        $csharp1 = "Process.Start" ascii nocase
        $csharp2 = "Runtime.exec" ascii nocase
        $csharp3 = "Assembly.Load" ascii nocase
        $csharp4 = "Activator.CreateInstance" ascii nocase
        
        // Web shell commands
        $cmd1 = "cmd.exe" ascii wide nocase
        $cmd2 = "powershell" ascii wide nocase
        $cmd3 = "/c" ascii wide nocase
        $cmd4 = "shell" ascii wide nocase
        
        // Request handling
        $req1 = "Request[" ascii nocase
        $req2 = "Request.Form" ascii nocase
        $req3 = "Request.QueryString" ascii nocase
        $req4 = "Request.InputStream" ascii nocase
        
        // Response handling
        $resp1 = "Response.Write" ascii nocase
        $resp2 = "Response.BinaryWrite" ascii nocase
        $resp3 = "Response.OutputStream" ascii nocase
        
        // File operations
        $file1 = "File.Exists" ascii nocase
        $file2 = "File.ReadAllText" ascii nocase
        $file3 = "File.WriteAllText" ascii nocase
        $file4 = "Directory.GetFiles" ascii nocase

    condition:
        (
            (1 of ($asp*) and 1 of ($csharp*)) or
            (1 of ($asp*) and 1 of ($cmd*) and 1 of ($req*)) or
            (1 of ($asp*) and 1 of ($file*) and 1 of ($req*)) or
            (1 of ($asp*) and 1 of ($resp*))
        )
}

rule JSP_Webshell_Advanced
{
    meta:
        author      = "Security Team"
        description = "Detects advanced JSP web shells and Java backdoors"
        category    = "webshell"
        severity    = "critical"
        date        = "2026-09-13"

    strings:
        // JSP indicators
        $jsp1 = "<%@" ascii
        $jsp2 = "<jsp:" ascii nocase
        $jsp3 = "<%" ascii
        $jsp4 = "javax.servlet" ascii
        $jsp5 = "java.io" ascii
        
        // Java execution patterns
        $java1 = "Runtime.getRuntime().exec" ascii
        $java2 = "ProcessBuilder" ascii
        $java3 = "new ProcessBuilder" ascii
        $java4 = "Runtime.exec" ascii
        
        // Reflection and class loading
        $ref1 = "Class.forName" ascii
        $ref2 = "ClassLoader" ascii
        $ref3 = "URLClassLoader" ascii
        $ref4 = "Method.invoke" ascii
        
        // Request handling
        $req1 = "request.getParameter" ascii
        $req2 = "request.getInputStream" ascii
        $req3 = "request.getReader" ascii
        $req4 = "request.getHeader" ascii
        
        // Response handling
        $resp1 = "response.getWriter" ascii
        $resp2 = "response.getOutputStream" ascii
        $resp3 = "response.setContentType" ascii
        
        // Command execution
        $cmd1 = "cmd.exe" ascii wide nocase
        $cmd2 = "/bin/sh" ascii
        $cmd3 = "/bin/bash" ascii
        $cmd4 = "bash" ascii wide nocase

    condition:
        (
            (1 of ($jsp*) and 1 of ($java*)) or
            (1 of ($jsp*) and 1 of ($ref*) and 1 of ($req*)) or
            (1 of ($java*) and 1 of ($cmd*) and 1 of ($req*)) or
            (1 of ($jsp*) and 1 of ($resp*))
        )
}

rule Webshell_File_Upload
{
    meta:
        author      = "Security Team"
        description = "Detects web shells with file upload capabilities"
        category    = "webshell"
        severity    = "critical"
        date        = "2026-09-13"

    strings:
        // File upload patterns
        $up1 = "upload" ascii nocase
        $up2 = "UploadFile" ascii nocase
        $up3 = "SaveAs" ascii nocase
        $up4 = "multipart" ascii nocase
        $up5 = "enctype" ascii nocase
        
        // File operations
        $file1 = "move_uploaded_file" ascii nocase
        $file2 = "copy(" ascii nocase
        $file3 = "rename(" ascii nocase
        $file4 = "file_put_contents" ascii nocase
        $file5 = "fwrite" ascii nocase
        
        // HTTP methods
        $http1 = "POST" ascii nocase
        $http2 = "multipart/form-data" ascii nocase
        $http3 = "Files" ascii nocase
        $http4 = "InputStream" ascii nocase
        
        // Execution patterns
        $exec1 = "eval(" ascii nocase
        $exec2 = "system(" ascii nocase
        $exec3 = "exec(" ascii nocase
        $exec4 = "Process.Start" ascii nocase

    condition:
        (
            (1 of ($up*) and 1 of ($file*)) or
            (1 of ($http*) and 1 of ($file*)) or
            (1 of ($up*) and 1 of ($exec*))
        )
}

rule Webshell_Database_Access
{
    meta:
        author      = "Security Team"
        description = "Detects web shells with database access capabilities"
        category    = "webshell"
        severity    = "high"
        date        = "2026-09-13"

    strings:
        // Database patterns
        $db1 = "mysql_connect" ascii nocase
        $db2 = "mysqli_connect" ascii nocase
        $db3 = "PDO" ascii nocase
        $db4 = "SqlConnection" ascii nocase
        $db5 = "OleDbConnection" ascii nocase
        
        // SQL commands
        $sql1 = "SELECT" ascii nocase
        $sql2 = "INSERT" ascii nocase
        $sql3 = "UPDATE" ascii nocase
        $sql4 = "DELETE" ascii nocase
        $sql5 = "DROP" ascii nocase
        
        // Web shell execution
        $exec1 = "eval(" ascii nocase
        $exec2 = "system(" ascii nocase
        $exec3 = "exec(" ascii nocase
        $exec4 = "shell_exec(" ascii nocase
        
        // Input handling
        $input1 = "$_GET" ascii
        $input2 = "$_POST" ascii
        $input3 = "Request[" ascii nocase
        $input4 = "request.getParameter" ascii

    condition:
        (
            (1 of ($db*) and 1 of ($sql*)) or
            (1 of ($db*) and 1 of ($exec*)) or
            (1 of ($sql*) and 1 of ($exec*) and 1 of ($input*))
        )
}

rule Webshell_Reverse_Shell
{
    meta:
        author      = "Security Team"
        description = "Detects web shells with reverse shell capabilities"
        category    = "webshell"
        severity    = "critical"
        date        = "2026-09-13"

    strings:
        // Network patterns
        $net1 = "fsockopen" ascii nocase
        $net2 = "socket_create" ascii nocase
        $net3 = "socket_connect" ascii nocase
        $net4 = "stream_socket_client" ascii nocase
        $net5 = "Socket" ascii nocase
        
        // Shell execution
        $shell1 = "shell_exec" ascii nocase
        $shell2 = "exec(" ascii nocase
        $shell3 = "system(" ascii nocase
        $shell4 = "passthru(" ascii nocase
        $shell5 = "popen(" ascii nocase
        
        // Process patterns
        $proc1 = "proc_open" ascii nocase
        $proc2 = "Process.Start" ascii nocase
        $proc3 = "Runtime.exec" ascii nocase
        
        // Shell commands
        $cmd1 = "/bin/sh" ascii
        $cmd2 = "/bin/bash" ascii
        $cmd3 = "cmd.exe" ascii wide nocase
        $cmd4 = "powershell" ascii wide nocase
        
        // Redirection patterns
        $redir1 = "2>&1" ascii
        $redir2 = ">&" ascii
        $redir3 = "popen" ascii nocase

    condition:
        (
            (1 of ($net*) and 1 of ($shell*)) or
            (1 of ($net*) and 1 of ($proc*)) or
            (1 of ($proc*) and 1 of ($cmd*) and 1 of ($net*)) or
            (1 of ($shell*) and 1 of ($redir*))
        )
}

rule Webshell_Crypto_Mining
{
    meta:
        author      = "Security Team"
        description = "Detects web shells with cryptocurrency mining capabilities"
        category    = "webshell"
        severity    = "high"
        date        = "2026-09-13"

    strings:
        // Mining patterns
        $mine1 = "xmrig" ascii nocase
        $mine2 = "minerd" ascii nocase
        $mine3 = "cpuminer" ascii nocase
        $mine4 = "cryptonight" ascii nocase
        $mine5 = "monero" ascii nocase
        
        // Execution patterns
        $exec1 = "system(" ascii nocase
        $exec2 = "exec(" ascii nocase
        $exec3 = "shell_exec(" ascii nocase
        $exec4 = "Process.Start" ascii nocase
        
        // Process persistence
        $pers1 = "nohup" ascii nocase
        $pers2 = "background" ascii nocase
        $pers3 = "Start-Process" ascii nocase
        $pers4 = "bg" ascii nocase
        
        // CPU usage patterns
        $cpu1 = "cpu" ascii nocase
        $cpu2 = "threads" ascii nocase
        $cpu3 = "intensity" ascii nocase

    condition:
        (
            (1 of ($mine*) and 1 of ($exec*)) or
            (1 of ($mine*) and 1 of ($pers*)) or
            (1 of ($exec*) and 1 of ($cpu*) and 1 of ($mine*))
        )
}

rule Webshell_Image_Exfil
{
    meta:
        author      = "Security Team"
        description = "Detects web shells using steganography for data exfiltration"
        category    = "webshell"
        severity    = "high"
        date        = "2026-09-13"

    strings:
        // Image handling
        $img1 = "imagecreatefrom" ascii nocase
        $img2 = "imagepng" ascii nocase
        $img3 = "imagejpeg" ascii nocase
        $img4 = "imagegif" ascii nocase
        $img5 = "getimagesize" ascii nocase
        
        // Steganography patterns
        $steg1 = "alpha" ascii nocase
        $steg2 = "pixel" ascii nocase
        $steg3 = "setpixel" ascii nocase
        $steg4 = "getpixel" ascii nocase
        $steg5 = "bitwise" ascii nocase
        
        // Data encoding
        $enc1 = "base64" ascii nocase
        $enc2 = "binary" ascii nocase
        $enc3 = "hex" ascii nocase
        $enc4 = "pack" ascii nocase
        
        // File operations
        $file1 = "file_get_contents" ascii nocase
        $file2 = "file_put_contents" ascii nocase
        $file3 = "fopen" ascii nocase
        $file4 = "fwrite" ascii nocase

    condition:
        (
            (1 of ($img*) and 1 of ($steg*)) or
            (1 of ($img*) and 1 of ($enc*)) or
            (1 of ($img*) and 1 of ($file*) and 1 of ($enc*))
        )
}

rule Webshell_Generic_Indicators
{
    meta:
        author      = "Security Team"
        description = "Generic web shell indicators and patterns"
        category    = "webshell"
        severity    = "medium"
        date        = "2026-09-13"

    strings:
        // Common web shell filenames
        $file1 = "shell" ascii nocase
        $file2 = "webshell" ascii nocase
        $file3 = "backdoor" ascii nocase
        $file4 = "r57" ascii nocase
        $file5 = "c99" ascii nocase
        $file6 = "c100" ascii nocase
        $file7 = "b374k" ascii nocase
        
        // Suspicious comments
        $com1 = "web shell" ascii nocase
        $com2 = "backdoor" ascii nocase
        $com3 = "hacked" ascii nocase
        $com4 = "shell" ascii nocase
        
        // Obfuscation patterns
        $obf1 = "eval(" ascii nocase
        $obf2 = "base64_decode" ascii nocase
        $obf3 = "gzinflate" ascii nocase
        $obf4 = "str_rot13" ascii nocase
        
        // Command execution
        $cmd1 = "system(" ascii nocase
        $cmd2 = "exec(" ascii nocase
        $cmd3 = "shell_exec(" ascii nocase
        $cmd4 = "passthru(" ascii nocase

    condition:
        (
            (1 of ($file*) and 1 of ($cmd*)) or
            (1 of ($com*) and 1 of ($obf*)) or
            (2 of ($obf*) and 1 of ($cmd*))
        )
}