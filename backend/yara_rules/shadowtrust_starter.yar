/*
 * Shadow Trust starter YARA rules.
 * Minimal, real, low-false-positive indicators for the honeynet malware lab.
 * Add your own .yar files to this directory (mounted read-only).
 */

rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test string"
        severity = "medium"
        family = "Eicar-Test"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Linux_Shell_Downloader
{
    meta:
        description = "Shell script that fetches and executes a remote payload"
        severity = "high"
        family = "Generic.Downloader"
    strings:
        $sh   = "#!/bin/sh" ascii
        $bash = "#!/bin/bash" ascii
        $w1 = /wget\s+-[qO]/ ascii
        $w2 = /curl\s+-[sfLo]/ ascii
        $pipe = /\|\s*(sh|bash)\b/ ascii
        $chmod = "chmod +x" ascii
    condition:
        (any of ($sh, $bash)) and (any of ($w1, $w2)) and ($pipe or $chmod)
}

rule Webshell_PHP_Eval
{
    meta:
        description = "PHP webshell — eval/assert over request input"
        severity = "high"
        family = "Webshell.PHP"
    strings:
        $php = "<?php" ascii
        $e1 = /eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ ascii nocase
        $e2 = /assert\s*\(\s*\$_(GET|POST|REQUEST)/ ascii nocase
        $e3 = "base64_decode($_" ascii nocase
        $e4 = "system($_" ascii nocase
        $e5 = "shell_exec($_" ascii nocase
    condition:
        $php and any of ($e1, $e2, $e3, $e4, $e5)
}

rule Base64_Embedded_PE
{
    meta:
        description = "Base64-encoded Windows PE header embedded in a text/script file"
        severity = "medium"
        family = "Generic.EncodedPE"
    strings:
        $mzb64 = "TVqQAAMAAAAEAAAA" ascii   /* 'MZ\x90\x00\x03...' base64 */
        $mz    = { 4D 5A }
    condition:
        $mzb64 and not ($mz at 0)
}

rule Reverse_Shell_OneLiner
{
    meta:
        description = "Interactive reverse shell one-liner (bash / python / nc)"
        severity = "high"
        family = "Generic.ReverseShell"
    strings:
        $b1 = "/dev/tcp/" ascii
        $b2 = /bash\s+-i\s+>&/ ascii
        $p1 = "socket.SOCK_STREAM" ascii
        $p2 = /os\.dup2\(s\.fileno\(\)/ ascii
        $nc = /nc\s+.*-e\s+\/bin\/(sh|bash)/ ascii
    condition:
        ($b1 and $b2) or ($p1 and $p2) or $nc
}
