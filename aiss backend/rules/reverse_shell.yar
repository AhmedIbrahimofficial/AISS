rule ReverseShell_Bash
{
    meta:
        description = "Detects bash/sh reverse shell payloads"
        severity    = "CRITICAL"
        author      = "AISS"
    strings:
        $s1 = "/dev/tcp/" ascii nocase
        $s2 = "bash -i" ascii nocase
        $s3 = "sh -i" ascii nocase
        $s4 = "exec 5<>/dev/tcp" ascii nocase
        $s5 = "0>&1 2>&1" ascii nocase
    condition:
        any of them
}

rule ReverseShell_Netcat
{
    meta:
        description = "Detects netcat reverse shell usage"
        severity    = "CRITICAL"
        author      = "AISS"
    strings:
        $s1 = "nc -e /bin/bash" ascii nocase
        $s2 = "nc -e /bin/sh" ascii nocase
        $s3 = "ncat --exec" ascii nocase
        $s4 = "nc.exe -e cmd" ascii nocase
    condition:
        any of them
}

rule ReverseShell_Python
{
    meta:
        description = "Detects Python reverse shell payloads"
        severity    = "CRITICAL"
        author      = "AISS"
    strings:
        $s1 = "import socket,subprocess,os" ascii
        $s2 = "socket.connect(" ascii
        $s3 = "os.dup2(s.fileno()" ascii
        $s4 = "pty.spawn" ascii
    condition:
        2 of them
}

rule ReverseShell_PowerShell
{
    meta:
        description = "Detects PowerShell reverse shell"
        severity    = "CRITICAL"
        author      = "AISS"
    strings:
        $s1 = "New-Object Net.Sockets.TCPClient" ascii nocase
        $s2 = "System.Net.Sockets.TCPClient" ascii nocase
        $s3 = "$stream.Write($sendbyte" ascii nocase
        $s4 = "Invoke-Expression" ascii nocase
        $s5 = "DownloadString('http" ascii nocase
    condition:
        2 of them
}
