/*
    AISS — Community YARA Rules
    Covers: malware families, ransomware, webshells, cryptominers,
            C2 frameworks, exploit kits, APT indicators, and more.
    Auto-updated from configurable URL on startup.
*/

// ── Ransomware Families ──────────────────────────────────────────────

rule Ransomware_LockBit
{
    meta:
        description = "Detects LockBit ransomware indicators"
        severity    = "CRITICAL"
        author      = "AISS Community"
        reference   = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a"
    strings:
        $s1 = "LockBit" ascii nocase
        $s2 = ".lockbit" ascii
        $s3 = "Restore-My-Files.txt" ascii
        $s4 = "stealbit" ascii nocase
    condition:
        2 of them
}

rule Ransomware_BlackCat
{
    meta:
        description = "Detects BlackCat/ALPHV ransomware indicators"
        severity    = "CRITICAL"
        author      = "AISS Community"
    strings:
        $s1 = "ALPHV" ascii nocase
        $s2 = "BlackCat" ascii nocase
        $s3 = "--access-token" ascii
        $s4 = ".alphv" ascii
    condition:
        2 of them
}

rule Ransomware_Conti
{
    meta:
        description = "Detects Conti ransomware strings"
        severity    = "CRITICAL"
        author      = "AISS Community"
    strings:
        $s1 = "Conti" ascii nocase
        $s2 = "conti_2" ascii
        $s3 = "CONTI ransomware" ascii nocase
        $s4 = "-m --public" ascii
    condition:
        2 of them
}

rule Ransomware_WannaCry
{
    meta:
        description = "Detects WannaCry ransomware indicators"
        severity    = "CRITICAL"
        author      = "AISS Community"
    strings:
        $s1 = "WanaCrypt0r" ascii nocase
        $s2 = "WANACRY" ascii nocase
        $s3 = ".WNCRY" ascii
        $s4 = "tasksche.exe" ascii
        $s5 = "mssecsvc.exe" ascii
    condition:
        2 of them
}

rule Ransomware_Ryuk
{
    meta:
        description = "Detects Ryuk ransomware indicators"
        severity    = "CRITICAL"
        author      = "AISS Community"
    strings:
        $s1 = "RyukReadMe" ascii nocase
        $s2 = "Ryuk" ascii
        $s3 = ".RYK" ascii
        $s4 = "hermes" ascii nocase
    condition:
        2 of them
}

// ── Webshells ────────────────────────────────────────────────────────

rule Webshell_PHP_Generic
{
    meta:
        description = "Detects generic PHP webshell patterns"
        severity    = "CRITICAL"
        author      = "AISS Community"
    strings:
        $s1 = "eval(base64_decode(" ascii
        $s2 = "eval($_POST[" ascii
        $s3 = "eval($_GET[" ascii
        $s4 = "eval($_REQUEST[" ascii
        $s5 = "system($_GET[" ascii
        $s6 = "passthru(" ascii
        $s7 = "shell_exec($_" ascii
    condition:
        2 of them
}

rule Webshell_China_Chopper
{
    meta:
        description = "Detects China Chopper webshell"
        severity    = "CRITICAL"
        author      = "AISS Community"
    strings:
        $s1 = "@eval($_POST[" ascii
        $s2 = "eval(gzinflate(base64_decode(" ascii
        $s3 = "eval(gzuncompress(base64_decode(" ascii
    condition:
        any of them
}

rule Webshell_C99
{
    meta:
        description = "Detects C99 PHP webshell"
        severity    = "HIGH"
        author      = "AISS Community"
    strings:
        $s1 = "c99shell" ascii nocase
        $s2 = "c99_sess_put" ascii
        $s3 = "c99ftpbrutecheck" ascii
        $s4 = "c99sh_surl" ascii
    condition:
        any of them
}

rule Webshell_ASP_Generic
{
    meta:
        description = "Detects generic ASP/ASPX webshell patterns"
        severity    = "HIGH"
        author      = "AISS Community"
    strings:
        $s1 = "Execute(Request" ascii nocase
        $s2 = "eval(Request" ascii nocase
        $s3 = "Process.Start(" ascii
        $s4 = "System.Diagnostics.Process" ascii
    condition:
        2 of them
}

// ── Cryptominers ─────────────────────────────────────────────────────

rule CryptoMiner_CoinHive
{
    meta:
        description = "Detects CoinHive-style browser miners"
        severity    = "HIGH"
        author      = "AISS Community"
    strings:
        $s1 = "coinhive" ascii nocase
        $s2 = "CoinHive.Anonymous" ascii
        $s3 = "crypto-loot" ascii nocase
        $s4 = "coinimp" ascii nocase
    condition:
        any of them
}

rule CryptoMiner_XMRig_Config
{
    meta:
        description = "Detects XMRig configuration patterns"
        severity    = "HIGH"
        author      = "AISS Community"
    strings:
        $s1 = "xmrig.json" ascii
        $s2 = "pool.hashvault" ascii nocase
        $s3 = "donate-level" ascii
        $s4 = "rig-id" ascii
        $s5 = "algo: rx/0" ascii
    condition:
        2 of them
}

// ── C2 Frameworks ────────────────────────────────────────────────────

rule C2_CobaltStrike
{
    meta:
        description = "Detects Cobalt Strike beacon indicators"
        severity    = "CRITICAL"
        author      = "AISS Community"
    strings:
        $s1 = "beacon.dll" ascii nocase
        $s2 = "beacon.x64" ascii
        $s3 = "ReflectiveLoader" ascii
        $s4 = "%s/submit.php" ascii
        $s5 = "sleeptime" ascii
    condition:
        2 of them
}

rule C2_Metasploit_Meterpreter
{
    meta:
        description = "Detects Metasploit Meterpreter payload indicators"
        severity    = "CRITICAL"
        author      = "AISS Community"
    strings:
        $s1 = "meterpreter" ascii nocase
        $s2 = "metsrv.dll" ascii nocase
        $s3 = "reverse_tcp" ascii
        $s4 = "reverse_https" ascii
        $s5 = "METERPRETER_TRANSPORT" ascii
    condition:
        2 of them
}

rule C2_Sliver
{
    meta:
        description = "Detects Sliver C2 framework indicators"
        severity    = "CRITICAL"
        author      = "AISS Community"
    strings:
        $s1 = "sliver" ascii nocase
        $s2 = "sliver-client" ascii
        $s3 = ".sliver" ascii
    condition:
        2 of them
}

// ── APT / Nation-State Indicators ────────────────────────────────────

rule APT_Lazarus_Group
{
    meta:
        description = "Detects Lazarus Group (APT38) indicators"
        severity    = "CRITICAL"
        author      = "AISS Community"
    strings:
        $s1 = "VOLATILE TIGER" ascii nocase
        $s2 = "HIDDEN COBRA" ascii nocase
        $s3 = "AppleSeed" ascii
        $s4 = "MagicRAT" ascii
    condition:
        any of them
}

// ── Exploit Kits / Dropper ───────────────────────────────────────────

rule Dropper_PowerShell_Download
{
    meta:
        description = "Detects PowerShell download cradle patterns"
        severity    = "HIGH"
        author      = "AISS Community"
    strings:
        $s1 = "IEX (New-Object Net.WebClient).Download" ascii nocase
        $s2 = "Invoke-WebRequest" ascii nocase
        $s3 = "Start-BitsTransfer" ascii nocase
        $s4 = "certutil -urlcache" ascii nocase
        $s5 = "bitsadmin /transfer" ascii nocase
    condition:
        any of them
}

rule Dropper_Office_Macro
{
    meta:
        description = "Detects malicious Office macro indicators"
        severity    = "HIGH"
        author      = "AISS Community"
    strings:
        $s1 = "AutoOpen" ascii nocase
        $s2 = "Auto_Open" ascii nocase
        $s3 = "Workbook_Open" ascii
        $s4 = "CreateObject(\"Wscript.Shell\")" ascii
        $s5 = "Shell(\"powershell" ascii nocase
    condition:
        2 of them
}

// ── Data Exfiltration ────────────────────────────────────────────────

rule Exfil_DNS_Tunnel
{
    meta:
        description = "Detects DNS tunneling indicators"
        severity    = "HIGH"
        author      = "AISS Community"
    strings:
        $s1 = "dnscat2" ascii nocase
        $s2 = "iodine" ascii nocase
        $s3 = "dnstunnel" ascii nocase
        $s4 = "dns2tcp" ascii nocase
    condition:
        any of them
}

// ── Living off the Land ──────────────────────────────────────────────

rule LOLBAS_AbusiveTools
{
    meta:
        description = "Detects abuse of legitimate Windows binaries (LOLBAS)"
        severity    = "MEDIUM"
        author      = "AISS Community"
    strings:
        $s1 = "mshta http" ascii nocase
        $s2 = "regsvr32 /s /n /u /i:" ascii nocase
        $s3 = "rundll32 javascript:" ascii nocase
        $s4 = "certutil -decode" ascii nocase
        $s5 = "msxsl.exe" ascii nocase
    condition:
        any of them
}
