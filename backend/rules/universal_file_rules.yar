/*
    AISS — Universal File Detection Rules
    These rules run on EVERY file regardless of extension or type.
    Covers: embedded shellcode, PE files in non-exe containers,
    malicious PDFs/Office docs, packed archives, memory-only loaders,
    backdoor strings, and generic high-confidence IOCs.
*/

// ── PE / Executable content in any file ──────────────────────────────

rule Embedded_PE_Header
{
    meta:
        description = "Detects a PE executable header embedded inside any file type (dropper, polyglot, embedded payload)"
        severity    = "HIGH"
        author      = "AISS"
    strings:
        $mz   = { 4D 5A }              // MZ header
        $pe   = { 50 45 00 00 }        // PE signature
        $rich = "Rich"                 // MSVC linker marker (confirms real PE)
    condition:
        $mz at 0 and $pe and $rich
}

rule PE_In_Non_PE_File
{
    meta:
        description = "Detects a PE binary embedded inside a document or archive — classic dropper technique"
        severity    = "HIGH"
        author      = "AISS"
    strings:
        $mz      = { 4D 5A 90 00 }
        $section = ".text" ascii
        $import  = "kernel32.dll" ascii nocase
    condition:
        $mz and $section and $import
}

// ── Shellcode patterns ────────────────────────────────────────────────

rule Shellcode_NOP_Sled
{
    meta:
        description = "Detects classic NOP sled shellcode pattern"
        severity    = "HIGH"
        author      = "AISS"
    strings:
        $nop = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
        $int3 = { CC CC CC CC CC CC CC CC }
    condition:
        any of them
}

rule Shellcode_Common_API_Hashes
{
    meta:
        description = "Detects API hashing patterns common in position-independent shellcode"
        severity    = "HIGH"
        author      = "AISS"
    strings:
        $h1 = { 8B 45 3C }       // MOV EAX, [EBP+0x3C] — PE header walk
        $h2 = { 60 89 E5 31 }    // PUSHAD; MOV EBP,ESP; XOR — shellcode prologue
        $h3 = { FC E8 }          // CLD; CALL — classic Metasploit stub
    condition:
        2 of them
}

// ── Malicious PDF ─────────────────────────────────────────────────────

rule PDF_Embedded_JavaScript
{
    meta:
        description = "Detects embedded JavaScript in PDF — used in PDF exploits"
        severity    = "HIGH"
        author      = "AISS"
    strings:
        $pdf    = { 25 50 44 46 }   // %PDF header
        $js1    = "/JavaScript" ascii
        $js2    = "/JS" ascii
        $action = "/OpenAction" ascii
        $launch = "/Launch" ascii
    condition:
        $pdf at 0 and (($js1 or $js2) and ($action or $launch))
}

rule PDF_Obfuscated_Exploit
{
    meta:
        description = "Detects heavily obfuscated / XOR-encoded PDF exploit payload"
        severity    = "HIGH"
        author      = "AISS"
    strings:
        $pdf  = { 25 50 44 46 }
        $hex1 = "/GoTo" ascii
        $hex2 = "/URI" ascii
        $aa   = "/AA" ascii
        $enc  = "eval(unescape(" ascii nocase
    condition:
        $pdf at 0 and ($enc or ($hex1 and $aa) or ($hex2 and $aa))
}

rule PDF_EmbeddedFile
{
    meta:
        description = "PDF contains an embedded file attachment (dropper)"
        severity    = "MEDIUM"
        author      = "AISS"
    strings:
        $pdf  = { 25 50 44 46 }
        $ef1  = "/EmbeddedFile" ascii
        $ef2  = "/Filespec" ascii nocase
        $ef3  = "/EmbeddedFiles" ascii
    condition:
        $pdf at 0 and any of ($ef1, $ef2, $ef3)
}

// ── Malicious Office Documents ────────────────────────────────────────

rule Office_Macro_AutoExec
{
    meta:
        description = "Detects Office document with auto-executing macro (OLE format)"
        severity    = "HIGH"
        author      = "AISS"
    strings:
        $ole      = { D0 CF 11 E0 A1 B1 1A E1 }   // OLE2 magic
        $auto1    = "AutoOpen" ascii nocase
        $auto2    = "Auto_Open" ascii nocase
        $auto3    = "Workbook_Open" ascii nocase
        $auto4    = "Document_Open" ascii nocase
        $shell    = "Shell" ascii
        $wsh      = "WScript.Shell" ascii nocase
    condition:
        $ole at 0 and (1 of ($auto1,$auto2,$auto3,$auto4)) and (1 of ($shell,$wsh))
}

rule Office_OOXML_Macro
{
    meta:
        description = "Detects OOXML (.docx/.xlsx) with embedded VBA macro project"
        severity    = "HIGH"
        author      = "AISS"
    strings:
        $zip    = { 50 4B 03 04 }          // ZIP/OOXML magic
        $vba1   = "vbaProject.bin" ascii
        $vba2   = "xl/vbaProject.bin" ascii
        $vba3   = "word/vbaProject.bin" ascii
    condition:
        $zip at 0 and any of ($vba1,$vba2,$vba3)
}

rule Office_External_Relationships
{
    meta:
        description = "Detects Office document with external OLE/DDE relationship (template injection)"
        severity    = "HIGH"
        author      = "AISS"
    strings:
        $zip  = { 50 4B 03 04 }
        $ext1 = "Target=\"http" ascii nocase
        $ext2 = "Target=\"ftp" ascii nocase
        $ext3 = "Target=\"smb" ascii nocase
        $type = "External" ascii
    condition:
        $zip at 0 and $type and any of ($ext1,$ext2,$ext3)
}

rule RTF_Exploit_Object
{
    meta:
        description = "Detects RTF file with embedded OLE object — common CVE-2017-11882 vector"
        severity    = "HIGH"
        author      = "AISS"
    strings:
        $rtf  = { 7B 5C 72 74 66 }   // {\rtf
        $obj1 = "\\objdata" ascii nocase
        $obj2 = "\\object" ascii nocase
        $eq   = "Equation.3" ascii
        $ole  = "OLE2Link" ascii
    condition:
        $rtf at 0 and ($eq or $ole or ($obj1 and $obj2))
}

// ── Packed / Obfuscated Binaries ──────────────────────────────────────

rule UPX_Packed
{
    meta:
        description = "Detects UPX-packed executable — often used to evade AV"
        severity    = "MEDIUM"
        author      = "AISS"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX!" ascii
    condition:
        2 of them
}

rule NSIS_Dropper
{
    meta:
        description = "Detects NSIS installer that may be used as a dropper"
        severity    = "MEDIUM"
        author      = "AISS"
    strings:
        $nsis  = "Nullsoft Install System" ascii nocase
        $drop1 = "NullsoftInst" ascii
        $aut   = "AutoIt" ascii
    condition:
        $nsis and any of ($drop1,$aut)
}

rule Generic_Packer_Strings
{
    meta:
        description = "Detects common packer/protector strings used to hide malware"
        severity    = "MEDIUM"
        author      = "AISS"
    strings:
        $p1 = "Themida" ascii
        $p2 = "WinLicense" ascii
        $p3 = "Enigma Protector" ascii
        $p4 = "ExeStealth" ascii
        $p5 = "PEcompact" ascii nocase
        $p6 = ".packed" ascii
    condition:
        any of them
}

// ── Archive containing executable ─────────────────────────────────────

rule ZIP_Contains_Executable
{
    meta:
        description = "ZIP archive containing an executable file (common malware delivery method)"
        severity    = "MEDIUM"
        author      = "AISS"
    strings:
        $zip  = { 50 4B 03 04 }
        $exe1 = ".exe" ascii nocase
        $exe2 = ".dll" ascii nocase
        $exe3 = ".scr" ascii nocase
        $exe4 = ".bat" ascii nocase
        $exe5 = ".ps1" ascii nocase
    condition:
        $zip at 0 and 2 of ($exe1,$exe2,$exe3,$exe4,$exe5)
}

// ── EICAR test file (standard AV test) ───────────────────────────────

rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test string — confirms scanner is working"
        severity    = "LOW"
        author      = "AISS"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
    condition:
        $eicar
}

// ── Generic backdoor / RAT strings ───────────────────────────────────

rule Generic_RAT_Strings
{
    meta:
        description = "Detects generic Remote Access Trojan command strings found in any file type"
        severity    = "HIGH"
        author      = "AISS"
    strings:
        $c1 = "cmd.exe /c" ascii nocase
        $c2 = "cmd /c" ascii nocase
        $c3 = "CreateRemoteThread" ascii
        $c4 = "VirtualAllocEx" ascii
        $c5 = "WriteProcessMemory" ascii
        $c6 = "SetWindowsHookEx" ascii
        $t1 = "keylog" ascii nocase
        $t2 = "screenshot" ascii nocase
        $t3 = "clipboard" ascii nocase
        $t4 = "webcam" ascii nocase
    condition:
        (2 of ($c1,$c2,$c3,$c4,$c5,$c6)) or (2 of ($t1,$t2,$t3,$t4))
}

rule Reverse_Shell_Strings
{
    meta:
        description = "Detects reverse shell payload strings embedded in any file"
        severity    = "CRITICAL"
        author      = "AISS"
    strings:
        $r1 = "/bin/bash -i >& /dev/tcp/" ascii
        $r2 = "bash -i >& /dev/tcp" ascii nocase
        $r3 = "nc -e /bin/sh" ascii nocase
        $r4 = "nc -e /bin/bash" ascii nocase
        $r5 = "python -c 'import socket,subprocess" ascii nocase
        $r6 = "perl -e 'use Socket;" ascii nocase
        $r7 = "ruby -rsocket -e" ascii nocase
        $r8 = "php -r '$sock=fsockopen" ascii nocase
    condition:
        any of them
}

rule Encoded_Payload_Base64
{
    meta:
        description = "Detects base64-encoded payload execution pattern — common obfuscation"
        severity    = "HIGH"
        author      = "AISS"
    strings:
        $b1 = "frombase64string" ascii nocase
        $b2 = "base64_decode" ascii nocase
        $b3 = "Convert.FromBase64String" ascii nocase
        $b4 = "[System.Convert]::FromBase64String" ascii nocase
        $b5 = "b64decode" ascii nocase
        $exec1 = "Invoke-Expression" ascii nocase
        $exec2 = "iex" ascii nocase
        $exec3 = "eval(" ascii nocase
        $exec4 = "exec(" ascii nocase
        $exec5 = "os.system" ascii nocase
        $exec6 = "subprocess" ascii nocase
    condition:
        (any of ($b1,$b2,$b3,$b4,$b5)) and (any of ($exec1,$exec2,$exec3,$exec4,$exec5,$exec6))
}

// ── Network IOC patterns ──────────────────────────────────────────────

rule Hardcoded_C2_Ports
{
    meta:
        description = "Detects hardcoded high-risk C2 port patterns in any file"
        severity    = "MEDIUM"
        author      = "AISS"
    strings:
        $p1 = ":4444" ascii    // Metasploit default
        $p2 = ":1337" ascii    // leet port — common C2
        $p3 = ":31337" ascii   // classic backdoor port
        $p4 = ":6666" ascii    // IRC/botnet
        $p5 = ":6667" ascii    // IRC/botnet
        $p6 = ":6969" ascii    // known RAT port
        $p7 = ":8888" ascii    // common shell handler
        $p8 = ":9999" ascii    // common shell handler
    condition:
        3 of them
}

// ── Credential theft patterns ─────────────────────────────────────────

rule CredentialAccess_LSASS
{
    meta:
        description = "Detects LSASS credential dumping strings found in any file"
        severity    = "CRITICAL"
        author      = "AISS"
    strings:
        $l1 = "lsass.exe" ascii nocase
        $l2 = "MiniDumpWriteDump" ascii
        $l3 = "OpenProcess" ascii
        $l4 = "PROCESS_ALL_ACCESS" ascii
        $l5 = "NtReadVirtualMemory" ascii
        $l6 = "ReadProcessMemory" ascii
    condition:
        $l1 and 2 of ($l2,$l3,$l4,$l5,$l6)
}
