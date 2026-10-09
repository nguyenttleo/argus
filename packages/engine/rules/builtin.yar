rule EICAR_Test_File : test signature
{
    meta:
        description = "EICAR standard antivirus test file (harmless)"
        severity = "critical"
        weight = 100
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PE_Imports : pe heuristic
{
    meta:
        description = "PE executable referencing process-injection / download-exec APIs"
        severity = "high"
        weight = 62
    strings:
        $a1 = "VirtualAllocEx" ascii wide nocase
        $a2 = "WriteProcessMemory" ascii wide nocase
        $a3 = "CreateRemoteThread" ascii wide nocase
        $a4 = "URLDownloadToFile" ascii wide nocase
        $a5 = "WinExec" ascii wide nocase
        $a6 = "ShellExecuteA" ascii wide nocase
        $a7 = "IsDebuggerPresent" ascii wide nocase
        $a8 = "VirtualProtect" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and 2 of ($a*)
}

rule Office_VBA_Macro : office macro
{
    meta:
        description = "Office document carrying VBA macros or auto-exec hooks"
        severity = "high"
        weight = 55
    strings:
        $vba = "vbaProject.bin" ascii nocase
        $a1 = "Auto_Open" ascii nocase
        $a2 = "AutoOpen" ascii nocase
        $a3 = "Document_Open" ascii nocase
        $a4 = "Workbook_Open" ascii nocase
        $a5 = "Attribute VB_Name" ascii
        $a6 = "Shell(" ascii nocase
    condition:
        any of them
}

rule PDF_Active_Content : pdf
{
    meta:
        description = "PDF containing JavaScript, auto-actions or a launch action"
        severity = "high"
        weight = 52
    strings:
        $js1 = "/JavaScript" nocase
        $js2 = "/JS" nocase
        $oa = "/OpenAction" nocase
        $launch = "/Launch" nocase
        $aa = "/AA" nocase
    condition:
        uint32(0) == 0x46445025 and any of them
}

rule PHP_Webshell_Generic : webshell
{
    meta:
        description = "PHP webshell - code execution driven by request input"
        severity = "critical"
        weight = 88
    strings:
        $php = "<?php"
        $e1 = /eval\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/ nocase
        $e2 = /assert\s*\(\s*\$_(POST|GET|REQUEST)/ nocase
        $e3 = "base64_decode($_" nocase
        $e4 = "system($_" nocase
        $e5 = "shell_exec($_" nocase
        $e6 = "passthru($_" nocase
    condition:
        $php and any of ($e*)
}

rule PowerShell_DownloadExec : powershell
{
    meta:
        description = "Obfuscated / encoded PowerShell download-and-execute"
        severity = "high"
        weight = 60
    strings:
        $i1 = "FromBase64String" nocase
        $i2 = "IEX" nocase
        $i3 = "Invoke-Expression" nocase
        $i4 = "-enc" nocase
        $i5 = "-nop" nocase
        $i6 = "DownloadString" nocase
        $i7 = "WebClient" nocase
        $i8 = "hidden" nocase
    condition:
        3 of them
}

rule Windows_Script_Dropper : script
{
    meta:
        description = "WSH/JS/VBS script using shell-exec or ActiveX to drop payloads"
        severity = "high"
        weight = 58
    strings:
        $s1 = "WScript.Shell" nocase
        $s2 = "ActiveXObject" nocase
        $s3 = "ADODB.Stream" nocase
        $s4 = "powershell" nocase
        $s5 = "cmd /c" nocase
        $s6 = ".Run(" nocase
    condition:
        2 of them
}
