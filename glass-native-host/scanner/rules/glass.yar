/*
 * Glass behavioral detection rules.
 *
 * Matches identify capabilities or patterns.
 * A match is not automatically malware — Glass combines
 * these signals with ClamAV and filename heuristics.
 */

rule Suspicious_Python_Networking
{
    meta:
        description = "Detects common network-capable Python patterns"
        category = "network"
        severity = "informational"

    strings:
        $socket1 = "socket.socket"
        $socket2 = ".connect("
        $socket3 = "socket.connect"
        $http1   = "urllib.request"
        $http2   = "requests.get"
        $http3   = "requests.post"
        $http4   = "http.client"

    condition:
        2 of them
}

rule Suspicious_Process_Execution
{
    meta:
        description = "Detects process or command execution capabilities"
        category = "process_execution"
        severity = "suspicious"

    strings:
        $a = "subprocess.Popen"
        $b = "subprocess.run"
        $c = "subprocess.call"
        $d = "os.system"
        $e = "os.exec"
        $f = "os.spawn"

    condition:
        1 of them
}

rule Suspicious_File_Activity
{
    meta:
        description = "Detects potentially important file operations"
        category = "file_activity"
        severity = "informational"

    strings:
        $a = "open("
        $b = ".write("
        $c = "os.remove"
        $d = "os.unlink"
        $e = "shutil.copy"
        $f = "shutil.move"

    condition:
        2 of them
}

rule Suspicious_Persistence
{
    meta:
        description = "Detects common persistence-related patterns"
        category = "persistence"
        severity = "high"

    strings:
        $linux1 = "/etc/cron"
        $linux2 = "crontab"
        $linux3 = ".config/autostart"
        $linux4 = "systemctl enable"
        $win1 = "CurrentVersion\\Run"
        $win2 = "CurrentVersion\\RunOnce"
        $win3 = "Startup"

    condition:
        1 of them
}

rule Suspicious_Obfuscation
{
    meta:
        description = "Detects common command/encoding patterns"
        category = "obfuscation"
        severity = "suspicious"

    strings:
        $a = "base64.b64decode"
        $b = "base64.b64encode"
        $c = "exec("
        $d = "eval("
        $e = "powershell -enc"
        $f = "FromBase64String"

    condition:
        2 of them
}

rule Suspicious_PowerShell_Encoded
{
    meta:
        description = "Detects encoded or hidden PowerShell command patterns"
        category = "process_execution"
        severity = "suspicious"

    strings:
        $a = "-EncodedCommand" nocase
        $b = "-enc " nocase
        $c = "FromBase64String" nocase
        $d = "IEX(" nocase
        $e = "Invoke-Expression" nocase
        $f = "DownloadString" nocase

    condition:
        2 of them
}

rule Suspicious_JS_Network
{
    meta:
        description = "Detects JavaScript that both evaluates code and talks to the network"
        category = "network"
        severity = "suspicious"

    strings:
        $eval = "eval("
        $fn = "Function("
        $fetch = "fetch("
        $xhr = "XMLHttpRequest"
        $ws = "WebSocket"

    condition:
        1 of ($eval, $fn) and 1 of ($fetch, $xhr, $ws)
}

rule Suspicious_PE_Packed
{
    meta:
        description = "Detects a Windows PE header with common packer or runtime strings"
        category = "obfuscation"
        severity = "informational"

    strings:
        $mz = "MZ"
        $upx = "UPX0"
        $upx2 = "UPX1"
        $themida = "Themida"
        $aspack = "aPLib"

    condition:
        $mz at 0 and 1 of ($upx, $upx2, $themida, $aspack)
}

rule Suspicious_Office_OLE_Macro
{
    meta:
        description = "Detects Office OLE / VBA macro markers"
        category = "macros"
        severity = "suspicious"

    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $vba = "VBA" ascii
        $auto = "Auto_Open" nocase
        $docopen = "Document_Open" nocase
        $xlopen = "Workbook_Open" nocase

    condition:
        $ole at 0 and 1 of ($vba, $auto, $docopen, $xlopen)
}
