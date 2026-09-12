/*
 *   SafeBox behavioral detection rules
 *
 *   IMPORTANT:
 *   These rules identify capabilities/patterns.
 *   A match is NOT automatically malware.
 *
 *   SafeBox combines these signals with:
 *     - ClamAV
 *     - heuristics
 *     - multiple behavior categories
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
