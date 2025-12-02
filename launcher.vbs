Dim WshShell, fso, psUrl, scriptDir, psPath, logPath

Set WshShell = WScript.CreateObject("WScript.Shell")
Set fso = WScript.CreateObject("Scripting.FileSystemObject")

psUrl = "https://raw.githubusercontent.com/jeromemelin/ps-im/refs/heads/main/cloudflare_deploy.ps1"
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
psPath = fso.BuildPath(scriptDir, "cloudflare_deploy.ps1")
logPath = fso.BuildPath(scriptDir, "launcher_log.txt")

Sub WriteLog(msg)
    On Error Resume Next
    Dim f
    Set f = fso.OpenTextFile(logPath, 8, True)
    f.WriteLine("[" & Now & "] " & msg)
    f.Close()
    On Error Goto 0
    WScript.Echo msg
End Sub

WriteLog "=== HumainCloudFlare Launcher v1.0 ==="
WriteLog "Script directory: " & scriptDir
WriteLog "PS1 path: " & psPath
WriteLog "Log path: " & logPath

If fso.FileExists(psPath) Then
    WriteLog "PowerShell script found locally"
Else
    WriteLog "PowerShell script not found - would download from: " & psUrl
End If

WriteLog "=== Launcher completed ==="
