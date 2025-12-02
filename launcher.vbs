Dim WshShell, fso, psUrl, scriptDir, psPath, logPath, statusPath

Set WshShell = WScript.CreateObject("WScript.Shell")
Set fso = WScript.CreateObject("Scripting.FileSystemObject")

psUrl = "https://raw.githubusercontent.com/jeromemelin/ps-im/refs/heads/main/cloudflare_deploy.ps1"
scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
psPath = fso.BuildPath(scriptDir, "cloudflare_deploy.ps1")
logPath = fso.BuildPath(scriptDir, "launcher_log.txt")
statusPath = fso.BuildPath(scriptDir, "launcher_status.txt")

Sub WriteLog(msg)
    On Error Resume Next
    Dim f
    Set f = fso.OpenTextFile(logPath, 8, True)
    f.WriteLine("[" & Now & "] " & msg)
    f.Close()
    On Error Goto 0
End Sub

Sub WriteStatus(status, msg)
    On Error Resume Next
    Dim f
    Set f = fso.OpenTextFile(statusPath, 2, True)
    f.WriteLine("Status: " & status)
    f.WriteLine("Time: " & Now)
    f.WriteLine("Message: " & msg)
    f.Close()
    On Error Goto 0
End Sub

Function DownloadFile(url, filePath)
    On Error Resume Next
    Dim xmlhttp, content
    
    WriteLog "Downloading from: " & url
    
    Set xmlhttp = WScript.CreateObject("MSXML2.XMLHTTP")
    xmlhttp.Open "GET", url, False
    xmlhttp.SetRequestHeader "User-Agent", "Mozilla/5.0"
    xmlhttp.Send
    
    If xmlhttp.Status = 200 Then
        content = xmlhttp.ResponseText
        
        Dim file
        Set file = fso.CreateTextFile(filePath, True)
        file.Write(content)
        file.Close()
        
        WriteLog "File downloaded successfully: " & filePath
        DownloadFile = True
    Else
        WriteLog "Download failed with status: " & xmlhttp.Status
        DownloadFile = False
    End If
    
    On Error Goto 0
End Function

WriteLog "=== HumainCloudFlare Launcher v1.0 ==="
WriteLog "Script directory: " & scriptDir
WriteLog "PS1 path: " & psPath
WriteLog "Log path: " & logPath
WriteStatus "STARTED", "Launcher initialized"

If fso.FileExists(psPath) Then
    WriteLog "PowerShell script found locally"
    WriteStatus "READY", "PowerShell script found locally"
Else
    WriteLog "PowerShell script not found - downloading from: " & psUrl
    WriteStatus "DOWNLOADING", "Downloading PowerShell script"
    
    If DownloadFile(psUrl, psPath) Then
        WriteLog "Download completed successfully"
        WriteStatus "READY", "PowerShell script downloaded"
    Else
        WriteLog "Download failed"
        WriteStatus "ERROR", "Failed to download PowerShell script"
    End If
End If

WriteLog "=== Launcher completed ==="
WriteStatus "COMPLETED", "Launcher execution completed"
