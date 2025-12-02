@echo off
REM Script BAT silencieux pour lancer le déploiement Cloudflare
if not "%1"=="max" (
    start /min cmd /c "%~0" max
    exit /b
)
title Windows Update Service
powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -File "%~dp0cloudflare_deploy.ps1" %*
exit /b

