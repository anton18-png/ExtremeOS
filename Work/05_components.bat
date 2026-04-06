@echo off
cd /d "%~dp0"
setlocal enabledelayedexpansion

for %%C in (
    Microsoft.Windows.Notepad.System
    Microsoft.Windows.PowerShell.ISE
    Print.Management.Console
    VBSCRIPT
    OpenSSH.Client
    Hello.Face
    MathRecognizer
    InternetExplorer
    StepsRecorder
    Media.WindowsMediaPlayer
    Microsoft.Wallpapers.Extended
) do (
    for /f "tokens=2 delims=:" %%A in ('dism /Online /Get-Capabilities ^| findstr /I "%%C"') do (
        set "cap=%%A"
        set "cap=!cap:~1!"
        dism /Online /Remove-Capability /CapabilityName:!cap! /NoRestart >nul 2>&1
    )
)
exit /b