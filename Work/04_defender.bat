@echo off
cd /d "%~dp0"

timeout /t 4 /nobreak >nul 2>&1

if exist "%USERPROFILE%\Desktop\DK\DefenderKiller.bat" set "DK=1" & set "DK=%USERPROFILE%\Desktop\DK\DefenderKiller.bat"
if exist "%USERPROFILE%\Desktop\DefenderKiller.bat" set "DK=1" & set "DK=%USERPROFILE%\Desktop\DefenderKiller.bat"
if exist "%USERPROFILE%\Desktop\DefenderKiller\DefenderKiller.bat" set "DK=1" & set "DK=%USERPROFILE%\Desktop\DefenderKiller\DefenderKiller.bat"

if defined DK (
    start /wait "" "!DK!" /DelWD
    :check
    reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Windows Defender/Operational" >nul 2>&1 && (
        timeout /t 10 >nul
        goto check
    )
)
exit /b