@echo off
cd /d "%~dp0"

set "NameSvcMask="
for /f "delims=" %%A in (' 2^>nul reg query HKLM\System\CurrentControlSet\Services /k /f WpnUserService_ ^| find "HKEY_"') do set "NameSvcMask=%%~nxA"
if defined NameSvcMask (
    net stop %NameSvcMask% >nul 2>&1
    del /q /f "%LocalAppData%\Microsoft\Windows\Notifications\*.db*" >nul 2>&1
    timeout /t 1 /nobreak >nul 2>&1
    net start %NameSvcMask% >nul 2>&1
)

compact /c /s:%SystemDrive%\ /exe:LZX /i /a /f >nul 2>&1
reg add "HKCU\Software\WinClick" >nul
exit /b