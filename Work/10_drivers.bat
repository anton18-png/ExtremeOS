@echo off
cd /d "%~dp0"
timeout /t 3 /nobreak >nul 2>&1

if exist "%USERPROFILE%\Desktop\Drivers" (
    pnputil /add-driver "%USERPROFILE%\Desktop\Drivers\*.inf" /subdirs /install >nul 2>&1
    timeout /t 3 /nobreak >nul 2>&1
)
exit /b