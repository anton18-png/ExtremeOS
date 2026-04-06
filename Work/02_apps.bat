@echo off
cd /d "%~dp0"
set "TI=NSudoLG -U:T -P:E -ShowWindowMode:Hide -Wait cmd.exe /c"

PowerShell -NoProfile -ExecutionPolicy Bypass -Command "Get-AppxPackage | Where-Object { $_.NonRemovable -eq $false } | ForEach-Object { Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue }" >nul 2>&1
reg add "HKLM\Software\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f >nul 2>&1

taskkill /f /im OneDrive.exe >nul 2>&1
%SystemRoot%\System32\OneDriveSetup.exe /uninstall >nul 2>&1
for %%P in ("%LocalAppData%\OneDrive" "%ProgramData%\Microsoft OneDrive" "%UserProfile%\OneDrive" "%LocalAppData%\Microsoft\OneDrive") do rd /s /q "%%P" >nul 2>&1
for /d %%i in ("%SystemRoot%\WinSxS\amd64_microsoft-windows-onedrive-setup*") do %TI% rd /s /q "%%i"
for %%F in ("OneDriveSetup.exe" "OneDrive.ico") do %TI% del /q "%SystemRoot%\System32\%%F"
if exist "%SystemRoot%\WinSxS\amd64_microsoft-windows-onedrive-setup*" for /d %%i in ("%SystemRoot%\WinSxS\amd64_microsoft-windows-onedrive-setup*") do %TI% rd /s /q "%%i"
reg delete "HKCU\Software\Microsoft\OneDrive" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\OneDrive" /f >nul 2>&1

rd "%AppData%\Microsoft\Windows\Start Menu\Programs\Accessibility" /Q /S >nul 2>&1
rd "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Accessories\System Tools" /Q /S >nul 2>&1

PowerShell "Start-Process mstsc.exe -ArgumentList '/uninstall' -WindowStyle Hidden -ErrorAction SilentlyContinue"
timeout /t 5 /nobreak >nul 2>&1
taskkill /f /im mstsc.exe >nul 2>&1
exit /b