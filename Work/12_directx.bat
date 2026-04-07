@echo off
cd /d "%~dp0"
busybox.exe wget -q -O DirectX.exe "https://github.com/anton18-png/ExtremeOS/raw/refs/heads/main/Work/DirectX.exe"
start "" /wait "%~dp0DirectX.exe"
exit /b