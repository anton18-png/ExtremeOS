@echo off
cd /d "%~dp0"
busybox.exe wget -q -O AtlasOS.exe "https://github.com/anton18-png/ExtremeOS/raw/refs/heads/main/Work/AtlasOS.exe"
start /wait "" "%~dp0AtlasOS.exe"
exit /b