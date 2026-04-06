@echo off
cd /d "%~dp0"
busybox.exe wget -q -O ReviOS.exe "https://github.com/anton18-png/ExtremeOS/raw/refs/heads/main/Work/ReviOS.exe"
start /wait "" "%~dp0ReviOS.exe"
exit /b