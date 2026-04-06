@echo off
cd /d "%~dp0"
set "TI=NSudoLG -U:T -P:E -ShowWindowMode:Hide -Wait cmd.exe /c"

%TI% taskkill /f /im MicrosoftEdge.exe >nul 2>&1
%TI% taskkill /f /im MicrosoftEdgeUpdate.exe >nul 2>&1
start /wait "" "%~dp0setup.exe" --uninstall --system-level --force-uninstall --msedge >nul 2>&1
start /wait "" "%~dp0setup.exe" --uninstall --system-level --force-uninstall --msedgewebview >nul 2>&1
exit /b