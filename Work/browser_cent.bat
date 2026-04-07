@echo off
chcp 65001 >nul
cd /d "%~dp0"
set "DESKTOP=%USERPROFILE%\Desktop"
set "BUSYBOX=%~dp0busybox.exe"

echo Скачивание Cent Browser...
"%BUSYBOX%" wget -q -O "%DESKTOP%\CentBrowser.exe" "https://static.centbrowser.com/win_stable/5.2.1168.83/centbrowser_5.2.1168.83_x64_portable.exe"

if exist "%DESKTOP%\CentBrowser.exe" (
    echo Готово! CentBrowser.exe на рабочем столе
) else (
    echo Ошибка: не удалось скачать Cent Browser
)
exit /b