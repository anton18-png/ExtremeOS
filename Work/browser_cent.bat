@echo off
chcp 65001 >nul
set "BUSYBOX=%~dp0busybox.exe"
set "TEMP_DIR=%TEMP%\CentBrowser"
mkdir "%TEMP_DIR%" 2>nul
cd /d "%TEMP_DIR%"

echo Скачивание Cent Browser...
"%BUSYBOX%" wget -q -O "CentBrowser.exe" "https://static.centbrowser.com/win_stable/5.2.1168.83/centbrowser_5.2.1168.83_x64_portable.exe"

if exist "CentBrowser.exe" (
    echo Запуск установщика Cent Browser...
    start "" "CentBrowser.exe"
    echo Установщик запущен
) else (
    echo Ошибка: не удалось скачать Cent Browser
)
exit /b