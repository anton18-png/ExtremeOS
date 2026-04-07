@echo off
chcp 65001 >nul
cd /d "%~dp0"
set "DESKTOP=%USERPROFILE%\Desktop"
set "BUSYBOX=%~dp0busybox.exe"

echo Скачивание Brave Portable...
"%BUSYBOX%" wget -q -O "%DESKTOP%\Brave-Setup.exe" "https://github.com/portapps/brave-portable/releases/download/1.85.118-98/brave-portable-win64-1.85.118-98-setup.exe"

if exist "%DESKTOP%\Brave-Setup.exe" (
    echo Готово! Brave-Setup.exe на рабочем столе
    echo Запустите его для установки
) else (
    echo Ошибка: не удалось скачать Brave
)
exit /b