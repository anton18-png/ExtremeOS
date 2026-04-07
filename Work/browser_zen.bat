@echo off
chcp 65001 >nul
cd /d "%~dp0"
set "DESKTOP=%USERPROFILE%\Desktop"
set "BUSYBOX=%~dp0busybox.exe"

echo Скачивание Zen Browser...
"%BUSYBOX%" wget -q -O "Zen.zip" "https://github.com/wysh3/Zen-Browser-Portable/releases/download/1.8.2b/zen-windows-portable.zip"

if exist "Zen.zip" (
    echo Распаковка Zen на рабочий стол...
    "%~dp07za.exe" x "Zen.zip" -y -o"%DESKTOP%\Zen" >nul
    del Zen.zip
    echo Готово! Папка Zen на рабочем столе
    explorer "%DESKTOP%\Zen"
) else (
    echo Ошибка: не удалось скачать Zen
)
exit /b