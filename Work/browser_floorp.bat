@echo off
chcp 65001 >nul
cd /d "%~dp0"
set "DESKTOP=%USERPROFILE%\Desktop"
set "BUSYBOX=%~dp0busybox.exe"

echo Скачивание Floorp...
"%BUSYBOX%" wget -q -O "Floorp.7z" "https://github.com/Floorp-Projects/Floorp-Portable-v2/releases/latest/download/floorp-windows-x86_64.portable.7z"

if exist "Floorp.7z" (
    echo Распаковка Floorp на рабочий стол...
    "%~dp07za.exe" x "Floorp.7z" -y -o"%DESKTOP%\Floorp" >nul
    del Floorp.7z
    echo Готово! Папка Floorp на рабочем столе
    explorer "%DESKTOP%\Floorp"
) else (
    echo Ошибка: не удалось скачать Floorp
)
exit /b