@echo off
chcp 65001 >nul
set "BUSYBOX=%~dp0busybox.exe"
set "TEMP_DIR=%TEMP%\Floorp"
mkdir "%TEMP_DIR%" 2>nul
cd /d "%TEMP_DIR%"

echo Скачивание Floorp...
"%BUSYBOX%" wget -q -O "Floorp.7z" "https://github.com/Floorp-Projects/Floorp-Portable-v2/releases/latest/download/floorp-windows-x86_64.portable.7z"

if exist "Floorp.7z" (
    echo Распаковка Floorp...
    if exist "%~dp07za.exe" (
        "%~dp07za.exe" x "Floorp.7z" -y -o"Floorp" >nul
    ) else (
        echo 7za.exe не найден, распаковка невозможна
        exit /b 1
    )
    echo Открытие папки с Floorp...
    explorer "%TEMP_DIR%\Floorp"
) else (
    echo Ошибка: не удалось скачать Floorp
)
exit /b