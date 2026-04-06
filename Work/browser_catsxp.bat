@echo off
chcp 65001 >nul
set "BUSYBOX=%~dp0busybox.exe"
set "TEMP_DIR=%TEMP%\CatsXP"
mkdir "%TEMP_DIR%" 2>nul
cd /d "%TEMP_DIR%"

echo Скачивание CatsXP...
"%BUSYBOX%" wget -q -O "CatsXP.zip" "https://b2.catsxp.com/catsxp_portable/win_x64/portable_x64_release_146_6_3_5.zip"

if exist "CatsXP.zip" (
    echo Распаковка CatsXP...
    if exist "%~dp07za.exe" (
        "%~dp07za.exe" x "CatsXP.zip" -y -o"CatsXP" >nul
    ) else (
        echo 7za.exe не найден, распаковка через PowerShell...
        powershell -command "Expand-Archive -Force -Path 'CatsXP.zip' -DestinationPath 'CatsXP'"
    )
    echo Открытие папки с CatsXP...
    explorer "%TEMP_DIR%\CatsXP"
) else (
    echo Ошибка: не удалось скачать CatsXP
)
exit /b