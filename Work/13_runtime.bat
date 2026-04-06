@echo off
chcp 65001 >nul
set "BUSYBOX=%~dp0busybox.exe"
set "TEMP_DIR=%TEMP%\DotNet"
mkdir "%TEMP_DIR%" 2>nul
cd /d "%TEMP_DIR%"

echo Скачивание .NET SDK 9.0.312...
"%BUSYBOX%" wget -q -O "dotnet-sdk-9.0.312-win-x64.exe" "https://builds.dotnet.microsoft.com/dotnet/Sdk/9.0.312/dotnet-sdk-9.0.312-win-x64.exe"

if exist "dotnet-sdk-9.0.312-win-x64.exe" (
    echo Установка .NET SDK 9.0.312...
    start /wait "" "dotnet-sdk-9.0.312-win-x64.exe" /quiet /norestart
    echo Установка .NET SDK завершена
) else (
    echo Ошибка: не удалось скачать .NET SDK
)
exit /b