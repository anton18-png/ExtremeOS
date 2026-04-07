@echo off
chcp 65001 >nul
cd /d "%~dp0"
set "DESKTOP=%USERPROFILE%\Desktop"
set "BUSYBOX=%~dp0busybox.exe"

echo Скачивание CatsXP...
"%BUSYBOX%" wget -q -O "CatsXP.zip" "https://b2.catsxp.com/catsxp_portable/win_x64/portable_x64_release_146_6_3_5.zip"

if exist "CatsXP.zip" (
    echo Распаковка CatsXP на рабочий стол...
    "%~dp07za.exe" x "CatsXP.zip" -y -o"%DESKTOP%\CatsXP" >nul
    del CatsXP.zip
    echo Готово! Папка CatsXP на рабочем столе
    explorer "%DESKTOP%\CatsXP"
) else (
    echo Ошибка: не удалось скачать CatsXP
)
exit /b