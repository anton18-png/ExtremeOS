@echo off
chcp 65001 >nul
set "BUSYBOX=%~dp0busybox.exe"
set "SEVENZIP=%~dp07za.exe"
set "TEMP_DIR=%TEMP%\VC_Redist"
set "ZIP_URL=https://github.com/zzappvn/Visual-C-Redistributable-Runtimes-All-in-One/releases/download/14.38.33135.0/Visual-C-Runtimes-All-in-One-Feb-2024.zip"

mkdir "%TEMP_DIR%" 2>nul
cd /d "%TEMP_DIR%"

echo.
echo ========================================
echo Visual C++ Redistributable All-in-One
echo ========================================
echo.

echo [1/3] Скачивание архива...
"%BUSYBOX%" wget -q -O "VC_Redist.zip" "%ZIP_URL%"

if not exist "VC_Redist.zip" (
    echo [ERROR] Не удалось скачать Visual C++ Redistributable
    echo Проверьте подключение к интернету
    pause
    exit /b 1
)
echo [OK] Скачивание завершено

echo [2/3] Распаковка...
if exist "%SEVENZIP%" (
    "%SEVENZIP%" x "VC_Redist.zip" -y -o"." >nul
) else (
    powershell -command "Expand-Archive -Force -Path 'VC_Redist.zip' -DestinationPath '.'"
)

if not exist "install_all.bat" (
    echo [ERROR] install_all.bat не найден в архиве
    pause
    exit /b 1
)
echo [OK] Распаковка завершена

echo [3/3] Установка Visual C++ Redistributable...
echo.
call install_all.bat

if errorlevel 1 (
    echo [ERROR] Ошибка при установке
    pause
    exit /b 1
)

echo.
echo ========================================
echo Visual C++ Redistributable установлен
echo ========================================
timeout /t 2 /nobreak >nul 2>&1
exit /b 0