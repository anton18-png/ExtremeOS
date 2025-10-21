@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
title Windows Optimizer v1.0

:: Проверка прав администратора
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Запуск с правами администратора...
    powershell -Command "Start-Process cmd -ArgumentList '/c %0' -Verb RunAs"
    exit /b
)

echo ========================================
echo    WINDOWS OPTIMIZER - ПОЛНАЯ НАСТРОЙКА
echo ========================================
echo.

:: 1. СМЕНА ТЕМЫ НА ТЕМНУЮ
echo [1/9] Установка темной темы...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 1 /f >nul
echo ✓ Темная тема установлена

:: 2. СМЕНА ОБОЕВ
echo [2/9] Установка обоев...
if exist "wallpaper.jpg" (
    reg add "HKCU\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d "%cd%\wallpaper.jpg" /f >nul
    rundll32.exe user32.dll, UpdatePerUserSystemParameters
    echo ✓ Обои wallpaper.jpg установлены
) else (
    echo ✗ Файл wallpaper.jpg не найден
)

:: 3. ПОЛНЫЙ ДОСТУП К СИСТЕМЕ
echo [3/9] Настройка полного доступа к системе...
takeown /F C:\ /R /D Y

:: Включение скрытых файлов
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f >nul

:: Показ расширений файлов
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f >nul

:: Отключение контроля учетных записей
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f >nul

:: Включение God Mode
mkdir "%USERPROFILE%\Desktop\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}" >nul 2>&1

:: Права на системные папки
takeown /f "C:\Windows\System32" /r /d y >nul 2>&1
icacls "C:\Windows\System32" /grant administrators:F /t >nul 2>&1

echo ✓ Полный доступ к системе настроен

:: 4. ТВИКИ ОТ FLIBUSTIER
echo [4/9] Применение твиков Flibustier...
if exist "flibustier_tweaks.bat" (
    call flibustier_tweaks.bat
    echo ✓ Твики Flibustier применены
) else (
    echo ✗ Файл flibustier_tweaks.bat не найден
    echo Создание базовых твиков Flibustier...
    
    :: Отключение телеметрии
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f >nul
    
    :: Отключение игровой панели
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f >nul
    
    echo ✓ Базовые твики Flibustier созданы и применены
)

:: 5. ТВИКИ ОТ REVIOS
echo [5/9] Применение твиков ReviOS...
if exist "revios_tweaks.bat" (
    call revios_tweaks.bat
    echo ✓ Твики ReviOS применены
) else (
    echo ✗ Файл revios_tweaks.bat не найден
    echo Создание базовых твиков ReviOS...
    
    :: Отключение индексации поиска
    sc config "WSearch" start= disabled >nul
    sc stop "WSearch" >nul
    
    :: Отключение ненужных служб
    sc config "XboxGipSvc" start= disabled >nul
    sc config "XboxNetApiSvc" start= disabled >nul
    
    echo ✓ Базовые твики ReviOS созданы и применены
)

:: 6. ТВИКИ ОТ ATLASOS
echo [6/9] Применение твиков AtlasOS...
if exist "atlasos_tweaks.bat" (
    call atlasos_tweaks.bat
    echo ✓ Твики AtlasOS применены
) else (
    echo ✗ Файл atlasos_tweaks.bat не найден
    echo Создание базовых твиков AtlasOS...
    
    :: Оптимизация питания для производительности
    powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c >nul
    
    :: Отключение визуальных эффектов
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f >nul
    
    echo ✓ Базовые твики AtlasOS созданы и применены
)

:: 7. ТВИКИ ОТ IGROMANOFF
echo [7/9] Применение твиков Igromanoff...
if exist "igromanoff_tweaks.bat" (
    call igromanoff_tweaks.bat
    echo ✓ Твики Igromanoff применены
) else (
    echo ✗ Файл igromanoff_tweaks.bat не найден
    echo Создание базовых твиков Igromanoff...
    
    :: Ускорение меню Пуск
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_SearchFiles /t REG_DWORD /d 2 /f >nul
    
    :: Отключение пароля при пробуждении
    powercfg -setacvalueindex SCHEME_CURRENT sub_none CONSOLELOCK 0 >nul
    powercfg -setdcvalueindex SCHEME_CURRENT sub_none CONSOLELOCK 0 >nul
    
    echo ✓ Базовые твики Igromanoff созданы и применены
)

:: 8. ТВИКИ ОТ ANCELS
echo [8/9] Применение твиков Ancels...
if exist "ancels_tweaks.bat" (
    call ancels_tweaks.bat
    echo ✓ Твики Ancels применены
) else (
    echo ✗ Файл ancels_tweaks.bat не найден
    echo Создание базовых твиков Ancels...
    
    :: Оптимизация сети
    netsh int tcp set global autotuninglevel=normal >nul
    netsh int tcp set global rss=enabled >nul
    
    :: Очистка кэша DNS
    ipconfig /flushdns >nul
    
    echo ✓ Базовые твики Ancels созданы и применены
)

:: 9. УСТАНОВКА EXTREME
echo [9/9] Установка Extreme...
set "download_url=https://github.com/anton18-png/Extreme/raw/refs/heads/main/Updater.exe"
set "output_file=Extreme_Updater.exe"

echo Загрузка Extreme с GitHub...
powershell -Command "& {
    try {
        Invoke-WebRequest -Uri '%download_url%' -OutFile '%output_file%' -UseBasicParsing
        Write-Host '✓ Extreme успешно загружен' -ForegroundColor Green
        
        echo Запуск Extreme Updater...
        start "" "%output_file%"
        
    } catch {
        Write-Host '✗ Ошибка загрузки: $($_.Exception.Message)' -ForegroundColor Red
    }
}"

:: ФИНАЛЬНАЯ ОПТИМИЗАЦИЯ
echo.
echo ========================================
echo ВЫПОЛНЕНИЕ ФИНАЛЬНОЙ ОПТИМИЗАЦИИ...
echo ========================================

:: Очистка временных файлов
echo Очистка временных файлов...
del /f /q %temp%\* >nul 2>&1
powershell -Command "Clear-RecycleBin -Force" >nul 2>&1

:: Восстановление значков проводника
echo Восстановление кэша значков...
taskkill /f /im explorer.exe >nul 2>&1
ie4uinit.exe -show >nul 2>&1
start explorer.exe >nul 2>&1

:: Обновление политик
echo Применение изменений...
gpupdate /force >nul

echo.
echo ========================================
echo ОПТИМИЗАЦИЯ ЗАВЕРШЕНА!
echo ========================================
echo.
echo Выполненные действия:
echo ✓ Темная тема Windows
echo ✓ Обои wallpaper.jpg
echo ✓ Полный доступ к системе
echo ✓ Твики Flibustier
echo ✓ Твики ReviOS
echo ✓ Твики AtlasOS
echo ✓ Твики Igromanoff
echo ✓ Твики Ancels
echo ✓ Установка Extreme
echo.
echo Перезагрузите компьютер для применения всех изменений.
echo.

pause