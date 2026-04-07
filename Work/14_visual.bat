@echo off
cd /d "%~dp0"
set "TI=NSudoLG -U:T -P:E -ShowWindowMode:Hide -Wait cmd.exe /c"

busybox.exe wget -q -O Discord.7z "https://github.com/anton18-png/ExtremeOS/raw/refs/heads/main/Work/Discord.7z"
7z.exe x -y Discord.7z -o"%~dp0"

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "HubMode" /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Software\Classes\CLSID\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Classes\Wow6432Node\CLSID\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f >nul

reg add "HKCU\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Classes\Wow6432Node\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d 0 /f >nul 2>&1

reg add "HKCU\Software\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f >nul 2>&1

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /t REG_DWORD /d 0 /f >nul 2>&1

rem copy "%~dp01.jpg" "%SystemRoot%\Web\Wallpaper\Windows" >nul 2>&1
rem reg add "HKCU\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d "%SystemRoot%\Web\Wallpaper\Windows\1.jpg" /f >nul 2>&1

%TI% copy "%SystemRoot%\System32\imageres.dll" "%SystemRoot%\System32\imageres.dll.bak"
%TI% copy "%SystemRoot%\System32\imagesp1.dll" "%SystemRoot%\System32\imagesp1.dll.bak"
%TI% copy "%SystemRoot%\System32\zipfldr.dll" "%SystemRoot%\System32\zipfldr.dll.bak"

%TI% copy "%~dp0Discord\imageres.dll" "%SystemRoot%\System32"
%TI% copy "%~dp0Discord\imagesp1.dll" "%SystemRoot%\System32"
%TI% copy "%~dp0Discord\zipfldr.dll" "%SystemRoot%\System32"

rem %TI% ren "%SystemRoot%\SystemResources\imageres.dll.mun" imageres.dll.mun_bak
rem %TI% copy "%~dp0BlueIcon\imageres.dll.mun" "%SystemRoot%\SystemResources"

for %%f in ("File Explorer.lnk" Проводник.lnk) do del /q "%AppData%\Microsoft\Windows\Start Menu\Programs\%%~f" "%AppData%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\%%~f" >nul 2>&1

copy "%~dp0BlueIcon\File Explorer.lnk" "%AppData%\Microsoft\Windows\Start Menu\Programs" /y >nul
copy "%~dp0BlueIcon\File Explorer.lnk" "%AppData%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar" /y >nul
copy "%~dp0BlueIcon\Blank.ico" "%SystemRoot%" /y >nul

xcopy "%~dp0BlueIcon\windows" "%SystemRoot%" /E /I /Y /H /K /C /R /F >nul
xcopy "%~dp0BlueIcon\x64" "%ProgramFiles%" /E /I /Y /H /K /C /R /F >nul
xcopy "%~dp0BlueIcon\x86" "%ProgramFiles(x86)%" /E /I /Y /H /K /C /R /F >nul
xcopy "%~dp0BlueIcon\users" "%SystemDrive%\Users" /E /I /Y /H /K /C /R /F >nul

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons" /v "179" /t REG_EXPAND_SZ /d "%SystemRoot%\Blank.ico,0" /f >nul

reg add "HKCR\CompressedFolder\DefaultIcon" /v "" /t REG_EXPAND_SZ /d "%SystemRoot%\System32\imageres.dll,165" /f >nul
reg add "HKCR\ArchiveFolder\DefaultIcon" /v "" /t REG_EXPAND_SZ /d "%SystemRoot%\System32\imageres.dll,165" /f >nul

pushd "%ProgramFiles%"
for %%p in (x64.ico desktop.ini) do attrib +h %%p >nul 2>&1
popd
pushd "%ProgramFiles(x86)%"
for %%p in (x86.ico desktop.ini) do attrib +h %%p >nul 2>&1
popd
pushd "%SystemDrive%\Users"
for %%p in (users.ico desktop.ini) do attrib +h %%p >nul 2>&1
popd
pushd "%SystemRoot%"
for %%p in (windows.ico desktop.ini) do attrib +h %%p >nul 2>&1
popd
for %%f in ("%ProgramFiles(x86)%" "%ProgramFiles%" "%SystemDrive%\Users" "%SystemRoot%") do ATTRIB +R "%%~f" >nul 2>&1

if not exist "%ProgramFiles%\WinClean\Preview" mkdir "%ProgramFiles%\WinClean\Preview" >nul 2>&1
for %%F in (avcodec-ics-61.dll avformat-ics-61.dll avutil-ics-59.dll IcarosCache.dll IcarosPropertyHandler.dll IcarosThumbnailProvider.dll libunarr-ics.dll swscale-ics-8.dll) do (
    copy "%~dp0Icaros\%%F" "%ProgramFiles%\WinClean\Preview" >nul 2>&1
)

reg add "HKLM\SOFTWARE\Classes\CLSID\{c5aec3ec-e812-4677-a9a7-4fee1f9aa000}" /ve /t REG_SZ /d "Icaros Thumbnail Provider" /f >nul
reg add "HKLM\SOFTWARE\Classes\CLSID\{c5aec3ec-e812-4677-a9a7-4fee1f9aa000}\InProcServer32" /ve /t REG_SZ /d "%ProgramFiles%\WinClean\Preview\IcarosThumbnailProvider.dll" /f >nul
reg add "HKLM\SOFTWARE\Classes\CLSID\{c5aec3ec-e812-4677-a9a7-4fee1f9aa000}\InProcServer32" /v "ThreadingModel" /t REG_SZ /d "Apartment" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved" /v "{c5aec3ec-e812-4677-a9a7-4fee1f9aa000}" /t REG_SZ /d "Icaros Thumbnail Provider" /f >nul

reg add "HKCU\Software\Icaros" /v "Cache" /t REG_DWORD /d 2 /f >nul 
reg add "HKCU\Software\Icaros" /v "FrameThresh" /t REG_DWORD /d 20 /f >nul 
reg add "HKCU\Software\Icaros" /v "UseCoverArt" /t REG_DWORD /d 2 /f >nul 
reg add "HKCU\Software\Icaros\Cache" /v "Location" /t REG_SZ /d "%ProgramFiles%\WinClean\Preview" /f >nul
reg add "HKCU\Software\Icaros\Cache\Locations" /v "%ProgramFiles%\WinClean\Preview" /t REG_DWORD /d 33554453 /f >nul

for %%E in (.3g2 .3gp .3gp2 .3gpp .ai .aiff .amv .ape .asf .avi .avif .bik .bmp .cb7 .cbr .cbz .cur .dds .divx .dpg .dv .dvr-ms .eps .epub .evo .exr .f4v .flac .flv .gif .hdmov .hdr .heic .heif .indd .jpg .k3g .m1v .m2t .m2ts .m2v .m4b .m4p .m4v .mk3d .mka .mkv .mov .mp2v .mp3 .mp4 .mp4v .mpc .mpe .mpeg .mpg .mpv2 .mpv4 .mqv .mts .mxf .nsv .odp .ods .odt .ofr .ofs .ogg .ogm .ogv .opus .png .psd .psxprj .px .qt .ram .rm .rmvb .skm .spx .swf .tak .tga .tif .tiff .tp .tpr .trp .ts .tta .vob .wav .webm .webp .wm .wmv .wv .xvid) do (
    reg add "HKLM\Software\Classes\%%E\ShellEx\{e357fccd-a995-4576-b01f-234630154e96}" /ve /t REG_SZ /d "{c5aec3ec-e812-4677-a9a7-4fee1f9aa000}" /f >nul 
    reg add "HKLM\Software\Classes\%%E\ShellEx\{BB2E617C-0920-11d1-9A0B-00C04FC2D6C1}" /ve /t REG_SZ /d "{c5aec3ec-e812-4677-a9a7-4fee1f9aa000}" /f >nul 
)

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSecondsInSystemClock /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Control Panel\International" /v sShortDate /t REG_SZ /d "ddd, dd.MM.yy" /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings" /v "TaskbarEndTask" /t REG_DWORD /d 1 /f >nul

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f >nul 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f >nul 

reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "HideRecommendedSection" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Education" /v "IsEducationEnvironment" /t REG_DWORD /d 1 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "HideRecommendedSection" /t REG_DWORD /d 1 /f >nul

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Start" /v "VisiblePlaces" /t REG_BINARY /d 86087352AA5143429F7B2776584659D4 /f >nul

reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d 0x64 /f >nul

reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v NoLockScreen /t REG_DWORD /d 1 /f >nul
reg add "HKLM\Software\Policies\Microsoft\Windows\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 1 /f >nul

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d 0 /f >nul

reg add  "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 0 /f >nul

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f >nul

exit /b
