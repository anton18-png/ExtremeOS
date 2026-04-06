@echo off
cd /d "%~dp0"
set "TI=NSudoLG -U:T -P:E -ShowWindowMode:Hide -Wait cmd.exe /c"

powercfg -h off >nul 2>&1
reg add "HKLM\System\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t REG_DWORD /d 0x0 /f >nul 2>&1

Dism /Online /Set-ReservedStorageState /State:Disabled >nul 2>&1

vssadmin resize shadowstorage /on=c: /for=c: /maxsize=1%% >nul 2>&1
PowerShell -Command "Disable-ComputerRestore -Drive '%SystemDrive%\'" >nul 2>&1
vssadmin delete shadows /all /quiet >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "RPSessionInterval" /f >nul 2>&1

for %%p in (EventSystem NlaSvc) do reg add "HKLM\System\CurrentControlSet\Services\%%p" /v "DelayedAutostart" /t reg_dword /d 1 /f >nul 2>&1

"%~dp0Eventlog" >nul 2>&1

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "MaxCachedIcons" /t REG_SZ /d 4096 /f >nul

PowerShell "$key = 'HKLM:\SYSTEM\CurrentControlSet\Control'; if (-not (Get-ItemProperty -Path $key -Name 'SvcHostSplitThresholdInKB' -ErrorAction SilentlyContinue)) { Write-Output ' Параметра SvcHostSplitThresholdInKB нет, отмена действий'; Pause; Exit } elseif (-not (Get-ItemProperty -Path $key -Name 'SvcHostSplitThresholdInKB_orig' -ErrorAction SilentlyContinue)) { Rename-ItemProperty -Path $key -Name 'SvcHostSplitThresholdInKB' -NewName 'SvcHostSplitThresholdInKB_orig'; $mem = (Get-CimInstance Win32_OperatingSystem).TotalVisibleMemorySize + 1024000; Set-ItemProperty -Path $key -Name 'SvcHostSplitThresholdInKB' -Value $mem -Type DWord }"

reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" /v "FolderType" /t REG_SZ /d NotSpecified /f >nul 2>&1
for %%k in (Directory.Audio Directory.Image Directory.Video) do (for %%c in (Enqueue Play) do (reg add "HKCR\SystemFileAssociations\%%k\shell\%%c" /v "LegacyDisable" /t REG_SZ /d "" /f >nul)) >nul 2>&1

bcdedit /set hypervisorlaunchtype off >nul
for %%p in (
    HypervisorEnforcedCodeIntegrity LsaCfgFlags RequirePlatformSecurityFeatures ConfigureSystemGuardLaunch ConfigureKernelShadowStacksLaunch
) do reg delete "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "%%p" /f >nul 2>&1
for %%p in (EnableVirtualizationBasedSecurity HVCIMATRequired) do reg add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "%%p" /t reg_dword /d 0 /f >nul 2>&1
for %%p in (WasEnabledBy WasEnabledBySysprep) do reg delete "HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "%%p" /f >nul 2>&1
for %%p in (Enabled HVCIMATRequired Locked) do reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "%%p" /t reg_dword /d 0 /f >nul 2>&1
for %%p in (EnableVirtualizationBasedSecurity RequirePlatformSecurityFeatures Locked) do reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "%%p" /t reg_dword /d 0 /f >nul 2>&1
for %%p in (Enabled AuditModeEnabled WasEnabledBy) do reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard\Scenarios\KernelShadowStacks" /v "%%p" /t reg_dword /d 0 /f >nul 2>&1

reg add "HKCR\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f >nul 
reg add "HKCR\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\Software\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "Value" /t REG_DWORD /d 0 /f >nul
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f >nul

%TI% reg add "HKLM\System\CurrentControlSet\Control\Power\User\PowerSchemes" /v ActivePowerScheme /t REG_SZ /d e9a42b02-d5df-448d-aa00-03f14749eb61 /f >nul

"%~dp0vivetool.exe" /disable /id:56517033 >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CrossDeviceResume\Configuration" /v "IsResumeAllowed" /t REG_DWORD /d 0 /f >nul 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CrossDeviceResume\Configuration" /v "IsOneDriveResumeAllowed" /t REG_DWORD /d 0 /f >nul
exit /b