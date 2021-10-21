Start-Transcript -Append C:\Support\Logs\PostDeploymentCleanupLog.txt

Start-Sleep -Seconds 120

# Reset Privacy settings to default
reg delete HKLM\SOFTWARE\Policies\Microsoft\Windows\OOBE /v DisablePrivacyExperience /f

# Disable autoLogon
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 0 /f

# Remove stored credentials
REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /f

# Start Automate installer in quiet mode
msiexec /i C:\Support\Installers\Automate-test.msi /q /L*V "C:\Support\Logs\automate.log"

$filePath = 'C:\Windows\LTSvc'
while (-not (Test-Path -Path $filePath)) {
    ## Wait a specific interval
    Start-Sleep -Seconds 300
}

# Run WindowsSetup2_0-WIP
# Forked from Cole's GitHub repo

PowerShell -ExecutionPolicy Bypass -File C:\Support\Scripts\WindowsSetup2_0-WIP.ps1

Remove-Item -Path C:\\Support\\Scripts -Recurse -Verbose
Remove-Item -Path C:\\Support\\Installers -Recurse -Verbose

Stop-Transcript
