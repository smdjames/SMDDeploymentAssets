Start-Transcript -Append C:\Support\Logs\PostDeploymentCleanupLog.txt

function Start-Sleep($seconds) {
    $doneDT = (Get-Date).AddSeconds($seconds)
    while($doneDT -gt (Get-Date)) {
        $secondsLeft = $doneDT.Subtract((Get-Date)).TotalSeconds
        $percent = ($seconds - $secondsLeft) / $seconds * 100
        Write-Progress -Activity "Sleeping" -Status "Sleeping..." -SecondsRemaining $secondsLeft -PercentComplete $percent
        [System.Threading.Thread]::Sleep(300000)
    }
    Write-Progress -Activity "Sleeping" -Status "Sleeping..." -SecondsRemaining 0 -Completed
}

# Reset Privacy settings to default
reg delete HKLM\SOFTWARE\Policies\Microsoft\Windows\OOBE /v DisablePrivacyExperience /f

# Disable autoLogon
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 0 /f

# Remove stored credentials
REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /f

# Start Automate installer in quiet mode
Start-Process msiexec -Wait -ArgumentList '/I C:\Support\Installers\Automate-test.msi /quiet'

# Run WindowsSetup2_0-WIP
# Forked from Cole's GitHub repo

PowerShell -ExecutionPolicy Bypass -File "C:\Support\Scripts\WindowsSetup2_0.ps1"

Remove-Item -Path C:\\Support\\Scripts -Recurse -Verbose
Remove-Item -Path C:\\Support\\Installers -Recurse -Verbose

Stop-Transcript
