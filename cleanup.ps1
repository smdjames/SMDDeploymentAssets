Start-Transcript -Append C:\Support\Logs\PostDeploymentCleanupLog.txt

#ni "C:\Support\Logs\Sleep.txt"

<#

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

#>

Start-Sleep -s 30

#ni "C:\Support\Logs\After-Sleep.txt"

# Reset Privacy settings to default
reg delete HKLM\SOFTWARE\Policies\Microsoft\Windows\OOBE /v DisablePrivacyExperience /f

# Disable autoLogon
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 0 /f

# Remove stored credentials
REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /f

# Start Automate installer in quiet mode
$arguments = "/i `"C:\Support\Installers\Automate-test.msi`" /quiet"
Start-Process msiexec.exe -ArgumentList $arguments -Wait

# Run WindowsSetup2_0-WIP
# Forked from Cole's GitHub repo


#PowerShell.exe -ExecutionPolicy Bypass -File C:\Support\Scripts\WindowsSetup2_0.ps1
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v !WindowsSetup2_0 /t REG_SZ /d 'PowerShell -ExecutionPolicy Bypass -File C:\Support\Scripts\WindowsSetup2_0.ps1' /f


Remove-Item -Path C:\\Support\\Scripts -Recurse -Verbose
Remove-Item -Path C:\\Support\\Installers -Recurse -Verbose

Stop-Transcript
