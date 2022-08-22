<#
Company: SystemsMD
Contact: james@systemsmd.com
Created: October 15, 2021
Last Modified: January 25, 2022

Credits:
James McGee created the basis of this script
Cole Bermudez added on and modified
Last Updated: January 25, 2022

Change Log:
1/25/2022
Changes By Cole Bermudez:
-Added lines 342-371 as a basis for dynamic installation of Automate once a CSV of Tokens is compiled.
#>

Write-Host -ForegroundColor Green "Windows Deployment will now begin. `nPlease refer to logs for review."

Start-Transcript -Append C:\Support\Logs\PostDeploymentCleanupLog.txt

# Sleep to let registry populate
Start-Sleep -s 60

# Reset Privacy settings to default
reg delete HKLM\SOFTWARE\Policies\Microsoft\Windows\OOBE /v DisablePrivacyExperience /f

# Disable autoLogon
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 0 /f

# Remove stored credentials
Write-Host -ForegroundColor Green "This will error out. This is expected. The action takes place as expected."
REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /f

# Run WindowsSetup2_0-WIP
# Forked from Cole's GitHub repo
iex -Command "C:\Support\Scripts\WindowsSetup2_0.ps1"

# Removes install directories except logs
Remove-Item -Path C:\\Support\\Scripts -Recurse -Verbose
Remove-Item -Path C:\\Support\\Installers -Recurse -Verbose
Remove-Item -Path C:\\Support\\CSVs -Recurse -Verbose

Write-Host -ForegroundColor Green "Windows deployment complete. `nThis window will close in 5 seconds."
#Sleep to read completion message
Start-Sleep -s 5

Stop-Transcript
