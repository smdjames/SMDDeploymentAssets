# SMDDeploymentAssets
Custom PowerShell script used with Windows Configuration Designer.
A provisioning package (.ppkg) is created to modify Windows machines from OOBE.

## cleanup.ps1
Cleanup does the following:
C- reates a log file
- Removes autoLogon and stored credentials
- Installs Automate which in turn installs ScreenConnect
- NOTE: To change this or disable completely, edit or comment-out line 343.
- Runs WindowsSetup2_0.ps1
- Deletes the working paths
- Displays a completion message to the user.


## WindowsSetup2_0.ps1
WindowsSetup does the following:
- Creates a log fie
- Changes PC name
- Creates CustLocAdmin user
- Enables F8 to boot to Safe Mode
- Sets Percentage for System Protection
- Configures TRIM for SSD drives
- Enables System Restore
- Creates a Restore Point
- Configures power settings
- Sets Time Zone
- Installs Chocolatey
- Installs Java Runtime Enviornment
- Installs Firefox
- Installs Google Chrome
- Installs Adobe Reader
- Installs 7-zip
- Sets all NICs to powersavea and wake-on-lan
- Imporves performance by disabling startup services
- Debloats Windows using Registry Keys and Removal of AppX Packages
- Installs Media Player
- Stops Egde from being default PDF viewer
- Removes Paint3D
- Diables Bing search and indexing
- Removes Cortana
- Diables UAC and other 'security'
- Stops Windows Update up to 3 years and set for Security updates only.
- Displays a completion message


To run Windows Setup use this in Powershell admin:

```iex ((New-Object System.Net.WebClient).DownloadString('rb.gy/8ctc3b'))```

OR

```iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/smdjames/SMDDeploymentAssets/main/WindowsSetup2_0-WIP.ps1'))```
