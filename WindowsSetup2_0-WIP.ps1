<#
Company: SystemsMD
Contact: james@systemsmd.com
Created: October 15, 2021
Last Modified: October 18, 2021

Credits:
Based on the initial concept of WindowsSetup.ps1
Created by Michael Bartlett
Modified by Cole Bermudez and James McGee
For sole and exclusive use by SystemsMD
Last updated: October 18, 2021
#>

# Create a log file for debugging
Start-Transcript -Append C:\Support\Logs\WindowsSetupLog.txt

#initiates the variables required for the script
$diskProps = (Get-PhysicalDisk | where size -gt 100gb)
$cortanaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
$HighPerf = powercfg -l | %{if($_.contains("High performance")) {$_.split()[3]}}
$confirmUac = 'n'
$confirmInfo = 'n'
$confirmPower = 'n'
$confirmDev = 'n'
$avCheck = $false
$installCheck = 'n'
$officeCheck = $false

#Set F8 to boot to Safe Mode
Write-Host -ForegroundColor Green "Setting boot menu to legacy"
bcdedit /set "{current}" bootmenupolicy legacy

#Set Percentage for System Protection
Write-Host -ForegroundColor Green "Setting size for system restore"
vssadmin resize shadowstorage /for=C: /on=C: /maxsize=5%

Write-Host -ForegroundColor Green "Configure Over Provisioning via TRIM"
fsutil behavior set DisableDeleteNotify 0

# Computer name is set by the deployment package

# Enable system restore on C:\

Write-Host -ForegroundColor Green "Enabling system restore..."
Enable-ComputerRestore -Drive "$env:SystemDrive"

#Force Restore point to not skip
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /T REG_DWORD /D 0 /F

#Disable sleep timers and create a restore point just in case
Checkpoint-Computer -Description "RestorePoint1" -RestorePointType "MODIFY_SETTINGS"

powercfg.exe -change -monitor-timeout-ac 0
powercfg.exe -change -monitor-timeout-dc 0
powercfg.exe -change -disk-timeout-ac 0
powercfg.exe -change -disk-timeout-dc 0
powercfg.exe -change -standby-timeout-ac 0
powercfg.exe -change -standby-timeout-dc 0
powercfg.exe -change -hibernate-timeout-ac 0
powercfg.exe -change -hibernate-timeout-dc 0
#Set Mountain Time Zone
Set-TimeZone -Id "Mountain Standard Time"
Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All

##########Essential Tweaks from Cole##########

#install Chocolatey and other programs
	Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
	choco install chocolatey-core.extension -y

#Install Java
    choco install jre8 -y

#Install Firefox
    choco install firefox -y

#Install Chrome
    choco install googlechrome -y --ignore-checksums

#Install Adobe Reader
    choco install adobereader -y

#Install 7-zip
#    choco install 7zip -y

#Use O&O Shutup to automate a lot
    Import-Module BitsTransfer
    # choco install shutup10 -y
	Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination C:\Support\Installers\OOSU10.exe
	C:\Support\Installers\OOSU10.exe C:\Support\Installers\ooshutup10.cfg /quiet

#Sets all NICs powersave and wake-on-lan modes correctly
Get-NetAdapter | where {$_.Name -like "*ethernet*" -or $_.Name -like '*wireless*' -or $_.Name -like '*Wi-Fi*'} | Set-NetAdapterPowerManagement -ArpOffload enabled -NSOffload enabled -DeviceSleepOnDisconnect disabled -SelectiveSuspend disabled -WakeOnMagicPacket enabled -WakeOnPattern enabled


    #Get Rid of nasty Windows stuff
    #Disables Windows Feedback Experience
    Write-Host -ForegroundColor Green "Disabling Windows Feedback Experience program"
    $Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
    If (Test-Path $Advertising) {
        Set-ItemProperty $Advertising Enabled -Value 0
    }

    #Stops Cortana from being used as part of your Windows Search Function
    Write-Host -ForegroundColor Green "Stopping Cortana from being used as part of your Windows Search Function"
    $Search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    If (Test-Path $Search) {
        Set-ItemProperty $Search AllowCortana -Value 0
    }

    #Disables Web Search in Start Menu
    Write-Host -ForegroundColor Green "Disabling Bing Search in Start Menu"
    $WebSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" BingSearchEnabled -Value 0
	If (!(Test-Path $WebSearch)) {
        New-Item $WebSearch
	}
	Set-ItemProperty $WebSearch DisableWebSearch -Value 1

    #Stops the Windows Feedback Experience from sending anonymous data
    Write-Host -ForegroundColor Green "Stopping the Windows Feedback Experience program"
    $Period = "HKCU:\Software\Microsoft\Siuf\Rules"
    If (!(Test-Path $Period)) {
    New-Item $Period
    }
    Set-ItemProperty $Period PeriodInNanoSeconds -Value 0

    #Prevents bloatware applications from returning and removes Start Menu suggestions
    Write-Host -ForegroundColor Green "Adding Registry key to prevent bloatware apps from returning"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $registryOEM = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    If (!(Test-Path $registryPath)) {
        New-Item $registryPath
    }
    Set-ItemProperty $registryPath DisableWindowsConsumerFeatures -Value 1

    If (!(Test-Path $registryOEM)) {
        New-Item $registryOEM
    }
        Set-ItemProperty $registryOEM  ContentDeliveryAllowed -Value 0
        Set-ItemProperty $registryOEM  OemPreInstalledAppsEnabled -Value 0
        Set-ItemProperty $registryOEM  PreInstalledAppsEnabled -Value 0
        Set-ItemProperty $registryOEM  PreInstalledAppsEverEnabled -Value 0
        Set-ItemProperty $registryOEM  SilentInstalledAppsEnabled -Value 0
        Set-ItemProperty $registryOEM  SystemPaneSuggestionsEnabled -Value 0

    #Preping mixed Reality Portal for removal
    Write-Host -ForegroundColor Green "Setting Mixed Reality Portal value to 0 so that you can uninstall it in Settings"
    $Holo = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic"
    If (Test-Path $Holo) {
        Set-ItemProperty $Holo  FirstRunSucceeded -Value 0
    }

    #Disables Wi-fi Sense
    Write-Host -ForegroundColor Green "Disabling Wi-Fi Sense"
    $WifiSense1 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
    $WifiSense2 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
    $WifiSense3 = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
    If (!(Test-Path $WifiSense1)) {
	    New-Item $WifiSense1
    }
    Set-ItemProperty $WifiSense1  Value -Value 0
	If (!(Test-Path $WifiSense2)) {
	    New-Item $WifiSense2
    }
    Set-ItemProperty $WifiSense2  Value -Value 0
	Set-ItemProperty $WifiSense3  AutoConnectAllowedOEM -Value 0

    #Disables live tiles
    Write-Host -ForegroundColor Green "Disabling live tiles"
    $Live = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
    If (!(Test-Path $Live)) {
        New-Item $Live
    }
    Set-ItemProperty $Live  NoTileApplicationNotification -Value 1

    #Turns off Data Collection via the AllowTelemtry key by changing it to 0
    Write-Host -ForegroundColor Green "Turning off Data Collection"
    $DataCollection1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
    $DataCollection2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $DataCollection3 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
    If (Test-Path $DataCollection1) {
        Set-ItemProperty $DataCollection1  AllowTelemetry -Value 0
    }
    If (Test-Path $DataCollection2) {
        Set-ItemProperty $DataCollection2  AllowTelemetry -Value 0
    }
    If (Test-Path $DataCollection3) {
        Set-ItemProperty $DataCollection3  AllowTelemetry -Value 0
    }

    #Disabling Location Tracking
    Write-Host -ForegroundColor Green "Disabling Location Tracking"
    $SensorState = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
    $LocationConfig = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
    If (!(Test-Path $SensorState)) {
        New-Item $SensorState
    }
    Set-ItemProperty $SensorState SensorPermissionState -Value 0
    If (!(Test-Path $LocationConfig)) {
        New-Item $LocationConfig
    }
    Set-ItemProperty $LocationConfig Status -Value 0

    #Disables People icon on Taskbar
    Write-Host -ForegroundColor Green "Disabling People icon on Taskbar"
    $People = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
    If (!(Test-Path $People)) {
        New-Item $People
    }
    Set-ItemProperty $People  PeopleBand -Value 0

    #Disables scheduled tasks that are considered unnecessary
    Write-Host -ForegroundColor Green "Disabling scheduled tasks"
    Get-ScheduledTask  XblGameSaveTask | Disable-ScheduledTask
    Get-ScheduledTask  Consolidator | Disable-ScheduledTask
    Get-ScheduledTask  UsbCeip | Disable-ScheduledTask
    Get-ScheduledTask  DmClient | Disable-ScheduledTask
    Get-ScheduledTask  DmClientOnScenarioDownload | Disable-ScheduledTask

    Write-Host -ForegroundColor Green "Stopping and disabling WAP Push Service"
    #Stop and disable WAP Push Service
	Stop-Service "dmwappushservice"
	Set-Service "dmwappushservice" -StartupType Disabled

    Write-Host -ForegroundColor Green "Stopping and disabling Diagnostics Tracking Service"
    #Disabling the Diagnostics Tracking Service
	Stop-Service "DiagTrack"
	Set-Service "DiagTrack" -StartupType Disabled

    #Kill it...kill it with fire
    #Telemetry
    Write-Host -ForegroundColor Green "Disabling Telemetry..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null

    #App suggestions
    Write-Host -ForegroundColor Green "Disabling Application suggestions..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
    Write-Host -ForegroundColor Green "Disabling Activity History..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
    Write-Host -ForegroundColor Green "Disabling Location Tracking..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
    Write-Host -ForegroundColor Green "Disabling automatic Maps updates..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
    Write-Host -ForegroundColor Green "Disabling Feedback..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
    Write-Host -ForegroundColor Green "Disabling Tailored Experiences..."
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
    Write-Host -ForegroundColor Green "Disabling Advertising ID..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
    Write-Host -ForegroundColor Green "Disabling Error reporting..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
    Write-Host -ForegroundColor Green "Restricting Windows Update P2P only to local network..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
	}
	#A lot more nasty stuff
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
    Write-Host -ForegroundColor Green "Stopping and disabling Diagnostics Tracking Service..."
	Stop-Service "DiagTrack" -WarningAction SilentlyContinue
	Set-Service "DiagTrack" -StartupType Disabled
    Write-Host -ForegroundColor Green "Stopping and disabling WAP Push Service..."
	Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
	Set-Service "dmwappushservice" -StartupType Disabled
    Write-Host -ForegroundColor Green "Enabling F8 boot menu options..."
	bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null
    Write-Host -ForegroundColor Green "Disabling Remote Assistance..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0
    Write-Host -ForegroundColor Green "Disabling Storage Sense..."
	Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
    Write-Host -ForegroundColor Green "Stopping and disabling Superfetch service..."
	Stop-Service "SysMain" -WarningAction SilentlyContinue
	Set-Service "SysMain" -StartupType Disabled
    Write-Host -ForegroundColor Green "Setting BIOS time to UTC..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1
    Write-Host -ForegroundColor Green "Disabling Hibernation..."
	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0
    Write-Host -ForegroundColor Green "Showing task manager details..."
	$taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
	Do {
		Start-Sleep -Milliseconds 100
		$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
	} Until ($preferences)
	Stop-Process $taskmgr
	$preferences.Preferences[28] = 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
    Write-Host -ForegroundColor Green "Showing file operations details..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
    Write-Host -ForegroundColor Green "Hiding Task View button..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
    Write-Host -ForegroundColor Green "Hiding People icon..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
    Write-Host -ForegroundColor Green "Showing all tray icons..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0
	Write-Host -ForegroundColor Green "Enabling NumLock after startup..."
	If (!(Test-Path "HKU:")) {
		New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
	}
	Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
	Add-Type -AssemblyName System.Windows.Forms
	If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}

    #Unpins all tiles from the Start Menu
    Write-Host -ForegroundColor Green "Unpinning all tiles from the start menu"
    (New-Object -Com Shell.Application).
    NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').
    Items() |
    %{ $_.Verbs() } |
    ?{$_.Name -match 'Un.*pin from Start'} |

    #Y this work but throw error?
    Write-Host -ForegroundColor Green "Changing default Explorer view to This PC"
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

    Write-Host -ForegroundColor Green "Hiding 3D Objects icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue

    # Network Tweaks
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 20

	# SVCHost Tweak
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value 4194304

#Warn about errors
Write-Host -ForegroundColor Green "WARNING!!! `nErrors in this section indicate that the AppX `nit is trying to uninstall is not present." 

#Finally debloat all the visible stuff
$Bloatware = @(

        #Unnecessary Windows 10 AppX Apps
        "Microsoft.549981C3F5F10"
        "Microsoft.3DBuilder"
        "Microsoft.AppConnector"
	    "Microsoft.BingFinance"
	    "Microsoft.BingNews"
	    "Microsoft.BingSports"
	    "Microsoft.BingTranslator"
	    "Microsoft.BingWeather"
        "Microsoft.GetHelp"
        "Microsoft.Getstarted"
        "Microsoft.Messaging"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.MicrosoftSolitaireCollection"
        "Microsoft.MixedReality.Portal"
        "Microsoft.People"
        "Microsoft.NetworkSpeedTest"
        "Microsoft.News"
        "Microsoft.Office.Lens"
        "Microsoft.Office.Sway"
        "Microsoft.OneConnect"
        "Microsoft.People"
        "Microsoft.Print3D"
        "Microsoft.SkypeApp"
        #"Microsoft.StorePurchaseApp"
        "Microsoft.Wallet"
        "Microsoft.Whiteboard"
        "Microsoft.WindowsAlarms"
        "Microsoft.windowscommunicationsapps"
        "Microsoft.WindowsFeedbackHub"
        "Microsoft.WindowsMaps"
        "Microsoft.WindowsSoundRecorder"
        "Microsoft.Xbox.TCUI"
        "Microsoft.XboxApp"
        "Microsoft.XboxGameOverlay"
        "Microsoft.XboxGamingOverlay"
        "Microsoft.XboxIdentityProvider"
        "Microsoft.XboxSpeechToTextOverlay"
        "Microsoft.YourPhone"
        "Microsoft.ZuneMusic"
        "Microsoft.ZuneVideo"

        #Sponsored Windows 10 AppX Apps
        #Add sponsored/featured apps to remove in the "*AppName*" format
        "*EclipseManager*"
        "*Amazon*"
        "*ActiproSoftwareLLC*"
        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
        "*Duolingo-LearnLanguagesforFree*"
        "*PandoraMediaInc*"
        "*CandyCrush*"
        "*BubbleWitch3Saga*"
        "*Wunderlist*"
        "*Flipboard*"
        "*Twitter*"
        "*Facebook*"
        "*Royal Revolt*"
        "*Sway*"
        "*Speed Test*"
        "*Dolby*"
        "*Viber*"
        "*ACGMediaPlayer*"
        "*Netflix*"
        "*OneCalendar*"
        "*LinkedInforWindows*"
        "*HiddenCityMysteryofShadows*"
        "*Hulu*"
        "*HiddenCity*"
        "*AdobePhotoshopExpress*"

        #If you're going for the grand slam debloat (You should)
        #Optional: Typically not removed but you can if you need to for some reason
        "*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*"
        "*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*"
        "*Microsoft.BingWeather*"
        #"*Microsoft.MSPaint*"
        #"*Microsoft.MicrosoftStickyNotes*"
        #"*Microsoft.Windows.Photos*"
        #"*Microsoft.WindowsCalculator*"
        #"*Microsoft.WindowsStore*"
    )
    #Use list to remove AppX software
    foreach ($Bloat in $Bloatware) {
        Get-AppxPackage -AllUsers -Name $Bloat| Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
        Write-Host -ForegroundColor Green "Trying to remove $Bloat."
    }

    #Install Media Player because Why not
    Write-Host -ForegroundColor Green "Installing Windows Media Player..."
    #Works outside Windows Sandbox.
	Enable-WindowsOptionalFeature -FeatureName "WindowsMediaPlayer" -All -Online -NoRestart -WarningAction SilentlyContinue | Out-Null

    #Stops edge from taking over as the default .PDF viewer
    Write-Host -ForegroundColor Green "Stopping Edge from taking over as the default .PDF viewer"
	# Identify the edge application class
	$Packages = "HKCU:SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages"
	$edge = Get-ChildItem $Packages -Recurse -include "MicrosoftEdge"

	# Specify the paths to the file and URL associations
	$FileAssocKey = Join-Path $edge.PSPath Capabilities\FileAssociations
	$URLAssocKey = Join-Path $edge.PSPath Capabilities\URLAssociations

	# get the software classes for the file and URL types that Edge will associate
	$FileTypes = Get-Item $FileAssocKey
	$URLTypes = Get-Item $URLAssocKey

	$FileAssoc = Get-ItemProperty $FileAssocKey
	$URLAssoc = Get-ItemProperty $URLAssocKey

	$Associations = @()
	$Filetypes.Property | foreach {$Associations += $FileAssoc.$_}
	$URLTypes.Property | foreach {$Associations += $URLAssoc.$_}

	# add registry values in each software class to stop edge from associating as the default
	foreach ($Association in $Associations)
			{
			$Class = Join-Path HKCU:SOFTWARE\Classes $Association
			#if (Test-Path $class)
			#   {write-host $Association}
			# Get-Item $Class
			Set-ItemProperty $Class -Name NoOpenWith -Value ""
			Set-ItemProperty $Class -Name NoStaticDefaultVerb -Value ""
			}

    #Removes Paint3D stuff from context menu
$Paint3Dstuff = @(
        "HKCR:\SystemFileAssociations\.3mf\Shell\3D Edit"
	"HKCR:\SystemFileAssociations\.bmp\Shell\3D Edit"
	"HKCR:\SystemFileAssociations\.fbx\Shell\3D Edit"
	"HKCR:\SystemFileAssociations\.gif\Shell\3D Edit"
	"HKCR:\SystemFileAssociations\.jfif\Shell\3D Edit"
	"HKCR:\SystemFileAssociations\.jpe\Shell\3D Edit"
	"HKCR:\SystemFileAssociations\.jpeg\Shell\3D Edit"
	"HKCR:\SystemFileAssociations\.jpg\Shell\3D Edit"
	"HKCR:\SystemFileAssociations\.png\Shell\3D Edit"
	"HKCR:\SystemFileAssociations\.tif\Shell\3D Edit"
	"HKCR:\SystemFileAssociations\.tiff\Shell\3D Edit"
    )

    #Rename reg key to remove it, so it's revertible
    foreach ($Paint3D in $Paint3Dstuff) {
        If (Test-Path $Paint3D) {
	    $rmPaint3D = $Paint3D + "_"
	    Set-Item $Paint3D $rmPaint3D
	}
    }

#Disables some search like bing and indexing
   Write-Host -ForegroundColor Green "Disabling Bing Search in Start Menu..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
    Write-Host -ForegroundColor Green "Stopping and disabling Windows Search indexing service..."
	Stop-Service "WSearch" -WarningAction SilentlyContinue
	Set-Service "WSearch" -StartupType Disabled
    Write-Host -ForegroundColor Green "Hiding Taskbar Search icon / box..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0

#Cortana: Hi! I'm Cortana, and I'm here to help.
#Me: NOT FOR LONG HEATHEN!
    Write-Host -ForegroundColor Green "Disabling Cortana..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0


#Diable UAC and disable other Windows 'Security'
    Write-Host -ForegroundColor Green "Lowering UAC level..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 0

    Write-Host -ForegroundColor Green "Disabling Meltdown (CVE-2017-5754) compatibility flag..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -ErrorAction SilentlyContinue

#Normal Windows Update
    Write-Host -ForegroundColor Green "Enabling driver offering through Windows Update..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
    Write-Host -ForegroundColor Green "Enabling Windows Update automatic restart..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -ErrorAction SilentlyContinue

#Close debugging log Transcript
Stop-Transcript

Write-Host -ForegroundColor Green "Windows Setup complete."
Start-Sleep -s 5

<#
###############################################
Checklist items:

Enable Wake on LAN #See Line 83
Disable Secure Boot

#####
Proceed through basic questions and license agreement
Choose Set up for an organization or, if not given that option, select use a local account instead
Choose Domain join if asked to use a Microsoft account after selecting the organization option
Who's Going to Use This PC?
Username: SystemsMD
Password: Use the current standard password
Security Questions:
Pick a random question
Mash random letters on the keyboard
Repeat two more times 
Decline Cortana
"Do more across devices..." - NO
"Choose privacy settings..."
Click on the top-left switch to turn it to "No"
Press TAB, then the left arrow key to turn the next one to "No"
Repeat until all options are "No"
"Support and Protection" - Ignore 1st screen, uncheck all on 2nd screen
Network Discovery - No
###### Operations done by Deployment Package

START UPDATES [] #Set Automatically. See Lines 563-572
SET COMPUTER NAME [] #Set by Deployment Package
ENABLE SYSTEM PROTECTION [] # See Lines 32-38
If the PC has an SSD, set the max usage to 5%
If the PC has an HDD, set the max usage to 10% #See Lines 33-34
DISABLE CORTANA [] #See Lines 553-552
ALLOW F8 TO BOOT TO SAFE MODE [] #See Line 29
DISABLE UAC [] #See Lines 555-558
CONFIGURE POWER OPTIONS [] #See Lines 43-50
CONFIGURE SSD OVERPROVISIONING [] #See Lines 36-37
ENSURE PC IS FULLY UPDATED [] #Can Check again?

5: SOFTWARE AND DRIVERS 
UPDATE AND CONFIGURE DEVICES [] #See Lines 572
Run devmgmt.msc
Right click on, and update the following devices:
Any and all video cards
Any and all NICs (Network Interface Cards) both Ethernet and WiFi
Touchpads (laptops)
Built-in keyboards (laptops)
Built-in monitors (laptops)
In properties, enable wake and disable powersave on the NICs #see line 83
In properties, disable powersave on all USB hubs
Ensure there are no unknown devices or devices with red/yellow icons #Possible WMIC command

UNINSTALL BLOATWARE [] #See Lines 76-531
INSTALL AND ACTIVATE OFFICE [] #Manual only
If the particular set up requires Office, install it now.
Make sure to install the correct version (Important to discern between pro and non-pro, yearly editions, and 365.
The method to install depends on the version of office, but generally it follows this pattern:
Old (pre-2016) version of Office - Install via an ISO on the support drive, use a volume license the client has in their evernote
Office 2016 or 2019 - Install via the website, or sometimes volume license
Office 365 - Go to aka.ms/office-install and log in with their account
Make sure office activates. Go to file > account and make sure you see "Product is activated"
INSTALL BASICS [] #See Lines 57-71
INSTALL 3.5 framework [] #See Line 53
INSTALL AUTOMATE [] #See Cleanup Script Lines 14-22
INSTALL ANTIVIRUS [] #Cannot be automated
Look up the client in Evernote and see what AV they use. Install it appropriately
Note that some AVs are installed via cloud, which can differ drastically from the classic software install method
INSTALL EXTRA SOFTWARE [] #Cannot be automated
If needed, call the client and ask them if they need any extra software
This is especially important for smaller clients
Examples: A law office might need software for legal documents, an accountant for a company may need quickbooks, and a tax firm might need specialized tax software
---SHUTDOWN PC--- []
###############################################
#>