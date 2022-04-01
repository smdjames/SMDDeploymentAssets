#Import a CSV with a list of location IDs and
$ClientList = Import-CSV -Path "C:\Support\Clients.csv"

#Write the Location IDs and Client names to the screen
Write-output $ClientList | Format-Table LocationID, Client

#Have the user select a client
$ClientSelection = Read-Host "Please select a client (enter a number)"

#Import a Token List
$TokenList = Import-CSV -Path "C:\Support\CSVs\TokenList.csv"

#Create another Global Variable for one line install
$LocID = $ClientSelection


#Test selection output
$i=$ClientSelection
Write-Output $i
$TokenID = $TokenList[$i-1] #For some reason ID needs to subtract one to set correctly
$Token = $TokenID.Token

#Test Token output 
Write-Output $Token
#Automate one-line install command pulls location ID and token for install
Install-Automate -Server 'systemsmd.hostedrmm.com' -LocationID $LocID -Token $Token -Silent -Force -Transcript