$ClientList = Import-CSV -Path "C:\Support\Clients.csv"

Write-output $ClientList | Format-Table LocationID, Client

$ClientSelection = Read-Host "Please select a client (enter a number)"

$TokenList = Import-CSV -Path "C:\Support\CSVs\TokenList.csv"

$LocID = $ClientSelection


#I don't know what to do for token
$i=$ClientSelection
Write-Output $i
$TokenID = $TokenList[$i-1]
$Token = $TokenID.Token
 
Write-Output $Token
#Install-Automate -Server 'systemsmd.hostedrmm.com' -LocationID $LocID -Token $Token -Silent -Force -Transcript