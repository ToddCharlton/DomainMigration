 # Script to compare AD objects (Users, Groups, Computers) between two domains:
 # Change the domains below as needed  

$Domain1 = "modtek.int"
$Domain2 = "inovar.local"

# Import Active Directory module
Import-Module ActiveDirectory

# --- Compare USERS ---
Write-Host "`nComparing Users..."
$modtekUsers = Get-ADUser -Server $Domain1 -Filter * -Properties SamAccountName | Select-Object -ExpandProperty SamAccountName
$inovarUsers = Get-ADUser -Server $Domain2 -Filter * -Properties SamAccountName | Select-Object -ExpandProperty SamAccountName
$missingUsers = $modtekUsers | Where-Object { $_ -notin $inovarUsers }

# --- Compare GROUPS ---
Write-Host "`nComparing Groups..."
$modtekGroups = Get-ADGroup -Server $Domain1 -Filter * -Properties SamAccountName | Select-Object -ExpandProperty SamAccountName
$inovarGroups = Get-ADGroup -Server $Domain2 -Filter * -Properties SamAccountName | Select-Object -ExpandProperty SamAccountName
$missingGroups = $modtekGroups | Where-Object { $_ -notin $inovarGroups }

# --- Compare COMPUTERS ---
Write-Host "`nComparing Computers..."
$modtekComputers = Get-ADComputer -Server $Domain1 -Filter * -Properties SamAccountName | Select-Object -ExpandProperty SamAccountName
$inovarComputers = Get-ADComputer -Server $Domain2 -Filter * -Properties SamAccountName | Select-Object -ExpandProperty SamAccountName
$missingComputers = $modtekComputers | Where-Object { $_ -notin $inovarComputers }

# --- OUTPUT RESULTS ---
Write-Host "`n--- USERS missing in $Domain2 ---"
$missingUsers | Sort-Object | Format-Table -AutoSize

Write-Host "`n--- GROUPS missing in $Domain2 ---"
$missingGroups | Sort-Object | Format-Table -AutoSize

Write-Host "`n--- COMPUTERS missing in $Domain2 ---"
$missingComputers | Sort-Object | Format-Table -AutoSize

# Optional: Export all to CSV
$missingUsers | ForEach-Object { [PSCustomObject]@{SamAccountName = $_ } } | Export-Csv "C:\logs\MissingUsers.csv" -NoTypeInformation
$missingGroups | ForEach-Object { [PSCustomObject]@{SamAccountName = $_ } } | Export-Csv "C:\logs\MissingGroups.csv" -NoTypeInformation
$missingComputers | ForEach-Object { [PSCustomObject]@{SamAccountName = $_ } } | Export-Csv "C:\logs\MissingComputers.csv" -NoTypeInformation
