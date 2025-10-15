 # Define domain controllers
$modtekDC = "MODTEK"
$inovarDC = "INOVAR"

# Get users, groups, and computers from modtek.int
$modtekUsers = Get-ADUser -Filter * -Server $modtekDC | Select-Object -ExpandProperty SamAccountName
$modtekGroups = Get-ADGroup -Filter * -Server $modtekDC | Select-Object -ExpandProperty SamAccountName
$modtekComputers = Get-ADComputer -Filter * -Server $modtekDC | Select-Object -ExpandProperty SamAccountName

# Get users, groups, and computers from inovar.local
$inovarUsers = Get-ADUser -Filter * -Server $inovarDC | Select-Object -ExpandProperty SamAccountName
$inovarGroups = Get-ADGroup -Filter * -Server $inovarDC | Select-Object -ExpandProperty SamAccountName
$inovarComputers = Get-ADComputer -Filter * -Server $inovarDC | Select-Object -ExpandProperty SamAccountName

# Compare and find missing objects
$missingUsers = $modtekUsers | Where-Object { $_ -notin $inovarUsers }
$missingGroups = $modtekGroups | Where-Object { $_ -notin $inovarGroups }
$missingComputers = $modtekComputers | Where-Object { $_ -notin $inovarComputers }

# Output results
Write-Host "`nUsers only in modtek.int:`n" -ForegroundColor Cyan
$missingUsers | ForEach-Object { Write-Host $_ }

Write-Host "`nGroups only in modtek.int:`n" -ForegroundColor Cyan
$missingGroups | ForEach-Object { Write-Host $_ }

Write-Host "`nComputers only in modtek.int:`n" -ForegroundColor Cyan
$missingComputers | ForEach-Object { Write-Host $_ }

# Optional: Export to CSV
$missingUsers | Out-File "C:\Temp\MissingUsers.txt"
$missingGroups | Out-File "C:\Temp\MissingGroups.txt"
$missingComputers | Out-File "C:\Temp\MissingComputers.txt"
 
