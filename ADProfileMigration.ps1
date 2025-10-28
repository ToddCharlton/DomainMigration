<#
.SYNOPSIS
    This script migrates file and folder permissions from a local domain to a new domain.

.DESCRIPTION
    This script migrates selected user profiles from their current domain to a new domain
    profile using USMT installed on a remote computer ($USMTPath) and joins the computer to
    the new domain ($newDomain).
    It uses hardlink migration (/hardlink /nocompress) to avoid copying files unnecessarily
    across the network.
    This script uses pop-ups for credential prompts, which will not work in the PowerShell ISE.

.AUTHOR
    Todd Charlton (todd.charlton@gmail.com)

.NOTES 
    Last modified: October 28, 2025
    Version: 1.0   
#>

# Config - Change these values as needed for your environment
$newDomain = "inovar.local"
$USMTPath = "\\modws08.modtek.int\USMT"
$StorePath = Join-Path $env:SystemDrive "USMT\Store"
#$currentDomain = (Get-WmiObject Win32_ComputerSystem).Domain
$USMTDomain = "modtek.int"
$EnableDebug = $false

# Ensure store path exists for hardlink
New-Item -ItemType Directory -Path $StorePath -Force | Out-Null

# Get profiles (non-special) and translate to NTAccount names
$profiles = Get-CimInstance -ClassName Win32_UserProfile |
  Where-Object {
    $_.LocalPath -and $_.LocalPath -like "$($env:SystemDrive)\Users\*" -and -not $_.Special
  } | ForEach-Object {
    try {
      $sid = New-Object System.Security.Principal.SecurityIdentifier($_.SID)
      $acct = $sid.Translate([System.Security.Principal.NTAccount]).Value
      [pscustomobject]@{ Account = $acct; Path = $_.LocalPath }
    } catch { $null }
  } | Where-Object { $_ } | Sort-Object Account

if (-not $profiles -or $profiles.Count -eq 0) {
  Write-Host "No user profiles found to migrate." -ForegroundColor Yellow
  exit 1
}

# Interactive selection UI
function Show-Menu {
  param(
    [array]$Items,
    [System.Collections.Generic.HashSet[int]]$Selected
  )
  Clear-Host
  Write-Host "Select user profile(s) to migrate:" -ForegroundColor Cyan
  Write-Host "Press number to toggle selection, 'A' to select all, ENTER to continue." -ForegroundColor DarkGray
  Write-Host ""
  for ($i = 0; $i -lt $Items.Count; $i++) {
    $num = $i + 1
    $isSel = $Selected.Contains($i)
    if ($isSel) {
      Write-Host ("[{0}] {1}" -f $num, $Items[$i].Account) -ForegroundColor Green
    } else {
      Write-Host -NoNewline "["; Write-Host -NoNewline "$num" -ForegroundColor Gray; Write-Host -NoNewline "] "
      Write-Host $Items[$i].Account
    }
  }
  if ($Selected.Count -gt 0) {
    Write-Host ""
    Write-Host "Profile selected. Press <ENTER> to process, or select more profiles" -ForegroundColor Green
  }
}

$selected = [System.Collections.Generic.HashSet[int]]::new()
Show-Menu -Items $profiles -Selected $selected

while ($true) {
  $key = [System.Console]::ReadKey($true)
  if ($key.Key -eq 'Enter') {
    if ($selected.Count -gt 0) { break } else { [console]::Beep(); continue }
  }
  elseif ($key.Key -eq 'A') {
    $selected.Clear()
    for ($i=0; $i -lt $profiles.Count; $i++) { $selected.Add($i) | Out-Null }
  }
  elseif ($key.Key -ge 'D0' -and $key.Key -le 'D9' -or $key.Key -ge 'NumPad0' -and $key.Key -le 'NumPad9') {
    # Map to number 0-9
    $num = 0
    switch ($key.Key) {
      'D0' { $num = 0 } 'D1' { $num = 1 } 'D2' { $num = 2 } 'D3' { $num = 3 } 'D4' { $num = 4 }
      'D5' { $num = 5 } 'D6' { $num = 6 } 'D7' { $num = 7 } 'D8' { $num = 8 } 'D9' { $num = 9 }
      'NumPad0' { $num = 0 } 'NumPad1' { $num = 1 } 'NumPad2' { $num = 2 } 'NumPad3' { $num = 3 } 'NumPad4' { $num = 4 }
      'NumPad5' { $num = 5 } 'NumPad6' { $num = 6 } 'NumPad7' { $num = 7 } 'NumPad8' { $num = 8 } 'NumPad9' { $num = 9 }
    }
    if ($num -ge 1 -and $num -le $profiles.Count) {
      $idx = $num - 1
      if ($selected.Contains($idx)) { $selected.Remove($idx) | Out-Null } else { $selected.Add($idx) | Out-Null }
    } else { [console]::Beep() }
  }
  Show-Menu -Items $profiles -Selected $selected
}

$selectedAccounts = $selected | ForEach-Object { $profiles[$_].Account }
Write-Host "Selected: $($selectedAccounts -join ', ')" -ForegroundColor Cyan

# Prompt for credentials to access USMT share.
Write-Host "Enter credentials to access USMT share ($USMTDomain domain):" -ForegroundColor Cyan
$usmtCreds = Get-Credential -Message "Enter Admin credentials for $USMTDomain"

# Prompt for credentials for the CURRENT domain (to unjoin)
$currentDomain = (Get-WmiObject Win32_ComputerSystem).Domain
Write-Host "Enter credentials with rights to REMOVE this computer from the CURRENT domain ($currentDomain):" -ForegroundColor Cyan
$currentDomainCreds = Get-Credential -Message "Enter an account from $currentDomain with rights to remove computers from the domain"

# Prompt for credentials for the NEW domain (to join)
Write-Host "Enter credentials with rights to JOIN this computer to the NEW domain ($newDomain):" -ForegroundColor Cyan
$newDomainCreds = Get-Credential -Message "Enter an account from $newDomain with rights to join computers to the domain"

# Map USMT share with net use (Windows-level drive letter)
$driveLetter = "U:"
$username = $usmtCreds.UserName
$password = $usmtCreds.GetNetworkCredential().Password

try {
  $netUseResult = & net use $driveLetter $USMTPath /user:$username $password 2>&1
  if ($LASTEXITCODE -ne 0) { throw "net use failed: $netUseResult" }
  Write-Host "USMT share mapped to $driveLetter successfully." -ForegroundColor Green
} catch {
  Write-Host "Failed to map USMT share: $($_.Exception.Message)" -ForegroundColor Red
  exit 1
}

# Copy USMT locally to avoid SYSTEM share access issues post-reboot
$LocalUSMTBin = Join-Path $env:SystemDrive "USMT\Bin"
try {
  New-Item -ItemType Directory -Path $LocalUSMTBin -Force | Out-Null
  Copy-Item -Path (Join-Path $driveLetter '*') -Destination $LocalUSMTBin -Recurse -Force -ErrorAction Stop
  Write-Host "Copied USMT to $LocalUSMTBin" -ForegroundColor Green
} catch {
  Write-Host "Failed to copy USMT locally: $($_.Exception.Message)" -ForegroundColor Red
  & net use $driveLetter /delete /yes | Out-Null
  exit 1
}

# Build ScanState arguments: only selected users
$scanExe = Join-Path $LocalUSMTBin 'scanstate.exe'
$scanArgs = @(
  "`"$StorePath`"",
  "/i:`"$LocalUSMTBin\miguser.xml`"",
  "/i:`"$LocalUSMTBin\migapp.xml`"",
  "/o", "/v:5", "/c", "/hardlink", "/nocompress",
  "/ue:*"
) + ($selectedAccounts | ForEach-Object { "/ui:`"$_`"" })
$scanArgsString = $scanArgs -join ' '

Write-Host "Running ScanState..." -ForegroundColor Cyan
try {
  $scan = Start-Process -FilePath $scanExe -ArgumentList $scanArgsString -NoNewWindow -Wait -PassThru
  $exitCode = $scan.ExitCode
} catch {
  Write-Host "Failed to start ScanState: $($_.Exception.Message)" -ForegroundColor Red
  & net use $driveLetter /delete /yes | Out-Null
  exit 1
}

if ($exitCode -ne 0) {
  Write-Host "ScanState failed with exit code $exitCode." -ForegroundColor Red
  & net use $driveLetter /delete /yes | Out-Null
  exit $exitCode
}

# Detect actual store path created by ScanState (for hardlink, it's usually $StorePath\USMT)
$actualStorePath = $StorePath
$storeSubdir = Join-Path $StorePath "USMT"
if (Test-Path $storeSubdir) {
  $actualStorePath = $storeSubdir
}
Write-Host "USMT store path for LoadState: $actualStorePath" -ForegroundColor Yellow

# Unmap share now; everything needed is local
& net use $driveLetter /delete /yes | Out-Null

# Prepare post-reboot LoadState script BEFORE joining domain
$PostRebootScript = "$env:SystemDrive\USMT_PostReboot.ps1"

# Build selected profiles (Account + Path) for ACL/registry fixes
$selectedProfileInfos = $profiles | Where-Object { $selectedAccounts -contains $_.Account }

# --- PRE-JOIN: Rename profile folder(s) and delete old ProfileList key(s) NOW (matches your manual flow) ---
foreach ($p in $selectedProfileInfos) {
  try {
    $oldAcct = $p.Account
    $user = $oldAcct.Split('\')[-1]

    # Rename C:\Users\name -> C:\Users\name.old (or .<stamp>.old if already exists)
    if (Test-Path -LiteralPath $p.Path) {
      $newPath = "$($p.Path).old"
      if (Test-Path -LiteralPath $newPath) {
        $stamp = Get-Date -Format "yyyyMMddHHmmss"
        $newPath = "$($p.Path).$stamp.old"
      }
      try {
        Move-Item -LiteralPath $p.Path -Destination $newPath -Force
        Write-Host "Renamed profile: $($p.Path) -> $newPath" -ForegroundColor Yellow
      } catch {
        Write-Host "Could not rename profile path $($p.Path): $($_.Exception.Message)" -ForegroundColor Yellow
      }
    }

    # Delete old SID key(s) from ProfileList for both local and current domain identities
    $candidates = @($oldAcct)
    if ($oldAcct -notlike "$($env:COMPUTERNAME)\*") { $candidates += "$($env:COMPUTERNAME)\$user" }
    if ($currentDomain -and ($oldAcct -notlike "$currentDomain\*")) { $candidates += "$currentDomain\$user" }

    foreach ($acct in $candidates | Select-Object -Unique) {
      try {
        $sid = (New-Object System.Security.Principal.NTAccount($acct)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $profKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
        if (Test-Path $profKey) {
          Remove-Item -Path $profKey -Recurse -Force -ErrorAction Stop
          Write-Host "Deleted ProfileList key for $acct ($sid)" -ForegroundColor Yellow
        }
        $profKeyBak = $profKey + ".bak"
        if (Test-Path $profKeyBak) {
          Remove-Item -Path $profKeyBak -Recurse -Force -ErrorAction Stop
          Write-Host "Deleted backup ProfileList key for $acct ($sid.bak)" -ForegroundColor Yellow
        }
      } catch {
        $msg = $_.Exception.Message
        Write-Host "ProfileList cleanup skipped for ${acct}: $($_.Exception.Message)" -ForegroundColor DarkYellow
      }
    }
  } catch {
    Write-Host "Pre-join prep failed for $($p.Account): $($_.Exception.Message)" -ForegroundColor DarkYellow
  }
}

# DEBUG: Show all .old folders and selected accounts
if ($EnableDebug) {
  $debugLog = "C:\TEMP\DEBUG_PreReboot.txt"
  "DEBUG: Folders in C:\Users after rename:" | Out-File -FilePath $debugLog -Encoding UTF8
  Get-ChildItem -Path "$env:SystemDrive\Users" -Directory | ForEach-Object { $_.FullName } | Out-File -FilePath $debugLog -Append -Encoding UTF8
  "DEBUG: SelectedAccounts:" | Out-File -FilePath $debugLog -Append -Encoding UTF8
  $selectedAccounts | Out-File -FilePath $debugLog -Append -Encoding UTF8
}

# REBUILD $selectedProfileInfos to reflect the new .old paths (robust matching)
$selectedProfileInfos = @()
$allFolders = Get-ChildItem -Path "$env:SystemDrive\Users" -Directory
foreach ($acct in $selectedAccounts) {
    $user = $acct.Split('\')[-1]
    # Find the most recent .old or .*.old folder for this user
    $matches = $allFolders | Where-Object {
        $_.Name -like "$user.old*" -or $_.Name -eq "$user.old"
    }
    if ($matches) {
        $folder = $matches | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        $selectedProfileInfos += [pscustomobject]@{ Account = $acct; Path = $folder.FullName }
    } else {
        "DEBUG: No .old folder found for $acct ($user)" | Out-File -FilePath $debugLog -Append -Encoding UTF8
    }
}

# DEBUG: Show what will be serialized for post-reboot
if ($EnableDebug) {
  "DEBUG: selectedProfileInfos for post-reboot:" | Out-File -FilePath $debugLog -Append -Encoding UTF8
  $selectedProfileInfos | Format-Table -AutoSize | Out-String | Out-File -FilePath $debugLog -Append -Encoding UTF8
}

# Assign $SelectedProfilesLiteral before writing any debug output or here-string usage
if ($selectedProfileInfos.Count -gt 0) {
  $SelectedProfilesLiteral = (
    $selectedProfileInfos | Where-Object { $_.Account -and $_.Path } | ForEach-Object {
      "    @{ Account = '$($_.Account)'; Path = '$($_.Path)' }"
    }
  ) -join ",`n"
} else {
  $SelectedProfilesLiteral = ""
}

# DEBUG: Show what will actually be injected into the post-reboot script
if ($EnableDebug) {
  Write-Host "DEBUG: SelectedProfilesLiteral:" -ForegroundColor Cyan
  Write-Host $SelectedProfilesLiteral -ForegroundColor Yellow
  "DEBUG: SelectedProfilesLiteral:" | Out-File -FilePath $debugLog -Append -Encoding UTF8
  $SelectedProfilesLiteral | Out-File -FilePath $debugLog -Append -Encoding UTF8
}

if ($selectedProfileInfos.Count -eq 0) {
  Write-Host "ERROR: No profiles found to serialize for post-reboot. The post-reboot script will not restore any profiles." -ForegroundColor Red
  if ($EnableDebug) {
    "ERROR: No profiles found to serialize for post-reboot. The post-reboot script will not restore any profiles." | Out-File -FilePath $debugLog -Append -Encoding UTF8
  }
}

# Build here-string with embedded values
$PostRebootContent = @"
# USMT LoadState post-reboot
`$ErrorActionPreference = 'Stop'
`$USMTBin = "$LocalUSMTBin"
`$StorePath = "$StorePath"
`$newDomain = "$newDomain"
`$currentDomain = "$currentDomain"

# Derive NetBIOS names from FQDNs and from selected profiles
`$newDomainNetBIOS = ((`$newDomain -split '\.')[0]).ToUpper()

# Ensure log dir and define log files
`$LogDir = "C:\TEMP"
try { New-Item -ItemType Directory -Path `$LogDir -Force | Out-Null } catch {}
`$LogPath = "C:\TEMP\loadstate.log"
`$ScriptLog = "C:\TEMP\LoadStateScript.log"

function Write-Log {
  param([string]`$Message)
  try {
    `$ts = Get-Date -Format o
    Add-Content -Path `$ScriptLog -Value "`$ts `$Message" -Encoding UTF8
  } catch {}
}

Write-Log "START: USMT LoadState post-reboot script"
Write-Log "USMTBin=`$USMTBin StorePath=`$StorePath NewDomain=`$newDomain CurrentDomain=`$currentDomain NewDomainNetBIOS=`$newDomainNetBIOS"

`$SelectedProfiles = @(
$SelectedProfilesLiteral)
Write-Log ("SelectedProfiles: " + ((`$SelectedProfiles | ForEach-Object { "`$(`$_.Account)->`$(`$_.Path)" }) -join ', '))

function Resolve-AccountSid {
  param([string]`$account,[int]`$TimeoutSec=180)
  `$sw=[System.Diagnostics.Stopwatch]::StartNew()
  while(`$sw.Elapsed.TotalSeconds -lt `$TimeoutSec){
    try{
      return (New-Object System.Security.Principal.NTAccount(`$account)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    }catch{}
    Start-Sleep -Seconds 5
  }
  throw "Could not resolve SID for `$account within `$TimeoutSec seconds"
}

try {
  # Small startup delay to ensure network and domain are available
  Write-Log "Waiting 30s for network/domain readiness..."
  Start-Sleep -Seconds 30

  # Ensure at least one target account resolves before proceeding
  try {
    `$probeUser = (`$SelectedProfiles | Select-Object -First 1).Account.Split('\')[-1]
    Write-Log "Probing SID for `${newDomainNetBIOS}\`${probeUser} ..."
    `$null = Resolve-AccountSid -account ("`${newDomainNetBIOS}\`${probeUser}") -TimeoutSec 300
    Write-Log "Domain SID resolution OK."
  } catch {
    Write-Log "ERROR: Domain not ready for SID translation: `$(`$_.Exception.Message)"
    throw
  }

  # Build /mu mappings: for each selected profile, map OLD_DOMAIN\user -> NEW_DOMAIN\user
  Write-Log "Building /mu arguments..."
  `$MuArgs = @()
  foreach (`$p in `$SelectedProfiles) {
    `$acct = `$p.Account
    if (`$acct -like "*\*") {
      `$parts = `$acct.Split('\', 2)
      if (`$parts.Count -eq 2) {
        `$srcDomain = `$parts[0]
        `$user = `$parts[1]
        `$MuArgs += "/mu:`${srcDomain}\`${user}:`${newDomainNetBIOS}\`${user}"
        Write-Log "Added /mu mapping: `${srcDomain}\`${user} -> `${newDomainNetBIOS}\`${user}"
      }
    }
  }
  Write-Log ("MuArgs: " + (`$MuArgs -join ' '))

  # Run LoadState
  `$loadExe = Join-Path `$USMTBin 'loadstate.exe'
  `$loadArgs = @(
    "`$StorePath",
    "/i:`$USMTBin\miguser.xml",
    "/i:`$USMTBin\migapp.xml",
    "/v:5", "/c", "/lac", "/lae",
    "/hardlink", "/nocompress",
    "/l:`$LogPath"
  ) + `$MuArgs

  Write-Log ('Executing: "' + `$loadExe + '" ' + (`$loadArgs -join ' '))
  Write-Host "Running LoadState..." -ForegroundColor Cyan
  Write-Host ("LoadState args: " + (`$loadArgs -join ' ')) -ForegroundColor DarkGray

  `$loadArgsString = `$loadArgs -join ' '
  `$proc = Start-Process -FilePath `$loadExe -ArgumentList `$loadArgsString -NoNewWindow -Wait -PassThru
  Write-Log ("LoadState exit code: " + `$proc.ExitCode)

  if (`$proc.ExitCode -ne 0) {
    Write-Host "LoadState failed with exit code `$(`$proc.ExitCode)." -ForegroundColor Red
    throw "LoadState failed with exit code `$(`$proc.ExitCode)"
  } else {
    Write-Host "LoadState completed." -ForegroundColor Green
    Write-Log "LoadState completed successfully."
  }

  # Optional: ensure State/RefCount are 0 for the new SID
  foreach (`$p in `$SelectedProfiles) {
    try {
      `$user = `$p.Account.Split('\')[-1]
      `$destAccount = "`${newDomainNetBIOS}\`${user}"
      `$destSid = (New-Object System.Security.Principal.NTAccount(`$destAccount)).Translate([System.Security.Principal.SecurityIdentifier]).Value
      `$profKeyNew = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\`$destSid"
      if (Test-Path `$profKeyNew) {
        New-ItemProperty -Path `$profKeyNew -Name "State" -Value 0 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path `$profKeyNew -Name "RefCount" -Value 0 -PropertyType DWord -Force | Out-Null
        Write-Log "Set State/RefCount=0 for SID `$destSid"
      } else {
        Write-Log "ProfileList key not found for SID `$destSid (skipped State/RefCount)."
      }
    } catch {
      Write-Log "Post-LoadState SID fix failed: `$(`$_.Exception.Message)"
    }
  }
}
catch {
  Write-Log "FATAL: `$(`$_.Exception.Message)"
}
finally {
  Write-Log "Attempting to unregister scheduled task USMT_LoadState..."
  try {
    Unregister-ScheduledTask -TaskName "USMT_LoadState" -Confirm:`$false -ErrorAction Stop
    Write-Log "Unregistered scheduled task USMT_LoadState."
  } catch {
    Write-Log "Unregister-ScheduledTask failed: `$(`$_.Exception.Message)"
  }

  Write-Log "Attempting to self-delete script..."
  try {
    Remove-Item -LiteralPath `$MyInvocation.MyCommand.Path -Force
    Write-Log "Self-delete OK."
  } catch {
    Write-Log "Self-delete failed: `$(`$_.Exception.Message)"
  }

  Write-Log "Rebooting in 2 seconds..."
  Start-Sleep -Seconds 2
  Restart-Computer -Force
}
"@

# --- Copy the generated post-reboot script to C:\TEMP for inspection ---
if ($EnableDebug) {
  try {
    Copy-Item -Path $PostRebootScript -Destination "C:\TEMP\USMT_PostReboot.ps1" -Force
    Write-Host "Copied USMT_PostReboot.ps1 to C:\TEMP for inspection." -ForegroundColor Yellow
  } catch {
    Write-Host "Failed to copy USMT_PostReboot.ps1 to C:\TEMP: $($_.Exception.Message)" -ForegroundColor Red
  }
}

# Create scheduled task to run LoadState after reboot
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PostRebootScript`""
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

try {
  Register-ScheduledTask -TaskName "USMT_LoadState" -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
  Write-Host "LoadState scheduled task created." -ForegroundColor Green
} catch {
  Write-Host "Failed to register scheduled task: $($_.Exception.Message)" -ForegroundColor Red
  exit 1
}

# --- Extra diagnostics: Write a marker file to confirm script reached this point ---
try {
  Set-Content -Path "$env:SystemDrive\USMT_ScheduleTaskCreated.txt" -Value "USMT_LoadState scheduled task created at $(Get-Date -Format o)" -Force
} catch {}

# Join domain
Write-Host "Joining domain $newDomain..." -ForegroundColor Cyan

# First, attempt to remove the existing computer account from the new domain (if it exists)
try {
  $computerName = $env:COMPUTERNAME
  Write-Host "Checking if computer account '$computerName' exists in $newDomain..." -ForegroundColor Yellow
  
  # Use Get-ADComputer to check if the account exists (requires RSAT or AD module)
  # Alternative: Use a try-catch with Remove-ADComputer directly
  $scriptBlock = {
    param($compName, $domain, $cred)
    try {
      # Attempt to remove the computer account
      $adComputer = Get-ADComputer -Identity $compName -Server $domain -Credential $cred -ErrorAction Stop
      Remove-ADComputer -Identity $compName -Server $domain -Credential $cred -Confirm:$false -ErrorAction Stop
      Write-Host "Removed existing computer account '$compName' from $domain." -ForegroundColor Green
    } catch {
      Write-Host "Computer account '$compName' does not exist in $domain or could not be removed. Proceeding with join." -ForegroundColor Yellow
    }
  }
  
  # Execute the removal (requires AD cmdlets, which may not be available)
  # If AD cmdlets are not available, skip this step and handle the error during Add-Computer
  if (Get-Command Get-ADComputer -ErrorAction SilentlyContinue) {
    & $scriptBlock -compName $computerName -domain $newDomain -cred $newDomainCreds
  } else {
    Write-Host "AD cmdlets not available. If the computer account exists, the join may fail. Consider deleting it manually." -ForegroundColor Yellow
  }
} catch {
  Write-Host "Could not check/remove existing computer account: $($_.Exception.Message)" -ForegroundColor Yellow
}

try {
  Add-Computer -DomainName $newDomain -Credential $newDomainCreds -UnjoinDomainCredential $currentDomainCreds -Force -Options AccountCreate,JoinWithNewName
  Write-Host "Domain join initiated. Rebooting to complete domain join and restore profiles..." -ForegroundColor Cyan
  Restart-Computer -Force
} catch {
  Write-Host "Domain join failed: $($_.Exception.Message)" -ForegroundColor Red
  Write-Host "TIP: If the computer account already exists in the new domain, delete it manually from Active Directory and try again." -ForegroundColor Yellow
  exit 1
}
