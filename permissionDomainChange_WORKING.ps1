<#
.SYNOPSIS
    This script is for switching a computer's local NTFS and share
    permissions to Inovar domain permissions.

.DESCRIPTION
    This script will look at permissions in the file path given using the
     -Path argument. It will then go through all domain user accounts for
     the local domain, find the matching account on the Inovar domain,
     and add identical permissions for the Inovar "version" of this account.
     The script will also change share permissions and NTFS permissions 
     for those shares if you answer "y" at the first prompt.
     Logs are saved in C:\Logs. There may be up to 2 logs: file/folder
     changes as well as a list of users NOT found in the Inovar domain.

.AUTHOR
    Todd Charlton (tcharlton@inovarpkg.com)

.PARAMETER Parameter1
     -DryRun
     If specified, the script will log what changes would be made, but not actually apply them. 
     Similar to -WhatIf in other cmdlets.

     -Path <System.String[]>
     Specifies the path of the location of the new item. The default is the current location when Path is omitted. You can specify the name of the new item in Name , or include it 
     in Path . Items names passed using the Name parameter are created relative to the value of the Path parameter.
        
     For this cmdlet, the Path parameter works like the LiteralPath parameter of other cmdlets. Wildcard characters are not interpreted. All characters are passed to the location's 
     provider. The provider may not support all characters. For example, you can't create a filename that contains an asterisk (`*`) character.

.EXAMPLE
    Example usage of the script/function.
    PS C:\> permissionDomainChange.ps1 -Path "C:\SharedFolder"
<#
.SYNOPSIS
    This script is for switching a computer's local NTFS and share
    permissions to Inovar domain permissions.

.DESCRIPTION
    This script will look at permissions in the file path given using the
     -Path argument. It will then go through all domain user accounts for
     the local domain, find the matching account on the Inovar domain,
     and add identical permissions for the Inovar "version" of this account.
     The script will also change share permissions and NTFS permissions 
     for those shares if you answer "y" at the first prompt.
     Logs are saved in C:\Logs. There may be up to 2 logs: file/folder
     changes as well as a list of users NOT found in the Inovar domain.

.AUTHOR
    Todd Charlton (tcharlton@inovarpkg.com)

.PARAMETER Parameter1
     -DryRun
     If specified, the script will log what changes would be made, but not actually apply them. 
     Similar to -WhatIf in other cmdlets.

     -Path <System.String[]>
     Specifies the path of the location of the new item. The default is the current location when Path is omitted. You can specify the name of the new item in Name , or include it 
     in Path . Items names passed using the Name parameter are created relative to the value of the Path parameter.
        
     For this cmdlet, the Path parameter works like the LiteralPath parameter of other cmdlets. Wildcard characters are not interpreted. All characters are passed to the location's 
     provider. The provider may not support all characters. For example, you can't create a filename that contains an asterisk (`*`) character.

.EXAMPLE
    Example usage of the script/function.
    PS C:\> permissionDomainChange.ps1 -Path "C:\SharedFolder"

.NOTES 
    Last modified: October 9, 2025
    Version: 1.2
    
    Added -DryRun switch parameter
    Added check for inherited permissions to speed up processing

    Requires the ActiveDirectory module.
    Run in an elevated PowerShell prompt.
    Tested on Windows 10 and Windows 11.
    Make sure to set the $localDomain variable to the correct local domain name.
    Make sure to edit the $AdditionalPaths variable if you want to add more folders
     to process.
    Make sure to run this script on the target computer.
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$Path,
    [switch]$DryRun,
    [switch]$DebugMode
)
$ErrorActionPreference = "SilentlyContinue"
# Uncomment and edit the following line to add multiple folders
# $AdditionalPaths = @("C:\Your\Path\Here", "C:\TESTDIR1")
$LogDir = "C:\logs"
$MissingUsersLog = "$LogDir\userDoesNotExist.log"
$ChangesLog = "$LogDir\Changes.log"
$ErrorLog = "$LogDir\errorlog.txt"

# Change the domain below to set the "local" domain
$localDomain = "MODTEK"
$LoggedMissingUsers = @{}
# Cache for resolved Inovar accounts to avoid repeated AD queries for same samAccountName
$InovarAccountCache = @{}

# Log files
if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
# Ensure log files exist and write header lines for easier debugging when no changes are made
if (!(Test-Path $MissingUsersLog)) { New-Item -Path $MissingUsersLog -ItemType File -Force | Out-Null }
if (!(Test-Path $ChangesLog)) { New-Item -Path $ChangesLog -ItemType File -Force | Out-Null }
if (!(Test-Path $ErrorLog)) { New-Item -Path $ErrorLog -ItemType File -Force | Out-Null }
Add-Content -Path $ChangesLog -Value "$(Get-Date -Format u) - INFO: Starting permissionDomainChange.ps1 - Path=$Path -DryRun=$DryRun"

function Write-ErrorLog {
    param ($Message)
    Add-Content -Path $ErrorLog -Value "$((Get-Date).ToString()) - ERROR: $Message"
}

function Write-ChangeLog {
    param ($Message)
    Add-Content -Path $ChangesLog -Value "$((Get-Date).ToString()) - CHANGE: $Message"
}


function Write-MissingUser {
    param (
        [string]$Username,
        [string]$Type = "Unknown"
    )
    if (-not $LoggedMissingUsers.ContainsKey($Username)) {
        Add-Content -Path $MissingUsersLog -Value "$((Get-Date).ToString()) - MISSING ($Type): $Username"
        $LoggedMissingUsers[$Username] = $true
    }
}



function Get-InovarAccount {
    param ($SamAccountName)

    try {
        # Request objectSid so we can use SIDs for ACL operations and verification
        $user = Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -Server "inovar.local" -Properties objectSid -ErrorAction SilentlyContinue
        if ($user) {
            try {
                if ($user.objectSid) {
                    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($user.objectSid,0)
                    $user | Add-Member -NotePropertyName SID -NotePropertyValue $sidObj -Force
                }
            } catch { }
            return $user
        }

        $group = Get-ADGroup -Filter "SamAccountName -eq '$SamAccountName'" -Server "inovar.local" -Properties objectSid -ErrorAction SilentlyContinue
        if ($group) {
            try {
                if ($group.objectSid) {
                    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($group.objectSid,0)
                    $group | Add-Member -NotePropertyName SID -NotePropertyValue $sidObj -Force
                }
            } catch { }
            return $group
        }

        return $null
    } catch {
        Write-ErrorLog -Message "Error looking up Inovar account for ${SamAccountName}: $_"
        return $null
    }
}


function Update-Permissions {
    param ($TargetPath)

    try {
        # Ensure $items is always an array so loops behave consistently. Use Get-ChildItem once
        # and include the root target via Get-Item; filter nulls efficiently.
        $items = @(Get-ChildItem -Path $TargetPath -Recurse -Force -ErrorAction SilentlyContinue)
        $rootItem = Get-Item -Path $TargetPath -Force -ErrorAction SilentlyContinue
        if ($rootItem) { $items += $rootItem }
        $total = $items.Count

        if ($total -eq 0) {
            Write-Host "No items found in $TargetPath"
            return
        }

        $counter = 0
        foreach ($item in $items) {
            $counter++
            $percent = [math]::Round(($counter / $total) * 100, 2)
            Write-Progress -Activity "Processing Permissions" -Status "Scanning $($item.FullName)" -PercentComplete $percent

            try {
                $acl = Get-Acl -Path $item.FullName -ErrorAction SilentlyContinue
            } catch {
                Write-ErrorLog -Message "Access denied or failed to get ACL for $($item.FullName): $_"
                continue
            }

            # First pass: look for any explicit ACEs that are NOT INOVAR and collect them.
            $explicitNonInovar = @()
            foreach ($access in $acl.Access) {
                if ($access.IsInherited) { continue }
                $identity = $access.IdentityReference.Value
                if ($identity -match '^(?<domain>[^\\]+)\\(?<name>.+)$') {
                    $acctDomain = $matches['domain']
                    $acctName = $matches['name']
                } else {
                    $acctDomain = $env:COMPUTERNAME
                    $acctName = $identity
                }
                if ($acctDomain -ieq 'INOVAR') { continue }
                # store a lightweight PSCustomObject with needed values to minimize repeated parsing
                $explicitNonInovar += [PSCustomObject]@{
                    Domain = $acctDomain
                    Name = $acctName
                    Rights = $access.FileSystemRights
                    InheritanceFlags = $access.InheritanceFlags
                    PropagationFlags = $access.PropagationFlags
                    AccessControlType = $access.AccessControlType
                }
            }

            # If there are no explicit non-INOVAR ACEs, skip expensive AD lookups and Set-Acl
            if ($explicitNonInovar.Count -eq 0) { continue }

            # For each explicit non-INOVAR ACE resolve an Inovar account (cached) and add new ACEs to a single ACL object
            $modified = $false
            foreach ($aceInfo in $explicitNonInovar) {
                $domainUser = $aceInfo.Name

                # Use cache to avoid repeated AD queries
                if ($InovarAccountCache.ContainsKey($domainUser)) {
                    $inovarAccount = $InovarAccountCache[$domainUser]
                } else {
                    try {
                        $inovarAccount = Get-InovarAccount -SamAccountName $domainUser
                    } catch {
                        Write-ErrorLog -Message "Error looking up Inovar account for ${domainUser}: $_"
                        $inovarAccount = $null
                    }
                    $InovarAccountCache[$domainUser] = $inovarAccount
                }

                if ($null -eq $inovarAccount) {
                    Write-MissingUser -Username $domainUser -Type "User/Group"
                    continue
                }

                if ($DebugMode) {
                    try { Add-Content -Path $ErrorLog -Value "$(Get-Date -Format u) - DEBUG: Found InovarAccount for ${domainUser}: $(( $inovarAccount | Select-Object Name, SamAccountName, SID ) -join ', ')" } catch { }
                }

                $identityRef = $null
                try {
                    if ($inovarAccount -and $inovarAccount.SID) {
                        $identityRef = $inovarAccount.SID
                    } else {
                        $identityRef = New-Object System.Security.Principal.NTAccount('INOVAR', $domainUser)
                    }

                    $newAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                        $identityRef,
                        $aceInfo.Rights,
                        $aceInfo.InheritanceFlags,
                        $aceInfo.PropagationFlags,
                        $aceInfo.AccessControlType
                    )

                    $acl.AddAccessRule($newAccessRule)
                    $modified = $true
                } catch {
                    $acctInfo = ''
                    try { $acctInfo = ($inovarAccount | Select-Object Name, SamAccountName, SID | Out-String) } catch { $acctInfo = "(unable to serialize inovarAccount)" }
                    Write-ErrorLog -Message "Failed to create/add access rule for INOVAR\\$domainUser on $($item.FullName): $_; InovarAccount: $acctInfo"
                    continue
                }
            }

            if ($modified) {
                if ($DryRun) {
                    # Log a single message per modified item to reduce IO
                    Write-ChangeLog -Message "[Dry Run] Would add INOVAR accounts to $($item.FullName)"
                } else {
                    try {
                        Set-Acl -Path $item.FullName -AclObject $acl -ErrorAction Stop
                        Write-ChangeLog -Message "Added INOVAR accounts to $($item.FullName)"
                    } catch {
                        Write-ErrorLog -Message "Failed to set ACL on $($item.FullName): $_"
                        continue
                    }
                }
            }
        }

        Write-Progress -Activity "Processing Permissions" -Completed -Status "Done with $TargetPath"
    } catch {
        Write-ErrorLog -Message "Failed to process ${TargetPath}: $_"
    }
}

# Prompt for share processing
Clear-Host
Write-Host "These are the non-admin shares on the current computer:`n"

try {
    $shares = Get-WmiObject -Class Win32_Share | Where-Object { $_.Path -ne $null -and $_.Name -notmatch '\$$' }
    foreach ($share in $shares) {
        Write-Host "Share Name: $($share.Name) | Path: $($share.Path)"
    }
} catch {
    Write-ErrorLog -Message "Failed to enumerate shares before prompt: $_"
    Write-Host "Unable to retrieve share information."
}

Write-Host ""
$processShares = Read-Host "Do you want to process NTFS permissions on shared folders? (y/n)"
if ($processShares -eq "y") {
    try {
        $shares = Get-WmiObject -Class Win32_Share | Where-Object { $_.Path -ne $null -and $_.Name -notmatch '\$$' }
        foreach ($share in $shares) {
            Update-Permissions -TargetPath $share.Path -DryRun:$DryRun
        }
    } catch {
        Write-ErrorLog -Message "Failed to enumerate shares: $_"
    }
}

# Process main path
Update-Permissions -TargetPath $Path -DryRun:$DryRun

# Process additional paths
foreach ($additionalPath in $AdditionalPaths) {
    Update-Permissions -TargetPath $additionalPath -DryRun:$DryRun
}

Write-Host "Permission migration completed. Check logs in $LogDir."