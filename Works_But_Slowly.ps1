<#
.SYNOPSIS
    This script is for taking a computer's local NTFS and share
    permissions containing domain accounts and adding a new domain permissions if the
    samAccountName matches.

.DESCRIPTION
    This script will look at permissions in the file path given using the
     -Path argument. It will then go through all domain user accounts for
     the local domain, find the matching account on the new domain,
     and add identical permissions for the new domain's "version" of this account.
     The script will also change share permissions and NTFS permissions 
     for those shares if you answer "y" at the first prompt.
     Logs are saved in C:\Logs. There may be up to 2 logs: file/folder
     changes as well as a list of users NOT found in the new domain.

.AUTHOR
    Todd Charlton (todd.charlton@gmail.com)

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
    Last modified: October 14, 2025
    Version: 1.3
    
    
    Added -DryRun switch parameter
    Added check for inherited permissions to speed up processing

    Requires the ActiveDirectory module.
    Run in an elevated PowerShell prompt.
    Tested on Windows 10 and Windows 11.
    Make sure to set the $localDomain variable to the correct local domain name.
    Make sure to edit the $AdditionalPaths variable if you want to add more folders
     to process.
    Make sure to run this script on the target computer.
    A trust must exist between the local and new domains.
#>

param (
    [string]$Path,
    [switch]$DryRun

)
$ErrorActionPreference = "SilentlyContinue"
# Uncomment and edit the following line to add multiple folders:
# $AdditionalPaths = @("C:\Your\Path\Here", "C:\TESTDIR1")

$LogDir = "C:\logs"
$MissingUsersLog = "$LogDir\userDoesNotExist.log"
$ChangesLog = "$LogDir\Changes.log"
$ErrorLog = "$LogDir\errorlog.txt"

# Change the domain below to set the "local" domain
$newDomain = "INOVAR"
$LoggedMissingUsers = @{}
# Cache for resolved accounts in new domain to avoid repeated AD queries for same samAccountName
$newDomainAccountCache = @{}

# Exclusions
$ExcludedShareNames = @('SYSVOL','NETLOGON')
$ExcludedPathNamePatterns = @('System Volume Information', '$RECYCLE.BIN', 'RECYCLER')

# Create log directory if it doesn't exist
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



function Get-NewDomainAccount {
    param ($SamAccountName)

    try {
        # Request objectSid so we can use SIDs for ACL operations and verification
        $user = Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -Server "$newDomain" -Properties objectSid -ErrorAction SilentlyContinue
        if ($user) {
            try {
                if ($user.objectSid) {
                    $sidObj = New-Object System.Security.Principal.SecurityIdentifier($user.objectSid,0)
                    $user | Add-Member -NotePropertyName SID -NotePropertyValue $sidObj -Force
                }
            } catch { }
            return $user
        }

        $group = Get-ADGroup -Filter "SamAccountName -eq '$SamAccountName'" -Server "$newDomain" -Properties objectSid -ErrorAction SilentlyContinue
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
        Write-ErrorLog -Message "Error looking up $newDomain account for ${SamAccountName}: $_"
        return $null
    }
}

# -------------------------
# New: safe recursive enumerator that logs enumeration failures
# Returns PSCustomObject entries with properties: Item, Acl  (only when -OnlyProtected is used)
function Get-ChildItemsSafe {
    param (
        [Parameter(Mandatory=$true)][string]$StartPath,
        [switch]$OnlyProtected
    )
    $results = @()
    try {
        $startItem = Get-Item -LiteralPath $StartPath -Force -ErrorAction Stop
    } catch {
        Write-ErrorLog -Message "Failed to get start item ${StartPath}: $_"
        return $results
    }

    $stack = New-Object System.Collections.Stack
    $stack.Push($startItem)

    while ($stack.Count -gt 0) {
        $node = $stack.Pop()
        try {
            $children = Get-ChildItem -LiteralPath $node.FullName -Force -ErrorAction Stop
        } catch {
            Write-ErrorLog -Message "Failed to enumerate children of $($node.FullName): $_"
            continue
        }
        foreach ($child in $children) {
            # Skip excluded system folders by name
            if ($ExcludedPathNamePatterns -contains $child.Name) { continue }
            # Only wrap in PSCustomObject if ACLs are protected or if caller wants all
            if ($OnlyProtected) {
                try {
                    $acl = Get-Acl -Path $child.FullName -ErrorAction Stop
                } catch {
                    Write-ErrorLog -Message "Access denied or failed to get ACL for $($child.FullName): $_"
                    continue
                }
                if ($acl.AreAccessRulesProtected) {
                    $results += [PSCustomObject]@{ Item = $child; Acl = $acl }
                }
            } else {
                # Fast path: only wrap if ACLs are not fully inherited
                try {
                    $acl = Get-Acl -Path $child.FullName -ErrorAction Stop
                    if ($acl.AreAccessRulesProtected -or ($acl.Access | Where-Object { -not $_.IsInherited })) {
                        $results += [PSCustomObject]@{ Item = $child; Acl = $acl }
                    }
                } catch {
                    # If ACL can't be read, just skip
                    continue
                }
            }
            if ($child.PSIsContainer) { $stack.Push($child) }
        }
    }
    return $results
}
# -------------------------

function Update-Permissions {
    param ($TargetPath)

    try {
    # Initial progress indicator so something appears immediately
    Write-Progress -Activity "Processing Permissions" -Status "Preparing items for $TargetPath" -PercentComplete 0
        # Collect items to process, including the root item
        $items = @()
        try {
            # Use safe enumerator so access-denied while recursing is logged
            # Process ALL items so we can add explicit ACEs even when ACLs are inherited
            $items = @(Get-ChildItemsSafe -StartPath $TargetPath)
        } catch {
            Write-ErrorLog -Message "Error enumerating items under ${TargetPath}: $_"
        }

        # Always include root path if possible
        try {
            $rootItem = Get-Item -LiteralPath $TargetPath -Force -ErrorAction Stop
            try {
                $rootAcl = Get-Acl -Path $rootItem.FullName -ErrorAction Stop
                # add as same PSCustomObject structure produced by enumerator
                $items = ,([PSCustomObject]@{ Item = $rootItem; Acl = $rootAcl }) + $items
            } catch {
                Write-ErrorLog -Message "Access denied or failed to get ACL for $($rootItem.FullName): $_"
            }
        } catch {
            Write-ErrorLog -Message "Failed to get root item ${TargetPath}: $_"
        }

            # If ACL is fully inherited and user wants explicit changes, optionally protect it
            if ($ProtectAcl -and -not $DryRun) {
                try {
                    if (-not $acl.AreAccessRulesProtected) {
                        # Protect the ACL but preserve existing inherited ACEs by copying them
                        $acl.SetAccessRuleProtection($true, $true)
                    }
                } catch {
                    Write-ErrorLog -Message "Failed to protect ACL on $($item.FullName): $_"
                }
            }

        $total = $items.Count

        if ($total -eq 0) { 
            Write-Progress -Activity "Processing Permissions" -Completed -Status "Nothing to change for $TargetPath"
            return 
        }

        # Small nudge to show progress before the loop starts
        Write-Progress -Activity "Processing Permissions" -Status "Starting scan in $TargetPath" -PercentComplete 1

        foreach ($entry in $items) {
            $item = if ($entry.PSObject.Properties.Name -contains 'Item') { $entry.Item } else { $entry }
            try {
                $acl = Get-Acl -Path $item.FullName -ErrorAction Stop
            } catch {
                Write-ErrorLog -Message "Failed to get ACL for $($item.FullName): $_"
                continue
            }

            Write-Progress -Activity "Processing Permissions" -Status "Processing $($item.FullName)" -PercentComplete 0
            if (-not $acl) { Write-ErrorLog -Message "Missing ACL object for $($item.FullName), skipping."; continue }

            $explicitNonNewDomain = @()
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
                if ($acctDomain -ieq $newDomain) { continue }
                $explicitNonNewDomain += [PSCustomObject]@{
                    Domain = $acctDomain
                    Name = $acctName
                    Rights = $access.FileSystemRights
                    InheritanceFlags = $access.InheritanceFlags
                    PropagationFlags = $access.PropagationFlags
                    AccessControlType = $access.AccessControlType
                }
            }

            if ($explicitNonNewDomain.Count -eq 0) { continue }

            $modified = $false
            foreach ($aceInfo in $explicitNonNewDomain) {
                $domainUser = $aceInfo.Name

                if ($NewDomainAccountCache.ContainsKey($domainUser)) {
                    $newDomainAccount = $NewDomainAccountCache[$domainUser]
                } else {
                    try {
                        $newDomainAccount = Get-NewDomainAccount -SamAccountName $domainUser
                    } catch {
                        Write-ErrorLog -Message "Error looking up $newDomain account for ${domainUser}: $_"
                        $newDomainAccount = $null
                    }
                    $NewDomainAccountCache[$domainUser] = $newDomainAccount
                }

                if ($null -eq $newDomainAccount) { Write-MissingUser -Username $domainUser -Type "User/Group"; continue }

                try {
                    $identityRef = if ($newDomainAccount.SID) {
                        $newDomainAccount.SID
                    } else {
                        New-Object System.Security.Principal.NTAccount($newDomain, $domainUser)
                    }

                    $newAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                        $identityRef,
                        $aceInfo.Rights,
                        $aceInfo.InheritanceFlags,
                        $aceInfo.PropagationFlags,
                        $aceInfo.AccessControlType
                    )
                    # Avoid adding duplicates: check if an equivalent rule exists
                    $existing = $false
                    foreach ($rule in $acl.Access) {
                        if ($rule.IdentityReference -eq $identityRef -and
                            $rule.FileSystemRights -eq $aceInfo.Rights -and
                            $rule.AccessControlType -eq $aceInfo.AccessControlType -and
                            $rule.InheritanceFlags -eq $aceInfo.InheritanceFlags -and
                            $rule.PropagationFlags -eq $aceInfo.PropagationFlags) {
                            $existing = $true; break
                        }
                    }
                    if (-not $existing) {
                        $acl.AddAccessRule($newAccessRule)
                        $modified = $true
                    }
                } catch {
                    Write-ErrorLog -Message "Failed to create/add access rule for $newDomain\\$domainUser on $($item.FullName): $_"; continue
                }
            }

            if ($modified) {
                if ($DryRun) {
                    Write-ChangeLog -Message "[Dry Run] Would add $newDomain accounts to $($item.FullName)"
                } else {
                    try {
                        Set-Acl -Path $item.FullName -AclObject $acl -ErrorAction Stop
                        Write-ChangeLog -Message "Added $newDomain accounts to $($item.FullName)"
                    } catch {
                        Write-ErrorLog -Message "Failed to set ACL on $($item.FullName): $_"; continue
                    }
                }
            }
        }

        Write-Progress -Activity "Processing Permissions" -Completed -Status "Done with $TargetPath"
    } catch {
        Write-ErrorLog -Message "Failed to process ${TargetPath}: $_"
    }
}

Clear-Host
Write-Host "These are the non-admin shares on the current computer:`n"

try {
    $shares = Get-WmiObject -Class Win32_Share | Where-Object { $_.Path -ne $null -and $_.Name -notmatch '\$$' -and ($ExcludedShareNames -notcontains $_.Name) }
    foreach ($share in $shares) {
        Write-Host "Share Name: $($share.Name) | Path: $($share.Path)"
    }
} catch {
    Write-ErrorLog -Message "Failed to enumerate shares before prompt: $_"
    Write-Host "Unable to retrieve share information."
}

Write-Host ""
$processShares = Read-Host "Do you want to process NTFS permissions on shared folders? (y/n)"
# Log the user's choice for auditing
Write-ChangeLog -Message "User response to process shared folders prompt: $processShares"

if ($processShares -eq "y") {
    try {
        $shares = Get-WmiObject -Class Win32_Share | Where-Object { $_.Path -ne $null -and $_.Name -notmatch '\$$' -and ($ExcludedShareNames -notcontains $_.Name) }
        foreach ($share in $shares) {
            Update-Permissions -TargetPath $share.Path -DryRun:$DryRun
        }
    } catch {
        Write-ErrorLog -Message "Failed to enumerate shares: $_"
    }
}

Update-Permissions -TargetPath $Path -DryRun:$DryRun

foreach ($additionalPath in $AdditionalPaths) {
    Update-Permissions -TargetPath $additionalPath -DryRun:$DryRun
}

Write-Host "Permission migration completed. Check logs in $LogDir."