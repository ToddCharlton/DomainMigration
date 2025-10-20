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
    Last modified: October 15, 2025
    Version: 1.4.1
    
    Optimized Resolve-NewDomainAccounts to bulk-resolve samAccountNames in a single LDAP query:
        Reduced repeated AD queries for same samAccountName
        Added parallel queries for users and groups
        Added caching of resolved accounts to avoid repeated queries
    Optimized for faster execution, reduced memory overhead, and better performance on Active Directory.
    Added Get-ChildItemsSafe to use a stack-based recursion to avoid deep recursion issues:
        Fixed access-denied errors not getting logged
        Reduced duplicate Get-Acl calls
    Updated Update-Permissions to use the new enumerator (Get-ChildItemsSafe)
    Fixed domain comparison bug
    Added logging of user response to processShares prompt  
    Added -DryRun switch parameter
    Added check for inherited permissions to speed up processing

    REQUIRES the ActiveDirectory module.
    Run in an elevated PowerShell prompt.
    Tested on Windows 10,11, and Server 2019.
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
[hashtable]$NewDomainAccountCache = @{}

# Create log directory if it doesn't exist
if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}
# Ensure log files exist and write header lines for easier debugging when no changes are made
if (!(Test-Path $MissingUsersLog)) { New-Item -Path $MissingUsersLog -ItemType File -Force | Out-Null }
if (!(Test-Path $ChangesLog)) { New-Item -Path $ChangesLog -ItemType File -Force | Out-Null }
if (!(Test-Path $ErrorLog)) { New-Item -Path $ErrorLog -ItemType File -Force | Out-Null }
Add-Content -Path $ChangesLog -Value "$(Get-Date -Format u) - INFO: Starting permissionDomainChange.ps1 - Path=$Path -DryRun=$DryRun"

# Use a shared date format for consistency and performance
$script:DateFormat = 'yyyy-MM-dd HH:mm:ss'

# Normalize an identity reference to 'DOMAIN\\Name' when possible
function Convert-IdentityToNTValue {
    param(
        [Parameter(Mandatory=$true)]
        [System.Security.Principal.IdentityReference]$Identity
    )
    try {
        return ($Identity.Translate([System.Security.Principal.NTAccount]).Value)
    } catch {
        return $Identity.Value
    }
}

# Robust ACL applier: try Set-Acl; if verification fails, use .NET SetAccessControl as fallback
function Set-AclRobust {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][System.Security.AccessControl.FileSystemSecurity]$Acl
    )
    try {
        Set-Acl -Path $Path -AclObject $Acl -ErrorAction Stop
        return $true
    } catch {
        # Fallback to .NET APIs
        try {
            $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
            if ($item.PSIsContainer) {
                $dirSec = [System.IO.Directory]::GetAccessControl($Path)
                $dirSec.SetSecurityDescriptorSddlForm($Acl.GetSecurityDescriptorSddlForm('All'))
                [System.IO.Directory]::SetAccessControl($Path, $dirSec)
            } else {
                $fileSec = [System.IO.File]::GetAccessControl($Path)
                $fileSec.SetSecurityDescriptorSddlForm($Acl.GetSecurityDescriptorSddlForm('All'))
                [System.IO.File]::SetAccessControl($Path, $fileSec)
            }
            return $true
        } catch {
            Write-ErrorLog -Message "Set-AclRobust fallback failed for ${Path}: $_"
            return $false
        }
    }
}

function Write-ErrorLog {
    param ($Message)
    Add-Content -Path $ErrorLog -Value "$((Get-Date).ToString($script:DateFormat)) - ERROR: $Message"
}

function Write-ChangeLog {
    param ($Message)
    Add-Content -Path $ChangesLog -Value "$((Get-Date).ToString($script:DateFormat)) - CHANGE: $Message"
}

function Write-MissingUser {
    param (
        [string]$Username,
        [string]$Type = "Unknown"
    )
    if (-not $LoggedMissingUsers.ContainsKey($Username)) {
        Add-Content -Path $MissingUsersLog -Value "$((Get-Date).ToString($script:DateFormat)) - MISSING ($Type): $Username"
        $LoggedMissingUsers[$Username] = $true
    }
}



function Get-NewDomainAccount {
    param ([string]$SamAccountName)

    if ([string]::IsNullOrWhiteSpace($SamAccountName)) { return $null }
    $key = $SamAccountName.Trim()

    if ($NewDomainAccountCache.ContainsKey($key)) { return $NewDomainAccountCache[$key] }

    # Bulk-resolve single name (will populate cache entry)
    Resolve-NewDomainAccounts -SamNames @($key)

    return $NewDomainAccountCache[$key]
}

# -------------------------
# New helper: Bulk-resolve a list of samAccountNames from the target domain and populate cache
function Resolve-NewDomainAccounts {
    param (
        [Parameter(Mandatory=$true)][string[]]$SamNames
    )
    try {
        # Optimize: combine filtering operations and use -notmatch for empty check
        $toResolve = $SamNames | 
            ForEach-Object { $_.Trim() } | 
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and -not $NewDomainAccountCache.ContainsKey($_) } | 
            Select-Object -Unique
        
        if ($toResolve.Count -eq 0) { return }

        # Build an LDAP OR filter: (|(sAMAccountName=name1)(sAMAccountName=name2)...)
        $clauses = $toResolve | ForEach-Object { "(sAMAccountName=$($_))" }
        $ldapFilter = '(|' + ($clauses -join '') + ')'

        # Query users and groups with a PS7-optimized path (Parallel) and 5.1 fallback
        $found = @()
        # Remove -Server parameter (use default domain context)
        try {
            $found += Get-ADUser -LDAPFilter $ldapFilter -Properties objectSid -ErrorAction SilentlyContinue
        } catch {}
        try {
            $found += Get-ADGroup -LDAPFilter $ldapFilter -Properties objectSid -ErrorAction SilentlyContinue
        } catch {}

        # Populate cache for found accounts
        foreach ($obj in $found) {
            $sam = $obj.SamAccountName
            if (-not $sam) { continue }
            
            try {
                if ($obj.objectSid) {
                    $sidObj = [System.Security.Principal.SecurityIdentifier]::new($obj.objectSid, 0)
                    $obj | Add-Member -NotePropertyName SID -NotePropertyValue $sidObj -Force
                }
            } catch { 
                # Continue even if SID conversion fails
            }
            $NewDomainAccountCache[$sam] = $obj
        }

        # Mark unresolved names as $null to avoid repeated queries
        foreach ($name in $toResolve) {
            if (-not $NewDomainAccountCache.ContainsKey($name)) {
                $NewDomainAccountCache[$name] = $null
            }
        }
    } catch {
        Write-ErrorLog -Message "Resolve-NewDomainAccounts failed: $_"
    }
}
# -------------------------

# New helper: unify share enumeration and prefer Get-SmbShare with a WMI fallback
function Get-NonAdminShares {
    try {
        if (Get-Command -Name Get-SmbShare -ErrorAction SilentlyContinue) {
            # Use Get-SmbShare for better performance on modern systems
            $smb = Get-SmbShare | Where-Object { 
                $_.Path -and 
                $_.Name -notmatch '\$|^(SYSVOL|NETLOGON)$' 
            }
            return $smb | ForEach-Object { [PSCustomObject]@{ Name = $_.Name; Path = $_.Path } }
        } else {
            # Fallback to CIM for better performance than WMI
            $shares = Get-CimInstance -ClassName Win32_Share -ErrorAction SilentlyContinue
            if ($null -eq $shares) {
                $shares = Get-WmiObject -Class Win32_Share -ErrorAction SilentlyContinue
            }
            if ($null -eq $shares) {
                $shares = @()
            }
            $shares = $shares | Where-Object { 
                $_.Path -and 
                $_.Name -notmatch '\$|^(SYSVOL|NETLOGON)$' 
            }
            return $shares | ForEach-Object { [PSCustomObject]@{ Name = $_.Name; Path = $_.Path } }
        }
    } catch {
        Write-ErrorLog -Message "Get-NonAdminShares failed: $_"
        return @()
    }
}

# -------------------------
# New: safe recursive enumerator that logs enumeration failures
# Returns PSCustomObject entries with properties: Item, Acl  (only when -OnlyProtected is used)
function Get-ChildItemsSafe {
    param (
        [Parameter(Mandatory=$true)][string]$StartPath,
        [switch]$OnlyProtected,
        [switch]$ShowProgress
    )
    $results = @()
    try {
        $startItem = Get-Item -LiteralPath $StartPath -Force -ErrorAction Stop
    } catch {
        Write-ErrorLog -Message "Failed to get start item ${StartPath}: $_"
        return $results
    }

    # Show an immediate progress indicator if requested
    if ($ShowProgress) {
        Write-Progress -Activity "Enumerating Items" -Status "Starting enumeration of $StartPath" -Id 2
    }

    $stack = New-Object System.Collections.Stack
    $stack.Push($startItem)
    $enumCounter = 0

    # Precompile regex for better performance
    $skipPattern = '\\(SYSVOL|NETLOGON|\$RECYCLE\.BIN|System Volume Information)($|\\)'
    
    while ($stack.Count -gt 0) {
        $node = $stack.Pop()
        # Skip excluded folders using single regex match
        if ($node.FullName -match $skipPattern) {
            continue
        }
        try {
            $children = Get-ChildItem -LiteralPath $node.FullName -Force -ErrorAction Stop
        } catch {
            Write-ErrorLog -Message "Failed to enumerate children of $($node.FullName): $_"
            continue
        }
        foreach ($child in $children) {
            # Skip excluded folders using precompiled regex
            if ($child.FullName -match $skipPattern) {
                continue
            }
            $enumCounter++
            # Update progress every 100 enumerated items to keep UI responsive
            if ($ShowProgress -and ($enumCounter % 100 -eq 0)) {
                Write-Progress -Activity "Enumerating Items" `
                               -Status "Enumerated $enumCounter items. Current: $($child.FullName)" `
                               -Id 2
            }

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
                $results += $child
            }
            if ($child.PSIsContainer) { $stack.Push($child) }
        }
    }

    if ($ShowProgress) {
        Write-Progress -Activity "Enumerating Items" -Completed -Status "Enumeration complete" -Id 2
    }
    return $results
}
# -------------------------

function Update-Permissions {
    param (
        $TargetPath,
        [switch]$ShowProgress
    )

    try {
        # Collect items to process, including the root item
        $items = @()
        try {
            # Use safe enumerator so access-denied while recursing is logged
            # Process ALL items (do not filter to only protected ACLs)
            $items = @(Get-ChildItemsSafe -StartPath $TargetPath -ShowProgress:$ShowProgress)
        } catch {
            Write-ErrorLog -Message "Error enumerating items under ${TargetPath}: $_"
        }

        # Always include root path if possible
        try {
            $rootItem = Get-Item -LiteralPath $TargetPath -Force -ErrorAction Stop
            $items = ,$rootItem + $items
        } catch {
            Write-ErrorLog -Message "Failed to get root item ${TargetPath}: $_"
        }

        $total = $items.Count

        if ($total -eq 0) {
            Write-Host "No items with protected ACLs found in $TargetPath"
            return
        }

        $counter = 0
        foreach ($entry in $items) {
            $counter++
            $percent = [math]::Round(($counter / $total) * 100, 2)

            # entry can be a PSCustomObject with .Item or directly a FileInfo/DirectoryInfo
            $item = if ($entry.PSObject.Properties.Name -contains 'Item') { $entry.Item } else { $entry }
            # Always get a fresh ACL before modifications to avoid stale data issues
            try {
                $acl = Get-Acl -Path $item.FullName -ErrorAction Stop
            } catch {
                Write-ErrorLog -Message "Failed to refresh ACL for $($item.FullName): $_"
                continue
            }

            Write-Progress -Activity "Processing Permissions" -Status "Scanning $($item.FullName)" -PercentComplete $percent

            if (-not $acl) {
                Write-ErrorLog -Message "Missing ACL object for $($item.FullName), skipping."
                continue
            }

            # Use ArrayList for better performance when adding items
            $explicitNonNewDomain = [System.Collections.ArrayList]::new()
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
                # Skip if already from the new domain
                if ($acctDomain -ieq $newDomain) { continue }
                
                [void]$explicitNonNewDomain.Add([PSCustomObject]@{
                    Domain = $acctDomain
                    Name = $acctName
                    Rights = $access.FileSystemRights
                    InheritanceFlags = $access.InheritanceFlags
                    PropagationFlags = $access.PropagationFlags
                    AccessControlType = $access.AccessControlType
                })
            }

            if ($explicitNonNewDomain.Count -eq 0) { continue }

            $modified = $false
            $addedCount = 0
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

                if ($null -eq $newDomainAccount) {
                    Write-MissingUser -Username $domainUser -Type "User/Group"
                    continue
                }

                try {
                    $identityRef = if ($newDomainAccount.SID) {
                        $newDomainAccount.SID
                    } else {
                        [System.Security.Principal.NTAccount]::new($newDomain, $domainUser)
                    }

                    # Skip adding rule if an identical one already exists
                    $identityValue = Convert-IdentityToNTValue -Identity $identityRef
                    $exists = $false
                    foreach ($ace in $acl.Access) {
                        try {
                            if (-not $ace.IsInherited -and
                                (Convert-IdentityToNTValue -Identity $ace.IdentityReference) -eq $identityValue -and
                                $ace.FileSystemRights -eq $aceInfo.Rights -and
                                $ace.InheritanceFlags -eq $aceInfo.InheritanceFlags -and
                                $ace.PropagationFlags -eq $aceInfo.PropagationFlags -and
                                $ace.AccessControlType -eq $aceInfo.AccessControlType) {
                                $exists = $true
                                break
                            }
                        } catch {}
                    }
                    if ($exists) { continue }

                    $newAccessRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                        $identityRef,
                        $aceInfo.Rights,
                        $aceInfo.InheritanceFlags,
                        $aceInfo.PropagationFlags,
                        $aceInfo.AccessControlType
                    )
                    if ($acl.AddAccessRule($newAccessRule)) {
                        $modified = $true
                        $addedCount++
                    } else {
                        # AddAccessRule returned false (no change). Continue trying other rules
                    }
                } catch {
                    Write-ErrorLog -Message "Failed to create/add access rule for $newDomain\\$domainUser on $($item.FullName): $_"
                    continue
                }
            }

            if ($modified) {
                if ($DryRun) {
                    Write-ChangeLog -Message "[Dry Run] Would add $addedCount access rule(s) for $newDomain to $($item.FullName)"
                } else {
                    try {
                        if (-not (Set-AclRobust -Path $item.FullName -Acl $acl)) { throw "Set-AclRobust failed" }
                        # Verify at least one of the new rules is present
                        $verifyAcl = Get-Acl -Path $item.FullName -ErrorAction Stop
                        $present = 0
                        foreach ($aceInfo in $explicitNonNewDomain) {
                            $idRef = if ($NewDomainAccountCache.ContainsKey($aceInfo.Name) -and $NewDomainAccountCache[$aceInfo.Name] -and $NewDomainAccountCache[$aceInfo.Name].SID) { $NewDomainAccountCache[$aceInfo.Name].SID } else { [System.Security.Principal.NTAccount]::new($newDomain,$aceInfo.Name) }
                            $idValue = Convert-IdentityToNTValue -Identity $idRef
                            foreach ($ace in $verifyAcl.Access) {
                                if ((-not $ace.IsInherited) -and (Convert-IdentityToNTValue -Identity $ace.IdentityReference) -eq $idValue -and $ace.FileSystemRights -eq $aceInfo.Rights) { $present++; break }
                            }
                        }
                        if ($present -gt 0) {
                            Write-ChangeLog -Message "Added $present/$addedCount access rule(s) for $newDomain to $($item.FullName)"
                        } else {
                            Write-ErrorLog -Message "Set-Acl reported success but no new rules detected on $($item.FullName). Possible inheritance or policy override."
                            Write-ChangeLog -Message "WARNING: No new rules detected after Set-Acl for $($item.FullName)"
                        }
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

Clear-Host
Write-Host "These are the non-admin shares on the current computer:`n"

try {
    $shares = Get-NonAdminShares
    foreach ($share in $shares) {
        Write-Host "Share Name: $($share.Name) | Path: $($share.Path)"
    }
} catch {
    Write-ErrorLog -Message "Failed to enumerate shares before prompt: $_"
    Write-Host "Unable to retrieve share information."
}

Write-Host ""
$processShares = Read-Host "Do you want to process NTFS permissions on shared folders? (y/n)"
# Normalize user input
$processShares = if ($processShares) { $processShares.Trim().ToLower() } else { "" }

# Immediate confirmation message so user sees input was received
Write-Host "You entered: $processShares."

# Log the user's choice once via helper; trap any failure
try { 
    Write-ChangeLog -Message "User response to process shared folders prompt: $processShares"
} catch { 
    Write-ErrorLog -Message "Write-ChangeLog failed while logging processShares: $_"
}

if ($processShares -eq "y") {
    try {
        # Force results into an array so .Count works reliably for 0/1/many items
        $shares = @(Get-NonAdminShares)
        $totalShares = $shares.Count
        if ($totalShares -eq 0) {
            Write-Host "No non-admin shares found on this computer."
            Write-ChangeLog -Message "No non-admin shares found to process."
        } else {
            # show an initial progress so user sees activity immediately
            Write-Progress -Activity "Processing Shares" -Status "Starting processing $totalShares share(s)" -PercentComplete 0 -Id 1
            for ($i = 0; $i -lt $totalShares; $i++) {
                $share = $shares[$i]
                $percent = [math]::Round((($i + 1) / $totalShares) * 100, 0)
                Write-Progress -Activity "Processing Shares" `
                               -Status "Processing share $($i + 1) of ${totalShares}: $($share.Name) ($($share.Path))" `
                               -PercentComplete $percent -Id 1
                Update-Permissions -TargetPath $share.Path -DryRun:$DryRun -ShowProgress
            }
            Write-Progress -Activity "Processing Shares" -Completed -Status "Done processing shares" -Id 1
            Write-ChangeLog -Message "Completed processing $totalShares share(s)."
        }
    } catch {
        Write-ErrorLog -Message "Failed to enumerate/process shares: $_"
    }
}

# Ensure main path calls show enumeration progress too
Update-Permissions -TargetPath $Path -DryRun:$DryRun -ShowProgress

# Guard AdditionalPaths iteration if it's undefined or empty
if ($PSBoundParameters.ContainsKey('AdditionalPaths') -or ($null -ne $AdditionalPaths)) {
    foreach ($additionalPath in $AdditionalPaths) {
        Update-Permissions -TargetPath $additionalPath -DryRun:$DryRun -ShowProgress
    }
}

Write-Host "Permission migration completed. Check logs in $LogDir."