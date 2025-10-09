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
    [switch]$DryRun
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

# Log files
if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

function Write-ErrorLog {
    param ($Message)
    Add-Content -Path $ErrorLog -Value "$((Get-Date).ToString()) - ERROR: $Message"
}

function Write-ChangeLog {
    param ($Message)
    Add-Content -Path $ChangesLog -Value "$((Get-Date).ToString()) - CHANGE: $Message"
}

function Write-MissingUser {
    param ($Username)
    if (-not $LoggedMissingUsers.ContainsKey($Username)) {
        Add-Content -Path $MissingUsersLog -Value "$((Get-Date).ToString()) - MISSING: $Username"
        $LoggedMissingUsers[$Username] = $true
    }
}

function Get-InovarAccount {
    param ($SamAccountName)
    try {
        return Get-ADUser -Filter "SamAccountName -eq '$SamAccountName'" -Server "inovar.local" -ErrorAction SilentlyContinue
    } catch {
        try {
            return Get-ADGroup -Filter "SamAccountName -eq '$SamAccountName'" -Server "inovar.local" -ErrorAction SilentlyContinue
        } catch {
            return $null
        }
    }
}

function Update-Permissions {
    param ($TargetPath)

    try {
        $items = Get-ChildItem -Path $TargetPath -Recurse -Force -ErrorAction SilentlyContinue
        $items += Get-Item -Path $TargetPath -Force
        $items = $items | Where-Object { $_.PSIsContainer -or $_.PSIsContainer -eq $false }
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
                if (-not $acl.AreAccessRulesProtected) {
                    continue # Skip items with inherited permissions to speed things up quite a bit
                }
            } catch {
                Write-ErrorLog -Message "Access denied or failed to get ACL for $($item.FullName): $_"
                continue
            }

            foreach ($access in $acl.Access) {
                if ($access.IdentityReference -like "$localDomain\*") {
                    $domainUser = $access.IdentityReference.Value.Split('\')[1]

                    $inovarAccount = $null
                    try {
                        $inovarAccount = Get-InovarAccount -SamAccountName $domainUser
                    } catch {
                        Write-ErrorLog -Message "Error looking up Inovar account for ${domainUser}: $_"
                        continue
                    }

                    if ($null -eq $inovarAccount) {
                        Write-MissingUser -Username $domainUser
                        continue
                    }

                    $newIdentity = "INOVAR\$domainUser"
                    try {
                        $newAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                            $newIdentity,
                            $access.FileSystemRights,
                            $access.InheritanceFlags,
                            $access.PropagationFlags,
                            $access.AccessControlType
                        )
                        $acl.AddAccessRule($newAccessRule)
                    } catch {
                        Write-ErrorLog -Message "Failed to create access rule for $newIdentity on $($item.FullName): $_"
                        continue
                    }

<#                    try {
                        Set-Acl -Path $item.FullName -AclObject $acl -ErrorAction SilentlyContinue
                        Write-ChangeLog -Message "Added $newIdentity to $($item.FullName) with rights $($access.FileSystemRights)"
                    } catch {
                        Write-ErrorLog -Message "Failed to set ACL on $($item.FullName): $_"
                        continue
                    }
#>
                    if ($DryRun) {
                        Write-ChangeLog -Message "[Dry Run] Would add $newIdentity to $($item.FullName) with rights $($access.FileSystemRights)"
                    } else {
                        try {
                            Set-Acl -Path $item.FullName -AclObject $acl -ErrorAction SilentlyContinue
                            Write-ChangeLog -Message "Added $newIdentity to $($item.FullName) with right $($access.FileSystemRights)"
                        } catch {
                            Write-ErrorLog -Message "Failed to set ACL on $($item.FullName): $_"
                            continue
                        }
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