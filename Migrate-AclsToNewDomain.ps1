<#
.SYNOPSIS
    This script is for switching a computer's local NTFS and share
    permissions to Inovar domain permissions.

.DESCRIPTION
    This script will look at permissions in the file path given using the
     -Path argument. It will then go through all domain user accounts for
     the local domain, find the matching account on the new domain,
     and add identical permissions for the new domain "version" of this account.
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
    Last modified: October 28, 2025
    Version: 2.1
    
    Changed entire script to work with PowerShell 7.
    Added -WhatIf switch parameter
    Added check for inherited permissions to speed up processing

    Requires the ActiveDirectory module.
    Run in an elevated PowerShell prompt.
    Tested on Windows 10 and Windows 11.
    Make sure to set the $OldDomain and $NewDomain variables to the correct local domain name.
    Make sure to run this script on the target computer.
#>

# Adds support for -WhatIf
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [string[]] $Path,
    [string] $NewDomain = 'INOVAR',
    [string] $OldDomain = 'MODTEK' # You can override; defaults to MODTEK
)

Clear-Host

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Ensure $Path is always an array
if ($Path) {
    $Path = @($Path)
}

if (-not $Path -or $Path.Count -eq 0) {
    $resp = Read-Host "No PATH entered. Continue to processing non-admin shares? (y/N)"
    if ($resp -notin @('y','Y')) {
        Write-Host "Exiting."
        return
    }
}

function New-LogFolder {
    $logDir = 'C:\logs'
    if (-not (Test-Path -LiteralPath $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
}
New-LogFolder
$ChangeLog = 'C:\logs\MigrationChanges.txt'
$ErrorLog  = 'C:\logs\MigrationErrorLog.txt'
$MissingLog = 'C:\logs\MigrationUserNotFound.txt'

function Write-ChangeLog([string]$msg) {
    Add-Content -LiteralPath $ChangeLog -Value ("{0} {1}" -f (Get-Date -Format s), $msg)
}
function Write-ErrorLog([string]$msg) {
    Add-Content -LiteralPath $ErrorLog -Value ("{0} {1}" -f (Get-Date -Format s), $msg)
}
function Write-MissingLog([string]$msg) {
    Add-Content -LiteralPath $MissingLog -Value ("{0} {1}" -f (Get-Date -Format s), $msg)
}

function Get-NonAdminShares {
    try {
        $shares = Get-SmbShare -ErrorAction Stop | Where-Object {
            -not $_.Special -and $_.Name -notin @('SYSVOL','NETLOGON')
        }
        # Filter to only shares with an existing local path
        $shares | Where-Object { $_.Path -and (Test-Path -LiteralPath $_.Path) }
    } catch {
        Write-ErrorLog "Failed to enumerate SMB shares: $($_.Exception.Message)"
        @()
    }
}

# Determine if a qualified name is a domain principal in the current (old) domain
function Test-IsDomainPrincipal([string]$qualifiedName, [string]$oldDomain) {
    if (-not $qualifiedName -or ($qualifiedName -notlike '*\*')) { return $false }
    $split = $qualifiedName.Split('\', 2)
    if ($split.Count -ne 2) { return $false }
    $dom = $split[0]
    $name = $split[1]
    # Ignore local accounts
    $ignored = @('NT AUTHORITY', 'CREATOR OWNER', $env:COMPUTERNAME)
    if ($ignored -contains $dom.ToUpperInvariant()) { return $false }
    if ($oldDomain -and ($dom.Trim()).ToUpperInvariant() -ne $oldDomain.ToUpperInvariant()) { return $false }
    return $true
}
# Resolve a domain account in the new domain; returns $null if not found
function Resolve-NtAccount([string]$domain, [string]$name) {
    try {
        $nt = New-Object System.Security.Principal.NTAccount($domain, $name)
        # Translate to SID to verify existence
        [void] $nt.Translate([System.Security.Principal.SecurityIdentifier])
        return $nt
    } catch {
        return $null
    }
}
# Check if equivalent permissions already exist in the ACL
function Test-EquivalentRule([System.Security.AccessControl.FileSystemSecurity] $acl,
                            [string] $domain, [string] $name,
                            $rights, $inheritFlags, $propFlags, $type) {
    $target = "$domain\$name"
    foreach ($r in $acl.Access) {
        if ($r.IdentityReference.Value -ieq $target -and
            [string]$r.FileSystemRights -eq [string]$rights -and
            [string]$r.InheritanceFlags -eq [string]$inheritFlags -and
            [string]$r.PropagationFlags -eq [string]$propFlags -and
            [string]$r.AccessControlType -eq [string]$type) {
            return $true
        }
    }
    return $false
}
# Get ACL safely, logging errors
function Get-AclSafe([string]$path) {
    try {
        return Get-Acl -LiteralPath $path -ErrorAction Stop
    } catch {
        Write-ErrorLog "Get-Acl failed for '$path': $($_.Exception.Message)"
        return $null
    }
}
# Check if directory has inheritance disabled
function Test-DirInheritanceOff([System.IO.DirectoryInfo] $dir) {
    $acl = Get-AclSafe -path $dir.FullName
    if (-not $acl) { return $false }
    return $acl.AreAccessRulesProtected
}
# Get directories with inheritance disabled under given roots
function Get-BrokenInheritanceDirs([string[]] $roots) {
    $result = New-Object System.Collections.Generic.List[System.IO.DirectoryInfo]
    foreach ($r in $roots) {
        try {
            if (-not (Test-Path -LiteralPath $r)) { continue }
            $dir = Get-Item -LiteralPath $r -ErrorAction Stop
            if ($dir -is [System.IO.FileInfo]) {
                $dir = $dir.Directory
                if (-not $dir) { continue }
            }
            # Skip recycle bin/system folders
            if ($dir.Name -match '^\$RECYCLE\.BIN$') { continue }
            # Include root if inheritance is off
            if (Test-DirInheritanceOff $dir) {
                $result.Add($dir)
            }
            # Recurse subdirectories
            Get-ChildItem -LiteralPath $dir.FullName -Directory -Force -Recurse -ErrorAction SilentlyContinue |
                Where-Object { 
                    -not $_.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -and
                    $_.Name -notmatch '^\$RECYCLE\.BIN$'
                } |
                ForEach-Object {
                    if (Test-DirInheritanceOff $_) {
                        $result.Add($_)
                    }
                }
        } catch {
            Write-ErrorLog "Scan failed under '$r': $($_.Exception.Message)"
        }
    }
    # Deduplicate by FullName (case-insensitive) and return as array
    $byPath = @{}
    foreach ($d in $result) { $byPath[$d.FullName.ToLowerInvariant()] = $d }
    return @($byPath.Values)
}
# Get topmost broken inheritance directories to avoid overlapping work
function Get-TopmostBrokenRoots([System.IO.DirectoryInfo[]] $brokenDirs) {
    # Keep dirs whose parent is either null or not broken
    $brokenSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($d in $brokenDirs) { [void]$brokenSet.Add($d.FullName) }
    $tops = New-Object System.Collections.Generic.List[System.IO.DirectoryInfo]
    foreach ($d in $brokenDirs) {
        $p = $d.Parent
        $isTop = $true
        while ($p) {
            if ($brokenSet.Contains($p.FullName)) { $isTop = $false; break }
            $p = $p.Parent
        }
        if ($isTop) { $tops.Add($d) }
    }
    return $tops
}
# Get all items (dirs and files) to process under a broken-inheritance root
function Get-ProcessItemsFromBrokenRoot([System.IO.DirectoryInfo] $root) {
    $items = New-Object System.Collections.Generic.List[System.IO.FileSystemInfo]
    # include the root directory itself
    if ($root.Name -notmatch '^\$RECYCLE\.BIN$') {
        $items.Add($root)
    }
    # include files in root
    try {
        Get-ChildItem -LiteralPath $root.FullName -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch '^\$RECYCLE\.BIN$' } |
            ForEach-Object { $items.Add($_) }
    } catch {
        Write-ErrorLog "Enumerate files failed in '$($root.FullName)': $($_.Exception.Message)"
    }

    $stack = New-Object System.Collections.Stack
    $stack.Push($root)

    while ($stack.Count -gt 0) {
        $dir = [System.IO.DirectoryInfo] $stack.Pop()
        try {
            # enumerate subdirectories
            $subs = Get-ChildItem -LiteralPath $dir.FullName -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object { 
                    -not $_.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint) -and
                    $_.Name -notmatch '^\$RECYCLE\.BIN$'
                }
            foreach ($sd in $subs) {
                $acl = Get-AclSafe -path $sd.FullName
                if (-not $acl) { continue }
                if ($acl.AreAccessRulesProtected) {
                    # include the directory, its files, and continue deeper
                    $items.Add($sd)
                    try {
                        Get-ChildItem -LiteralPath $sd.FullName -File -Force -ErrorAction SilentlyContinue |
                            Where-Object { $_.Name -notmatch '^\$RECYCLE\.BIN$' } |
                            ForEach-Object { $items.Add($_) }
                    } catch {
                        Write-ErrorLog "Enumerate files failed in '$($sd.FullName)': $($_.Exception.Message)"
                    }
                    $stack.Push($sd)
                } else {
                    # stop at this boundary; do not include or traverse further
                    continue
                }
            }
        } catch {
            Write-ErrorLog "Enumerate subdirectories failed in '$($dir.FullName)': $($_.Exception.Message)"
        }
    }

    # Deduplicate by FullName and return as array
    $byPath = @{}
    foreach ($i in $items) { $byPath[$i.FullName.ToLowerInvariant()] = $i }
    return @($byPath.Values)
}
# Copy ACLs from old domain to new domain for given items
function Migrate-Acls([System.IO.FileSystemInfo[]] $items, [string] $oldDomain, [string] $newDomain) {
    $total = ($items | Measure-Object).Count
    $i = 0
    foreach ($it in $items) {
        $i++
        $percent = if ($total -gt 0) { [int](($i / $total) * 100) } else { 0 }
        Write-Progress -Activity "Migrating ACLs to $newDomain" -Status $it.FullName -PercentComplete $percent

        $acl = Get-AclSafe -path $it.FullName
        if (-not $acl) { continue }

        $changed = $false
        foreach ($ace in $acl.Access) {
            $idRef = $ace.IdentityReference.Value
            if (-not (Test-IsDomainPrincipal -qualifiedName $idRef -oldDomain $oldDomain)) { continue }

            $split = $idRef -split '\\', 2
            if ($split.Count -ne 2) { continue }
            $dom = $split[0]
            $name = $split[1]

            # Translate target account in new domain
            $newNt = Resolve-NtAccount -domain $newDomain -name $name
            if (-not $newNt) {
                Write-MissingLog "Missing in ${newDomain}: '$name' (from $idRef) on '$($it.FullName)'"
                continue
            }

            # Skip if equivalent rule already exists
            if (Test-EquivalentRule -acl $acl -domain $newDomain -name $name `
                                   -rights $ace.FileSystemRights `
                                   -inheritFlags $ace.InheritanceFlags `
                                   -propFlags $ace.PropagationFlags `
                                   -type $ace.AccessControlType) {
                continue
            }

            try {
                $newRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $newNt,
                    $ace.FileSystemRights,
                    $ace.InheritanceFlags,
                    $ace.PropagationFlags,
                    $ace.AccessControlType
                )

                $action = "Add ACL $($ace.AccessControlType) $($ace.FileSystemRights) for $($newNt.Value) on $($it.FullName)"
                if ($PSCmdlet.ShouldProcess($it.FullName, $action)) {
                    $acl.AddAccessRule($newRule)
                    try {
                        Set-Acl -LiteralPath $it.FullName -AclObject $acl -ErrorAction Stop
                        $changed = $true
                        Write-ChangeLog "$action"
                    } catch {
                        Write-ErrorLog "Set-Acl failed '$($it.FullName)': $($_.Exception.Message)"
                    }
                } else {
                    Write-ChangeLog "[WhatIf] $action"
                }
            } catch {
                Write-ErrorLog "Failed to construct/add rule for '$($newNt.Value)' on '$($it.FullName)': $($_.Exception.Message)"
            }
        }
    }

    Write-Progress -Activity "Migrating ACLs to $newDomain" -Completed -Status "Done"
}

# ----------------- Main -----------------

# List non-admin shares and prompt to include their NTFS paths
$shares = Get-NonAdminShares
if (($shares | Measure-Object).Count -gt 0) {
    Write-Host "Non-admin shares on this server (excluding SYSVOL/NETLOGON):"
    $shares | Sort-Object Name | ForEach-Object { Write-Host (" - {0} => {1}" -f $_.Name, $_.Path) }
} else {
    Write-Host "No non-admin shares found (or access denied)."
}

$includeShares = Read-Host "Also include NTFS permissions on these shared folders? (y/N)"
$targetRoots = New-Object System.Collections.Generic.List[string]
# Add -Path arguments
if ($Path -and $Path.Count -gt 0) {
    foreach ($p in $Path) {
        if (Test-Path -LiteralPath $p) { $targetRoots.Add((Resolve-Path -LiteralPath $p).Path) }
        else { Write-ErrorLog "Path does not exist: $p" }
    }
}
# Add shares if requested
if ($includeShares -match '^(y|yes)$') {
    foreach ($s in $shares) { $targetRoots.Add($s.Path) }
}

# De-dup targets
$targetRoots = @($targetRoots.ToArray() | Sort-Object -Unique)

if (@($targetRoots).Count -eq 0) {
    Write-Host "No valid paths to process. Exiting."
    return
}

Write-Host "Scanning for directories with inheritance disabled under:"
$targetRoots | ForEach-Object { Write-Host (" - {0}" -f $_) }

# Show progress bar while scanning each root
$brokenDirs = New-Object System.Collections.Generic.List[System.IO.DirectoryInfo]
$totalRoots = $targetRoots.Count
$idx = 0
foreach ($root in $targetRoots) {
    $idx++
    Write-Progress -Activity "Scanning for broken inheritance" `
                   -Status "Scanning $root" `
                   -PercentComplete ([int](($idx / $totalRoots) * 100))
    $found = Get-BrokenInheritanceDirs -roots @($root)
    foreach ($d in $found) { $brokenDirs.Add($d) }
}
Write-Progress -Activity "Scanning for broken inheritance" -Completed -Status "Done"

# Deduplicate after scanning
$brokenDirs = @($brokenDirs.ToArray() | Sort-Object FullName -Unique)

if (($brokenDirs | Measure-Object).Count -eq 0) {
    Write-Host "No directories with inheritance disabled were found. Nothing to do."
    return
}

# Compute topmost broken roots to avoid overlapping work
$topBrokenRoots = @(Get-TopmostBrokenRoots -brokenDirs $brokenDirs)

Write-Host "Found $(($brokenDirs | Measure-Object).Count) directories with inheritance disabled."
Write-Host "Processing $(($topBrokenRoots | Measure-Object).Count) topmost broken-inheritance roots."

# Build item list to process
$allItems = New-Object System.Collections.Generic.List[System.IO.FileSystemInfo]
foreach ($root in $topBrokenRoots) {
    $items = Get-ProcessItemsFromBrokenRoot -root $root
    foreach ($it in $items) { $allItems.Add($it) }
}
# De-dup
$allItems = @($allItems.ToArray() | Sort-Object FullName -Unique)

Write-Host ("Total items to scan/apply: {0}" -f (($allItems | Measure-Object).Count))

# Try to infer current domain if OldDomain not set explicitly and still default
if ($OldDomain -eq 'MODTEK') {
    try {
        $cur = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        if ($cur) {
            # Try to use NetBIOS if available; else use DNS root name left-most label
            $nb = $cur.NetBiosName
            if ($nb) { $OldDomain = $nb }
        }
    } catch {
        # Keep provided default
    }
}

Migrate-Acls -items $allItems -oldDomain $OldDomain -newDomain $NewDomain

Write-Host "Done. See logs:"
Write-Host " - Changes: $ChangeLog"
Write-Host " - Errors:  $ErrorLog"
Write-Host " - Missing: $MissingLog"
