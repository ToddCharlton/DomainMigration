<#
    .SYNOPSIS
    Removes or lists orphaned SIDs from Active Directory objects.

    .DESCRIPTION
    This script scans Active Directory objects for access control entries (ACEs) that reference SIDs which no longer exist in the domain.
    It can either just list these orphaned SIDs or remove them from the ACLs, based on the parameters provided.

    .PARAMETER Filter
    Specifies the starting point for the scan. Use "All" for the entire forest or provide a specific DN like "OU=Users,DC=example,DC=com".

    .PARAMETER Remove
    If specified, the script will remove the orphaned SIDs from the ACLs. Without this switch, it only shows them.

    .PARAMETER WhatIf
    When used with -Remove, shows what would happen if the script were to run without actually making changes.

    .EXAMPLE
    .\RemoveOrphanedSID-AD.ps1 -Filter "All"
    Scans the entire forest for orphaned SIDs without removing them.

    .EXAMPLE
    .\RemoveOrphanedSID-AD.ps1 -Filter "OU=Users,DC=example,DC=com" -Remove
    Removes orphaned SIDs from the specified OU.

    .EXAMPLE
    .\RemoveOrphanedSID-AD.ps1 -Filter "OU=Users,DC=example,DC=com" -Remove -WhatIf
    Shows what would be changed without actually altering the ACLs.

    .LINK
    www.alitajran.com/remove-orphaned-sids/

    .NOTES
    Written by: ALI TAJRAN
    Website:    www.alitajran.com
    LinkedIn:   linkedin.com/in/alitajran
    X:          x.com/alitajran

    .CHANGELOG
    V2.00, 01/27/2025 - Major rework of the script
#>

# Define script parameters
param (
    [Parameter(Mandatory = $true)][string]$Filter,
    [switch]$Remove,
    [switch]$WhatIf
)

$Forest = Get-ADRootDSE
$ForestName = $Forest.rootDomainNamingContext
$domsid = (Get-ADDomain -Identity $ForestName).DomainSID.ToString()

# Start transcript at the beginning of the script
$Logs = "C:\temp\RemoveOrphanedSID-AD.txt"
Start-Transcript -Path $Logs -Append -Force

if ($Filter -eq "All") {
    $Folder = $ForestName
    Write-Host "Listing all objects in the forest: $ForestName" -ForegroundColor Cyan
}
else {
    $Folder = $Filter
    Write-Host "Analyzing the following object: $Folder" -ForegroundColor Cyan
}

# Function to remove orphaned SIDs from access control lists
function RemovePerms {
    param ([string]$fold)
    $fName = $fold
    Write-Host $fName

    $acl = Get-ACL "AD:$fName"
    $modified = $false
    $previousSID = ""

    foreach ($ace in $acl.Access) {
        if ($ace.IdentityReference.Value -like "$domsid*") {
            $sid = $ace.IdentityReference.Value
            if ($previousSID -ne $sid) {
                Write-Host "Orphaned SID $sid on $fName" -ForegroundColor Yellow
                $previousSID = $sid
            }
            if ($Remove -and -not $WhatIf) {
                $acl.RemoveAccessRuleSpecific($ace)
                $modified = $true
            }
            elseif ($Remove -and $WhatIf) {
                Write-Host "Would remove orphaned SID $sid on $fName" -ForegroundColor Green
            }
        }
    }
    if ($modified -and -not $WhatIf) {
        Set-ACL -Path "AD:$fName" -AclObject $acl
        Write-Host "Orphaned SID removed on $fName" -ForegroundColor Red
    }
}

# Function to recursively analyze the access control lists of nested folders
function RecurseFolder {
    param ([string]$fold)
    $folders = Get-ADObject -LDAPFilter "(objectClass=*)" -SearchBase $fold -SearchScope OneLevel
    foreach ($entry in $folders) {
        $dn = $entry.DistinguishedName
        RemovePerms -fold $dn
    }
    foreach ($entry in $folders) {
        RecurseFolder -fold $entry.DistinguishedName
    }
}

# Clean up orphaned SIDs from folder ACLs
RemovePerms -fold $Folder
RecurseFolder -fold $Folder

Stop-Transcript