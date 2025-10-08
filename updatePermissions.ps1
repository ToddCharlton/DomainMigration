# Define domains
$OldDomain = "modtek.int"
$NewDomain = "inovar.local"

# Set up logging
$LogFile = "C:\MigrationLogs\PermissionMigration.log"
$logDir = Split-Path $LogFile
if (!(Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}
New-Item -Path $LogFile -ItemType File -Force | Out-Null

function Log {
    param ([string]$Message)
    Add-Content -Path $LogFile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
}

# Update NTFS permissions
function Update-NTFSPermissions {
    param ([string]$Path)
    try {
        $acl = Get-Acl -Path $Path
        $updated = $false

        foreach ($ace in $acl.Access) {
            if ($ace.IdentityReference -like "$OldDomain\*") {
                $accountName = $ace.IdentityReference.Value.Split('\')[1]
                $newIdentity = "$NewDomain\$accountName"
                Log "Updating NTFS: $($ace.IdentityReference.Value) → $newIdentity on $Path"

                $acl.RemoveAccessRule($ace)
                $newRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $newIdentity,
                    $ace.FileSystemRights,
                    $ace.InheritanceFlags,
                    $ace.PropagationFlags,
                    $ace.AccessControlType
                )
                $acl.AddAccessRule($newRule)
                $updated = $true
            }
        }

        if ($updated) {
            Set-Acl -Path $Path -AclObject $acl
        }
    } catch {
        Log "Error updating NTFS permissions on ${Path}: $_"
    }
}

# Update Registry permissions
function Update-RegistryPermissions {
    param ([string]$RegPath)
    try {
        $acl = Get-Acl -Path $RegPath
        $updated = $false

        foreach ($ace in $acl.Access) {
            if ($ace.IdentityReference -like "$OldDomain\*") {
                $accountName = $ace.IdentityReference.Value.Split('\')[1]
                $newIdentity = "$NewDomain\$accountName"
                Log "Updating Registry: $($ace.IdentityReference.Value) → $newIdentity on $RegPath"

                $acl.RemoveAccessRule($ace)
                $newRule = New-Object System.Security.AccessControl.RegistryAccessRule(
                    $newIdentity,
                    $ace.RegistryRights,
                    $ace.InheritanceFlags,
                    $ace.PropagationFlags,
                    $ace.AccessControlType
                )
                $acl.AddAccessRule($newRule)
                $updated = $true
            }
        }

        if ($updated) {
            Set-Acl -Path $RegPath -AclObject $acl
        }
    } catch {
        Log "Error updating registry permissions on $RegPath: $_"
    }
}

# Update Service permissions
function Update-ServicePermissions {
    $services = Get-WmiObject -Class Win32_Service

    foreach ($service in $services) {
        try {
            $sd = Get-Acl -Path "Service:$($service.Name)"
            $updated = $false

            foreach ($ace in $sd.Access) {
                if ($ace.IdentityReference -like "$OldDomain\*") {
                    $accountName = $ace.IdentityReference.Value.Split('\')[1]
                    $newIdentity = "$NewDomain\$accountName"
                    Log "Updating Service: $($ace.IdentityReference.Value) → $newIdentity on $($service.Name)"

                    $sd.RemoveAccessRule($ace)
                    $newRule = New-Object System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList $false, $false, $sd.GetSecurityDescriptorSddlForm("All")
                    $updated = $true
                }
            }

            if ($updated) {
                Set-Acl -Path "Service:$($service.Name)" -AclObject $sd
            }
        } catch {
            Log "Error updating service permissions on $($service.Name): $_"
        }
    }
}

# Update Share permissions
function Update-SharePermissions {
    $shares = Get-WmiObject -Class Win32_Share | Where-Object { $_.Type -eq 0 }

    foreach ($share in $shares) {
        $path = $share.Path
        Log "Scanning share '$($share.Name)' at path '$path'"

        if (Test-Path $path) {
            Update-NTFSPermissions -Path $path
        } else {
            Log "Share path '$path' does not exist."
        }
    }
}

# Run updates
Update-SharePermissions

$AdditionalPaths = @("D:\Data", "E:\Shares", "C:\Users")
foreach ($folder in $AdditionalPaths) {
    if (Test-Path $folder) {
        Get-ChildItem -Path $folder -Recurse -Directory | ForEach-Object {
            Update-NTFSPermissions -Path $_.FullName
        }
    }
}

$RegistryKeys = @(
    "HKLM:\Software\CustomApp",
    "HKLM:\System\CurrentControlSet\Services\SomeService"
)
foreach ($key in $RegistryKeys) {
    if (Test-Path $key) {
        Update-RegistryPermissions -RegPath $key
    }
}

Update-ServicePermissions

Log "Permission migration complete."
