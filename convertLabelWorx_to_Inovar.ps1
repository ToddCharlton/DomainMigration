# Set new target OU location for user
$TargetOU = "OU=Pennsauken,OU=Users,OU=Azure AD Sync,DC=inovar,DC=local"

# Prompt for Labelworx user's username
$username = Read-Host "Enter the username"

# Get current user AD attributes
$user = Get-AdUser -Identity $username -Properties EmailAddress, Office, UserPrincipalName, ProxyAddresses
$originalProxyAddresses = $user.ProxyAddresses
$proxyAddresses = $user.proxyAddresses

# Display current settings
Write-Host "E-mail: $($user.EmailAddress)"
Write-Host "Office: $($user.Office)"
Write-Host "UPN: $($user.UserPrincipalName)"
Write-Host "Current ProxyAddresses: $($originalProxyAddresses)"
$newProxies = $user.ProxyAddresses |
    ForEach-Object {
                $proxyAddress = $_ -replace '^SMTP', 'smtp'
                if ($proxyAddress -like '*@inovarpkg.com') {
                    $proxyAddress -replace '^smtp', 'SMTP'
                } else {
                    $proxyAddress
                }
                
            }
            $user.ProxyAddresses = $newProxies
Write-Host "New Proxy Addresses   : $($newProxies)"
Write-Host "proxyAddress: $($proxyAddress)"

# Prompt to verify that the info is correct and to convert the account
$convert = Read-Host "Do you want to convert this user account? (yes/no)"

# Convert user attributes
if ($convert -eq "yes") {
    # Update user attributes
    $newEmail = $user.EmailAddress -replace "@labelworx.net", "@inovarpkg.com"
    $newUPN = $user.UserPrincipalName -replace "@labelworx.net", "@inovarpkg.com"
    $proxyAddresses = $user.proxyAddresses
    
      
    Set-ADUser -Identity $username -EmailAddress $newEmail -Office "Pennsauken" -UserPrincipalName $newUPN -Replace @{ProxyAddresses=$newProxies}
    Move-ADObject -Identity $user.DistinguishedName -TargetPath $TargetOU
   
    Write-Host "User account converted successfully."
   
} else {
    Write-Host "No changes made to the user account $($username)."
}