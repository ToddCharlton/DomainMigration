# AD Profile Migration for Windows and Macos
![ScreenRecording](https://github.com/ToddCharlton/DomainMigration/blob/main/MigrationAnimation.gif)
### Migrate-AclsToNewDomain.ps1
This script (see image above) will look at permissions in the file path given using the
-Path argument. It will then go through all domain user accounts for
the local domain, find the matching account on the new domain,
and add identical permissions for the new domain "version" of this account.
The script will also change share permissions and NTFS permissions 
for those shares if you answer "y" at the first prompt.
Logs are saved in C:\Logs. There may be up to 2 logs: file/folder
changes as well as a list of users NOT found in the new domain.

### ADProfileMigration.ps1
This is a PowerShell script for Windows that migrates selected user profiles from their current domain to a new domain
profile using USMT installed on a remote computer ($USMTPath) and joins the computer to
the new domain ($newDomain).
It uses hardlink migration (/hardlink /nocompress) to avoid copying files unnecessarily
across the network.
This script uses pop-ups for credential prompts, which will not work in the PowerShell ISE.

### compareAD.ps1
This is a very simple PowerShell script that will write differences between users, computers,
and groups between two trusted domains into three csv files.

### MigrateUserHomeToADDomainAcct.sh
This is a BASH script is based off of Patrick Gallagher's (https://twitter.com/patgmac) original scriptfor macOS.
The script essentially does what ADProfileMigration.ps1 does for Windows machines.

### removeOrphanedSIDs.ps1
Untested script to remove orphaned SIDs prior to running ADProfileMigration