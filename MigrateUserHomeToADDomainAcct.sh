#!/bin/sh
#
# Script Name: MigrateUserHomeToADDomainAcct.sh
# Version=1.6
# Original source: [Patrick Gallagher/https://twitter.com/patgmac]
# 
# Modified by Rich Trouton
# Modified 09.15.2025 by Todd Charlton
# Version 1.6 - Added check for SIP (system integrity protection)
# Steps:
# 1. Disable SIP by rebooting into recovery mode (Cmd+R on boot) and running "csrutil disable" from the terminal
# 2. Unbind from the old domain and bind to the new domain
# 3. Run this script

# Check SIP status
SIP_STATUS=$(csrutil status | grep -i "System Integrity Protection status" | awk '{print $NF}' | tr -d '.')

clear

if [ "$SIP_STATUS" == "enabled" ]; then
    echo "System Integrity Protection is ENABLED."
    echo "This script cannot continue while SIP is active."
	echo "Reboot into Recovery Mode, open Terminal, and run 'csrutil disable'."
	echo "Then reboot normally and run this script again."
	echo "Upon completion of this script, it is recommended to re-enable SIP by rebooting into Recovery Mode and running 'csrutil enable'."
    exit 1
else

clear
fi

# Get the current AD domain (if bound)
CURRENT_DOMAIN=$(dsconfigad -show | awk -F '= ' '/Active Directory Domain/{print $2}' | xargs)

if [ -z "$CURRENT_DOMAIN" ]; then
    echo "This Mac is not currently bound to any Active Directory domain."
    exit 1
fi

if [[ "$CURRENT_DOMAIN" == "modtek.int" ]]; then
    echo "Still connected to modtek domain."
    echo "Unbind from modtek.int and rebind to inovar.local before running this script."
    exit 0
elif [[ "$CURRENT_DOMAIN" == "inovar.local" ]]; then
    echo "Connected to inovar.local domain. Continuing..."
    # Place the rest of your script logic below this line
else
    echo "Connected to unexpected domain: $CURRENT_DOMAIN"
    exit 1
fi

netIDprompt="Please enter the AD account for this user: "
listUsers="$(/usr/bin/dscl . list /Users | grep -v _ | grep -v root | grep -v uucp | grep -v amavisd | grep -v nobody | grep -v messagebus | grep -v daemon | grep -v www | grep -v Guest | grep -v xgrid | grep -v windowserver | grep -v unknown | grep -v unknown | grep -v tokend | grep -v sshd | grep -v securityagent | grep -v mailman | grep -v mysql | grep -v postfix | grep -v qtss | grep -v jabber | grep -v cyrusimap | grep -v clamav | grep -v appserver | grep -v appowner) FINISHED"
#listUsers="$(/usr/bin/dscl . list /Users | grep -v -e _ -e root -e uucp -e nobody -e messagebus -e daemon -e www -v Guest -e xgrid -e windowserver -e unknown -e tokend -e sshd -e securityagent -e mailman -e mysql -e postfix -e qtss -e jabber -e cyrusimap -e clamav -e appserver -e appowner) FINISHED"
FullScriptName=`basename "$0"`
ShowVersion="$FullScriptName $Version"
check4AD=`/usr/bin/dscl localhost -list . | grep "Active Directory"`
osvers=$(sw_vers -productVersion | awk -F. '{print $2}')
# Save current IFS state

OLDIFS=$IFS

IFS='.' read osvers_major osvers_minor osvers_dot_version <<< "$(/usr/bin/sw_vers -productVersion)"

# restore IFS to previous state

IFS=$OLDIFS

echo "********* Running $FullScriptName Version $Version *********"

# If the machine is not bound to AD, then there's no purpose going any further. 
if [ "${check4AD}" != "Active Directory" ]; then
	echo "This machine is not bound to Active Directory.\nPlease bind to AD first. "; exit 1
fi

RunAsRoot()
{
        ##  Pass in the full path to the executable as $1
        if [[ "${USER}" != "root" ]] ; then
                echo
                echo "***  This application must be run as root.  Please authenticate below.  ***"
                echo
                sudo "${1}" && exit 0
        fi
}

RunAsRoot "${0}"

until [ "$user" == "FINISHED" ]; do

	printf "%b" "\a\n\nSelect a user to convert or select FINISHED:\n" >&2
	select user in $listUsers; do
	
		if [ "$user" = "FINISHED" ]; then
			echo "Finished converting users to AD"
			break
		elif [ -n "$user" ]; then
			if [ `who | grep console | awk '{print $1}'` == "$user" ]; then
				echo "This user is logged in.\nPlease log this user out and log in as another admin"
				exit 1
			fi
			# Verify NetID
				printf "\e[1m$netIDprompt"
				read netname
				/usr/bin/id $netname
				echo "Did the information displayed include a line similar to this: gid=1360859114 (DOMAIN\domain users)? It should be the second item listed."
				select yn in "Yes" "No"; do
    					case $yn in
        					Yes) echo "Great! It looks like this Mac is communicating with AD correctly. Script will continue the migration process."; break;;
        					No ) echo "It doesn't look like this Mac is communicating with AD correctly. Exiting the script."; exit 0;;
    					esac
				done

			# Determine location of the users home folder
			userHome=`/usr/bin/dscl . read /Users/$user NFSHomeDirectory | cut -c 19-`
			
			# Get list of groups
			echo "Checking group memberships for local user $user"
			lgroups="$(/usr/bin/id -Gn $user)"
			
			
			if [[ $? -eq 0 ]] && [[ -n "$(/usr/bin/dscl . -search /Groups GroupMembership "$user")" ]]; then 
			# Delete user from each group it is a member of
				for lg in $lgroups; 
					do
						/usr/bin/dscl . -delete /Groups/${lg} GroupMembership $user >&/dev/null
					done
			fi
			# Delete the primary group
			if [[ -n "$(/usr/bin/dscl . -search /Groups name "$user")" ]]; then
  				/usr/sbin/dseditgroup -o delete "$user"
			fi
			# Get the users guid and set it as a var
			guid="$(/usr/bin/dscl . -read "/Users/$user" GeneratedUID | /usr/bin/awk '{print $NF;}')"
			if [[ -f "/private/var/db/shadow/hash/$guid" ]]; then
 				/bin/rm -f /private/var/db/shadow/hash/$guid
			fi
			# Delete the user
			/bin/mv $userHome /Users/old_$user
			/usr/bin/dscl . -delete "/Users/$user"

				# Refresh Directory Services
				if [[ ( ${osvers_major} -eq 10 && ${osvers_minor} -lt 7 ) ]]; then
					/usr/bin/killall DirectoryService
				else
					/usr/bin/killall opendirectoryd
				fi
				sleep 20
				/usr/bin/id $netname
				# Check if there's a home folder there already, if there is, exit before we wipe it
				if [ -f /Users/$netname ]; then
					echo "Oops, theres a home folder there already for $netname.\nIf you don't want that one, delete it in the Finder first,\nthen run this script again."
					exit 1
				else
					/bin/mv /Users/old_$user /Users/$netname
					/usr/sbin/chown -R ${netname} /Users/$netname
					echo "Home for $netname now located at /Users/$netname"
					/System/Library/CoreServices/ManagedClient.app/Contents/Resources/createmobileaccount -n $netname
					echo "Account for $netname has been created on this computer"			
				fi
				echo "Do you want to give the $netname account admin rights?"
				select yn in "Yes" "No"; do
    					case $yn in
        					Yes) /usr/sbin/dseditgroup -o edit -a "$netname" -t user admin; echo "Admin rights given to this account"; break;;
        					No ) echo "No admin rights given"; break;;
    					esac
				done
			break
		else
			echo "Invalid selection!"
		fi
	done
done
