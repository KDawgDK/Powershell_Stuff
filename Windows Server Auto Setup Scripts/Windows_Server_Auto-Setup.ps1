## Variables for the configuration
    $Credential = Get-Credential -Credential "$DomainName\Administrator"
    # Computer Settings
        $adapter = (Get-NetAdapter -Physical | Select-Object -First 1).ifIndex
        $ComputerName = "DCServ"
        $ComputerIP = "192.168.20.6"
        $Prefix = "24"
        # Windows Features
            $WindowsFeatures = 'AD-Domain-Services, DNS' # Separate the Features with ','
    # AD Configurations if you do use it
        $DomainName = "it-prods"
        $DomainExtension = "local"
        $OUs = "Supportere, Produktion, Levering" # Separate the OUs with ','
        # Drive Maps Configuration
            $DrivePermissions = "" # Separate the permissions with ','
            $DriveLetters = "S, P, L" # Separate the Letters
            $AccessTo = ""
    # DHCP Scope configurations
        $ScopeName = ""
        $StartRangeIP = ""
        $EndRangeIP = ""

# Check if they are blank or have information, and if they don't go through manual configuration that will be saved to a config on C:\ServerConfig.txt
function BlankOrNotConfig {

}


## Functions for the different things
function ComputerSettings {
    ## New scheduled task that will run the powershell script at logon (Might need to be at the end of all of the configuration, either manually put into the variables or while it is running)
    $actions = (New-ScheduledTaskAction -Execute 'Windows_Server_Auto-Setup.ps1')
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "$DomainName\Administrator" -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -WakeToRun
    $task = New-ScheduledTask -Action $actions -Principal $principal -Trigger $trigger -Settings $settings
    Register-ScheduledTask 'Windows-Server-Setup' -InputObject $task
    # Gateway
        $octets = $ComputerIP -split '\.' # Split the IP address into its octets
        $octets[3] = '1' # Set the last octet to 1 (192.168.20.*1* as an example)
        $GatewayIP = $octets -join '.' # Reassemble the modified IP address
    # Setup network interface
        New-NetIPAddress -IPAddress $ComputerIP -InterfaceIndex $adapter -DefaultGateway $GatewayIP -AddressFamily IPv4 -PrefixLength $Prefix;
        Set-DnsClientServerAddress -InterfaceIndex $adapter -ServerAddresses $ComputerIP
    Rename-Computer -NewName $ComputerName
    # Define the comma-separated list of Windows features
    # Split the string into an array, trimming any leading or trailing whitespace from each feature
    $FeatureList = $WindowsFeatures -split ',\s*'
    # Iterate over each feature in the array
    foreach ($Feature in $FeatureList) {
        # Perform your desired action with each feature
        Install-WindowsFeature -Name $Feature -IncludeManagementTools
    }
    Restart-Computer
}

function ForestSetup {
    Install-ADDSForest -DomainName "$DomainName.$DomainExtension" -InstallDNS;
    Restart-Computer
}

function DHCPSetup {
    # Scope ID
        $octets = $ComputerIP -split '\.' # Split the IP address into its octets
        $octets[3] = '0' # Set the last octet to 1 (192.168.20.*0* as an example)
        $ScopeID = $octets -join '.' # Reassemble the modified IP address
    Restart-Service dhcpserver
    Add-DhcpServerv4Scope -name $ScopeName -StartRange $StartRangeIP -EndRange $EndRangeIP
    Set-DhcpServerv4OptionValue -Value $GatewayIP -ScopeID $ScopeID
    Set-DhcpServerv4OptionValue -DnsDomain "$DomainName.$DomainExtension" -DnsServer $ComputerIP q
    Add-DhcpServerInDC -DnsName "$ComputerName.$DomainName" -IPAddress $ComputerIP 
}

function MakeOUs {
    $OUList = $OUs -split ',\s*'
    foreach ($OU in $OUList) {
        New-ADOrganizationalUnit -Name $OU
    }
}

function MakeOUFolders {
    mkdir 'C:\OUFolders'
    $OUList = $OUs -split ',\s*'
    foreach ($OU in $OUList) {
        mkdir "C:\OUFolders\$OU"
    }
}

function MakeADGroups {
    $OUList = $OUs -split ',\s*'
    foreach ($OU in $OUList) {
        # Perform your desired action with each OU
        New-ADGroup -Name Supporter -GroupCategory Security -GroupScope Global -DisplayName "$OU Afdeling" -Path "OU=$OU,DC=$DomainName,DC=$DomainExtension"
    }
}

function MakeGPOs {
    $OUList = $OUs -split ',\s*'
    foreach ($OU in $OUList) {
    New-GPO $OU -Comment "This is a GPO for $OU"
    }
}

function LinkGPOsToOUs {
    $OUList = $OUs -split ',\s*'
    foreach ($OU in $FeatureList) {
    New-GPLink -Name $OU -Target "ou=$OU,dc=$DomainName,dc=$DomainExtension"
    }
}

function MakeDriveMaps {
    $OUList = $OUs -split ',\s*'
    $DriveLettersList = $DriveLetters -split ',\s*'
    $DrivePermissionsList = $DrivePermissions -split ',\s*'

    # Ensure all lists have the same count
    $count = [math]::Min($OUList.Count, $DriveLettersList.Count, $DrivePermissionsList.Count)

    for ($i = 0; $i -lt $count; $i++) {
        $OU = $OUList[$i]
        $DriveLetter = $DriveLettersList[$i]
        $PermissionGroup = $DrivePermissionsList[$i]

        # Create the drive mapping
        New-PSDrive -Name $DriveLetter -Root "\\$ComputerName\$OU" -Persist -PSProvider FileSystem

        # Set NTFS Permissions
        $acl = Get-Acl -Path "\\$ComputerName\$OU"
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($PermissionGroup, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path "\\$ComputerName\$OU" -AclObject $acl

        # Set Share Permissions
        Grant-SmbShareAccess -Name $OU -AccountName $PermissionGroup -AccessRight Full -Force
    }
}

function MakeADUsers {
    $ADUsers = Import-Csv E:\employee-automation.csv -Delimiter ";"
    # Define UPN
    $Domain = "$DomainName.$DomainExtension"
    # Loop through each row containing user details in the CSV file
    foreach ($User in $ADUsers) {
        #Read user data from each field in each row and assign the data to a variable as below
        $username   = $User.username
        $password   = $User.password
        $firstname  = $User.firstname
        $lastname   = $User.lastname
        $OU         = $User.ou #This field refers to the OU the user account is to be created in
        $email      = $User.email
        $Department = $User.group
        # Checks if the user already exists in the Active Directory
        if (Get-ADUser -F { SamAccountName -eq $username }) {
            # If user does exist, give a warning
            Write-Warning "A user account with username $username already exists in Active Directory."
        }
        else {
    
            # User does not exist then proceed to create the new user account
            # Account will be created in the OU provided by the $OU variable read from the CSV file        
            New-ADUser `
                -SamAccountName $username `
                -UserPrincipalName "$username@$Domain" `
                -Name "$firstname $lastname" `
                -GivenName $firstname `
                -Surname $lastname `
                -Enabled $True `
                -DisplayName "$lastname, $firstname" `
                -Department  $Department `
                -Path $OU `
                -EmailAddress $email `
                -AccountPassword (ConvertTo-secureString $password -AsPlainText -Force) -ChangePasswordAtLogon $False
            Add-ADGroupMember `
                -Identity $Department `
                -Members $username
                # If user is created, show message.
            Write-Host "The user account $username has been created and added to the '$Department' security group." -ForegroundColor Cyan
        }
    }
    Unregister-ScheduledTask -TaskName 'Windows-Server-Setup'
}


## Actual Running of the configuration functions
