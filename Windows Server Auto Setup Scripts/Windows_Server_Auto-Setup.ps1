## Variables for the configuration
    $Credential = Get-Credential -Credential "$DomainName\Administrator"
    # Computer Settings
        $adapter = (Get-NetAdapter -Physical | Select-Object -First 1).ifIndex
        $ComputerName = "DCServ"
        $ComputerIP = "192.168.20.6"
        $Prefix = "24" # Change this to whatever you wish it to be
        # Windows Features
            $WindowsFeatures = 'AD-Domain-Services, DNS, DHCP' # Separate the Features with ','
    # AD Configurations if you do use it
        $DomainName = "it-prods"
        $DomainExtension = "local"
        $OUs = "Supportere, Produktion, Levering" # Separate the OUs with ','
        $ManualUserCreate = "N" # Either 'Y'es or 'N'o to manually create users
        # Drive Maps Configuration
            $DrivePermissions = "FullControl, Modify, " # Separate the permissions with ','
            $DriveLetters = "S, P, L" # Separate the Letters
            # $AccessTo = ""
    # DHCP Scope configurations
        $ScopeName = ""
        $StartRangeIP = ""
        $EndRangeIP = ""

## Functions for the different things
function BlankOrNotConfig { # Check if the variables are blank or have information, and if they don't, you go through manual configuration that will be saved to a config on C:\ServerConfig.txt
    New-Item -ItemType File -Name "ServerConfig.txt" -Path "C:"
    if ($ComputerName -eq "") { # Asks the user for a computer name
        $ComputerName = Read-Host = "What do you want to call your server"
        Add-Content -Path "C:\ServerConfig.txt" -Value "Computer Name = $ComputerName"
    }
    if ($ComputerIP -eq "") { # Asks the user for a IPv4 Address
        $ComputerIP = Read-Host = "What IPv4 Address do you want your server to have?"
        Add-Content -Path "C:\ServerConfig.txt" -Value "Computer IP = $ComputerIP"
    }
    if ($Prefix -eq "") { # Asks the user for a subnet prefix
        $Prefix = Read-Host = "What do you want the subnet prefix to be?"
        Add-Content -Path "C:\ServerConfig.txt" -Value "IP Prefix = $Prefix"
    }
    if ($WindowsFeatures -like "*AD-Domain-Services*") { # Make it check if AD-Domain Services is included in $WindowsFeatures and then follow with the 2 other if statements
        if (($DomainName -and $DomainExtension) -eq "") { # Asks the user for a full domain name
            $FullDomain = Read-Host "What domain do you want to have? example: 'name.extension' where 'extension' can be like 'com' or 'local'"
            $Domain = $FullDomain-split '.\s*'
            $DomainName = $Domain[1]
            $DomainExtension = $Domain[2]
            Add-Content -Path "C:\ServerConfig.txt" -Value "Domain Name = $DomainName"
            Add-Content -Path "C:\ServerConfig.txt" -Value "Domain Extension $DomainExtension"
        }
        if ($OUs -eq "") { # Asks the user for Operational Units
            $OUs = Read-Host "What Operational Units do you have or want to have? note separate them with commas ',' "
            Add-Content -Path "C:\ServerConfig.txt" -Value "OUs = $OUs"
        }
    }
    if ($WindowsFeatures -like "*DHCP*") { # Checks if the WindowsFeatures variable includes DHCP to configure DHCP stuff
        if ($ScopeName -eq "") { # Manually name the scope if the variable is blank
            $ScopeName = Read-Host "What do you want the scope name to be? default will be {DomainName}-DHCP_Scope"
            if ($ScopeName -ne "") { # Adds the scope name config to the ServerConfig.txt file if the user enteret in anything
                Add-Content -Path "C:\ServerConfig.txt" -Value "Scope Name = $ScopeName"
            }
        }
        if ($StartRangeIP -eq "") { # Manually input the start range if the variable is blank
            $StartRangeIP = Read-Host "Where should the start of the range be?"
            Add-Content -Path "C:\ServerConfig.txt" -Value "Start Range = $StartRangeIP"
        }
        if ($EndRangeIP -eq "") { # Manually input the end range if the variable is blank
            $EndRangeIP = Read-Host "Where should the end of the range be?"
            Add-Content -Path "C:\ServerConfig.txt" -Value "End Range = $EndRangeIP"
        }
    }
    Set-ItemProperty -Path "HKLM:\SYSTEM\ServerScript" -Name "Progress" -Value 2
}

function ComputerSettings {
    ## New scheduled task that will run the powershell script at logon
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
    Rename-Computer -NewName $ComputerName # Renames the "computer" with the name specified in the variable or that you manually input at the start
    # Define the comma-separated list of Windows features
    # Split the string into an array, trimming any leading or trailing whitespace from each feature
    $FeatureList = $WindowsFeatures -split ',\s*'
    # Iterate over each feature in the array
    foreach ($Feature in $FeatureList) {
        # Perform your desired action with each feature
        Install-WindowsFeature -Name $Feature -IncludeManagementTools
    }
    Set-ItemProperty -Path "HKLM:\SYSTEM\ServerScript" -Name "Progress" -Value 3
    Restart-Computer
}

function ForestSetup {
    Install-ADDSForest -DomainName "$DomainName.$DomainExtension" -InstallDNS;
    Set-ItemProperty -Path "HKLM:\SYSTEM\ServerScript" -Name "Progress" -Value 4
    Restart-Computer
}

function DHCPSetup {
    if ($WindowsFeatures -like "*AD-Domain-Services*") {
        if ($ScopeName -eq "") {
            $ScopeName = "$DomainName-DHCP_Scope"
        }
        # Scope ID
            $octets = $ComputerIP -split '\.' # Split the IP address into its octets
            $octets[3] = '0' # Set the last octet to 0 (192.168.20.*0* as an example)
            $ScopeID = $octets -join '.' # Reassemble the modified IP address
        Restart-Service dhcpserver
        Add-DhcpServerv4Scope -name $ScopeName -StartRange $StartRangeIP -EndRange $EndRangeIP
        Set-DhcpServerv4OptionValue -Value $GatewayIP -ScopeID $ScopeID
        Set-DhcpServerv4OptionValue -DnsDomain "$DomainName.$DomainExtension" -DnsServer $ComputerIP q
        Add-DhcpServerInDC -DnsName "$ComputerName.$DomainName" -IPAddress $ComputerIP 
    }
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
        New-ADGroup -Name $OU -GroupCategory Security -GroupScope Global -DisplayName "$OU Afdeling" -Path "OU=$OU,DC=$DomainName,DC=$DomainExtension"
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
    foreach ($OU in $OUList) {
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
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($OU, $PermissionGroup, "ContainerInherit,ObjectInherit", "None", "Allow")
        $acl.SetAccessRule($accessRule)
        Set-Acl -Path "\\$ComputerName\$OU" -AclObject $acl

        # Set Share Permissions
        Grant-SmbShareAccess -Name $OU -AccountName $PermissionGroup -AccessRight Full -Force
    }
}

function MakeADUsers {
    $Domain = "$DomainName.$DomainExtension"
    if ($ManualUserCreate -eq "Y") { # Manual User Creation
        $WantedUsers = Read-Host "How many users do you want to make?"
        for ($i=1; $i -le $WantedUsers; $i++) { # Goes up by one after earch user untill the imputted value entered before
            $SAM_Name = Read-Host "What will your username be?"
            if (Get-ADUser -F { SamAccountName -eq $SAM_Name }) { # If user exist, It'll give a warning
                Write-Warning "A user account with username $SAM_Name already exists in Active Directory."
            }
            else { # User does not exist and can be created
                $department = Read-Host "What department will they be in?"
                $firstname = Read-Host "What is your first name?"
                $lastname = Read-Host "What is your last name?"
                $password = Read-Host "What will your password be?"
                $email = Read-Host "What is their email?"
                
                New-ADUser `
                -SamAccountName $username `
                -UserPrincipalName "$username@$UPN" `
                -Name "$firstname $lastname" `
                -GivenName $firstname `
                -Surname $lastname `
                -Enabled $True `
                -DisplayName "$lastname, $firstname" `
                -Department  $department `
                -Path $OU `
                -EmailAddress $email `
                -AccountPassword (ConvertTo-secureString $password -AsPlainText -Force) -ChangePasswordAtLogon $False
                
                Add-ADGroupMember `
                -Identity $Department `
                -Members $username
                # If user is created, show message.
            Write-Host "The user account $username has been created and added to the '$Department' security group." -ForegroundColor Cyan
            }
    } else { # Automatic CSV User Creation
    $ADUsers = Import-Csv E:\employee-automation.csv -Delimiter ";"

        foreach ($User in $ADUsers) {    # Loop through each row containing user details in the CSV file
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
    }
    Unregister-ScheduledTask -TaskName 'Windows-Server-Setup'
    Set-ItemProperty -Path "HKLM:\SYSTEM\ServerScript" -Name "Progress" -Value 0
    }
}
New-Item -Path "HKLM:\SYSTEM" -Name "ServerScript"
New-ItemProperty -Path "HKLM:\SYSTEM\ServerScript" -Name "Progress" -Value 1

## Actual Running of the configuration functions

$Progress = Get-ItemPropertyValue 'HKLM:\ServerScript' -Name "Progress"

switch ($Progress) { # Looks for the value and runs the result in the switch statement
    0 { Menu }
    1 { BlankOrNotConfig }
    2 { ComputerSettings }
    3 { ForestSetup }
    4 { DHCPSetup;
        MakeOUs;
        MakeOUFolders;
        MakeADGroups;
        MakeGPOs;
        LinkGPOsToOUs;
        MakeDriveMaps;
        MakeADUsers; }
}

DHCPSetup

MakeOUs
MakeOUFolders
MakeADGroups
MakeGPOs
LinkGPOsToOUs
MakeDriveMaps
MakeADUsers