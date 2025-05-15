## Variables for the configuration
    # Computer Settings
        $adapter = (Get-NetAdapter -Physical | Select-Object -First 1).ifIndex
        $ComputerName = "DCServ"
        $ComputerIP = "192.168.20.6"
        $Prefix = "24" # Change this to whatever you wish it to be
        # Windows Features
            $WindowsFeatures = 'AD-Domain-Services, DNS, DHCP' # Separate the Features with ','
    # AD Configurations if you do use it
        $DomainName = "it-prods"    # {DomainName}.{DomainExtension}
        $DomainExtension = "local"  
        $OUs = "Supportere, Produktion, Levering" # Separate the OUs with ','
        $ManualUserCreate = "N" # Either 'Y'es or 'N'o to manually create users
        $DriveFullAccessSMB = "Supportere" # What group has access to a drive, which is typically admins and the it supporter group
    # DHCP Scope configurations
        $ScopeName = "$Domain-DHCPScope"
        $StartRangeIP = "192.168.20.20" # Never start with 0 as it will comflict with the ScopeID
        $EndRangeIP = "192.168.20.254" # Never end with 255 as it will conflict with the broadcast
        $SubnetMask = "255.255.255.0"
        $DNSservers = "1.1.1.1,1.0.0.1" # Add the DNS servers you want to use, separate with ',' if you have more than one

# Create registry key for the progress if it doesn't exist
    $registryPath = 'HKLM:\SYSTEM\ServerScript'
    $valueName = 'Progress'
    $valueData = 1
    
    # Check if the registry key exists; if not, create it
    if (-not (Test-Path -Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
        Write-Host "Created registry key: $registryPath"
    }
    
    # Check if the DWORD value exists; if not, create it
    if (-not (Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path $registryPath -Name $valueName -Value $valueData -PropertyType DWORD -Force | Out-Null
        Write-Host "Created DWORD value '$valueName' with data '$valueData' in '$registryPath'."
    } else {
        
    }
## Functions for the different things
function BlankOrNotConfig { # Check if the variables are blank or have information, and if they are blank, go through manual configuration that will be saved to a config on C:\ServerConfig.txt
    # Helper function to prompt for user input until a non-empty value is provided
    function PromptForInput {
        param (
            [string]$PromptMessage
        )
        do {
            $inputValue = Read-Host $PromptMessage
            if ([string]::IsNullOrEmpty($inputValue)) {
                Write-Host "Input cannot be empty. Please provide a value."
            }
        } while ([string]::IsNullOrEmpty($inputValue))
        return $inputValue
    }

    # Check if all relevant variables are empty
    if (-not ($ComputerName -or $ComputerIP -or $Prefix -or $WindowsFeatures -or $DomainName -or $DomainExtension -or $OUs -or $ScopeName -or $StartRangeIP -or $EndRangeIP)) {
        # Define the configuration file path
        $configFilePath = "C:\ServerConfig.txt"

        # Check if the configuration file already exists
        if (-not (Test-Path -Path $configFilePath)) {
            # Create the configuration file
            New-Item -ItemType File -Path $configFilePath -Force | Out-Null
        }

        # Prompt for Computer Name if not set
        if ([string]::IsNullOrEmpty($ComputerName)) {
            $ComputerName = Prompt-ForInput -PromptMessage "What do you want to call your server?"
            Add-Content -Path $configFilePath -Value "Computer Name = $ComputerName"
        }

        # Prompt for Computer IP if not set
        if ([string]::IsNullOrEmpty($ComputerIP)) {
            $ComputerIP = Prompt-ForInput -PromptMessage "What IPv4 Address do you want your server to have?"
            Add-Content -Path $configFilePath -Value "Computer IP = $ComputerIP"
        }

        # Prompt for Subnet Prefix if not set
        if ([string]::IsNullOrEmpty($Prefix)) {
            $Prefix = Prompt-ForInput -PromptMessage "What do you want the subnet prefix to be?"
            Add-Content -Path $configFilePath -Value "IP Prefix = $Prefix"
        }

        # Check if Windows Features include AD-Domain-Services
        if ($WindowsFeatures -like "*AD-Domain-Services*") {
            # Prompt for Domain Name and Extension if not set
            if ([string]::IsNullOrEmpty($DomainName) -or [string]::IsNullOrEmpty($DomainExtension)) {
                $FullDomain = Prompt-ForInput -PromptMessage "Enter the domain (e.g., 'name.extension'):"
                $DomainParts = $FullDomain -split '\.'
                if ($DomainParts.Count -ge 2) {
                    $DomainName = $DomainParts[0]
                    $DomainExtension = $DomainParts[1]
                    Add-Content -Path $configFilePath -Value "Domain Name = $DomainName"
                    Add-Content -Path $configFilePath -Value "Domain Extension = $DomainExtension"
                } else {
                    Write-Host "Invalid domain format. Please enter in 'name.extension' format."
                }
            }

            # Prompt for Organizational Units if not set
            if ([string]::IsNullOrEmpty($OUs)) {
                $OUs = Prompt-ForInput -PromptMessage "Enter Organizational Units (separate with commas):"
                Add-Content -Path $configFilePath -Value "OUs = $OUs"
            }
        }

        # Check if Windows Features include DHCP
        if ($WindowsFeatures -like "*DHCP*") {
            # Prompt for Scope Name if not set
            if ([string]::IsNullOrEmpty($ScopeName)) {
                $ScopeName = Read-Host "Enter the scope name (default: ${DomainName}-DHCP_Scope)"
                if (-not [string]::IsNullOrEmpty($ScopeName)) {
                    Add-Content -Path $configFilePath -Value "Scope Name = $ScopeName"
                }
            }

            # Prompt for Start Range IP if not set
            if ([string]::IsNullOrEmpty($StartRangeIP)) {
                $StartRangeIP = Prompt-ForInput -PromptMessage "Enter the start of the IP range:"
                Add-Content -Path $configFilePath -Value "Start Range = $StartRangeIP"
            }

            # Prompt for End Range IP if not set
            if ([string]::IsNullOrEmpty($EndRangeIP)) {
                $EndRangeIP = Prompt-ForInput -PromptMessage "Enter the end of the IP range:"
                Add-Content -Path $configFilePath -Value "End Range = $EndRangeIP"
            }
        }
    }
}

function ComputerSettings {
    ## New scheduled task that will run the powershell script at logon
        # Define the path to the PowerShell script
        $scriptPath = "e:\Windows_Server_Auto-Setup.ps1"

        # Create the action to run the script
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""

        # Create a trigger to run the task at logon
        $trigger = New-ScheduledTaskTrigger -AtLogOn

        # Define the principal (user account) to run the task
        $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -RunLevel Highest

        # Define additional task settings
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

        # Combine everything into a scheduled task
        $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings

        # Register the scheduled task
        Register-ScheduledTask -TaskName "Windows-Server-Setup" -InputObject $task
    # Define the comma-separated list of Windows features
    # Split the string into an array, trimming any leading or trailing whitespace from each feature
    $FeatureList = $WindowsFeatures -split ',\s*'
    # Iterate over each feature in the array
    foreach ($Feature in $FeatureList) {
        # Perform your desired action with each feature
        Install-WindowsFeature -Name $Feature -IncludeManagementTools
    }
        # Gateway
        $octets = $ComputerIP -split '\.' # Split the IP address into its octets
        $octets[3] = '1' # Set the last octet to 1 (192.168.20.*1* as an example)
        $GatewayIP = $octets -join '.' # Reassemble the modified IP address
    # Setup network interface
        New-NetIPAddress -IPAddress $ComputerIP -InterfaceIndex $adapter -DefaultGateway $GatewayIP -AddressFamily IPv4 -PrefixLength $Prefix;
        Set-DnsClientServerAddress -InterfaceIndex $adapter -ServerAddresses $ComputerIP
    Rename-Computer -NewName $ComputerName # Renames the "computer" with the name specified in the variable or that you manually input at the start
    Set-ItemProperty -Path "HKLM:\SYSTEM\ServerScript" -Name "Progress" -Value 2
    Restart-Computer
}

function ForestSetup {
    Install-ADDSForest -DomainName "$DomainName.$DomainExtension";
    Set-ItemProperty -Path "HKLM:\SYSTEM\ServerScript" -Name "Progress" -Value 3;
}

function DHCPSetup {
    if ($WindowsFeatures -like "*DHCP*") {
        if ($ScopeName -eq "") {
            $ScopeName = "$DomainName-DHCP_Scope"
        }
        # Scope ID
            $octets = $ComputerIP -split '\.' # Split the IP address into its octets
            $octets[3] = '0' # Sets the last octet to 0 (192.168.20.*0* as an example)
            $ScopeID = $octets -join '.' # Reassemble the modified IP address
        Add-DhcpServerv4Scope -name $ScopeName -StartRange $StartRangeIP -EndRange $EndRangeIP -SubnetMask $SubnetMask -State Active
        Set-DhcpServerv4OptionValue -OptionID 3 -Value $StartRangeIP -ScopeID $ScopeID -ComputerName $ComputerName
        Set-DhcpServerv4OptionValue -DnsDomain "$DomainName.$DomainExtension" -DnsServer $ComputerIP
        $Credential = Get-Credential -Credential "$DomainName\Administrator"
        Set-DhcpServerDnsCredential -Credential $Credential -ComputerName $ComputerName
        Add-DhcpServerInDC -DnsName "$ComputerName.$DomainName.$DomainExtension" -IPAddress $ComputerIP
        Restart-Service dhcpserver
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\ServerManager\Roles\12' -Name ConfigurationState -Value 2 # Needed for it to be marked as configured in the server manager
        Set-ItemProperty -Path "HKLM:\SYSTEM\ServerScript" -Name "Progress" -Value 4
        Restart-Computer
    }
}

function LookupZones {
    $octets = $ComputerIP -split '\.'
    $octets[3] = '0' # Sets the last octet to 0 (192.168.20.*0* as an example)
    $NetworkID = $octets -join '.' # Reassemble the modified IP address
    $DNSserverList = $DNSservers -split ',\s*'
    Add-DnsServerPrimaryZone -Name "$DomainName.$DomainExtension" -NetworkID $NetworkID -ZoneFile "$DomainName.dns" -DynamicUpdate None
    Add-DnsServerResourceRecordA -Name "www" -ZoneName "$DomainName.$DomainExtension" -IPv4Address $IPAddress -TimeToLive 00:01:00
    Add-DnsServerResourceRecordPtr -Name $octets[3] -NetworkID "$NetworkID/24" -PtrDomainName "$ComputerName.$DomainName.$DomainExtension"
    Add-DnsServerPrimaryZone -NetworkID "$NetworkID/24" -ReplicationScope "Forest"
    foreach ($DNSserver in $DNSserverList) {
        Add-DnsServerForwarder -IPAddress $DNSserver
    }
}

function MakeOUs {
    $OUList = $OUs -split ',\s*'
    foreach ($OU in $OUList) {
        New-ADOrganizationalUnit -Name $OU -Path "DC=$DomainName,DC=$DomainExtension"
    }
}

function MakeADGroups {
    $OUList = $OUs -split ',\s*'
    foreach ($OU in $OUList) {
        # Perform your desired action with each OU
        New-ADGroup -Name "$OU-SG" -GroupCategory Security -GroupScope Global -DisplayName "$OU Afdeling" -Path "OU=$OU,DC=$DomainName,DC=$DomainExtension"
    }
}

function MakeOUFolders {
    $basePath = 'C:\OUFolders'
    New-Item -ItemType Directory -Path $basePath -Force | Out-Null
    $OUList = $OUs -split ',\s*'

    for ($i = 0; $i -lt $OUList.Count; $i++) {
        $OU = $OUList[$i]
        $folderPath = Join-Path -Path $basePath -ChildPath $OU
        New-Item -ItemType Directory -Path $folderPath -Force | Out-Null

        # Add a small delay to ensure the folder is fully created
        Start-Sleep -Milliseconds 500

        # Share the folder
        New-SmbShare -Name $OU -Path $folderPath `
        -FullAccess "BUILTIN\Administrators", "SYSTEM", "$DomainName\$DriveFullAccessSMB-SG" `
        -ChangeAccess "$DomainName\$OU-SG"

        # Get the current ACL
        $acl = Get-Acl -Path $folderPath
        # Enable protection to prevent inheritance
        $acl.SetAccessRuleProtection($true, $false)
        # Remove all existing access rules
        $acl.Access | ForEach-Object {
            $acl.RemoveAccessRule($_)
        }
        Set-Acl -Path $folderPath -AclObject $acl

        # Grant Full Control to SYSTEM and Administrators inheriting the container and object(OI and CI), this is being performed on the subdirectories too and will not stop on errors and display success messages
        icacls $folderPath /grant "BUILTIN\Administrators:(OI)(CI)F" /T /C /q
        icacls $folderPath /grant "SYSTEM:(OI)(CI)F" /T /C /q

        # Grant Full Control to the group in the FullAccessSMB variable inheriting the container and object(OI and CI), this is being performed on the subdirectories too and will not stop on errors and display success messages
        icacls $folderPath /grant "$DomainName\$DriveFullAccessSMB-SG:(OI)(CI)F" /T /C /q

        # Grant Modify permissions to the OU-specific security group inheriting the container and object(OI and CI), this is being performed on the subdirectories too and will not stop on errors and display success messages
        icacls $folderPath /grant "$DomainName\$OU-SG:(OI)(CI)M" /T /C /q
    }
}

function MakeGPOs {
    $OUList = $OUs -split ',\s*'
    foreach ($OU in $OUList) {
    New-GPO $OU
    }
}

function LinkGPOsToOUs {
    $OUList = $OUs -split ',\s*'
    foreach ($OU in $OUList) {
    New-GPLink -Name $OU -Target "ou=$OU,dc=$DomainName,dc=$DomainExtension"
    }
}

function MakeADUsers {
    $ManualUserCreate = $ManualUserCreate.Trim().ToUpper()
    $Domain = "$DomainName.$DomainExtension"
    if ($ManualUserCreate -eq "Y") { # Manual User Creation
        $WantedUsers = Read-Host "How many users do you want to make?"
        for ($i=1; $i -le $WantedUsers; $i++) { # Goes up by one after earch user untill the imputted value entered before
            $SAM_Name = Read-Host "What will their username be?"
            if (Get-ADUser -F { SamAccountName -eq $SAM_Name }) { # If user exist, It'll give a warning
                Write-Warning "A user account with username $SAM_Name already exists in Active Directory."
            } else { # User does not exist and can be created
                $department = Read-Host "What department will they be in?"
                $firstname = Read-Host "What is your first name?"
                $lastname = Read-Host "What is your last name?"
                $password = Read-Host "What will your password be?"
                $email = Read-Host "What is their email?"
                $path = "ou=$department,dc=$DomainName,dc=$DomainExtension"

                New-ADUser `
                -SamAccountName $username `
                -UserPrincipalName "$username@$UPN" `
                -Name "$firstname $lastname" `
                -GivenName $firstname `
                -Surname $lastname `
                -Enabled $True `
                -DisplayName "$lastname, $firstname" `
                -Department  $department `
                -Path $path `
                -EmailAddress $email `
                -AccountPassword (ConvertTo-secureString $password -AsPlainText -Force) -ChangePasswordAtLogon $False
                
                Add-ADGroupMember `
                -Identity "$Department-SG" `
                -Members $username
                # If user is created, show message.
            Write-Host "The user account $username has been created and added to the '$Department-SG' security group." -ForegroundColor Cyan
            }
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
            $department = $User.department
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
                    -Department  $department `
                    -Path $OU `
                    -EmailAddress $email `
                    -AccountPassword (ConvertTo-secureString $password -AsPlainText -Force) -ChangePasswordAtLogon $False
                Add-ADGroupMember `
                    -Identity "$department-SG" `
                    -Members $username
                    # If user is created, show message.
                Write-Host "The user account $username has been created and added to the '$department-SG' security group." -ForegroundColor Cyan
            }
        }
    }
    #Unregister-ScheduledTask -TaskName 'Windows-Server-Setup'
    Set-ItemProperty -Path "HKLM:\SYSTEM\ServerScript" -Name "Progress" -Value 0
    netsh DHCP add SecurityGroups
}

## Actual Running of the configuration functions

$Progress = Get-ItemPropertyValue 'HKLM:\SYSTEM\ServerScript' -Name "Progress"

switch ($Progress) { # Looks for the value and runs the result in the switch statement
    0 { Menu }
    1 { 
        BlankOrNotConfig;
        ComputerSettings;
    }
    2 { 
        ForestSetup;
    }
    3 { 
        DHCPSetup;
    }
    4 {
        LookupZones;
        #MakeOUs;
        #MakeADGroups;
        #MakeOUFolders;
        #MakeGPOs;
        #LinkGPOsToOUs;
        #MakeADUsers;
    }
}