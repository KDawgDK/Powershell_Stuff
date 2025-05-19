## Variables for the configuration
    # Computer Settings
        $adapter = (Get-NetAdapter -Physical | Select-Object -First 1).ifIndex # Do not touch this, it will automatically get the first network adapter
        $ComputerName = "" # Change this to whatever you wish it to be
        $ComputerIP = "" # Change this to whatever you wish it to be between 0 to 255 in each octet
        # Windows Features
            $WindowsFeatures = '' # Separate the Features with ','
    # AD Configurations if you do use it
        $DomainName = "" # Change this to whatever you wish it to be
        $DomainExtension = "" # Change this to whatever you wish it to be
        $OUs = "" # Separate the OUs with ','
        $ManualUserCreate = "" # Either 'Y'es or 'N'o to manually create users
        $DriveFullAccessSMB = "" # What group has access to a drive, which is typically admins and the it supporter group
    # DHCP Scope configurations if you do use it
        $ScopeName = "" # You can change this to whatever you want, but it will be set to the domain name by default(e.g., "$Domain-DHCPScope")
        $StartRangeIP = "" # Never start with 0 as it will conflict with the ScopeID
        $EndRangeIP = "" # Never end with 255 as it will conflict with the broadcast
        $SubnetMask = "" # Change this to whatever you wish it to be between 0 to 255 in each octet
        $Prefix = "" # Change this to whatever you wish it to be between 0-32, make sure it corrosponds to the subnet mask you made
        $DNSServers = "" # Change this to whatever you wish it to be between 0 to 255 in each octet, usually you would use googles dns server(8.8.8.8,8.8.4.4) or cloudflares (1.1.1.1,1.1.0.0)

## Functions for the different things
function BlankOrNotConfig {
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

    # Define the configuration file path
    $configFilePath = "C:\ServerConfig.txt"

    # Check if the configuration file exists
    if (Test-Path -Path $configFilePath) {
        # Read the configuration file and map its contents to variables
        $configContent = Get-Content -Path $configFilePath
        foreach ($line in $configContent) {
            if ($line -match "^(.*?)\s*=\s*(.*)$") {
                $key = $matches[1].Trim()
                $value = $matches[2].Trim()
                switch ($key) { # all of the variables need to be "$global:variableName" to be used in the other functions
                    # Computer Settings
                    "Computer Name" { $global:ComputerName = $value }
                    "Computer IP" { $global:ComputerIP = $value }
                    "Windows Features" { $global:WindowsFeatures = $value }
                    "Subnet Mask" { $global:SubnetMask = $value }
                    "IP Prefix" { $global:Prefix = $value }
                    # ADDS
                    "Domain Name" { $global:DomainName = $value }
                    "Domain Extension" { $global:DomainExtension = $value }
                    "Manual User Creation" { $global:ManualUserCreate = $value }
                    "OUs" { $global:OUs = $value }
                    "Drive Full Access SMB" { $global:DriveFullAccessSMB = $value }
                    # DHCP
                    "Scope Name" { $global:ScopeName = $value }
                    "Start Range" { $global:StartRangeIP = $value }
                    "End Range" { $global:EndRangeIP = $value }
                    "DNS Servers" { $global:DNSServers = $value }
                }
            }
        }
    } else {
        # If the configuration file doesn't exist, create it
        New-Item -ItemType File -Path $configFilePath -Force | Out-Null
    }

    # Prompt for missing variables and save them to the configuration file
    if ([string]::IsNullOrEmpty($ComputerName)) {
        $ComputerName = PromptForInput -PromptMessage "What do you want to call your server?"
        Add-Content -Path $configFilePath -Value "Computer Name = $ComputerName"
    }

    # Prompt for the missing Windows Features
    if ([string]::IsNullOrEmpty($WindowsFeatures)) {
        $WindowsFeatures = PromptForInput -PromptMessage "What Windows Features do you want to install? Separate with ',' (e.g., 'AD-Domain-Services, DNS, DHCP')"
        Add-Content -Path $configFilePath -Value "Windows Features = $WindowsFeatures"
    }
            if ([string]::IsNullOrEmpty($DNSServers)) {
            $DNSServers = PromptForInput -PromptMessage "Enter DNS servers (e.g., '8.8.8.8, 8.8.4.4')"
            Add-Content -Path $configFilePath -Value "DNS Servers = $DNSServers"
        }
    # Prompt for the missing IP Address for the server
    if ([string]::IsNullOrEmpty($ComputerIP)) {
        $ComputerIP = PromptForInput -PromptMessage "What IPv4 Address do you want your server to have?"
        Add-Content -Path $configFilePath -Value "Computer IP = $ComputerIP"
    }
    # Prompt for the missing subnet mask
        if ([string]::IsNullOrEmpty($SubnetMask)) {
        $SubnetMask = PromptForInput -PromptMessage "Please enter a subnet mask"
        Add-Content -Path $configFilePath -Value "Subnet Mask = $SubnetMask"
    }
    if ([string]::IsNullOrEmpty($Prefix)) {
        $Prefix = PromptForInput -PromptMessage "What do you want the subnet prefix to be?"
        Add-Content -Path $configFilePath -Value "IP Prefix = $Prefix"
    }

    # Prompt for the missing manual user creation answer
    if ([string]::IsNullOrEmpty($ManualUserCreate)) {
        $ManualUserCreate = PromptForInput -PromptMessage "Do you want to create users manually? (Y/N)"
        Add-Content -Path $configFilePath -Value "Manual User Creation = $ManualUserCreate"
    }
    if ($WindowsFeatures -like "*AD-Domain-Services*") {
            if ([string]::IsNullOrEmpty($DomainName) -or [string]::IsNullOrEmpty($DomainExtension)) {
                $FullDomain = PromptForInput -PromptMessage "Enter the domain (e.g., 'name.extension')"
                $DomainParts = $FullDomain -split '\.'
                if ($DomainParts.Count -ge 2 -and $DomainParts.Count -le 2) {
                    $DomainName = $DomainParts[0]
                    $DomainExtension = $DomainParts[1]
                    Add-Content -Path $configFilePath -Value "Domain Name = $DomainName"
                    Add-Content -Path $configFilePath -Value "Domain Extension = $DomainExtension"
                } else {
                    Write-Host "Invalid domain format. Please enter in 'name.extension' format."
                }

                if ([string]::IsNullOrEmpty($OUs)) {
                    $OUs = PromptForInput -PromptMessage "Enter Organizational Units (separate with commas)"
                    Add-Content -Path $configFilePath -Value "OUs = $OUs"
                }
                if ([string]::IsNullOrEmpty($DriveFullAccessSMB)) {
                    $DriveFullAccessSMB = PromptForInput -PromptMessage "What group has full access to drives?"
                    Add-Content -Path $configFilePath -Value "Drive Full Access SMB = $DriveFullAccessSMB"
                }
            }


        if ([string]::IsNullOrEmpty($ManualUserCreate)) {
            $ManualUserCreate = PromptForInput -PromptMessage "Do you want to create users manually? (Y/N)"
            Add-Content -Path $configFilePath -Value "Manual User Creation = $ManualUserCreate"
        }
    }
        if ($WindowsFeatures -like "*DNS*") {
            if ([string]::IsNullOrEmpty($DNSServers)) {
                $DNSServers = PromptForInput -PromptMessage "Enter DNS servers (e.g., '8.8.8.8, 8.8.4.4')"
                Add-Content -Path $configFilePath -Value "DNS Servers = $DNSServers"
            }
        }

    if ($WindowsFeatures -like "*DHCP*") {
        if ([string]::IsNullOrEmpty($ScopeName)) {
            $ScopeName = Read-Host "Enter the scope name (default: ${DomainName}-DHCP_Scope)"
            if (-not [string]::IsNullOrEmpty($ScopeName)) {
                Add-Content -Path $configFilePath -Value "Scope Name = $ScopeName"
            }
        }

        if ([string]::IsNullOrEmpty($StartRangeIP)) {
            $StartRangeIP = PromptForInput -PromptMessage "Enter the start of the IP range"
            Add-Content -Path $configFilePath -Value "Start Range = $StartRangeIP"
        }

        if ([string]::IsNullOrEmpty($EndRangeIP)) {
            $EndRangeIP = PromptForInput -PromptMessage "Enter the end of the IP range"
            Add-Content -Path $configFilePath -Value "End Range = $EndRangeIP"
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
    if ($WindowsFeatures -like "*AD-Domain-Services*") {
    Install-ADDSForest -DomainName "$DomainName.$DomainExtension";
    Set-ItemProperty -Path "HKLM:\SYSTEM\ServerScript" -Name "Progress" -Value 3;
    }
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

function ReverseLookup {
    $octets = $ComputerIP -split '\.'
    $octets[3] = '0' # Sets the last octet to 0 (192.168.20.*0* as an example)
    $NetworkID = $octets -join '.' # Reassemble the modified IP address
    Add-DnsServerPrimaryZone -NetworkID "$NetworkID/$Prefix" -ReplicationScope "Forest"
    Add-DnsServerConditionalForwarderZone -Name "$DomainName.$DomainExtension" -MasterServers $DNSServers -PassThru
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
    Unregister-ScheduledTask -TaskName 'Windows-Server-Setup'
    Set-ItemProperty -Path "HKLM:\SYSTEM\ServerScript" -Name "Progress" -Value 0
    if (Test-Path -Path $configFilePath) {
        Remove-Item -Path $configFilePath -Force
    }
    netsh DHCP add SecurityGroups
}

## Actual Running of the configuration functions
$configFilePath = "C:\ServerConfig.txt"
$Progress = Get-ItemPropertyValue 'HKLM:\SYSTEM\ServerScript' -Name "Progress"

if ($Progress -eq $null -and (Test-Path -Path $configFilePath)) {
    # If the registry value doesn't exist, run the function twice
    BlankOrNotConfig;
    BlankOrNotConfig;  
} else {
    # If the registry value exists, run the function once
    BlankOrNotConfig;
}

# Create registry key for the progress if it doesn't exist
    if (-not (Test-Path -Path 'HKLM:\SYSTEM\ServerScript')) {
        New-Item -Path 'HKLM:\SYSTEM\ServerScript' -Force | Out-Null
    }
    
    # Check if the DWORD value exists; if not, create it
    if (-not (Get-ItemProperty -Path 'HKLM:\SYSTEM\ServerScript' -Name 'Progress' -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path 'HKLM:\SYSTEM\ServerScript' -Name 'Progress' -Value 1 -PropertyType DWORD -Force | Out-Null
    }


switch ($Progress) { # Looks for the value and runs the result in the switch statement
    0 { 
        Menu 
    }
    1 { 
        ComputerSettings;
    }
    2 { 
        ForestSetup;
    }
    3 { 
        DHCPSetup;
    }
    4 {
        ReverseLookup;
        MakeOUs;
        MakeADGroups;
        MakeOUFolders;
        MakeGPOs;
        LinkGPOsToOUs;
        MakeADUsers;
    }
}