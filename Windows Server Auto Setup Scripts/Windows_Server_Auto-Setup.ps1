## Variables for the configuration
    # Computer/Server Settings
        $global:adapter = (Get-NetAdapter -Physical | Select-Object -First 1).ifIndex # Do not touch this, it will automatically get the first network adapter
        $global:ComputerName = "DCServ" # Change this to whatever you wish it to be
        $global:ComputerIP = "172.16.1.6" # Change this to whatever you wish it to be between 0 to 255 in each 4 octets
        # Windows Features
            $global:WindowsFeatures = "AD-Domain-Services, DNS, DHCP, Print-Server" # Separate the Features with ','(e.g., 'AD-Domain-Services, DNS, DHCP')
    # AD Configurations if you do use it
        $global:DomainName = "IT-Prods" # Change this to whatever you wish it to be
        $global:DomainExtension = "local" # Change this to whatever you wish it to be
        $global:OUs = "Supportere, Produktion, Levering" # Separate the OUs with ','
        $global:DriveFullAccessSMB = "Supportere" # What group has access to a drive, which is typically admins and the it supporter group
        $global:ManualUserCreate = "N" # Either 'Y'es or 'N'o to manually create users
    # DHCP Scope configurations if you do use it
        $global:ScopeName = "$Domain-DHCPScope" # You can change this to whatever you want, but it will be set to the domain name by default(e.g., "$Domain-DHCPScope")
        $global:StartRangeIP = "172.16.1.100" # Never start with 0 as it will conflict with the ScopeID
        $global:EndRangeIP = "172.16.1.200" # Never end with 255 as it will conflict with the broadcast
        $global:SubnetMask = "255.255.255.0" # Change this to whatever you wish it to be between 0 to 255 in each 4 octets
        $global:Prefix = "24" # Change this to whatever you wish it to be between 0-32, make sure it corrosponds to the subnet mask you made
        $global:DNSServers = "1.1.1.1, 1.0.0.1" # Change this to whatever you wish it to be between 0 to 255 in each octet, usually you would use googles dns server(8.8.8.8,8.8.4.4) or cloudflares (1.1.1.1,1.1.0.0)
    #Printer Stuff
        $global:PrinterName = "HP LaserJet M209dwe" # Name for the printer
        $global:PrinterDriver = "HP Universal Driver" # Change this to the driver you want to use, look for the printer driver name inside of the INF file you are using
        $global:PrinterDriverINFPath = "E:\HPEasyStart-16.2.4-LJM207-M212_U_52_3_4930_Webpack - Drivers\hpypclms32_v4.inf" # Path to the driver folder, this is used to add the printer driver
        $global:PrinterIP = "172.16.1.4" # Change this to whatever you wish it to be between 0 to 255 in each 4 octets

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
                    # Computer/Server Settings
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
                    # Printer Stuff
                    "Printer Name" { $global:PrinterName = $value }
                    "Printer INF Path" { $global:PrinterDriverPath = $value }
                    "Printer IP" { $global:PrinterIP = $value }
                }
            }
        }
    } else {
        # If the configuration file doesn't exist, create it
        New-Item -ItemType File -Path $configFilePath -Force | Out-Null
    }

    # Prompt for missing variables and save them to the configuration file
    if ([string]::IsNullOrEmpty($global:ComputerName)) {
        $global:ComputerName = PromptForInput -PromptMessage "What do you want to call your server?"
        Add-Content -Path $configFilePath -Value "Computer Name = $global:ComputerName"
    }

    # Prompt for the missing Windows Features
    if ([string]::IsNullOrEmpty($global:WindowsFeatures)) {
        $global:WindowsFeatures = PromptForInput -PromptMessage "What Windows Features do you want to install? Separate with ',' (e.g., 'AD-Domain-Services, DNS, DHCP')"
        Add-Content -Path $configFilePath -Value "Windows Features = $global:WindowsFeatures"
    }
    # Prompt for the missing IP Address for the server
    if ([string]::IsNullOrEmpty($global:ComputerIP)) {
        $global:ComputerIP = PromptForInput -PromptMessage "What IPv4 Address do you want your server to have?"
        Add-Content -Path $configFilePath -Value "Computer IP = $global:ComputerIP"
    }
    # Prompt for the missing subnet mask
        if ([string]::IsNullOrEmpty($global:SubnetMask)) {
        $global:SubnetMask = PromptForInput -PromptMessage "Please enter a subnet mask"
        Add-Content -Path $configFilePath -Value "Subnet Mask = $global:SubnetMask"
    }
    if ([string]::IsNullOrEmpty($global:Prefix)) {
        $global:Prefix = PromptForInput -PromptMessage "What do you want the subnet prefix to be?"
        Add-Content -Path $configFilePath -Value "IP Prefix = $global:Prefix"
    }


    if ($global:WindowsFeatures -like "*AD-Domain-Services*") {
            if ([string]::IsNullOrEmpty($global:DomainName) -or [string]::IsNullOrEmpty($global:DomainExtension)) {
                $global:FullDomain = PromptForInput -PromptMessage "Enter the domain (e.g., 'name,extension' or CompanyName,local)"
                $DomainParts = $global:FullDomain -split ','
                if ($DomainParts.Count -ge 2 -and $DomainParts.Count -le 2) {
                    $global:DomainName = $DomainParts[0]
                    $global:DomainExtension = $DomainParts[1]
                    Add-Content -Path $configFilePath -Value "Domain Name = $global:DomainName"
                    Add-Content -Path $configFilePath -Value "Domain Extension = $global:DomainExtension"
                } else {
                    Write-Host "Invalid domain format. Please enter in 'name,extension' format."
                }
                    # Prompt for the missing manual user creation answer
                if ([string]::IsNullOrEmpty($global:ManualUserCreate)) {
                    $global:ManualUserCreate = PromptForInput -PromptMessage "Do you want to create users manually? (Y/N)"
                    Add-Content -Path $configFilePath -Value "Manual User Creation = $global:ManualUserCreate"
                }
                if ([string]::IsNullOrEmpty($global:OUs)) {
                    $global:OUs = PromptForInput -PromptMessage "Enter Organizational Units (separate with commas)"
                    Add-Content -Path $configFilePath -Value "OUs = $global:OUs"
                }
                if ([string]::IsNullOrEmpty($global:DriveFullAccessSMB)) {
                    $global:DriveFullAccessSMB = PromptForInput -PromptMessage "What group has full access to drives?"
                    Add-Content -Path $configFilePath -Value "Drive Full Access SMB = $global:DriveFullAccessSMB"
                }
            }

    }
        if ($global:WindowsFeatures -like "*DNS*") {
            if ([string]::IsNullOrEmpty($global:DNSServers)) {
                $global:DNSServers = PromptForInput -PromptMessage "Enter DNS servers (e.g., '8.8.8.8, 8.8.4.4')"
                Add-Content -Path $configFilePath -Value "DNS Servers = $global:DNSServers"
            }
        }

    if ($global:WindowsFeatures -like "*DHCP*") {
        if ([string]::IsNullOrEmpty($global:ScopeName)) {
            $inputScopeName = Read-Host "Enter the scope name (default: $($global:DomainName)-DHCP_Scope)"
            if ([string]::IsNullOrEmpty($inputScopeName)) {
                $global:ScopeName = "$($global:DomainName)-DHCP_Scope"
            } else {
                $global:ScopeName = $inputScopeName
            }
            Add-Content -Path $configFilePath -Value "Scope Name = $global:ScopeName"
        }

        if ([string]::IsNullOrEmpty($global:StartRangeIP)) {
            $global:StartRangeIP = PromptForInput -PromptMessage "Enter the start of the IP range"
            Add-Content -Path $configFilePath -Value "Start Range = $global:StartRangeIP"
        }

        if ([string]::IsNullOrEmpty($global:EndRangeIP)) {
            $global:EndRangeIP = PromptForInput -PromptMessage "Enter the end of the IP range"
            Add-Content -Path $configFilePath -Value "End Range = $global:EndRangeIP"
        }
    }
    if ($WindowsFeatures -like "*Print-Server*") {
        if ([string]::IsNullOrEmpty($global:PrinterName)) {
            $global:PrinterName = PromptForInput -PromptMessage "Enter the printer name"
            Add-Content -Path $configFilePath -Value "Printer Name = $global:PrinterName"
        }
        if ([string]::IsNullOrEmpty($global:PrinterDriverPath)) {
            $global:PrinterDriverPath = PromptForInput -PromptMessage "Enther the path to the printer driver INF File"
            Add-Content -Path $configFilePath -Value "Printer INF Path = $global:PrinterDriverPath"
        }
        if ([string]::IsNullOrEmpty($global:PrinterIP)) {
            $global:PrinterIP = PromptForInput -PromptMessage "Enter the Printer IP Address"
            Add-Content -Path $configFilePath -Value "PrinterIP = $global:PrinterIP"
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

function LoadConfigFromFile {
    $configFilePath = "C:\ServerConfig.txt"
    if (Test-Path -Path $configFilePath) {
        $configContent = Get-Content -Path $configFilePath
        foreach ($line in $configContent) {
            if ($line -match "^(.*?)\s*=\s*(.*)$") {
                $key = $matches[1].Trim()
                $value = $matches[2].Trim()
                switch ($key) {
                    "Computer Name" { $global:ComputerName = $value }
                    "Computer IP" { $global:ComputerIP = $value }
                    "Windows Features" { $global:WindowsFeatures = $value }
                    "Subnet Mask" { $global:SubnetMask = $value }
                    "IP Prefix" { $global:Prefix = $value }
                    "Domain Name" { $global:DomainName = $value }
                    "Domain Extension" { $global:DomainExtension = $value }
                    "Manual User Creation" { $global:ManualUserCreate = $value }
                    "OUs" { $global:OUs = $value }
                    "Drive Full Access SMB" { $global:DriveFullAccessSMB = $value }
                    "Scope Name" { $global:ScopeName = $value }
                    "Start Range" { $global:StartRangeIP = $value }
                    "End Range" { $global:EndRangeIP = $value }
                    "DNS Servers" { $global:DNSServers = $value }
                    "Printer Name" { $global:PrinterName = $value }
                }
            }
        }
    }
}

function ForestSetup {
    if ($global:WindowsFeatures -like "*AD-Domain-Services*") {
    Install-ADDSForest -DomainName "$global:DomainName.$global:DomainExtension";
    }
    if ($global:WindowsFeatures -like "*DHCP*") {
        Set-ItemProperty -Path "HKLM:\SYSTEM\ServerScript" -Name "Progress" -Value 3;
    } else {
        Set-ItemProperty -Path "HKLM:\SYSTEM\ServerScript" -Name "Progress" -Value 4;
    }
}

function DHCPSetup {
    if ($global:WindowsFeatures -like "*DHCP*") {
        if ($global:ScopeName -eq "") {
            $global:ScopeName = "$global:DomainName-DHCP_Scope"
        }
        # Scope ID
            $octets = $global:ComputerIP -split '\.' # Split the IP address into its octets
            $octets[3] = '0' # Sets the last octet to 0 (192.168.20.*0* as an example)
            $ScopeID = $octets -join '.' # Reassemble the modified IP address
        Add-DhcpServerv4Scope -name $global:ScopeName -StartRange $global:StartRangeIP -EndRange $global:EndRangeIP -SubnetMask $global:SubnetMask -State Active
        Set-DhcpServerv4OptionValue -OptionID 3 -Value $global:StartRangeIP -ScopeID $ScopeID -ComputerName $global:ComputerName
        Set-DhcpServerv4OptionValue -DnsDomain "$global:DomainName.$global:DomainExtension" -DnsServer $global:ComputerIP
        $Credential = Get-Credential -Credential "$global:DomainName\Administrator"
        Set-DhcpServerDnsCredential -Credential $Credential -ComputerName $global:ComputerName
        Add-DhcpServerInDC -DnsName "$global:ComputerName.$global:DomainName.$global:DomainExtension" -IPAddress $global:ComputerIP
        Restart-Service dhcpserver
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\ServerManager\Roles\12' -Name ConfigurationState -Value 2 # Needed for it to be marked as configured in the server manager
        Set-ItemProperty -Path "HKLM:\SYSTEM\ServerScript" -Name "Progress" -Value 4
        Restart-Computer
    }
}

function ReverseLookup {
    $octets = $global:ComputerIP -split '\.'
    $octets[3] = '0' # Sets the last octet to 0 (192.168.20.*0* as an example)
    $NetworkID = $octets -join '.' # Reassemble the modified IP address
    Add-DnsServerPrimaryZone -NetworkID "$NetworkID/$global:Prefix" -ReplicationScope "Forest"
    Add-DnsServerConditionalForwarderZone -Name "$global:DomainName.$global:DomainExtension" -MasterServers $global:DNSServers -PassThru
}

function MakeOUs {
    $OUList = $global:OUs -split ',\s*'
    foreach ($OU in $OUList) {
        New-ADOrganizationalUnit -Name $OU -Path "DC=$global:DomainName,DC=$global:DomainExtension"
    }
}

function MakeADGroups {
    $OUList = $global:OUs -split ',\s*'
    foreach ($OU in $OUList) {
        # Perform your desired action with each OU
        New-ADGroup -Name "$OU-SG" -GroupCategory Security -GroupScope Global -DisplayName "$OU Afdeling" -Path "OU=$OU,DC=$global:DomainName,DC=$global:DomainExtension"
    }
}

function MakeOUFolders {
    $basePath = 'C:\OUFolders'
    New-Item -ItemType Directory -Path $basePath -Force | Out-Null
    $OUList = $global:OUs -split ',\s*'

    for ($i = 0; $i -lt $OUList.Count; $i++) {
        $OU = $OUList[$i]
        $folderPath = Join-Path -Path $basePath -ChildPath $OU
        New-Item -ItemType Directory -Path $folderPath -Force | Out-Null

        # Add a small delay to ensure the folder is fully created
        Start-Sleep -Milliseconds 500

        # Share the folder
        New-SmbShare -Name $OU -Path $folderPath `
        -FullAccess "BUILTIN\Administrators", "SYSTEM", "$global:DomainName\$global:DriveFullAccessSMB-SG" `
        -ChangeAccess "$global:DomainName\$OU-SG"

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
        icacls $folderPath /grant "$global:DomainName\$global:DriveFullAccessSMB-SG:(OI)(CI)F" /T /C /q

        # Grant Modify permissions to the OU-specific security group inheriting the container and object(OI and CI), this is being performed on the subdirectories too and will not stop on errors and display success messages
        icacls $folderPath /grant "$global:DomainName\$OU-SG:(OI)(CI)M" /T /C /q
    }
}

function MakeGPOs {
    $OUList = $global:OUs -split ',\s*'
    foreach ($OU in $OUList) {
    New-GPO $OU
    }
}

function LinkGPOsToOUs {
    $OUList = $global:OUs -split ',\s*'
    foreach ($OU in $OUList) {
    New-GPLink -Name $OU -Target "ou=$OU,dc=$global:DomainName,dc=$global:DomainExtension"
    }
}

function PrinterSetup {
    if ($global:WindowsFeatures -Like "*Print-Server*") {
        $global:PrinterPath = "\\$global:ComputerName\$global:PrinterName"
        set-location $global:PrinterDriverPath
        pnputil /add-driver $global:PrinterDriverINF -install
        # Add the printer driver and port
        Add-PrinterDriver -Name $global:PrinterDriver
        Add-PrinterPort -Name "TCPPort:" -PrinterHostAddress $global:PrinterIP
        Add-Printer -Name $global:PrinterName -DriverName $global:PrinterDriver -PortName "TCPPort:" -Shared -ShareName $global:PrinterPath
    }
}

function MakeADUsers {
    $ManualUserCreate = $global:ManualUserCreate.Trim().ToUpper()
    $Domain = "$global:DomainName.$global:DomainExtension"
    if ($global:ManualUserCreate -eq "Y") { # Manual User Creation
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
                $path = "ou=$department,dc=$global:DomainName,dc=$global:DomainExtension"

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

if (-not (Test-Path -Path 'HKLM:\SYSTEM\ServerScript') -and (-not (Test-Path -Path "C:\ServerConfig.txt"))) {
    BlankOrNotConfig;
}
LoadConfigFromFile;

# Create registry key for the progress if it doesn't exist
    if (-not (Test-Path -Path 'HKLM:\SYSTEM\ServerScript')) {
        New-Item -Path 'HKLM:\SYSTEM\ServerScript' -Force | Out-Null
    }
    
    # Check if the DWORD value exists; if not, create it
    if (-not (Get-ItemProperty -Path 'HKLM:\SYSTEM\ServerScript' -Name 'Progress' -ErrorAction SilentlyContinue)) {
        New-ItemProperty -Path 'HKLM:\SYSTEM\ServerScript' -Name 'Progress' -Value 1 -PropertyType DWORD -Force | Out-Null
    }
$Progress = Get-ItemPropertyValue 'HKLM:\SYSTEM\ServerScript' -Name "Progress"

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
        PrinterSetup;
        MakeADUsers;
    }
}