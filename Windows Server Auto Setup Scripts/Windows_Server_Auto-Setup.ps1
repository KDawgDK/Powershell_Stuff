## Variables for the configuration
    # Computer Settings
        $adapter = (Get-NetAdapter -Physical | Select-Object -First 1).ifIndex
        $ComputerName = "DCServ"
        $ComputerIP = "192.168.20.6"
        $Prefix = "24" # Change this to whatever you wish it to be
        # Windows Features
            $WindowsFeatures = 'AD-Domain-Services, DNS' # Separate the Features with ','
    # AD Configurations if you do use it
        $DomainName = "it-prods"
        $DomainExtension = "local"
        $OUs = "Supportere, Produktion, Levering" # Separate the OUs with ','
        $ManualUserCreate = "N" # Either 'Y'es or 'N'o to manually create users
        # Drive Maps Configuration
            $DrivePermissions = "FullControl, Modify" # Separate the permissions with ','
            $DriveLetters = "S, P, L" # Separate the Letters with ','
            $DriveFullAccessSMB = "Supportere"
            $DriveModifyAccessSMB = "Produktion, Levering"
            ## $AccessTo = "Produktion" # Separate who has access to what with ',', use $OUs as a guide since it follows that order you wrote them in
            # $AccessToPerm = "" # Separate who has access to what with ',', use $DrivePermissions as a guide since it follows that order you wrote them in
    # DHCP Scope configurations
        $ScopeName = "$Domain-DHCPScope"
        $StartRangeIP = "" # Never start with 0 as it will comflict with the ScopeID
        $EndRangeIP = "" # Never end with 255 as it will conflict with the broadcast
        $SubnetMask = ""

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
function BlankOrNotConfig { # Check if the variables are blank or have information, and if they don't, you go through manual configuration that will be saved to a config on C:\ServerConfig.txt
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
    Set-ItemProperty -Path "HKLM:\SYSTEM\ServerScript" -Name "Progress" -Value 2
    Restart-Computer
}

function ForestSetup {
    Install-ADDSForest -DomainName "$DomainName.$DomainExtension" -InstallDNS;
    Set-ItemProperty -Path "HKLM:\SYSTEM\ServerScript" -Name "Progress" -Value 3
}

function DHCPSetup {
    if ($WindowsFeatures -like "*DHCP*") {
        if ($ScopeName -eq "") {
            $ScopeName = "$DomainName-DHCP_Scope"
        }
        # Scope ID
            $octets = $ComputerIP -split '\.' # Split the IP address into its octets
            $octets[3] = '0' # Set the last octet to 0 (192.168.20.*0* as an example)
            $ScopeID = $octets -join '.' # Reassemble the modified IP address
        Restart-Service dhcpserver
        Add-DhcpServerv4Scope -name $ScopeName -StartRange $StartRangeIP -EndRange $EndRangeIP -SubnetMask $SubnetMask -State Active
        Set-DhcpServerv4OptionValue -OptionID 3 -Value $StartRangeIP -ScopeID $ScopeID -ComputerName $ComputerName
        Set-DhcpServerv4OptionValue -DnsDomain "$DomainName.$DomainExtension" -DnsServer $ComputerIP
        Add-DhcpServerInDC -DnsName "$ComputerName.$DomainName.$DomainExtension" -IPAddress $ComputerIP
        $Credential = Get-Credential -Credential "$DomainName\Administrator"
        Set-DhcpServerDnsCredential -Credential $Credential -ComputerName $ComputerName
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
    $DriveModifyAccessSMBList = $DriveModifyAccessSMB -split ',\s*'
    $OUList = $OUs -split ',\s*'

    for ($i = 0; $i -lt $OUList.Count; $i++) {
        $OU = $OUList[$i]
        $folderPath = Join-Path -Path $basePath -ChildPath $OU
        New-Item -ItemType Directory -Path $folderPath -Force | Out-Null

        # Share the folder
        New-SmbShare -Name $OU -Path $folderPath -FullAccess "$DomainName\$DriveFullAccessSMB-SG" -ErrorAction SilentlyContinue
        New-SmbShare -Name $OU -Path $folderPath -ChangeAccess "$DomainName\$DriveModifyAccessSMBList-SG" -ErrorAction SilentlyContinue

        # Get the current ACL
        $acl = Get-Acl -Path $folderPath
        # Enable protection to prevent inheritance
        $acl.SetAccessRuleProtection($true, $false)
        # Remove all existing access rules
        $acl.Access | ForEach-Object {
            $acl.RemoveAccessRule($_)
        }
        Set-Acl -Path $folderPath -AclObject $acl

        # Grant Full Control to Administrators
        icacls $folderPath /grant "BUILTIN\Administrators:(OI)(CI)F" /T /C

        # Grant Full Control to the FullAccessSMB group
        icacls $folderPath /grant "$DomainName\$DriveFullAccessSMB-SG:(OI)(CI)F" /T /C

        # Grant Modify permissions to the OU-specific security group
        icacls $folderPath /grant "$DomainName\$OU-SG:(OI)(CI)M" /T /C
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
    $Credential = Get-Credential -Credential "$DomainName\Administrator"

    # Collect the counts of each list
    $counts = @($OUList.Count, $DriveLettersList.Count, $DrivePermissionsList.Count)

    # Determine the minimum count
    $count = ($counts | Measure-Object -Minimum).Minimum

    for ($i = 0; $i -lt $count; $i++) {
        $OU = $OUList[$i]
        $DriveLetter = $DriveLettersList[$i]
        $PermissionGroup = $DrivePermissionsList[$i]

                # Set NTFS Permissions
                $acl = Get-Acl -Path "\\$ComputerName\$OU"
                $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($OU, $PermissionGroup, "ContainerInherit,ObjectInherit", "None", "Allow")
                $acl.SetAccessRule($accessRule)
                Set-Acl -Path "\\$ComputerName\$OU" -AclObject $acl
        
                # Set Share Permissions
                Grant-SmbShareAccess -Name $OU -AccountName $PermissionGroup -AccessRight Full -Force

        # Create the drive mapping
        New-PSDrive -Name $DriveLetter -Root "\\$ComputerName\$OU" -Persist -PSProvider FileSystem -Credential $Credential -Scope Global
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
    netsh DHCP add SecurityGroups
}


## Actual Running of the configuration functions

$Progress = Get-ItemPropertyValue 'HKLM:\SYSTEM\ServerScript' -Name "Progress"

switch ($Progress) { # Looks for the value and runs the result in the switch statement
    0 { Menu }
    1 { BlankOrNotConfig;
        ComputerSettings  }
    2 { ForestSetup }
    3 { 
        DHCPSetup;
        MakeOUs;
        MakeADGroups;
        MakeOUFolders;
        MakeGPOs;
        LinkGPOsToOUs;
        MakeDriveMaps;
        MakeADUsers;
    }
}