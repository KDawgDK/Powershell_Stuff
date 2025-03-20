## Variables for the configuration
    $Credential = Get-Credential -Credential "$DomainName\Administrator"
    # Computer Settings
        $adapter = (Get-NetAdapter -Physical | Select-Object -First 1).ifIndex
        $ComputerName = "DCServ"
        $ComputerIP = "192.168.20.6"
        $Prefix = "24"
        # Windows Features
            $WindowsFeatures = 'AD-Domain-Services, DNS'
    # AD Configurations if you do use it
        $DomainName = "it-prods.local"
        $OUs = "Supportere, Produktion, Levering" # Separate the OUs with ','
    # DHCP Scope configurations
        $ScopeName = ""
        $StartRangeIP = ""
        $EndRangeIP = ""

## New scheduled task that will run the powershell script at logon (Might need to be at the end of all of the configuration, either manually put into the variables or while it is running)
    $actions = (New-ScheduledTaskAction -Execute 'Windows_Server_Auto-Setup.ps1')
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "$DomainName\Administrator" -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -WakeToRun
    $task = New-ScheduledTask -Action $actions -Principal $principal -Trigger $trigger -Settings $settings

    Register-ScheduledTask 'Windows-Server-Setup' -InputObject $task

function ComputerSettings {
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
    Install-ADDSForest -DomainName "$DomainName" -InstallDNS;
    Restart-Computer
}

function DHCPSetup {
    # Scope ID
        $octets = $ComputerIP -split '\.' # Split the IP address into its octets
        $octets[3] = '0' # Set the last octet to 1 (192.168.20.*0* as an example)
        $GatewayIP = $octets -join '.' # Reassemble the modified IP address
    Restart-Service dhcpserver
    Add-DhcpServerv4Scope -name $ScopeName -StartRange $StartRangeIP -EndRange $EndRangeIP
    Set-DhcpServerv4OptionValue -Value 192.168.20.1 -ScopeID 192.168.20.0
    Set-DhcpServerv4OptionValue -DnsDomain "it-prods.local" -DnsServer $ComputerIP q
    Add-DhcpServerInDC -DnsName "$ComputerName.$DomainName" -IPAddress $ComputerIP 
}

function MakeADGroups {

}

function MakeADUsers {




    $ADGroups
}


# Add this to the last function = Unregister-ScheduledTask -TaskName 'Windows-Server-Setup'
## Actual Running of the configuration functions
