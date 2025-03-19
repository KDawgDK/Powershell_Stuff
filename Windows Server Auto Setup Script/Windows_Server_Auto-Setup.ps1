## Variables for the configuration
    # Computer Settings
        $adapter = (Get-NetAdapter -Physical | Select-Object -First 1).ifIndex
        $ComputerName = "DCServ"
        $ComputerIP = "192.168.20.6"
        $DomainName = ""
        $Prefix = "24"
        # Gateway
            # Split the IP address into its octets
            $octets = $ComputerIP -split '\.'
            # Set the last octet to 1
            $octets[3] = '1'
            # Reassemble the modified IP address
            $GatewayIP = $octets -join '.'
            # Output the gateway IP address
            Write-Output $GatewayIP
        # Windows Features
            $WindowsFeatures = "AD-Domain-Services, DNS"


## New scheduled task that will run the powershell script at logon (Might need to be at the end of all of the configuration, either manually put into the variables or while it is running)
$actions = (New-ScheduledTaskAction -Execute 'Windows_Server_Auto-Setup.ps1')
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId '$DomainName\user' -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -WakeToRun
$task = New-ScheduledTask -Action $actions -Principal $principal -Trigger $trigger -Settings $settings

Register-ScheduledTask 'Windows-Server-Setup' -InputObject $task



function ComputerSettings {
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
    Install-ADDSForest -DomainName $DomainName -InstallDNS;
}


## Actual Running of the configurations
# Add this to the last function "Unregister-ScheduledTask -TaskName 'Windows-Server-Setup' "