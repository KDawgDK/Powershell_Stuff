#schtasks /create /sc ONLOGON /tn "Second-Powershell-Script" /tr "powershell.exe E:\Windows-Powershell-setup-2.ps1"

$adapter = (Get-NetAdapter -Physical | Select-Object -First 1).ifIndex

New-NetIPAddress -IPAddress 192.168.20.6 -InterfaceIndex $adapter -DefaultGateway 192.168.20.1 -AddressFamily IPv4 -PrefixLength 24; #Setting the IP adress of the server to the one specified at -IPAddress and Gateway specified at -DefaultGateway
Set-DnsClientServerAddress -InterfaceIndex $adapter -ServerAddresses 192.168.20.6
Rename-Computer -NewName "IT-Prods-DCServ" ;# Renames the server
Install-WindowsFeature DHCP -IncludeManagementTools; # Installs the DHCP windows feature
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools; # Installs the ADDS windows feature
Install-WindowsFeature DNS -IncludeManagementTools 
Restart-Computer
 hej med dig