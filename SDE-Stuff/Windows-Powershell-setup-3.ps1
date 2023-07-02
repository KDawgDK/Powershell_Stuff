#schtasks /delete /tn "Third-Powershell-Script" /f; # Deletes the task while also supressing the confirmation

netsh DHCP add SecurityGroups; # Adds 
Restart-Service dhcpserver


<#
Add-DhcpServerv4Scope -name "IT-Prods DHCP" -StartRange 192.168.20.1 -EndRange 192.168.20.254 -SubnetMask 255.255.255.0 -State Active

Add-DhcpServerv4ExclusionRange -ScopeID 192.168.20.0 -StartRange 192.168.20.1 -EndRange 192.168.20.20
Set-DhcpServerv4OptionValue -OptionID 3 -Value 192.168.20.1 -ScopeID 192.168.20.0 -ComputerName "IT-Prods-DCServ"
Set-DhcpServerv4OptionValue -DnsDomain "it-prods.local" -DnsServer 192.168.20.6
Add-DhcpServerInDC -DnsName IT-Prods-DCServ.IT-Prods.local -IPAddress 192.168.20.6; # Authorizes the DHCP server, you can view the available DHCP servers by using the 'Get-DhcpServerInDC' command



$Credential = Get-Credential -Credential "it-prods\Administrator"
Set-DhcpServerDnsCredential -Credential $Credential -ComputerName "IT-Prods-DCServ"




New-ADOrganizationalUnit -Name "Supporter"; # Makes a OU/Organizational Unit with the name Supportere
New-ADOrganizationalUnit -Name "Produktion"; # Makes a OU/Organizational Unit with the name Produktion
New-ADOrganizationalUnit -Name "Levering"; # Makes a OU/Organizational Unit with the name Levering



New-ADGroup -Name Supporter -GroupCategory Security -GroupScope Global -DisplayName 'Supporter Afdeling' -Path "OU=Supporter,DC=IT-Prods,DC=local"; # Makes a new Security Group with the name 'Supportere' and adds it to the OU named Supporter
New-ADGroup -Name Produktion -GroupCategory Security -GroupScope Global -DisplayName 'Produktions Afdeling' -Path "OU=Produktion,DC=IT-Prods,DC=local"; # Makes a new Security Group with the name 'Produktion' and adds it to the OU named Produktion
New-ADGroup -Name Levering -GroupCategory Security -GroupScope Global -DisplayName 'Leverings Afdeling' -Path "OU=Levering,DC=IT-Prods,DC=local"; # Makes a new Security Group with the name 'Levering' and adds it to the OU named Levering
#>


mkdir 'C:\Share Folders'
mkdir 'C:\Share Folders\Global'
$ProduktionsParametre = @{
    Name = 'Global'
    Path = 'C:\Share Folders\Global'
    ChangeAccess = 'IT-Prods\Produktion' 
    ReadAccess = 'IT-Prods\Levering'
}
New-SmbShare -Name 'share-folder' -Path 'C:\Share Folders\share-folder'

mkdir 'C:\Share Folders\Produktion'
$ProduktionsParametre = @{
    Name = 'Produktion'
    Path = 'C:\Share Folders\Produktion'
    FullAccess = 'Administrators', 'IT-Prods\Supporter'
    ChangeAccess = 'IT-Prods\Produktion' 
    ReadAccess = 'IT-Prods\Levering'
}
New-SmbShare @ProduktionsParametre

mkdir 'C:\Share Folders\Supportere'
$SupporterParametre = @{
    Name = 'Supportere'
    Path = 'C:\Share Folders\Supportere'
    FullAccess = 'Administrators'
    ChangeAccess = 'IT-Prods\Supporter'
}
New-SmbShare @SupporterParametre

mkdir 'C:\Share Folders\Levering'
$SupporterParametre = @{
    Name = 'Levering'
    Path = 'C:\Share Folders\Levering'
    FullAccess = 'Administrators'
    ChangeAccess = 'IT-Prods\Levering'
}
New-SmbShare @LeveringsParametre

New-PSDrive -Name "G" -PSProvider "FileSystem" -Root "C:\Share Folders\share-folder" -Persist -Credential $Credential; # Creates a drivemap named 'share-folder' at the stated location that can be used by all

<#
New-PSDrive -Name "H" -PSProvider "FileSystem" -Root "C:\Share Folders\Levering" -Credential $Credential
$Acl = Get-Acl "H:"; # Gets the 'Levering' drive map ready to be configured
$ArLevering = New-Object System.Security.AccessControl.FileSystemAccessRule("IT-Prods.local\Levering","ReadAndExecute","Allow");
$ArLeveringWrite = New-Object System.Security.AccessControl.FileSystemAccessRule("IT-Prods.local\Levering","Write","Allow");
$ArSupporter = New-Object System.Security.AccessControl.FileSystemAccessRule("IT-Prods.local\Supporter","ReadAndExecute","Allow");
$ArSupporterWrite = New-Object System.Security.AccessControl.FileSystemAccessRule("IT-Prods.local\Supporter","Write","Allow");
$ArProduktion = New-Object System.Security.AccessControl.FileSystemAccessRule("IT-Prods.local\Produktion","ReadAndExecute","Allow");
$Acl.SetAccessRule($ArLevering);
$Acl.SetAccessRule($ArLeveringWrite);
$Acl.SetAccessRule($ArSupporter);
$Acl.SetAccessRule($ArSupporterWrite);
$Acl.SetAccessRule($ArProduktion);
Set-Acl "C:\Share Folders\Levering" $Acl;
New-ItemProperty -Path "HKCU:\Network" -Name "Levering" -Value "H:" -PropertyType String; # Automatically maps 'Levering' on startup



New-PSDrive -Name "J" -PSProvider "FileSystem" -Root "C:\Share Folders\Supportere" -Credential $Credential
$Acl = Get-Acl "J:"; # Gets the 'Supportere' drive map ready to be configured
$ArSupporter = New-Object System.Security.AccessControl.FileSystemAccessRule("IT-Prods.local\Supporter","ReadAndExecute","Allow");
$ArSupporterWrite = New-Object System.Security.AccessControl.FileSystemAccessRule("IT-Prods.local\Supporter","Write","Allow");
$Acl.SetAccessRule($ArSupporter);
$Acl.SetAccessRule($ArSupporterWrite);
Set-Acl "C:\Share Folders\Supportere" $Acl;
New-ItemProperty -Path "HKCU:\Network" -Name "Supportere" -Value "J:" -PropertyType String; # Automatically maps 'Supportere' on startup



New-PSDrive -Name "K" -PSProvider "FileSystem" -Root "C:\Share Folders\Produktion" -Credential $Credential
$Acl = Get-Acl "K:"; # Gets the 'Produktion' drive map ready to be configured
$ArLevering = New-Object System.Security.AccessControl.FileSystemAccessRule("IT-Prods.local\Levering","ReadAndExecute","Allow");
$ArLeveringWrite = New-Object System.Security.AccessControl.FileSystemAccessRule("IT-Prods.local\Levering","Write","Allow");
$ArSupporter = New-Object System.Security.AccessControl.FileSystemAccessRule("IT-Prods.local\Supporter","ReadAndExecute","Allow");
$ArSupporterWrite = New-Object System.Security.AccessControl.FileSystemAccessRule("IT-Prods.local\Supporter","Write","Allow");
$ArProduktion = New-Object System.Security.AccessControl.FileSystemAccessRule("IT-Prods.local\Produktion","ReadAndExecute","Allow");
$ArProduktion = New-Object System.Security.AccessControl.FileSystemAccessRule("IT-Prods.local\Supporter","Write","Allow");
$Acl.SetAccessRule($ArLevering);
$Acl.SetAccessRule($ArLeveringWrite);
$Acl.SetAccessRule($ArSupporter);
$Acl.SetAccessRule($ArSupporterWrite);
$Acl.SetAccessRule($ArProduktion);
Set-Acl "C:\Share Folders\Produktion" $Acl;
New-ItemProperty -Path "HKCU:\Network" -Name "Produktion" -Value "K:" -PropertyType String; # Automatically maps 'Produktion' on startup



E:\AD-User-Creation.ps1; # Runs the AD User Creation powershell script
#>
