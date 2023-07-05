#schtasks /delete /tn "Third-Powershell-Script" /f; # Deletes the task while also supressing the confirmation

netsh DHCP add SecurityGroups; # Adds 
Restart-Service dhcpserver



Add-DhcpServerv4Scope -name "IT-Prods DHCP" -StartRange 192.168.20.1 -EndRange 192.168.20.254 -SubnetMask 255.255.255.0 -State Active

Add-DhcpServerv4ExclusionRange -ScopeID 192.168.20.0 -StartRange 192.168.20.1 -EndRange 192.168.20.20
Set-DhcpServerv4OptionValue -OptionID 3 -Value 192.168.20.1 -ScopeID 192.168.20.0 -ComputerName "IT-Prods-DCServ"
Set-DhcpServerv4OptionValue -DnsDomain "it-prods.local" -DnsServer 192.168.20.6
Add-DhcpServerInDC -DnsName IT-Prods-DCServ.IT-Prods.local -IPAddress 192.168.20.6; # Authorizes the DHCP server, you can view the available DHCP servers by using the 'Get-DhcpServerInDC' command



$Credential = Get-Credential -Credential "it-prods\Administrator"
Set-DhcpServerDnsCredential -Credential $Credential -ComputerName "IT-Prods-DCServ"


$OUParameter1 = @{
    Name = "Supporter"
    Path = "DC=IT-Prods,DC=local"
}
New-ADOrganizationalUnit @OUParameter1; # Makes a OU/Organizational Unit with the name Supporter
$OUParameter2 = @{
    Name = "Produktion"
    Path = "DC=IT-Prods,DC=local"
}
New-ADOrganizationalUnit @OUParameter2; # Makes a OU/Organizational Unit with the name Produktion
$OUParameter3 = @{
    Name = "Levering"
    Path = "DC=IT-Prods,DC=local"
}
New-ADOrganizationalUnit @OUParameter3; # Makes a OU/Organizational Unit with the name Levering


$SGParameter1 = @{
    Name = "Supporter"
    GroupCategory = Security
    DisplayName = "Supporter Adfeling"
    Path = "OU=Supporter,DC=IT-Prods,DC=local"
}
New-ADGroup @SGParameter1; # Makes a new Security Group with the name 'Supportere' and adds it to the OU named Supporter
$SGParameter2 = @{
    Name = "Produktion"
    GroupCategory = Security
    GroupScope = Global
    DisplayName = "Produktions Afdeling"
    Path = "OU=Produktion,DC=IT-Prods,DC=local"
}
New-ADGroup  @SGParameter2; # Makes a new Security Group with the name 'Produktion' and adds it to the OU named Produktion
$SGParameter3 = @{
    Name = "Levering"
    GroupCategory = Security
    GroupScope = Global
    DisplayName = "Leverings Afdeling"
    Path = "OU=Levering,DC=IT-Prods,DC=local"
}
New-ADGroup  @SGParameter3; # Makes a new Security Group with the name 'Levering' and adds it to the OU named Levering


#>
<#
mkdir 'C:\Share Folders'
mkdir 'C:\Share Folders\Global'
$GlobalSMBParameter = @{
    Name = 'Global Drev'
    Path = 'C:\Share Folders\Global'
    FullAccess = 'Administrators'
    ChangeAccess = 'IT-Prods\Produktion', 'IT-Prods\Levering', 'IT-Prods\Supporter'
}
New-SmbShare @GlobalSMBParameter
#>

mkdir 'C:\Share Folders\Produktion'
$SMBParameter1 = @{
    Name = 'Produktion'
    Path = 'C:\Share Folders\Produktion'
    FullAccess = 'Administrators'
    ChangeAccess = 'IT-Prods\Produktion' 
    ReadAccess = 'IT-Prods\Levering'
}
New-SmbShare @SMBParameter1

mkdir 'C:\Share Folders\Supportere'
$SMBParameter2 = @{
    Name = 'Supportere'
    Path = 'C:\Share Folders\Supportere'
    FullAccess = 'Administrators'
    ChangeAccess = 'IT-Prods\Supporter'
}
New-SmbShare @SMBParameter2


mkdir 'C:\Share Folders\Levering'
$SMBParameter3 = @{
    Name = 'Levering'
    Path = 'C:\Share Folders\Levering'
    FullAccess = 'Administrators'
    ChangeAccess = 'IT-Prods\Levering'
}
New-SmbShare @SMBParameter3


#New-PSDrive -Name "G" -PSProvider "FileSystem" -Root "C:\Share Folders\Global" -Persist -Credential $Credential; # Creates a drivemap named 'share-folder' at the stated location that can be used by all



$DriveMapParameter1 = @{
    Name = "H"
    PSProvider = "FileSystem"
    Root = "C:\Share-Folders\Levering"
    Credential = $Credential
}

New-PSDrive @DriveMapParameter1
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


$DriveMapParameter2 = @{
    Name = "J"
    PSProvider = "FileSystem"
    Root = "C:\Share-Folders\Supportere"
    Credential = $Credential
}

New-PSDrive @DriveMapParameter2
$Acl = Get-Acl "J:"; # Gets the 'Supportere' drive map ready to be configured
$ArSupporter = New-Object System.Security.AccessControl.FileSystemAccessRule("IT-Prods.local\Supporter","ReadAndExecute","Allow");
$ArSupporterWrite = New-Object System.Security.AccessControl.FileSystemAccessRule("IT-Prods.local\Supporter","Write","Allow");
$Acl.SetAccessRule($ArSupporter);
$Acl.SetAccessRule($ArSupporterWrite);
Set-Acl "C:\Share Folders\Supportere" $Acl;
New-ItemProperty -Path "HKCU:\Network" -Name "Supportere" -Value "J:" -PropertyType String; # Automatically maps 'Supportere' on startup



$DriveMapParameter3 = @{
    Name = "K"
    PSProvider = "FileSystem"
    Root = "C:\Share-Folders\Produktion"
    Credential = $Credential
}

New-PSDrive @DriveMapParameter3
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
#>



# Import active directory module for running AD cmdlets
Import-Module ActiveDirectory
  
# Store the data from NewUsersFinal.csv in the $ADUsers variable
$ADUsers = Import-Csv E:\employee-automation.csv -Delimiter ";"

# Define UPN
$UPN = "it-prods.local"

# Loop through each row containing user details in the CSV file
foreach ($User in $ADUsers) {

    #Read user data from each field in each row and assign the data to a variable as below
    $username  = $User.username
    $password  = $User.password
    $firstname = $User.firstname
    $lastname  = $User.lastname
    $OU        = $User.ou #This field refers to the OU the user account is to be created in
    $email     = $User.email

    # Check to see if the user already exists in AD
    if (Get-ADUser -F { SamAccountName -eq $username }) {
        
        # If user does exist, give a warning
        Write-Warning "A user account with username $username already exists in Active Directory."
    }
    else {

        # User does not exist then proceed to create the new user account
        # Account will be created in the OU provided by the $OU variable read from the CSV file
        New-ADUser `
            -SamAccountName $username `
            -UserPrincipalName "$username@$UPN" `
            -Name "$firstname $lastname" `
            -GivenName $firstname `
            -Surname $lastname `
            -Enabled $True `
            -DisplayName "$lastname, $firstname" `
            -Path $OU `
            -EmailAddress $email `
            -AccountPassword (ConvertTo-secureString $password -AsPlainText -Force) -ChangePasswordAtLogon $False `
        # If user is created, show message.
        Write-Host "The user account $username is created." -ForegroundColor Cyan
    }
}

Read-Host -Prompt "Press Enter to exit"
