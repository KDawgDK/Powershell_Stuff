#schtasks /delete /tn "Third-Powershell-Script" /f; # Deletes the task while also supressing the confirmation
# Import active directory module for running AD cmdlets
Import-Module ActiveDirectory

netsh DHCP add SecurityGroups; # Adds 
Restart-Service dhcpserver



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

mkdir 'C:\Share-Folders'
mkdir 'C:\Share-Folders\Global'
<#
$GlobalParameter = @{
    Name = 'Global'
    Path = 'C:\Share-Folders\Global'
    ChangeAccess = 'IT-Prods\Produktion', 'IT-Prods\Supporter', 'IT-Prods\Levering'
}#>
#New-SmbShare @GlobalParameter
New-SmbShare -Name 'Global' -Path 'C:\Share-Folders\Global' -FullAccess 'Administrators' -ChangeAccess 'IT-Prods\Produktion', 'IT-Prods\Supporter', 'IT-Prods\Levering'
<#
mkdir 'C:\Share-Folders\Produktion'
$ProduktionsParameter = @{
    Name = 'Produktion'
    Path = 'C:\Share-Folders\Produktion'
    FullAccess = 'Administrators'
    ChangeAccess = 'IT-Prods\Produktion' 
    ReadAccess = 'IT-Prods\Levering'
}
New-SmbShare @ProduktionsParameter
#>
mkdir 'C:\Share-Folders\Supporter'
<#
$SupporterParameter = @{
    Name = 'Supporter'
    Path = 'C:\Share-Folders\Supporter'
    FullAccess = 'Administrators'
    ChangeAccess = 'IT-Prods\Supporter'
}
#>
#New-SmbShare @SupporterParameter
New-SmbShare -Name 'Supporter' -Path 'C:\Share-Folders\Supporter' -FullAccess 'Administrators' -ChangeAccess 'IT-Prods\Supporter'
<#
mkdir 'C:\Share-Folders\Levering'
$SupporterParameter = @{
    Name = 'Levering'
    Path = 'C:\Share-Folders\Levering'
    FullAccess = 'Administrators'
    ChangeAccess = 'IT-Prods\Levering'
}
New-SmbShare @LeveringsParameter
#>
New-PSDrive -Name "G" -PSProvider "FileSystem" -Root "C:\Share-Folders\share-folder" -Credential $Credential; # Creates a drivemap named 'share-folder' at the stated location that can be used by all

<#
New-PSDrive -Name "H" -PSProvider "FileSystem" -Root "C:\Share-Folders\Levering" -Credential $Credential
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
Set-Acl "C:\Share-Folders\Levering" $Acl;
New-ItemProperty -Path "HKCU:\Network" -Name "Levering" -Value "H:" -PropertyType String; # Automatically maps 'Levering' on startup
#>


New-PSDrive -Name "J" -PSProvider "FileSystem" -Root "C:\Share-Folders\Supporter" -Credential $Credential
$Acl = Get-Acl "J:"; # Gets the 'Supportere' drive map ready to be configured
$ArSupporter = New-Object System.Security.AccessControl.FileSystemAccessRule("IT-Prods.local\Supporter","ReadAndExecute","Allow");
$ArSupporterWrite = New-Object System.Security.AccessControl.FileSystemAccessRule("IT-Prods.local\Supporter","Write","Allow");
$Acl.SetAccessRule($ArSupporter);
$Acl.SetAccessRule($ArSupporterWrite);
Set-Acl "C:\Share-Folders\Supporter" $Acl;
New-ItemProperty -Path "HKCU:\Network" -Name "Supporter" -Value "J:" -PropertyType String; # Automatically maps 'Supportere' on startup


<#
New-PSDrive -Name "K" -PSProvider "FileSystem" -Root "C:\Share-Folders\Produktion" -Credential $Credential
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
Set-Acl "C:\Share-Folders\Produktion" $Acl;
New-ItemProperty -Path "HKCU:\Network" -Name "Produktion" -Value "K:" -PropertyType String; # Automatically maps 'Produktion' on startup

#>

# Store the data from NewUsersFinal.csv in the $ADUsers variable
$ADUsers = Import-Csv E:\employee-automation.csv -Delimiter ";"

# Define UPN
$UPN = "it-prods.local"

# Loop through each row containing user details in the CSV file
foreach ($User in $ADUsers) {

    #Read user data from each field in each row and assign the data to a variable as below
    $username   = $User.username
    $password   = $User.password
    $firstname  = $User.firstname
    $lastname   = $User.lastname
    $OU         = $User.ou #This field refers to the OU the user account is to be created in
    $email      = $User.email
    $Department = $User.group


    # Check to see if the user already exists in AD
    if (Get-ADUser -F { SamAccountName -eq $username }) {
        
        # If user does exist, give a warning
        Write-Warning "A user account with username $username already exists in Active Directory."
    }
    else {

        # User does not exist then proceed to create the new user account
        # Account will be created in the OU provided by the $OU variable read from the CSV file
        $NewUserParams = @{
            SamAccountName = $username
            UserPrincipalName= "$username@$UPN"
            Name = "$firstname $lastname"
            GivenName = $firstname
            Surname = $lastname
            Enabled = $True
            DisplayName = "$lastname, $firstname"
            Department  = $Department
            Path = $OU
            EmailAddress = $email
            AccountPassword = (ConvertTo-secureString $password -AsPlainText -Force) 
            ChangePasswordAtLogon = $False
        }
        New-ADUser @NewUserParams
        <#
        New-ADUser `
            -SamAccountName $username `
            -UserPrincipalName "$username@$UPN" `
            -Name "$firstname $lastname" `
            -GivenName $firstname `
            -Surname $lastname `
            -Enabled $True `
            -DisplayName "$lastname, $firstname" `
            -Department  $Department `
            -Path $OU `
            -EmailAddress $email `
            -AccountPassword (ConvertTo-secureString $password -AsPlainText -Force) -ChangePasswordAtLogon $False;
        #>
        $UserGroupParams = @{
            Identity = $Department
            Members = $username
        }
        Add-ADGroupMember @UserGroupParams
        <#
        Add-ADGroupMember `
            -Identity $Department `
            -Members $username;
            # If user is created, show message.
        Write-Host "The user account $username is created and added to its Security Group." -ForegroundColor Cyan
        #>
    }
}

Read-Host -Prompt "Press Enter to exit"
#>