Function AD-User-Creation {
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
}