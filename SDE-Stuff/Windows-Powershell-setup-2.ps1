#schtasks /delete /tn "Second-Powershell-Script" /f; # Deletes the task while also supressing the confirmation
#schtasks /create /sc ONLOGON /tn "Third-Powershell-Script" /tr "powershell.exe E:\Windows-Powershell-setup-3.ps1"
Install-ADDSForest -DomainName "IT-Prods.local" -InstallDNS; # Installs a ADDS forest wth the domain name of it-prods.local and DNS, it will prompt you afterwards to put in a password for Directory Services Restore Mode (DSRM)
