## New task that will run the powershell script at logon
$actions = (New-ScheduledTaskAction -Execute 'Windows_Server_Auto-Setup.ps1')
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId 'DOMAIN\user' -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -WakeToRun
$task = New-ScheduledTask -Action $actions -Principal $principal -Trigger $trigger -Settings $settings

Register-ScheduledTask 'baz' -InputObject $task

