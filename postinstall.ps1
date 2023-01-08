Send-ALNotification -Activity "Rebooting Lab Machines" -Message " " -Provider Toast
Write-ScreenInfo -Message 'Disable AutoLogon & Reboot Machines'
$VMs =@(Get-LabVM)
#Restart Lab VMs (without DC)
foreach ($VM in $VMs){
    $VMRole = $VM.Roles
    $VMRoleName = $VMRole.Name
    If ($VMRoleName -eq "RootDC"){continue}
    Disable-LabAutoLogon -ComputerName "$VM"
    Restart-LabVM -ComputerName "$VM"
}

#Restart Lab DC
foreach ($VM in $VMs){
    $VMRole = $VM.Roles
    $VMRoleName = $VMRole.Name
    If (!($VMRoleName -eq "RootDC")){continue}
    Disable-LabAutoLogon -ComputerName "$VM"
    Restart-LabVM -ComputerName "$VM"
}
#Disable-LabAutoLogon -ComputerName "$SRV01"
#Restart-LabVM -ComputerName "$SRV01"

Write-ScreenInfo -Message 'Removing Windows Defender Exclusions'
Remove-MpPreference -ExclusionProcess code.exe,powershell.exe,powershell_ise.exe

Show-LabDeploymentSummary
