Write-ScreenInfo -Message "Starting Actions for $PC01"

#Prepare AD Credentials
$secpasswd = ConvertTo-SecureString $TestLabSecPwd -AsPlainText -Force
$secuser = $TestLabSecUser
$creds = New-Object System.Management.Automation.PSCredential ($secuser, $secpasswd)

#region Populate local Administrators
Write-ScreenInfo -Message "Populate local Groups at $PC01" -TaskStart
Invoke-LabCommand -ActivityName "Add locAdmin to Administrators" -ComputerName $PC01 -ScriptBlock {
    Add-LocalGroupMember -Group "Administrators" -Member "maxxys\locAdmin"
} -Credential $creds

Invoke-LabCommand -ActivityName "Add Domain Users to Remote Desktop Users" -ComputerName $PC01 -ScriptBlock {
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member "maxxys\Domain Users"
} -Credential $creds
#endregion