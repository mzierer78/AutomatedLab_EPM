Write-ScreenInfo -Message "Starting Actions for $PC02"

#Prepare AD Credentials
$secpasswd = ConvertTo-SecureString $TestLabSecPwd -AsPlainText -Force
$secuser = $TestLabSecUser
$creds = New-Object System.Management.Automation.PSCredential ($secuser, $secpasswd)

#region Populate local Administrators
Write-ScreenInfo -Message "Populate local Groups at $PC02" -TaskStart
Invoke-LabCommand -ActivityName "Add locAdmin to Administrators" -ComputerName $PC02 -ScriptBlock {
    Add-LocalGroupMember -Group "Administrators" -Member "maxxys\locAdmin"
} -Credential $creds

#Invoke-LabCommand -ActivityName "Add Domain Users to Remote Desktop Users" -ComputerName $PC02 -ScriptBlock {
#    Add-LocalGroupMember -Group "Remote Desktop Users" -Member "maxxys\Domain Users"
#} -Credential $creds
#endregion