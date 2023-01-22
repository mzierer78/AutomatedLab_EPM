Write-ScreenInfo -Message "Starting Actions for $DC"

#Prepare AD Credentials
Send-ALNotification -Activity "Actions for $DC" -Message "Prepare AD Credentials" -Provider Toast
$secpasswd = ConvertTo-SecureString $TestLabSecPwd -AsPlainText -Force
$secuser = $TestLabSecUser
$creds = New-Object System.Management.Automation.PSCredential ($secuser, $secpasswd)

#Prepare AD Domain Name
Send-ALNotification -Activity "Actions for $DC" -Message "Prepare AD Domain Name" -Provider Toast
$TestLabDomainName = $TestLabDomain.Split(".")[0]

#region Create AD OU's
Write-ScreenInfo -Message "start creating default OU's"
$DefaultLabName = 'maxxys'
Invoke-LabCommand -ActivityName "Add OU $DefaultLabName" -ComputerName $DC -ScriptBlock {
    New-ADOrganizationalUnit -Name "$DefaultLabName" -Path "DC=$TestLabDomainName,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds -Variable (Get-Variable -Name DefaultLabName),(Get-Variable -Name TestLabDomainName)

$DefaultLabOUName = 'Accounts'
Invoke-LabCommand -ActivityName "Add OU $DefaultLabOUName" -ComputerName $DC -ScriptBlock {
    New-ADOrganizationalUnit -Name $DefaultLabOUName -Path "OU=$DefaultLabName,DC=$TestLabDomainName,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds -Variable (Get-Variable -Name DefaultLabOUName),(Get-Variable -Name DefaultLabName),(Get-Variable -Name TestLabDomainName)
Remove-Variable -Name DefaultLabOUName

$DefaultLabOUName = 'Groups'
Invoke-LabCommand -ActivityName "Add OU $DefaultLabOUName" -ComputerName $DC -ScriptBlock {
    New-ADOrganizationalUnit -Name $DefaultLabOUName -Path "OU=$DefaultLabName,DC=$TestLabDomainName,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds -Variable (Get-Variable -Name DefaultLabOUName),(Get-Variable -Name DefaultLabName),(Get-Variable -Name TestLabDomainName)
Remove-Variable -Name DefaultLabOUName

$DefaultLabOUName = 'Admins'
Invoke-LabCommand -ActivityName "Add OU $DefaultLabOUName" -ComputerName $DC -ScriptBlock {
    New-ADOrganizationalUnit -Name $DefaultLabOUName -Path "OU=$DefaultLabName,DC=$TestLabDomainName,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds -Variable (Get-Variable -Name DefaultLabOUName),(Get-Variable -Name DefaultLabName),(Get-Variable -Name TestLabDomainName)
Remove-Variable -Name DefaultLabOUName

Write-ScreenInfo -Message "creating default OU's finished"

Write-ScreenInfo -Message "start creating Lab OU's"
Invoke-LabCommand -ActivityName "Add OU $TestLabName" -ComputerName $DC -ScriptBlock {
    New-ADOrganizationalUnit -Name $TestLabName -Path "DC=$TestLabDomainName,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds -Variable (Get-Variable -Name TestLabName),(Get-Variable -Name TestLabDomainName)

$TestLabOUName = 'Clients'
Invoke-LabCommand -ActivityName "Add OU $TestLabOUName" -ComputerName $DC -ScriptBlock {
    New-ADOrganizationalUnit -Name $TestLabOUName -Path "OU=$TestLabName,DC=$TestLabDomainName,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds -Variable (Get-Variable -Name TestLabOUName),(Get-Variable -Name TestLabName),(Get-Variable -Name TestLabDomainName)
Remove-Variable -Name TestLabOUName

$TestLabOUName = 'Server'
Invoke-LabCommand -ActivityName "Add OU $TestLabOUName" -ComputerName $DC -ScriptBlock {
    New-ADOrganizationalUnit -Name $TestLabOUName -Path "OU=$TestLabName,DC=$TestLabDomainName,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds -Variable (Get-Variable -Name TestLabOUName),(Get-Variable -Name TestLabName),(Get-Variable -Name TestLabDomainName)
Remove-Variable -Name TestLabOUName
#endregion

#region Move Computers to OU's
Write-Screeninfo -Message "start moving Computers"

#$Identity = "CN=$PC01,CN=Computers,DC=$TestLabDomainName,DC=local"
#$TargetPath = "OU=TS,OU=$TestLabName,DC=$TestLabDomainName,DC=local"
#Invoke-LabCommand -ActivityName "Move $Identity to $TargetPath" -ComputerName $DC -ScriptBlock {
#    Move-ADObject -Identity $Identity -TargetPath $TargetPath
#} -Credential $creds -Variable (Get-Variable -Name Identity),(Get-Variable -Name TargetPath)
#Remove-Variable -Name Identity
#Remove-Variable -Name TargetPath

Write-ScreenInfo -Message "end moving computers"
#endregion

#region create additional users
Write-ScreenInfo -Message "start creating Users"

$Pwd = 'Pa55word'
$User = 'domAdmin'
Invoke-LabCommand -ActivityName "CreateUser $User" -ComputerName $DC -ScriptBlock {
    Import-Module ActiveDirectory
    $secpwd = ConvertTo-SecureString $Pwd -AsPlainText -Force
    New-ADUser -Name $User -AccountPassword $secpwd -Enabled $true -ChangePasswordAtLogon $false
} -Credential $creds -Variable (Get-Variable -Name User),(Get-Variable -Name Pwd)
Remove-Variable -Name User

$User = 'locAdmin'
Invoke-LabCommand -ActivityName "CreateUser $User" -ComputerName $DC -ScriptBlock {
    Import-Module ActiveDirectory
    $secpwd = ConvertTo-SecureString $Pwd -AsPlainText -Force
    New-ADUser -Name $User -AccountPassword $secpwd -Enabled $true -ChangePasswordAtLogon $false
} -Credential $creds -Variable (Get-Variable -Name User),(Get-Variable -Name Pwd)
Remove-Variable -Name User

$User = 'sqlAdmin'
Invoke-LabCommand -ActivityName "CreateUser $User" -ComputerName $DC -ScriptBlock {
    Import-Module ActiveDirectory
    $secpwd = ConvertTo-SecureString $Pwd -AsPlainText -Force
    New-ADUser -Name $User -AccountPassword $secpwd -Enabled $true -ChangePasswordAtLogon $false
} -Credential $creds -Variable (Get-Variable -Name User),(Get-Variable -Name Pwd)
Remove-Variable -Name User

$User = 'user1'
Invoke-LabCommand -ActivityName "CreateUser $User" -ComputerName $DC -ScriptBlock {
    Import-Module ActiveDirectory
    $secpwd = ConvertTo-SecureString $Pwd -AsPlainText -Force
    New-ADUser -Name $User -AccountPassword $secpwd -Enabled $true -ChangePasswordAtLogon $false
} -Credential $creds -Variable (Get-Variable -Name User),(Get-Variable -Name Pwd)
Remove-Variable -Name User

$User = 'user2'
Invoke-LabCommand -ActivityName "CreateUser $User" -ComputerName $DC -ScriptBlock {
    Import-Module ActiveDirectory
    $secpwd = ConvertTo-SecureString $Pwd -AsPlainText -Force
    New-ADUser -Name $User -AccountPassword $secpwd -Enabled $true -ChangePasswordAtLogon $false
} -Credential $creds -Variable (Get-Variable -Name User),(Get-Variable -Name Pwd)
Remove-Variable -Name User

Write-ScreenInfo -Message "end creating Users"
#endregion

#region Move Users to OU's
Write-Screeninfo -Message "start moving default Users"

$Identity = "CN=domAdmin,CN=Users,DC=$TestLabDomainName,DC=local"
$TargetPath = "OU=Admins,OU=maxxys,DC=$TestLabDomainName,DC=local"
Invoke-LabCommand -ActivityName "Move $Identity to $TargetPath" -ComputerName $DC -ScriptBlock {
    Move-ADObject -Identity $Identity -TargetPath $TargetPath
} -Credential $creds -Variable (Get-Variable -Name Identity),(Get-Variable -Name TargetPath)
Remove-Variable -Name Identity
Remove-Variable -Name TargetPath

$Identity = "CN=locAdmin,CN=Users,DC=$TestLabDomainName,DC=local"
$TargetPath = "OU=Admins,OU=maxxys,DC=$TestLabDomainName,DC=local"
Invoke-LabCommand -ActivityName "Move $Identity to $TargetPath" -ComputerName $DC -ScriptBlock {
    Move-ADObject -Identity $Identity -TargetPath $TargetPath
} -Credential $creds -Variable (Get-Variable -Name Identity),(Get-Variable -Name TargetPath)
Remove-Variable -Name Identity
Remove-Variable -Name TargetPath

$Identity = "CN=sqlAdmin,CN=Users,DC=$TestLabDomainName,DC=local"
$TargetPath = "OU=Admins,OU=maxxys,DC=$TestLabDomainName,DC=local"
Invoke-LabCommand -ActivityName "Move $Identity to $TargetPath" -ComputerName $DC -ScriptBlock {
    Move-ADObject -Identity $Identity -TargetPath $TargetPath
} -Credential $creds -Variable (Get-Variable -Name Identity),(Get-Variable -Name TargetPath)
Remove-Variable -Name Identity
Remove-Variable -Name TargetPath

$Identity = "CN=user1,CN=Users,DC=$TestLabDomainName,DC=local"
$TargetPath = "OU=Accounts,OU=maxxys,DC=$TestLabDomainName,DC=local"
Invoke-LabCommand -ActivityName "Move $Identity to $TargetPath" -ComputerName $DC -ScriptBlock {
    Move-ADObject -Identity $Identity -TargetPath $TargetPath
} -Credential $creds -Variable (Get-Variable -Name Identity),(Get-Variable -Name TargetPath)
Remove-Variable -Name Identity
Remove-Variable -Name TargetPath

$Identity = "CN=user2,CN=Users,DC=$TestLabDomainName,DC=local"
$TargetPath = "OU=Accounts,OU=maxxys,DC=$TestLabDomainName,DC=local"
Invoke-LabCommand -ActivityName "Move $Identity to $TargetPath" -ComputerName $DC -ScriptBlock {
    Move-ADObject -Identity $Identity -TargetPath $TargetPath
} -Credential $creds -Variable (Get-Variable -Name Identity),(Get-Variable -Name TargetPath)
Remove-Variable -Name Identity
Remove-Variable -Name TargetPath

#endregion

#region Create AD Groups
Write-ScreenInfo -Message "start creating AD Groups"
#Create AD Groups
$Name = "Local-Admins"
$Identity = "CN=$Name,OU=Groups,OU=maxxys,DC=$TestLabDomainName,DC=local"
$TargetPath = "OU=Groups,OU=maxxys,DC=$TestLabDomainName,DC=local"
Invoke-LabCommand -ActivityName "Create Group Local Admins" -ComputerName $DC -ScriptBlock {
    New-ADObject -Name $Name -Type Group -Path $TargetPath
    Set-ADGroup -Identity $Identity -SAMAccountName $Name
} -Credential $creds -Variable (Get-Variable -Name TargetPath),(Get-Variable -Name Identity),(Get-Variable -Name Name)
Remove-Variable -Name Name
Remove-Variable -Name Identity
Remove-Variable -Name TargetPath

Write-ScreenInfo -Message "end creating AD Groups"
#endregion

#region Maintain Group Membership
$User = "domAdmin"
$Group = "CN=Domain Admins,CN=Users,DC=$TestLabDomainName,DC=LOCAL"
Invoke-LabCommand -ActivityName "Add User $User to Group $Group" -ComputerName $DC -ScriptBlock {
    Add-ADGroupMember -Identity $Group -Members $User
} -Credential $creds -Variable (Get-Variable -Name User),(Get-Variable -Name Group)
Remove-Variable -Name User
Remove-Variable -Name Group

$User = "locAdmin"
$Group = "CN=Local-Admins,OU=Groups,OU=maxxys,DC=$TestLabDomainName,DC=LOCAL"
Invoke-LabCommand -ActivityName "Add User $User to Group $Group" -ComputerName $DC -ScriptBlock {
    Add-ADGroupMember -Identity $Group -Members $User
} -Credential $creds -Variable (Get-Variable -Name User),(Get-Variable -Name Group)
Remove-Variable -Name User
Remove-Variable -Name Group
#endregion

#region Enable DHCP Server
Invoke-LabCommand -ActivityName "Enable DHCP Server" -ComputerName $DC -ScriptBlock {
    Install-WindowsFeature DHCP -IncludeManagementTools -IncludeAllSubFeature | Out-Null
} -Credential $creds

Invoke-LabCommand -ActivityName "Configure DHCP Scope" -ComputerName $DC -ScriptBlock {
    Import-Module DHCPServer
    Add-DhcpServerv4Scope -Name 'Default Scope' -StartRange $TestLabDHCPScopeStart -EndRange $TestLabDHCPScopeEnd -SubnetMask $TestLabDHCPScopeMask -Description 'Default Scope for DHCP'
    Set-DhcpServerv4OptionValue -ScopeId $TestLabDHCPScope -OptionId 006 -Value $TestLabDHCPScopeDNSSRV
} -Credential $creds -Variable ((Get-Variable -Name TestLabDHCPScopeStart),(Get-Variable -Name TestlabDHCPScopeEnd),(Get-Variable -Name TestLabDHCPScopeMask),(Get-Variable -Name TestLabDHCPScope),(Get-Variable -Name TestLabDHCPScopeDNSSRV))

Invoke-LabCommand -ActivityName "Configure DNS Credentials" -ComputerName $DC -ScriptBlock {
    netsh dhcp server set dnscredentials Administrator learn.local $TestLabSecPwd
} -Credential $creds -Variable (Get-Variable -Name TestLabSecPwd)

$DomainSuffix = "." + $TestLabDomainName + ".local"
Invoke-LabCommand -ActivityName "Authorize DHCP Server" -ComputerName $DC -ScriptBlock {
    $DNSServer = $DC + $DomainSuffix
    Add-DHCPServerinDC -DnsName $DNSServer
} -Credential $creds -Variable (Get-Variable -Name DC),(Get-Variable -Name DomainSuffix)
#endregion

Send-ALNotification -Activity "Actions for $DC" -Message "All actions for $DC done" -Provider Toast