Send-ALNotification -Activity "Actions for $DC" -Message " " -Provider Toast
Write-ScreenInfo -Message "Starting Actions for $DC"

#Prepare AD Credentials
Send-ALNotification -Activity "Actions for $DC" -Message "Prepare AD Credentials" -Provider Toast
$secpasswd = ConvertTo-SecureString $TestLabSecPwd -AsPlainText -Force
$secuser = $TestLabSecUser
$creds = New-Object System.Management.Automation.PSCredential ($secuser, $secpasswd)

#Prepare AD Domain Name
Send-ALNotification -Activity "Actions for $DC" -Message "Prepare AD Domain Name" -Provider Toast
$TestLabDomainName = $TestLabDomain.Split(".")[0]

#Create AD OU's
Send-ALNotification -Activity "Actions for $DC" -Message "Create AD OU's" -Provider Toast
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

Send-ALNotification -Activity "Actions for $DC" -Message "Create Lab OU's" -Provider Toast
Write-ScreenInfo -Message "start creating Lab OU's"

Invoke-LabCommand -ActivityName "Add OU $TestLabName" -ComputerName $DC -ScriptBlock {
    New-ADOrganizationalUnit -Name $TestLabName -Path "DC=$TestLabDomainName,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds -Variable (Get-Variable -Name TestLabName),(Get-Variable -Name TestLabDomainName)

$TestLabOUName = 'OU1'
Invoke-LabCommand -ActivityName "Add OU $TestLabOUName" -ComputerName $DC -ScriptBlock {
    New-ADOrganizationalUnit -Name $TestLabOUName -Path "OU=$TestLabName,DC=$TestLabDomainName,DC=LOCAL" -ProtectedFromAccidentalDeletion $False
} -Credential $creds -Variable (Get-Variable -Name TestLabOUName),(Get-Variable -Name TestLabName),(Get-Variable -Name TestLabDomainName)
Remove-Variable -Name TestLabOUName


#Move Computers to OU's
Send-ALNotification -Activity "Actions for $DC" -Message "Move Computers" -Provider Toast
Write-Screeninfo -Message "start moving Computers"

#$Identity = "CN=$PC01,CN=Computers,DC=$TestLabDomainName,DC=local"
#$TargetPath = "OU=TS,OU=$TestLabName,DC=$TestLabDomainName,DC=local"
#Invoke-LabCommand -ActivityName "Move $Identity to $TargetPath" -ComputerName $DC -ScriptBlock {
#    Move-ADObject -Identity $Identity -TargetPath $TargetPath
#} -Credential $creds -Variable (Get-Variable -Name Identity),(Get-Variable -Name TargetPath)
#Remove-Variable -Name Identity
#Remove-Variable -Name TargetPath

Write-ScreenInfo -Message "end moving computers"

#create additional users
Send-ALNotification -Activity "Actions for $DC" -Message "Create Users" -Provider Toast
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

Write-ScreenInfo -Message "end creating Users"

#Install software
#Install-LabSoftwarePackage -ComputerName $DC -Path $labSources\Labs\$TestLabName\SoftwarePackages\GoogleChromeStandaloneEnterprise64.msi -CommandLine /qn

Send-ALNotification -Activity "Actions for $DC" -Message "All actions for $DC done" -Provider Toast
