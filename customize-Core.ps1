param(
    $EPMEXEFileName = "Ivanti2022_3q1jmhy5.exe",
    $VSCodeFileName = "VSCodeSetup-x64-1.74.2.exe",
    [switch]$Debug
)
If ($Debug){
    $TestLabSecPwd = "Pa55word"
    $TestLabSecUser = "maxxys\Administrator"
}
Write-ScreenInfo -Message "Starting Actions for $SRV01"

#Prepare AD Credentials
$secpasswd = ConvertTo-SecureString $TestLabSecPwd -AsPlainText -Force
$secuser = $TestLabSecUser
$creds = New-Object System.Management.Automation.PSCredential ($secuser, $secpasswd)

#Populate local Administrators
Write-ScreenInfo -Message "Populate local Admins at $SRV01" -TaskStart
Invoke-LabCommand -ActivityName "Add locAdmin to Administrators" -ComputerName $SRV01 -ScriptBlock {
    Add-LocalGroupMember -Group "Administrators" -Member "maxxys\locAdmin"
} -Credential $creds

#Copy files
Write-ScreenInfo -Message "Copying files to $SRV01" -TaskStart
Write-ProgressIndicator
Copy-LabFileItem -Path $labsources\SoftwarePackages\$EPMEXEFileName -ComputerName $SRV01 -DestinationFolderPath C:\PostInstall
Copy-LabFileItem -Path $labsources\SoftwarePackages\$VSCodeFileName -ComputerName $SRV01 -DestinationFolderPath C:\PostInstall
Write-ProgressIndicatorEnd
Write-ScreenInfo -Message 'File copy finished' -TaskEnd

#Extract EPM Installer
Invoke-LabCommand -ActivityName "Extract EPM files" -ComputerName $SRV01 -ScriptBlock {
    Start-Process -FilePath "C:\Postinstall\$EPMEXEFileName" -ArgumentList "/s"
    $ProcessName = $EPMEXEFileName.Split(".")[0]
    $ProcessRunning = $true
    while ($ProcessRunning) {
        Start-Sleep -Seconds 5
        If (!(Get-Process -Name $ProcessName)){
            $ProcessRunning = $false
            Stop-Process -Name setup
        }
    }
} -Credential $creds -Variable (Get-Variable -Name EPMEXEFileName)

#Run EPM Installer
$InstallerPath = Join-Path "C:" -ChildPath $EPMEXEFileName.Split("_")[0]
Install-LabSoftwarePackage -ComputerName $SRV01 -LocalPath "$InstallerPath\setup.exe" -CommandLine "/s Feature=Core" -Timeout 90

#Add additional Network for Internet Access
$AddSwitch = $true
$VMSwitches = @(Get-VMNetworkAdapter -VMName $SRV01 )
foreach ($VMSwitch in $VMSwitches){
    If ($VMSwitch.SwitchName -eq "Default Switch"){
        $AddSwitch = $false
    }
}

If ($AddSwitch){
    Add-VMNetworkAdapter -VMName $SRV01 -SwitchName "Default Switch"
}
