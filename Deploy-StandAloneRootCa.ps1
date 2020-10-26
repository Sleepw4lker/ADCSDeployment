[cmdletbinding()]
param()

$Script:BaseDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

# Loading all Libary Scripts we depend on
Get-ChildItem -Path "$Script:BaseDirectory\lib" -Filter *.ps1 | ForEach-Object {
    . ($_.FullName)
}

New-AdcsCaDeployment `
    -StandAloneRootCA `
    -CaName "ADCS Labor Root CA 1" `
    -CaPolFile "$($Script:BaseDirectory)\Samples\capolicy_RootCA.inf" `
    -CaCertValidityPeriodUnits 16 `

Complete-AdcsCaDeployment `
    -DsConfigDn "CN=Configuration,DC=Fabrikam,DC=com" `
    -Cdp "http://pki.adcslabor.de/CertData/%3%8%9.crl","ldap:///CN=%7%8,CN=%3,CN=cdp,CN=Public Key Services,CN=Services,%6%10" `
    -Aia "http://pki.adcslabor.de/CertData/%3%4.crt","ldap:///CN=%7,CN=aia,CN=Public Key Services,CN=Services,%6%11" `
    -ValidityPeriodUnits 8 `
    -CrlPeriodUnits 6 `
    -CrlPeriod "Weeks" `
    -CrlOverlapUnits 6 `
    -CrlOverlapPeriod "Weeks"