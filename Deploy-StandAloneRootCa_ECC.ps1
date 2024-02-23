[cmdletbinding()]
param()

$Script:BaseDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

# Loading all Libary Scripts we depend on
Get-ChildItem -Path "$Script:BaseDirectory\lib" -Filter *.ps1 | ForEach-Object {
    . ($_.FullName)
}

New-AdcsCaDeployment `
    -StandAloneRootCA `
    -CaName "ADCS Labor Root CA NG 1" `
    -KeyAlgorithm "ECDSA_P256" `
    -CaPolFile "$($Script:BaseDirectory)\Samples\capolicy_RootCA_ECC.inf" `
    -CaCertValidityPeriodUnits 16 `
    -Cdp "http://pki.adcslabor.de/CertData/%3%8%9.crl" `
    -Aia "http://pki.adcslabor.de/CertData/%3%4.crt" `
    -ValidityPeriodUnits 8 `
    -CrlPeriodUnits 6 `
    -CrlPeriod "Weeks" `
    -CrlOverlapUnits 6 `
    -CrlOverlapPeriod "Weeks"