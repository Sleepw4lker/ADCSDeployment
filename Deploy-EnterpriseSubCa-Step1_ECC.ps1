[cmdletbinding()]
param()

$Script:BaseDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

# Loading all Libary Scripts we depend on
Get-ChildItem -Path "$Script:BaseDirectory\lib" -Filter *.ps1 | ForEach-Object {
    . ($_.FullName)
}

New-AdcsCaDeployment `
    -EnterpriseSubordinateCA `
    -KeyAlgorithm "ECDSA_P256" `
    -CaName "ADCS Labor Issuing CA NG 1" `
    -DnSuffix "O=ADCS Labor" `
    -CaPolFile "$($Script:BaseDirectory)\Samples\capolicy_SubCA_ECC.inf" `
    -Cdp "http://pki.adcslabor.de/CertData/%3%8%9.crl","ldap:///CN=%7%8,CN=%3,CN=cdp,CN=Public Key Services,CN=Services,%6%10" `
    -Aia "http://pki.adcslabor.de/CertData/%3%4.crt","ldap:///CN=%7,CN=aia,CN=Public Key Services,CN=Services,%6%11","http://ocsp.adcslabor.de/ocsp" `
    -AuditFilter 126 `
    -ValidityPeriodUnits 2 `
    -CrlPeriodUnits 4 `
    -CrlPeriod "Days" `
    -CrlOverlapUnits 4 `
    -CrlOverlapPeriod "Days"