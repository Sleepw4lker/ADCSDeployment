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
    -DnSuffix "O=ADCS Labor" ` # the DN Suffix should be specified, otherwise the one from the Domain is taken
    -CaPolFile "$($Script:BaseDirectory)\Samples\capolicy_SubCA_ECC.inf"