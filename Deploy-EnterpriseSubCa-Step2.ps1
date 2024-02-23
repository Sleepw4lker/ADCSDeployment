[cmdletbinding()]
param()

$Script:BaseDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

# Loading all Libary Scripts we depend on
Get-ChildItem -Path "$Script:BaseDirectory\lib" -Filter *.ps1 | ForEach-Object {
    . ($_.FullName)
}

Complete-AdcsCaDeployment -Certfile ".\certnew.cer"