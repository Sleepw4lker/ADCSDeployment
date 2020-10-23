function Get-AdcsKspName {

    [CmdletBinding()]
    param()

    begin {
        New-Variable -Name RegistryRoot -Value "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" -Option Constant
    }

    process {


        Try {
            $Provider = (Get-ItemProperty -Path $RegistryRoot\$(Get-AdcsActiveCaName)\CSP -Name Provider -ErrorAction Stop).Provider
            return [String]$Provider
        }
        Catch {
            Write-Warning "No Certification Authority installed?"
            return
        }

    }

}