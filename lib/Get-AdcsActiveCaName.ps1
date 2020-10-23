function Get-AdcsActiveCaName {

    [CmdletBinding()]
    param()

    begin {
        New-Variable -Name RegistryRoot -Value "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" -Option Constant
    }

    process {

        Try {
            $CaName = (Get-ItemProperty -Path $RegistryRoot -Name Active -ErrorAction Stop).Active
            return $CaName
        }
        Catch {
            Write-Warning "No Certification Authority installed?"
            return
        }

    }
}