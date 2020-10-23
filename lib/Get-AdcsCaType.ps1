function Get-AdcsCaType {

    [CmdletBinding()]
    param()

    begin {
        New-Variable -Name RegistryRoot -Value "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" -Option Constant
    }

    process {


        Try {
            $CaType = (Get-ItemProperty -Path $RegistryRoot\$(Get-AdcsActiveCaName) -Name CaType -ErrorAction Stop).CaType
            return [Int]$CaType
        }
        Catch {
            Write-Warning "No Certification Authority installed?"
            return
        }

    }

}