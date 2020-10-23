function Get-AdcsCaSetupStatus {

    [CmdletBinding()]
    param()

    begin {
        New-Variable -Name RegistryRoot -Value "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" -Option Constant
    }

    process {


        Try {
            $SetupStatus = (Get-ItemProperty -Path $RegistryRoot\$(Get-AdcsActiveCaName) -Name SetupStatus -ErrorAction Stop).SetupStatus
            return [Int]$SetupStatus
        }
        Catch {
            Write-Warning "No Certification Authority installed?"
            return
        }

    }

}