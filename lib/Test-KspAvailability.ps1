Function Test-KspAvailability {

    param (
        [Parameter(Mandatory=$True)]
        [string]
        $Name
    )

    process {

        $KspList = certutil -csplist
        $KspList | Foreach-Object -Process {
            If ($_ -match $Name) {
                return $True
            }
        }

        Write-Warning "Key Storage Provider $Name not found on this machine!"
        return $False

    }
    
}