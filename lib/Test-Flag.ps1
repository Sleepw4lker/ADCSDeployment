function Test-Flag {

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $True)]
        [Int]
        $Flags,

        [Parameter(Mandatory = $True)]
        [Int]
        $Flag
    )

    If (($Flags -bAnd $Flag) -eq $Flag) {
        return $True
    }
    Else {
        return $False
    }

}