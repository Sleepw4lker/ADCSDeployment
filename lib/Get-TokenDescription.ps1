Function Get-TokenDescription {

    # Replaces Tokens with a meaningful name
    # This is just for convenience to get a better readable Log

    param (
        [Parameter(Mandatory=$True)]
        [string]
        $String
    )

    # Two-Digit Numbers before one-digit numbers!
    $String = $($String.Replace("%10","<CDPObjectClass>"))
    $String = $($String.Replace("%11","<CAObjectClass>"))

    $String = $($String.Replace("%1","<ServerDNSName>"))
    $String = $($String.Replace("%2","<ServerShortName>"))
    $String = $($String.Replace("%3","<CAName>"))
    $String = $($String.Replace("%4","<CertificateName>"))
    $String = $($String.Replace("%6","<ConfigurationContainer>"))
    $String = $($String.Replace("%7","<CATruncatedName>"))
    $String = $($String.Replace("%8","<CRLNameSuffix>"))
    $String = $($String.Replace("%9","<DeltaCRLAllowed>"))

    return $String
}