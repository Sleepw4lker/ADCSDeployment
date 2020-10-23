function Get-SanitizedFileName {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        $FileName
    )

    $FileName = $FileName.Replace(" ","-")
    $FileName = $FileName.Replace(".","")

    return $FileName
}