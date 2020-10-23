Function Test-AdcsServiceAvailability {

    [cmdletbinding()]
    param()

    process {

        # First we try to get the ICertAdmin2 Interface
        Try {
            $CertConfig = New-Object -ComObject CertificateAuthority.Config
            $Config = $CertConfig.GetConfig(0)
            $CertAdmin = New-Object -ComObject CertificateAuthority.Admin.1
        }
        Catch  {
            Return $False
        }

        # Then we try to do a Query over the Interface
        Try {
            [void]($CertAdmin.GetCAProperty($Config,0x6,0,4,0))
            Return $True
        }
        Catch {
            Return $False
        }

    }

}