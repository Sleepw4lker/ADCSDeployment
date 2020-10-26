Function Test-AdcsServiceAvailability {

    [cmdletbinding()]
    param()

    begin {
        # https://docs.microsoft.com/en-us/windows/desktop/api/certcli/nf-certcli-icertconfig-getconfig
        New-Variable -Option Constant -Name CC_LOCALCONFIG -Value 0x00000003

        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/87135fdf-d681-4de0-9953-a0399b6902ee
        New-Variable -Option Constant -Name CR_PROP_CANAME -Value 0x00000006

        # https://docs.microsoft.com/en-us/windows/win32/api/certcli/nf-certcli-icertrequest2-getfullresponseproperty
        New-Variable -Option Constant -Name PROPTYPE_STRING -Value 4
    }

    process {

        Try {
            # We determine the Config String of the locally installed CA
            # https://docs.microsoft.com/en-us/windows/desktop/api/certcli/nf-certcli-icertconfig-getconfig
            $CertConfig = New-Object -ComObject CertificateAuthority.Config
            $ConfigString = $CertConfig.GetConfig($CC_LOCALCONFIG)

            # Then we build the ICertAdmin2 Interface
            $CertAdmin = New-Object -ComObject CertificateAuthority.Admin.1
        }
        Catch  {
            Return $False
        }

        
        Try {
            # Then we try to query the CA Name over the ICertAdmin2 Interface
            # https://docs.microsoft.com/en-us/windows/win32/api/certadm/nn-certadm-icertadmin2#
            $PropIndex = 0
            $Flags = 0
            [void]($CertAdmin.GetCAProperty(
                $ConfigString,
                $CR_PROP_CANAME,
                $PropIndex,
                $PROPTYPE_STRING,
                $Flags)
            )
            Return $True
        }
        Catch {
            Return $False
        }

    }

}