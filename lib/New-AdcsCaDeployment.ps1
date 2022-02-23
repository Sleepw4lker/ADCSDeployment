#Requires -Modules @{ ModuleName="ServerManager"; ModuleVersion="2.0.0.0" }
function New-AdcsCaDeployment {

    [cmdletbinding(DefaultParameterSetName = "StandaloneRootCA")]
    param (

        # Determines the CA Type to be installed, and the four different Parameter Sets

        [Parameter(ParameterSetName = "StandaloneRootCA", Mandatory=$True)]
        [Switch]
        $StandaloneRootCA,

        [Parameter(ParameterSetName = "EnterpriseRootCA", Mandatory=$True)]
        [Switch]
        $EnterpriseRootCA,

        [Parameter(ParameterSetName = "StandaloneSubordinateCA", Mandatory=$True)]
        [Switch]
        $StandaloneSubordinateCA,

        [Parameter(ParameterSetName = "EnterpriseSubordinateCA", Mandatory=$True)]
        [Switch]
        $EnterpriseSubordinateCA,

        # Specific to Root CAs

        [Parameter(ParameterSetName = "StandaloneRootCA", Mandatory=$False)]
        [Parameter(ParameterSetName = "EnterpriseRootCA", Mandatory=$False)]
        [ValidateSet("Minutes","Hours","Days","Weeks","Months","Years")]
        [String]
        $CaCertValidityPeriod = "Years",

        [Parameter(ParameterSetName = "StandaloneRootCA", Mandatory=$False)]
        [Parameter(ParameterSetName = "EnterpriseRootCA", Mandatory=$False)]
        [Int]
        $CaCertValidityPeriodUnits = 8,

        [Parameter(ParameterSetName = "StandaloneRootCA", Mandatory=$False)]
        [Parameter(ParameterSetName = "EnterpriseRootCA", Mandatory=$False)]
        [ValidateScript({$_ -in (Get-Timezone -ListAvailable).Id})]
        [String]
        $DesiredTimeZone = "W. Europe Standard Time",

        # Specific to Subordinate CAs
        
        [Parameter(ParameterSetName = "StandaloneSubordinateCA", Mandatory=$False)]
        [Parameter(ParameterSetName = "EnterpriseSubordinateCA", Mandatory=$False)]
        [String]
        $CsrFile = "$($env:SystemDrive)\csr_$($CaName.Replace(" ","_")).req",

        # Generic Parameters that apply to all CA Types

        [Parameter(Mandatory=$True)]
        [String]
        $CaName,

        [Parameter(Mandatory=$False)]
        [String]
        $DnSuffix,

        [Parameter(Mandatory=$True)]
        [ValidateScript({Test-Path -Path $_})]
        [String]
        $CaPolFile,

        [Parameter(Mandatory=$False)]
        [String]
        $CaDbDir = "$($env:systemroot)\System32\CertLog",

        [Parameter(Mandatory=$False)]
        [String]
        $CaDbLogDir = $CaDbDir,

        [Parameter(Mandatory=$False)]
        [ValidateSet(
            "Microsoft Software Key Storage Provider",
            "Utimaco CryptoServer Key Storage Provider",
            "nCipher Security World Key Storage Provider",
            "SafeNet Key Storage Provider",
            "Cavium Key Storage Provider"
        )]
        [ValidateScript({Test-KspAvailability -Name $_})]
        [String]
        $KspName = "Microsoft Software Key Storage Provider",

        [Parameter(Mandatory=$False)]
        [ValidateSet("RSA","ECDSA_P256","ECDSA_P384","ECDSA_P521")]
        [String]
        $KeyAlgorithm = "RSA",

        [Parameter(Mandatory=$False)]
        [ValidateSet(1024,2048,3072,4096)]
        [Int]
        $KeyLength = 4096,

        [Parameter(Mandatory=$False)]
        [Switch]
        $AllowAdminInteraction,

        [Parameter(Mandatory=$False)]
        [ValidateSet("MD5","SHA1","SHA256","SHA384","SHA512")]
        [String]
        $HashAlgorithm = "SHA256"

    )

    begin {
        New-Variable -Option Constant -Name BUILD_NUMBER_WINDOWS_2012 -Value 9200
        New-Variable -Option Constant -Name SETUP_SERVER_FLAG -Value 1

        If ($StandaloneRootCA.IsPresent) { $CaType = "StandaloneRootCA" }
        If ($EnterpriseRootCA.IsPresent) { $CaType = "EnterpriseRootCA" }
        If ($StandaloneSubordinateCA.IsPresent) { $CaType = "StandaloneSubordinateCA" }
        If ($EnterpriseSubordinateCA.IsPresent) { $CaType = "EnterpriseSubordinateCA" }
    }

    process {

        # Ensuring the Script will be run on a supported Operating System
        If ([int32](Get-WmiObject Win32_OperatingSystem).BuildNumber -lt $BUILD_NUMBER_WINDOWS_2012) {
            Write-Error -Message "This must be run on Windows Server 2012 or newer! Aborting."
            Return 
        }

        # Ensuring the Script will be run with Elevation
        If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Error -Message "This must be run as Administrator! Aborting."
            Return
        }

        # Time Zone is important especially on a Standalone CA. Otherwise we mess up our issued Certificates.
        # For an Enterprise CA, we assume that there is working time synchronization.
        If (($CaType -match "Standalone*") -and (Get-TimeZone).Id -ne $DesiredTimeZone) {
            Write-Error "System Time Zone is not $DesiredTimeZone!"
            Return
        }

        # Checking if Interactive Services Detection is enabled. If not, we must reboot after setting it.
        If (($AllowAdminInteraction.IsPresent) -and (((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Windows" -Name NoInteractiveServices -ErrorAction SilentlyContinue).NoInteractiveServices) -ne 0)) {

            # Setting the correct value for Interactive Services Detection
            Write-Warning "Enabling Interactive Services Detection. This requires rebooting the machine before continuing."
            Write-Warning "Run the Script again after the Reboot."

            [Microsoft.Win32.Registry]::SetValue(
                "HKEY_LOCAL_MACHONE\SYSTEM\CurrentControlSet\Control\Windows",
                "NoInteractiveServices",
                0x0,
                [Microsoft.Win32.RegistryValueKind]::DWORD
                )

            Return
        }

        # Placing the capolicy.inf in the Windows Folder
        # We must ensure that the capolicy.inf is stored in Windows-1252 (ANSI) to reflect Umlauts and the like
        [void](Remove-Item -Path "$($env:systemroot)\capolicy.inf" -Force -ErrorAction SilentlyContinue)
        
        [System.IO.File]::WriteAllText(
            "$($env:systemroot)\capolicy.inf",
            (Get-Content -Path $CaPolFile -Encoding UTF8 -Raw),
            [System.Text.Encoding]::GetEncoding('iso-8859-1')
            )

        [void](New-Item -Path $CaDbDir -ItemType Directory -ErrorAction SilentlyContinue)
        [void](New-Item -Path $CaDbLogDir -ItemType Directory -ErrorAction SilentlyContinue)

        $Arguments = @{
            CAType = $CaType
            CACommonName = $CaName
            DatabaseDirectory = $CaDbDir
            LogDirectory = $CaDbLogDir
            HashAlgorithm = $HashAlgorithm
            CryptoProviderName = "$($KeyAlgorithm)#$($KspName)"
            OverwriteExistingKey = $True
            OverwriteExistingDatabase = $True
            Force = $True
        }

        Switch ($KeyAlgorithm) {

            "ECDSA_P256" { $Arguments.Add("KeyLength", 256) }
            "ECDSA_P384" { $Arguments.Add("KeyLength", 384) }
            "ECDSA_P521" { $Arguments.Add("KeyLength", 521) }
            "RSA"        { $Arguments.Add("KeyLength", $KeyLength) }
        }

        If ($DnSuffix) {
            $Arguments.Add("CADistinguishedNameSuffix", $DnSuffix)
        }

        If ($AllowAdminInteraction.IsPresent) {
            $Arguments.Add("AllowAdministratorInteraction", $True)
        }

        If ($CaType -match "RootCA") {
            $Arguments.Add("ValidityPeriod", $CaCertValidityPeriod)
            $Arguments.Add("ValidityPeriodUnits", $CaCertValidityPeriodUnits)
        }

        If ($CaType -match "Subordinate") {
            $Arguments.Add("OutputCertRequestFile", $CsrFile)
        }

        # This Installs and configures the CA Role
        Try {
            [void](Install-WindowsFeature -Name Adcs-Cert-Authority -IncludeManagementTools)
            [void](Install-AdcsCertificationAuthority @Arguments)
        }
        Catch {
            Write-Error -Message $PSItem.Exception.Message
            return
        }

        # We assume that there is an Interaction needed with the CA Service when this is enabled
        If ($AllowAdminInteraction.IsPresent) {
            Write-Warning "The Active Directory Certificates Service Startup Type was set to Manual due to required Administrator Interaction Setting."
            Set-Service -Name CertSvc -StartupType Manual
        }

        If ($CaType -match "Enterprise") {
            Write-Warning "It is advised that you reboot the Machine after the Deployment has finished to reflect its newly-added Domain Group Memberships."
        }

    }

}