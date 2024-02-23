#Requires -Modules @{ ModuleName="ServerManager"; ModuleVersion="2.0.0.0" }

#TODO: Prevent usage on PowerShell Core
#TODO: (Add ability to) Remove SMIME Capabilities
#TODO: Tell user where the CSR file is to be found
#TODO: Restart CA Service for Root CAs (Sub CAs end in stopped state anyway)
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

        # Specific to Enterprise CAs

        [Parameter(ParameterSetName = "EnterpriseRootCA", Mandatory=$False)]
        [Parameter(ParameterSetName = "EnterpriseSubordinateCA", Mandatory=$False)]
        [Switch]
        $AllowRenewalOnBehalfOf,

        # Specific to Standalone CAs

        [Parameter(ParameterSetName = "StandaloneRootCA", Mandatory=$False)]
        [Parameter(ParameterSetName = "StandaloneSubordinateCA", Mandatory=$False)]
        [String]
        $DsConfigDn,

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
        [ValidateSet(
            "Microsoft Software Key Storage Provider",
            "Utimaco CryptoServer Key Storage Provider",
            "nCipher Security World Key Storage Provider",
            "SafeNet Key Storage Provider",
            "Cavium Key Storage Provider"
        )]
        [ValidateScript({Test-KspAvailability -Name $_})]
        [String]
        $EncryptionCsp = "Microsoft Software Key Storage Provider",

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
        $HashAlgorithm = "SHA256",

        [Parameter(Mandatory=$False)]
        [Switch]
        $KeepProprietaryExtensions, # We will remove Microsoft Specific Certificate Extensions by default

        [Parameter(Mandatory=$False)]
        [Switch]
        $LegacyProfile, # We will conform to Common PKI Profile by default

        [Parameter(Mandatory=$True)]
        [String[]]
        $Cdp,

        [Parameter(Mandatory=$True)]
        [String[]]
        $Aia,

        [Parameter(Mandatory=$False)]
        [ValidateRange(1,999)]
        [Int]
        $CrlPeriodUnits = 7,

        [Parameter(Mandatory=$False)]
        [ValidateSet("Minutes","Hours","Days","Weeks","Months","Years")]
        [String]
        $CrlPeriod = "Days",

        [Parameter(Mandatory=$False)]
        [ValidateRange(0,999)]
        [String]
        $CrlOverlapUnits = 0,

        [Parameter(Mandatory=$False)]
        [ValidateSet("Minutes","Hours","Days","Weeks","Months","Years")]
        [String]
        $CrlOverlapPeriod = "Days",

        [Parameter(Mandatory=$False)]
        [ValidateRange(0,999)]
        [Int]
        $CrlDeltaPeriodUnits = 0, 

        [Parameter(Mandatory=$False)]
        [ValidateSet("Minutes","Hours","Days","Weeks","Months","Years")]
        [String]
        $CrlDeltaPeriod = "Days", 

        [Parameter(Mandatory=$False)]
        [ValidateRange(0,999)]
        [Int]
        $CrlDeltaOverlapUnits = 0, 

        [Parameter(Mandatory=$False)]
        [ValidateSet("Minutes","Hours","Days","Weeks","Months","Years")]
        [String]
        $CrlDeltaOverlapPeriod = "Days",

        [Parameter(Mandatory=$False)]
        [ValidateRange(0,127)]
        [String]
        $AuditFilter = 127,

        [Parameter(Mandatory=$False)]
        [ValidateRange(0,10)]
        [Int]
        $CaPathLength,

        [Parameter(Mandatory=$False)]
        [ValidateRange(0,5)]
        [Int]
        $LogLevel = 3,

        [Parameter(Mandatory=$False)]
        [ValidateRange(0,365)]
        [Int]
        $ValidityPeriodUnits = 2,

        [Parameter(Mandatory=$False)]
        [ValidateSet("Minutes","Hours","Days","Weeks","Months","Years")]
        [String]
        $ValidityPeriod = "Years",

        [Parameter(Mandatory=$False)]
        [Switch]
        $NoEnforceX500NameLengths # We will not allow Subject Strings longer than 64 Characters by default, as this violates Common PKI
    )

    begin {
        New-Variable -Option Constant -Name BUILD_NUMBER_WINDOWS_2016 -Value 14393

        New-Variable -Option Constant -Name CA_SERVICE_STOP_WAIT_SECONDS -Value 30
        New-Variable -Option Constant -Name CA_SERVICE_START_WAIT_SECONDS -Value 10

        New-Variable -Option Constant -Name DIRECTORY_CERTENROLL -Value "$($env:systemroot)\System32\CertSrv\CertEnroll"

        New-Variable -Option Constant -Name ENUM_ENTERPRISE_ROOTCA -Value 0
        New-Variable -Option Constant -Name ENUM_ENTERPRISE_SUBCA -Value 1
        New-Variable -Option Constant -Name ENUM_STANDALONE_ROOTCA -Value 3
        New-Variable -Option Constant -Name ENUM_STANDALONE_SUBCA -Value 4

        New-Variable -Option Constant -Name szOID_ENROLL_CERTTYPE_EXTENSION -Value "1.3.6.1.4.1.311.20.2"
        New-Variable -Option Constant -Name szOID_CERTSRV_CA_VERSION -Value "1.3.6.1.4.1.311.21.1"
        New-Variable -Option Constant -Name szOID_CERTSRV_PREVIOUS_CERT_HASH -Value "1.3.6.1.4.1.311.21.2"
        New-Variable -Option Constant -Name szOID_APPLICATION_CERT_POLICIES -Value "1.3.6.1.4.1.311.21.10"

        If ($StandaloneRootCA.IsPresent) { $CaType = $ENUM_STANDALONE_ROOTCA }
        If ($EnterpriseRootCA.IsPresent) { $CaType = $ENUM_ENTERPRISE_ROOTCA }
        If ($StandaloneSubordinateCA.IsPresent) { $CaType = $ENUM_STANDALONE_SUBCA }
        If ($EnterpriseSubordinateCA.IsPresent) { $CaType = $ENUM_ENTERPRISE_SUBCA }
    }

    process {

        # Ensuring the Script will be run on a supported Operating System
        If ([int](Get-WmiObject -Class Win32_OperatingSystem).BuildNumber -lt $BUILD_NUMBER_WINDOWS_2016) {
            Write-Error -Message "This must be run on Windows Server 2016 or newer! Aborting."
            Return 
        }

        # Ensuring the Script will be run with Elevation
        If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Error -Message "This must be run as Administrator! Aborting."
            Return
        }

        # Time Zone is important especially on a Standalone CA. Otherwise we mess up our issued Certificates.
        # For an Enterprise CA, we assume that there is working time synchronization.
        If (-not (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -and (Get-TimeZone).Id -ne $DesiredTimeZone) {
            Write-Error "System Time Zone is not $DesiredTimeZone!"
            Return
        }

        # Checking if Interactive Services Detection is enabled. If not, we must reboot after setting it.
        If (($AllowAdminInteraction.IsPresent) -and (((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Windows" -Name NoInteractiveServices -ErrorAction SilentlyContinue).NoInteractiveServices) -ne 0)) {

            # Setting the correct value for Interactive Services Detection
            Write-Warning -Message "Enabling Interactive Services Detection. This requires rebooting the machine before continuing."
            Write-Warning -Message "Run the Script again after the Reboot."

            [Microsoft.Win32.Registry]::SetValue(
                "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Windows",
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
            CACommonName = $CaName
            DatabaseDirectory = $CaDbDir
            LogDirectory = $CaDbLogDir
            HashAlgorithm = $HashAlgorithm
            CryptoProviderName = "$($KeyAlgorithm)#$($KspName)"
            OverwriteExistingKey = $True
            OverwriteExistingDatabase = $True
            Force = $True
        }

        Switch ($CaType) {

            $ENUM_STANDALONE_ROOTCA { $Arguments.Add("CAType", "StandaloneRootCA") }
            $ENUM_ENTERPRISE_ROOTCA { $Arguments.Add("CAType", "EnterpriseRootCA") }
            $ENUM_STANDALONE_SUBCA  { $Arguments.Add("CAType", "StandaloneSubordinateCA") }
            $ENUM_ENTERPRISE_SUBCA  { $Arguments.Add("CAType", "EnterpriseSubordinateCA") }
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

        If (($CaType -eq $ENUM_STANDALONE_ROOTCA) -or ($CaType -eq $ENUM_ENTERPRISE_ROOTCA)) {
            $Arguments.Add("ValidityPeriod", $CaCertValidityPeriod)
            $Arguments.Add("ValidityPeriodUnits", $CaCertValidityPeriodUnits)
        }

        If (($CaType -eq $ENUM_STANDALONE_SUBCA) -or ($CaType -eq $ENUM_ENTERPRISE_SUBCA)) {
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

        # Steps specific for Enterprise CAs
        If (($CaType -eq $ENUM_ENTERPRISE_ROOTCA) -or ($CaType -eq $ENUM_ENTERPRISE_SUBCA)) {

            # To set the policy configuration to enable audit of template events, run the following command:
            # From <https://technet.microsoft.com/en-us/library/dn786432(v=ws.11).aspx> 
            certutil -setreg policy\EditFlags +EDITF_AUDITCERTTEMPLATELOAD

            # Allow Renewal on Behalf of, which is required for Key-based Renewal
            If ($AllowRenewalOnBehalfOf.IsPresent) {
                certutil -setreg policy\EditFlags +EDITF_ENABLERENEWONBEHALFOF
            }
        }

        # Steps specific for Standalone CAs
        If (($CaType -eq $ENUM_STANDALONE_ROOTCA) -or ($CaType -eq $ENUM_STANDALONE_SUBCA)) {

            # Settings required to issue Certificates compliant to BSI requirements
            If (-not $LegacyProfile.IsPresent) {

                # Remove Digital Signature from the Key Usage Extension
                # Make the Key Usage Extension Critical
                certutil -setreg policy\EditFlags -EDITF_ADDOLDKEYUSAGE
            }

            # Remove Microsoft specific Extensions from issued Certificates
            If (-not $KeepProprietaryExtensions.IsPresent) {

                certutil -setreg policy\DisableExtensionList +$szOID_ENROLL_CERTTYPE_EXTENSION
            }
        }

        # Remove Microsoft specific Extensions from issued Certificates
        If (-not $KeepProprietaryExtensions.IsPresent) {

            certutil -setreg policy\DisableExtensionList +$szOID_CERTSRV_CA_VERSION
            certutil -setreg policy\DisableExtensionList +$szOID_CERTSRV_PREVIOUS_CERT_HASH
            certutil -setreg policy\DisableExtensionList +$szOID_APPLICATION_CERT_POLICIES
        }

        # Apply Path Length Constraint
        If ($CaPathLength) {
            certutil -setreg Policy\CAPathLength $CaPathLength
        }

        If ($DsConfigDn) {
            certutil -setreg CA\DSConfigDN $DsConfigDn
        }

        If ($NoEnforceX500NameLengths.IsPresent) {
            certutil -setreg CA\EnforceX500NameLengths 0
        }

        certutil -setreg CA\Loglevel $LogLevel
        certutil -setreg CA\CRLPeriodUnits $CrlPeriodUnits 
        certutil -setreg CA\CRLPeriod $CrlPeriod  
        certutil -setreg CA\CRLDeltaPeriodUnits $CrlDeltaPeriodUnits 
        certutil -setreg CA\CRLDeltaPeriod $CrlDeltaPeriod 
        certutil -setreg CA\CRLOverlapUnits $CrlOverlapUnits
        certutil -setreg CA\CRLOverlapPeriod $CrlOverlapPeriod
        certutil -setreg CA\CRLDeltaOverlapUnits $CrlDeltaOverlapUnits  
        certutil -setreg CA\CRLDeltaOverlapPeriod $CrlDeltaOverlapPeriod  
        certutil -setreg CA\ValidityPeriodUnits $ValidityPeriodUnits  
        certutil -setreg CA\ValidityPeriod $ValidityPeriod
        certutil -setreg CA\EncryptionCSP\Provider $EncryptionCsp

        # Enable Auditing at the CA Level
        certutil -setreg CA\Auditfilter $AuditFilter

        # Enable Auditing at the OS Level
        If ($AuditFilter -gt 0) {
            Write-Warning -Message "Configuring local Audit Policy to enable Object Access Auditing for Certification Services. You should enforce this setting via a Group Policy!"
            auditpol /set /subcategory:"{0CCE9221-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
        }

        # Clear the existing AIA Configuration, leaving only the default local Path
        Get-CaAuthorityInformationAccess | Where-Object  { 
            -not ($_.Uri -match ($DIRECTORY_CERTENROLL).Replace("\","\\")) 
        } | Foreach-Object -Process {
            Write-Verbose "Removing Default AIA $($_.Uri)"
            [void](Remove-CaAuthorityInformationAccess $_.Uri -Force)
        }

        ForEach ($Uri in $Aia) {

            $Arguments = @{
                Force = $True
                Uri = $Uri.Trim()
            }

            # Web Urls
            If ($Uri.StartsWith("http://")) {

                If ($Uri.EndsWith("/ocsp")) {

                    # Allow requesting Certificates with an AKI Extension (for OCSP Response Signing Certificates)
                    # https://technet.microsoft.com/en-us/library/cc754774(v=ws.11).aspx
                    certutil -setreg CA\UseDefinedCACertInRequest 1

                    $Arguments.Add("AddToCertificateOcsp", $True)    
                }
                Else {
                    $Arguments.Add("AddToCertificateAia", $True)
                }
            }

            # LDAP Paths
            If ($Uri.StartsWith("ldap://")) {
                $Arguments.Add("AddToCertificateAia", $True)
            }
            
            [void](Add-CaAuthorityInformationAccess @Arguments)
        }

        # Clear the existing CDP Configuration, leaving only the default local Path
        Get-CaCrlDistributionPoint | Where-Object  { 
            -not ($_.Uri -match ($DIRECTORY_CERTENROLL).Replace("\","\\")) 
        } | Foreach-Object -Process {
            Write-Verbose "Removing Default CDP $($_.Uri)"
            [void](Remove-CaCrlDistributionPoint $_.Uri -Force)
        } 

        ForEach ($Uri in $Cdp) {

            $Arguments = @{
                Force = $True
                Uri = $Uri.Trim()
            }

            # Web Urls
            If ($Uri.StartsWith("http://")) {
                $Arguments.Add("AddToCertificateCdp", $True)
                $Arguments.Add("AddToFreshestCrl", $True)
            }

            # LDAP Paths
            If ($Uri.StartsWith("ldap://")) {
                $Arguments.Add("AddToCertificateCdp", $True)
                $Arguments.Add("AddToCrlCdp", $True)
                $Arguments.Add("AddToFreshestCrl", $True)

                # Steps specific for Enterprise CAs
                If (($CaType -eq $ENUM_ENTERPRISE_ROOTCA) -or ($CaType -eq $ENUM_ENTERPRISE_SUBCA)) {
                    $Arguments.Add("PublishToServer", $True)
                    $Arguments.Add("PublishDeltaToServer", $True)
                }
            }

            # UNC or File System Path
            If ($Uri -match "\\") {
                $Arguments.Add("PublishToServer", $True)
                $Arguments.Add("PublishDeltaToServer", $True)
            }
            
            [void](Add-CaCrlDistributionPoint @Arguments)
        }

        If (($CaType -eq $ENUM_ENTERPRISE_ROOTCA) -or ($CaType -eq $ENUM_STANDALONE_ROOTCA)) {

            # Restart Certificate Services to reflect new Configuration

            Stop-Service -Name CertSvc

            # Implement a delay if not using the default Software KSP
            # Some HSM KSPs need some time to clean up their stuff before the Service can be started again
            If ((Get-AdcsKspName) -ne "Microsoft Software Key Storage Provider") {
                Write-Warning -Message "Waiting $CA_SERVICE_STOP_WAIT_SECONDS Seconds for KSPs to close their Handles..."
                Start-Sleep -Second $CA_SERVICE_STOP_WAIT_SECONDS
            }

            Start-Service -Name CertSvc
        }

        # We assume that there is an Interaction needed with the CA Service when this is enabled
        If ($AllowAdminInteraction.IsPresent) {
            Write-Warning -Message "The Active Directory Certificates Service Startup Type was set to Manual due to required Administrator Interaction Setting."
            Set-Service -Name CertSvc -StartupType Manual
        }

        If (($CaType -eq $ENUM_ENTERPRISE_ROOTCA) -or ($CaType -eq $ENUM_ENTERPRISE_SUBCA)) {

            Write-Warning -Message "It is advised that you reboot the machine after the deployment has finished to reflect its newly-added Domain Group memberships."
        }
    }

    end {}
}