Function Complete-AdcsCaDeployment {

    [CmdletBinding(DefaultParameterSetName="StandaloneRootCA")]
    param(

        [Parameter(Mandatory=$False)]
        [ValidateSet(
            "Microsoft Software Key Storage Provider",
            "Utimaco CryptoServer Key Storage Provider",
            "nCipher Security World Key Storage Provider",
            "SafeNet Luna Key Storage Provider"
        )]
        [ValidateScript({Test-KspAvailability -Name $_})]
        [String]
        $EncryptionCsp = "Microsoft Software Key Storage Provider",

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
        [ValidateRange(1,365)]
        [Int]
        $CrlPeriodUnits = 3,

        [Parameter(Mandatory=$False)]
        [ValidateSet("Minutes","Hours","Days","Weeks","Months","Years")]
        [String]
        $CrlPeriod = "Months",

        [Parameter(Mandatory=$False)]
        [ValidateRange(0,365)]
        [String]
        $CrlOverlapUnits = 3,

        [Parameter(Mandatory=$False)]
        [ValidateSet("Minutes","Hours","Days","Weeks","Months","Years")]
        [String]
        $CrlOverlapPeriod = "Months",

        [Parameter(Mandatory=$False)]
        [ValidateRange(0,365)]
        [Int]
        $CrlDeltaPeriodUnits = 0, 

        [Parameter(Mandatory=$False)]
        [ValidateSet("Minutes","Hours","Days","Weeks","Months","Years")]
        [String]
        $CrlDeltaPeriod = "Days", 

        [Parameter(Mandatory=$False)]
        [ValidateRange(0,365)]
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
        [ValidateRange(0,365)]
        [Int]
        $ValidityPeriodUnits = 2,

        [Parameter(Mandatory=$False)]
        [ValidateSet("Minutes","Hours","Days","Weeks","Months","Years")]
        [String]
        $ValidityPeriod = "Years",

        [Parameter(Mandatory=$False)]
        [Switch]
        $EnforceX500NameLengths, # We will allow Subject Strings longer than 64 Characters by default

        [Parameter(Mandatory=$False)]
        [Switch]
        $KeepProprietaryExtensions, # We will remove Microsoft Specific Certificate Extensions by default

        # Specific to Standalone CAs
        [String]
        $DsConfigDn,

        # Specific to Subordinate CAs
        [ValidateScript({Test-Path -Path $_})]
        [String]
        $CertFile,

        # Specific to Enterprise CAs
        [Switch]
        $AllowRenewalOnBehalfOf
        
    )

    begin {

        New-Variable -Option Constant -Name BUILD_NUMBER_WINDOWS_2012 -Value 9200
        New-Variable -Option Constant -Name CA_SERVICE_STOP_WAIT_SECONDS -Value 30
        New-Variable -Option Constant -Name CA_SERVICE_START_WAIT_SECONDS -Value 10
        New-Variable -Option Constant -Name CertEnrollFolder -Value "$($env:systemroot)\System32\CertSrv\CertEnroll"
        New-Variable -Option Constant -Name DefaultLdapCdp -Value "ldap:///CN=%7%8,CN=%2,CN=CDP,CN=Public Key Services,CN=Services,%6%10"

        New-Variable -Option Constant -Name SETUP_SERVER_FLAG -Value 1
        New-Variable -Option Constant -Name SETUP_SUSPEND_FLAG -Value 4
        New-Variable -Option Constant -Name SETUP_REQUEST_FLAG -Value 8

        New-Variable -Option Constant -Name ENUM_ENTERPRISE_ROOTCA -Value 0
        New-Variable -Option Constant -Name ENUM_ENTERPRISE_SUBCA -Value 1
        New-Variable -Option Constant -Name ENUM_STANDALONE_ROOTCA -Value 3
        New-Variable -Option Constant -Name ENUM_STANDALONE_SUBCA -Value 4

    }

    process {

        # Ensuring the Script will be run on a supported Operating System
        If ([int32](Get-WmiObject Win32_OperatingSystem).BuildNumber -lt $BUILD_NUMBER_WINDOWS_2012) {
            Write-Error "Script must be run on Windows Server 2012 or newer! Aborting."
            Return 
        }

        # Ensuring the Script will be run with Elevation
        If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Error "Script must be run as Administrator! Aborting."
            Return
        }

        # Determine the current CA Setup Status
        $CaSetupStatus = Get-AdcsCaSetupStatus

        # Test if there is any CA Service installed
        If (-not (Test-Flag -Flags $CaSetupStatus -Flag $SETUP_SERVER_FLAG)) {
            Write-Error "Seems there is no CA installed that could be configured?"
            return
        }

        $CaType = Get-AdcsCaType

        # Steps specific for a subordinate CA
        If (($CaType -eq $ENUM_ENTERPRISE_SUBCA) -or ($CaType -eq $ENUM_STANDALONE_SUBCA)) {

            # Test if there is a Certificate Request Pending
            If (Test-Flag -Flags $CaSetupStatus -Flag $SETUP_REQUEST_FLAG) {

                # To Do: Try to cast the Certificate into an X509Certificate2 Object to ensure sanity, or even implement this as a Test Script
    
                    # Ensuring that new CA Certificate File is in place
                    If (Test-Path $CertFile) {
                        # Updating Machine Policy to ensure Root CA Cert was downloaded from AD
                        # This will both trigger Propagation via Group Policy and via AutoEnrollment
                        certutil -pulse
                        Start-Sleep -Second 15
                        # Installing the CA Certificate
                        certutil -installcert $CertFile
    
                        If ($LASTEXITCODE -ne 0) {
                            Write-Error "An Error occurred while installing CA Certificate $($CertFile). Aborting!" 
                            return
                        }
                    }
                    Else { 
                        Write-Error "No CA certificate found in $($CertFile). Aborting!"
                        return 
                    }
    
                }

            # Allow Renewal on Behalf of, which is required for Key-based Renewal
            If ($AllowRenewalOnBehalfOf.IsPresent) {
                certutil -setreg policy\EditFlags +EDITF_ENABLERENEWONBEHALFOF
            }

        }

        # Steps specific for Enterprise CAs
        If (($CaType -eq $ENUM_ENTERPRISE_ROOTCA) -or ($CaType -eq $ENUM_ENTERPRISE_SUBCA)) {

            If ($AuditFilter -gt 0) {

                # To set the policy configuration to enable audit of template events, run the following command:
                # From <https://technet.microsoft.com/en-us/library/dn786432(v=ws.11).aspx> 
                certutil -setreg policy\EditFlags +EDITF_AUDITCERTTEMPLATELOAD

            }

        }

        # Steps specific for Standalone CAs
        If (($CaType -eq $ENUM_STANDALONE_ROOTCA) -or ($CaType -eq $ENUM_STANDALONE_SUBCA)) {

            # Settings required to issue Certificates compliant to BSI requirements
            If (-not ($LegacyProfile).IsPresent) {

                # Remove Digital Signature from the Key Usage Extension
                # Make the Key Usage Extension Critical
                certutil -setreg policy\EditFlags -EDITF_ADDOLDKEYUSAGE
            
            }

            # Remove Microsoft specific Extensions from issued Certificates
            If (-not ($KeepProprietaryExtensions)) {

                # szOID_ENROLL_CERTTYPE_EXTENSION (v1 Template Name)
                certutil -setreg policy\DisableExtensionList +1.3.6.1.4.1.311.20.2

            }

        }

        # Settings required to issue Certificates compliant to BSI requirements
        If (-not ($LegacyProfile).IsPresent) {

            # Force UTF-8 Encoding of Subject Names
            # Applies to all kinds of Certification Authorities
            certutil -setreg CA\ForceTeleTex +ENUM_TELETEX_FORCEUTF8

        }

        # Remove Microsoft specific Extensions from issued Certificates
        If (-not ($KeepProprietaryExtensions)) {

            # szOID_CERTSRV_CA_VERSION (CA Version)
            certutil -setreg policy\DisableExtensionList +1.3.6.1.4.1.311.21.1

            # szOID_CERTSRV_PREVIOUS_CERT_HASH (Previous CA Certificate Hash)
            certutil -setreg policy\DisableExtensionList +1.3.6.1.4.1.311.21.2

        }

        # Applying Path Length Constraint
        If ($CaPathLength) {
            certutil -setreg Policy\CAPathLength $CaPathLength
        }

        If ($DsConfigDn) {
            certutil -setreg CA\DSConfigDN $DsConfigDn
        }
        
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

        # Enabling Auditing at the CA Level
        certutil -setreg CA\Auditfilter $AuditFilter

        If (-not ($EnforceX500NameLengths.IsPresent)) {
            certutil -setreg ca\EnforceX500NameLengths 0
        }

        # Enabling Auditing at the OS Level
        If ($AuditFilter -gt 0) {
            Write-Warning "Configuring local Audit Policy to enable Object Access Auditing for Certification Services. You should enforce this setting via a Group Policy!"
            auditpol /set /subcategory:"{0CCE9221-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
        }

        # If the EncryptionCsp has been specified, we make the setting in the Registry
        If ($EncryptionCsp) {
            certutil -setreg CA\EncryptionCSP\Provider $EncryptionCsp
        }

        # Clearing the existing CDP Configuration, leaving only the default local Path
        Get-CaCrlDistributionPoint | Where-Object  { -not ($_.Uri -match ($env:Systemroot).Replace("\","\\")) } | Foreach-Object -Process {
            Write-Verbose "Removing Default CDP $($_.Uri)"
            Remove-CaCrlDistributionPoint $_.Uri -Force
        } 

        # Clearing the existing AIA Configuration, leaving only the default local Path
        Get-CaAuthorityInformationAccess | Where-Object  { -not ($_.Uri -match ($env:Systemroot).Replace("\","\\")) } | Foreach-Object -Process {
            Write-Verbose "Removing Default AIA $($_.Uri)"
            Remove-CaAuthorityInformationAccess $_.Uri -Force
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
            
            Add-CaAuthorityInformationAccess @Arguments
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

            # File System Path
            If ($Uri -match "\\") {
                $Arguments.Add("PublishToServer",$True)
                $Arguments.Add("PublishDeltaToServer",$True)
            }
            
            Add-CaCrlDistributionPoint @Arguments
        }

        # Restarting Certificate Services to reflect new Configuration

        Stop-Service -Name CertSvc 

        If ((Get-AdcsKspName) -ne "Microsoft Software Key Storage Provider") {
            Write-Host "Waiting $CA_SERVICE_STOP_WAIT_SECONDS Seconds for KSPs to close their Handles..." -ForegroundColor Yellow
            Start-Sleep -Second $CA_SERVICE_STOP_WAIT_SECONDS
        }

        Start-Service -Name CertSvc 

        Do {

            # We should not poll too often as every time the Query fails, we will
            # have an ugly DCOM Error Message 10016 in the System Event Log
            Start-Sleep $CA_SERVICE_START_WAIT_SECONDS

            Write-Host "Waiting for the ICertAdmin2 Interface to become available..."

        } While ((Test-AdcsServiceAvailability) -ne $True)

        # Deleting the old default CRLs
        Get-ChildItem -Path $CertEnrollFolder "$($CaName)*.crl" | Remove-Item

        # Issuing a new CRL
        certutil -CRL

        $Cdp | Where-Object { $_ -match ("ldap://") } | ForEach-Object -Process {

            If ($_ -notmatch $DefaultLdapCdp) {
        
                Write-Host "Creating non-Standard LDAP CDP Object Container"
        
                # Creating the Object by Force
                Get-ChildItem $CertEnrollFolder "$($CaName)*.crl" | Foreach-Object {
                    certutil -f -dspublish "$($_.FullName)"
                }
        
                # Issuing a new CRL - should work now if System already has been rebooted
                certutil -CRL
        
            }
        }

    }
}