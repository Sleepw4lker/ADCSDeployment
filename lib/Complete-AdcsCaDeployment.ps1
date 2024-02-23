Function Complete-AdcsCaDeployment {

    [CmdletBinding(DefaultParameterSetName="StandaloneRootCA")]
    param(
        # Specific to Subordinate CAs
        [Parameter(Mandatory=$True)]
        [ValidateScript({Test-Path -Path $_})]
        [String]
        $CertFile        
    )

    begin {

        New-Variable -Option Constant -Name BUILD_NUMBER_WINDOWS_2012 -Value 9200
        New-Variable -Option Constant -Name CA_SERVICE_STOP_WAIT_SECONDS -Value 30
        New-Variable -Option Constant -Name CA_SERVICE_START_WAIT_SECONDS -Value 10
        New-Variable -Option Constant -Name DIRECTORY_CERTENROLL -Value "$($env:systemroot)\System32\CertSrv\CertEnroll"
        New-Variable -Option Constant -Name DEFAULT_LDAP_CDP -Value "ldap:///CN=%7%8,CN=%2,CN=CDP,CN=Public Key Services,CN=Services,%6%10"

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
            return 
        }

        # Ensuring the Script will be run with Elevation
        If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Error "Script must be run as Administrator! Aborting."
            return
        }

        # Determine the current CA Setup Status
        $CaSetupStatus = Get-AdcsCaSetupStatus

        # Test if there is any CA Service installed
        If (-not (Test-Flag -Flags $CaSetupStatus -Flag $SETUP_SERVER_FLAG)) {
            Write-Error "Seems there is no CA installed that could be configured! Aborting."
            return
        }

        # This reads the CA Type from the Registry
        $CaType = Get-AdcsCaType

        # Steps specific for a subordinate CA
        If (($CaType -eq $ENUM_ENTERPRISE_SUBCA) -or ($CaType -eq $ENUM_STANDALONE_SUBCA)) {

            # Determine if there is a certificate request pending and install CA Certificate if so
            If (Test-Flag -Flags $CaSetupStatus -Flag $SETUP_REQUEST_FLAG) {

                # Ensure that new CA Certificate File is in place
                If (Test-Path $CertFile) {

                    # Ensure Root CA Cert was downloaded from AD, (hopefully you published it there
                    Invoke-AutoEnrollmentTask -MachineContext

                    Start-Sleep -Second 15
                    
                    # Install the CA Certificate
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
        }

        # Restart Certificate Services to reflect new Configuration

        Stop-Service -Name CertSvc 

        # Implement a delay if not using the default Software KSP
        # Some HSM KSPs need some time to clean up their stuff before the Service can be started again
        If ((Get-AdcsKspName) -ne "Microsoft Software Key Storage Provider") {
            Write-Warning "Waiting $CA_SERVICE_STOP_WAIT_SECONDS Seconds for KSPs to close their Handles..."
            Start-Sleep -Second $CA_SERVICE_STOP_WAIT_SECONDS
        }

        Start-Service -Name CertSvc 

        # The CertSrv.Admin Interface won't be instantly available
        # Thus we give it some time before tampering with it again
        Do {

            # We should not poll too often as every time the Query fails, we will
            # get another ugly DCOM Error Message 10016 in the System Event Log
            Start-Sleep -Seconds $CA_SERVICE_START_WAIT_SECONDS

            Write-Warning "Waiting for the ICertAdmin2 Interface to become available..."

        } While ((Test-AdcsServiceAvailability) -ne $True)

        # Delete the old default CRLs
        Get-ChildItem -Path $DIRECTORY_CERTENROLL "$($CaName)*.crl" | Remove-Item

        # Issuing a new CRL - this might fail if a non-Standard LDAP Path was configured
        certutil -CRL

        Get-CaCrlDistributionPoint | Where-Object { $_.Uri.StartsWith("ldap://") } | ForEach-Object -Process {

            If ($_ -notmatch $DEFAULT_LDAP_CDP) {
        
                Write-Host "Creating non-Standard LDAP CDP Object Container"
        
                # Creating the Object by Force
                Get-ChildItem $DIRECTORY_CERTENROLL "$($CaName)*.crl" | Foreach-Object {
                    certutil -f -dspublish "$($_.FullName)"
                }
        
                # Issuing a new CRL - should work now if System already has been rebooted
                certutil -CRL
            }
        }
    }
}