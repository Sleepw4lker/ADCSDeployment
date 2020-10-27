# ADCSDeployment

Scripts to easily deploy Microsoft Certification Authorities.

It will comply to all requirements specified by the Common PKI Certificate Standard by default.

## Usage

* `New-AdcsCaDeployment` installs the CA Role.
* `Complete-AdcsCaDeployment` does all the necessary configuration, like installing the CA Certificate, populating Registry Values and the like.

## Samples

See the sample files:
* Deploy-StandAloneRootCa.ps1
* Deploy-EnterpriseSubCa-Step1.ps1
* Deploy-EnterpriseSubCa-Step2.ps1