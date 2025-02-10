<#
.SYNOPSIS
Creates a self-signed certificate and exports it as a PFX for use in the unit tests.

.DESCRIPTION
This script creates a self-signed certificate for a specified DNS Common Name (`CN`). The certificate is temporarily placed in the CurrentUser "My" certificate store for processing. It is then exported to a `.pfx` file with a predefined password. Optionally, you can choose to leave the certificate in the certificate store using the `-ImportCertificate` switch. Otherwise, the certificate is removed from the store after exporting.

.PARAMETER CommonName
The DNS Common Name (`CN`) for which the self-signed certificate will be generated. This is a required parameter.

.PARAMETER CertFileName
The path and filename for the `.pfx` file to which the certificate will be exported. This is a required parameter.

.PARAMETER ImportCertificate
A switch parameter that, if provided, leaves the certificate in the certificate store after export. If omitted, the certificate is removed from the store.

.EXAMPLE
.\CreateCert.ps1 -CommonName "UrlLaunchSdkIntegratingParty" -CertFileName "integrating_party_test_cert.pfx"

Description:
Creates a self-signed certificate for `UrlLaunchSdkIntegratingParty`, exports it to `integrating_party_test_cert.pfx`, and removes the certificate from the store after export.

.EXAMPLE
.\CreateCert.ps1 -CommonName "UrlLaunchSdkIntegratingParty" -CertFileName "integrating_party_test_cert.pfx" -ImportCertificate

Description:
Creates a self-signed certificate for `UrlLaunchSdkIntegratingParty`, exports it to `integrating_party_test_cert.pfx`, and leaves the certificate in the store for later use.

.INPUTS
None. The script does not accept piped input.

.OUTPUTS
None. The script generates a `.pfx` file as an output artifact.

.NOTES
Author: Sectra
Version: 1.0
Date: 2025-03-10

The script uses a hardcoded password ("test") for the `.pfx` file.

The script requires administrator privileges to execute correctly.
#>
param (
    [Parameter(Mandatory=$true)]
    [string] $CommonName,
    [Parameter(Mandatory=$true)]
    [string] $CertFileName,
    [switch] $ImportCertificate
)

# Set the password for the .pfx file (`SecureString` required for Export-PfxCertificate)
$password = ConvertTo-SecureString -String "test" -Force -AsPlainText

# Define the certificate store location (temporary)
$certStore = "Cert:\CurrentUser\My"

try {
    Write-Host "Creating self-signed certificate for Common Name: $CommonName" -ForegroundColor Green

    # Create a self-signed certificate and temporarily place it in the store
    $certificate = New-SelfSignedCertificate -DnsName $CommonName -CertStoreLocation $certStore

    # Export the certificate to a .pfx file
    Write-Host "Exporting certificate to file: $CertFileName" -ForegroundColor Green
    Export-PfxCertificate -Cert $certificate -FilePath $CertFileName -Password $password

    # Optionally import the certificate into the certificate store (if `-ImportCertificate` is supplied)
    if ($ImportCertificate) {
        Write-Host "Certificate will remain in certificate store (as per request)." -ForegroundColor Yellow
    } else {
        # Remove the certificate from the store to clean up
        Write-Host "Removing certificate from the store to avoid leftovers." -ForegroundColor Green
        Remove-Item -Path $certStore\$($certificate.Thumbprint) -Force
    }
} catch {
    Write-Host "An error occurred: $_" -ForegroundColor Red
    exit 1
} finally {
    Write-Host "Operation completed." -ForegroundColor Cyan
}
