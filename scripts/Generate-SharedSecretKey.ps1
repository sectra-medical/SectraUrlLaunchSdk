<#
.SYNOPSIS
Generates a random Base64-encoded key to be used with the Sectra Shared Secret URL-launch algorithm.

.DESCRIPTION
The script generates a 32-byte secure random value encoded as a Base64 string, which can be used for cryptographic purposes or unique identifiers.

.EXAMPLE
.\GenerateBase64.ps1

Description:
Generates a random Base64 key.

.INPUTS
None. The script does not accept piped input.

.OUTPUTS
If successful, the script outputs a 32-byte Base64-encoded string.

.NOTES
Author: Sectra
Version: 1.0.0
Date: 2025-03-10

Minimum PowerShell version required: 7.3
This script uses .NET’s System.Security.Cryptography.RandomNumberGenerator to generate secure random bytes.

.LINK
Learn more about secure random number generation in PowerShell:
https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.randomnumbergenerator
#>

# Minimum required PowerShell version
$requiredVersion = [version]"7.3"

# Check the current version of PowerShell
if ($PSVersionTable.PSVersion -lt $requiredVersion) {
    # Display a friendly error message and terminate the script
    Write-Host "Error: This script requires PowerShell version $requiredVersion or higher." -ForegroundColor Red
    Write-Host "You are running PowerShell version $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)." -ForegroundColor Yellow
    Write-Host "Please update your PowerShell installation from https://github.com/PowerShell/PowerShell to continue." -ForegroundColor Cyan
    exit 1
}

[Convert]::ToBase64String([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
