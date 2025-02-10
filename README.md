# Sectra URL Launch SDK

The Sectra URL Launch SDK is a powerful toolkit designed to help partners integrate seamlessly with Sectra's URL Launch protocol. This SDK enables third-party applications to interact with Sectra solutions by leveraging standard URL-based commands for launching and controlling workflows.

With the Sectra URL Launch SDK, partners can:
- Easily initiate Sectra product functionalities, such as launching specific modules or workflows, directly from their own applications.
- Pass contextual information (e.g., patient data, study identifiers) through URL parameters to enrich integration capabilities.
- Simplify inter-application communication using a well-documented and reliable protocol.

This SDK is particularly valuable for healthcare partners who wish to extend or optimize their workflows by integrating with Sectra's ecosystem of medical imaging and enterprise solutions.

## Getting started
To build and use this SDK the latest .NET LTS SDK is needed.

### Installing .NET SDK
Go to the [official website](https://dotnet.microsoft.com/en-us/download) for .NET and download and install the latest LTS version.

### Building the solution
1. Open a command prompt in the SDK root folder
1. Execute `dotnet build`

### Running the unit tests
1. Open a command prompt in the SDK root folder
1. Execute `dotnet test`

### Building the NuGet packages
1. Open a command prompt in the SDK root folder
1. Execute `dotnet pack -o deliverables`

## Using the SDK

In order to use the SDK you have to:

1. Build the NuGet packages `dotnet pack -o deliverables`
1. Create a new project
    1. `cd ..`
    1. `mkdir UrlLaunchTest`
    1. `cd UrlLaunchTest`
    1. `dotnet new console`
1. Add NuGet source `dotnet nuget add source "$(Resolve-Path ..\SectraUrlLaunchSdk\deliverables)" -n SectraLocalSource` using PowerShell
1. Add NuGet packages to project
    1. `dotnet add UrlLaunchTest.csproj package Sectra.UrlLaunch.SharedSecret`
    1. `dotnet add UrlLaunchTest.csproj package Sectra.UrlLaunch.UrlAccessString`
1. Add the code example below
1. Run using `dotnet run`

```csharp
using Sectra.UrlLaunch.SharedSecret;
using Sectra.UrlLaunch.UrlAccessString;

// Use the same key as in the UrlLaunchExample.WebApi example
var base64Key = "EpNnJ5vPSEL5vqSgG7Oe8fzgICZ3pzcqn1bEoHqzDA8=";
var key = Convert.FromBase64String(base64Key);

// Create a plain text query string
var parameters = new Parameters {
    UserId = "MyUserName",
};
var plainTextQueryString = QueryString.GetQueryString(parameters);

// Create an encrypted launch string using the Shared Secret encryption algorithm
var encryptedQueryString = SectraSharedSecretEncryption.Secure(plainTextQueryString, key);

var launchString = $"http://localhost:5079/UrlLaunchExampleApi/?{encryptedQueryString}";

Console.WriteLine($"Ready to launch: {launchString}");
```

You can find [example programs](examples) capable of generating URL access strings and encrypting it using PKI or Shared Secret encryption algorithms.

## Encryption algorithms explained

The Sectra encryption algorithms are based on industry standard encryption algorithms wrapped in a format suitable for URLs.

### PKI

The Public Key Infrastructure (PKI) algorithm uses certificate based asymmetric encryption. This method requires two certificates, one for the integrating party and one for the sectra system.

### Shared Secret

The Shared Secret algorithm uses a 32 byte encryption key that is shared between the integrating party and the sectra system. The algorithm includes a timestamp that is only valid for 30 seconds after generation.

## Integrating with Sectra using URL launch in practice

Note that the generation of a URL launch access string and encrypting it properly is only part of securing the integration.

### Considerations

This list is in no means complete but can act as a starting point when creating a secure and user-friendly integration with Sectra products.

- Storing the encryption keys securely. The encryption keys should not be accessible on the end-user client but the URL launch access string should be generated server-side only for authenticated users.
- Encrypting the URL launch access string is important both for security and patient privacy, for example in case the URL launch access string is stored in the browser history. An encrypted URL launch access string also gives the possibility for single sign-on (SSO).
- The URL launch API is "fire and forget" and does not automatically keep the integrating party software in sync. It is up to the launching software to ensure that the integration is safe to use and that the patient context synchronization is done sufficiently.
    - Web products can usually be embedded and can thus be closed or updated if the patient context changed in the integrating software.
    - Desktop application patient context can be updated using subsequent URL launches. However, from an API standpoint there is no guarantee that the context is updated properly. Sectra prodvides additional patient context synchonization options, please discuss the integration with your Sectra representative.

### Generating secure keys for Shared Secret encryption

The keys should be 32 bytes and can be either used as a byte array or a base64 encoded string. You can use [Generate-SharedSecretKey.ps1](scripts/Generate-SharedSecretKey.ps1) to easily generate keys.

### Generating certificates for PKI encryption

Certificate requirements:

- An encryption key with a length of 2048 bits
- Hash functions: SHA-256 or SHA-512 for creating the certificate
- Microsoft RSA SChannel Cryptographic Provider
- Key Usage can be either:
    - "Key Encipherment, Data Encipherment (30)"
    - "Data Encipherment (10)"
