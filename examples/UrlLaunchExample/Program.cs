/** Sectra URL integration example
 * 
 * This code is an example on how the URL integration with Sectra products
 * works. The example is not intended to be used as-is since exposing
 * encryption keys on command line is a security flaw.
 * 
 * Not all available URL-launch parameters are included in this example. For a
 * complete reference, see the Sectra.UrlLaunch.UrlAccessString project.
 *
 */

using Sectra.UrlLaunch.UrlAccessString;
using System.CommandLine;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

namespace UrlLaunchExample;

public class Program {

    /// <summary>
    /// Example applications
    /// </summary>
    enum Application {
        Example,
        Ids7,
        Ids7Using3pStart,
        Uniview,
    }

    static async Task<int> Main(string[] args) {
        var hostArgument = new Argument<string>(
            name: "host",
            description: "Hostname of launched system") {
            Arity = new ArgumentArity(1, 1),
        };

        var applicationArgument = new Argument<Application>(
            name: "application",
            description: "Application name") {
            Arity = new ArgumentArity(1, 1),
        };

        var userIdOption = new Option<string>(
            name: "--userId",
            description: "User ID",
            getDefaultValue: () => "TestUser");

        var patientIdOption = new Option<string>(
            name: "--patientId",
            description: "Patient ID",
            getDefaultValue: () => "12121212-1212");

        var mrnIntegrationIdOption = new Option<string>(
            name: "--mrnIntegrationId",
            description: "MRN integration ID",
            getDefaultValue: () => "MrnIntegrationId");

        // Do not expose the shared secret key on command line in production, this option is only included for testing purpose.
        var sharedSecretKeyOption = new Option<string>(
            name: "--sharedSecret",
            description: "Base64 encoded shared secret key (Do not expose the system password on command line in production!)");

        var integratingPartyCertOption = new Option<string>(
            name: "--integratingPartyPrivateCert",
            description: "Integrating party certificate subject name (certificate must include private key)");

        var sectraPacsCertOption = new Option<string>(
            name: "--sectraPacsPublicCert",
            description: "The Sectra PACS public certificate subject name");

        var rootCommand = new RootCommand("Example implementation of Sectra URL launch");
        rootCommand.AddArgument(hostArgument);
        rootCommand.AddArgument(applicationArgument);
        rootCommand.AddOption(userIdOption);
        rootCommand.AddOption(patientIdOption);
        rootCommand.AddOption(mrnIntegrationIdOption);
        rootCommand.AddOption(sharedSecretKeyOption);
        rootCommand.AddOption(integratingPartyCertOption);
        rootCommand.AddOption(sectraPacsCertOption);

        rootCommand.SetHandler(
            UrlLaunch,
            hostArgument,
            applicationArgument,
            userIdOption,
            patientIdOption,
            mrnIntegrationIdOption,
            sharedSecretKeyOption,
            integratingPartyCertOption,
            sectraPacsCertOption);

        return await rootCommand.InvokeAsync(args);
    }

    /// <summary>
    /// Retrieves the query string and opens the application
    /// </summary>
    static void UrlLaunch(string host, Application application, string userId, string patientId, string mrnIntegrationId, string sharedSecretKey, string integratingPartyCert, string sectraPacsCert) {

        var parameters = new Parameters {
            UserId = userId,
            PatientId = patientId,
            MrnIntegrationId = mrnIntegrationId,
        };
        var queryString = QueryString.GetQueryString(parameters);

        Console.WriteLine($"Launch query: {queryString}");
        Console.WriteLine();

        if (!string.IsNullOrEmpty(integratingPartyCert) && !string.IsNullOrEmpty(sectraPacsCert)) {
            Console.WriteLine($"Encrypting using Sectra UrlLaunchSecurity with {integratingPartyCert} and {sectraPacsCert}");
            var sectraCertificate = GetCertificateFromPersonalStore(sectraPacsCert).FirstOrDefault();
            var integratingPartyCertificate = GetCertificateFromPersonalStore(integratingPartyCert).FirstOrDefault();
            if (sectraCertificate == null) {
                Console.WriteLine($"Could not find system certificate with identifier: {sectraPacsCert}");
                return;
            }
            if (integratingPartyCertificate == null) {
                Console.WriteLine($"Could not find integrating party certificate with identifier: {integratingPartyCert}");
                return;
            }
            queryString = Sectra.UrlLaunch.Pki.SectraPkiEncryption.Secure(queryString, integratingPartyCertificate, sectraCertificate);

            Console.WriteLine($"Encrypted launch query: {queryString}");
            Console.WriteLine();
        } else if (!string.IsNullOrEmpty(sharedSecretKey)) {
            Console.WriteLine($"Encrypting using Sectra SharedSecret");
            queryString = Sectra.UrlLaunch.SharedSecret.SectraSharedSecretEncryption.Secure(queryString, sharedSecretKey);

            Console.WriteLine($"Encrypted launch query: {queryString}");
            Console.WriteLine();
        }

        switch (application) {
            case Application.Example:
                OpenUri($"http://{host}/UrlLaunchExampleApi/?{queryString}");
                break;
            case Application.Ids7:
                Console.WriteLine($"Make sure the Sectra Launcher is installed, it can be downloaded and installed from https://{host}/ids7/");
                OpenUri($"sectra:?url=https://{host}/SectraHealthcareServer/&softwareUrl=https://{host}/ids7/&productId=IDS7&{queryString}");
                break;
            case Application.Ids7Using3pStart:
                Console.WriteLine($"The 3pstart page is only kept as compatibility for old PACS versions. Use the Sectra launcher protocol if possible.");
                OpenUri($"https://{host}/ids7/3pstart.aspx?{queryString}");
                break;
            case Application.Uniview:
                OpenUri($"https://{host}/uniview/#/apiLaunch?{queryString}");
                break;
        }
    }

    /// <summary>
    /// Opens a URI with the default browser or protocol handler
    /// </summary>
    static void OpenUri(string uri) {
        try {
            Console.WriteLine($"Opening URI: {uri}");
            var startInfo = new ProcessStartInfo(uri) {
                UseShellExecute = true,
            };
            Process.Start(startInfo);
        }
        catch (Exception ex) {
            Console.WriteLine($"Error when opening URI: {ex}");
            throw;
        }
    }

    /// <summary>
    /// Getting certificates from the personal certificate store by subject name
    /// </summary>
    private static X509Certificate2Collection GetCertificateFromPersonalStore(string subjectName) {
        var matchingCerts = new X509Certificate2Collection();
        var storeLocations = new List<StoreLocation> { StoreLocation.LocalMachine, StoreLocation.CurrentUser };

        // Get certificates in all store locations
        foreach (StoreLocation storeLocation in storeLocations) {
            // Get and open the Personal store
            var certStore = new X509Store("My", storeLocation);
            certStore.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            // Find matching certificates
            var collection = certStore.Certificates;
            matchingCerts.AddRange(collection.Find(X509FindType.FindBySubjectName, subjectName, false));
        }

        return matchingCerts;
    }

}
