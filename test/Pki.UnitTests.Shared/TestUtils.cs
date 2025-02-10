using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;

namespace Sectra.UrlLaunch.Pki;
public static class TestUtils {
    private const string certificatePassword = "test";
    public static X509Certificate2 GetCertificate(string certName = "integrating_party_test_cert.pfx") {
        var assembly = Assembly.GetExecutingAssembly();
        var resourceName = $"Sectra.UrlLaunchSecurity.{certName}";

        byte[] certData;

        using (Stream stream = assembly.GetManifestResourceStream(resourceName))
        using (var destination = new MemoryStream()) {
            stream.CopyTo(destination);
            certData = destination.ToArray();
        }

        return new X509Certificate2(certData, certificatePassword, X509KeyStorageFlags.PersistKeySet);
    }
}
