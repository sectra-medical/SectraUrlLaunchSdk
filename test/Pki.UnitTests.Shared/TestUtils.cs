using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;

namespace Sectra.UrlLaunch.Pki;

public static class TestUtils {
    private const string certificatePassword = "test";
    public static X509Certificate2 GetCertificate(string certName = "integrating_party_test_cert.pfx") {
        var assembly = Assembly.GetExecutingAssembly();
        var resourceName = $"{assembly.GetName().Name}.{certName}";

        using var stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException($"Embedded resource '{resourceName}' not found.");
        using var destination = new MemoryStream();
        stream.CopyTo(destination);
        var certData = destination.ToArray();

#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12(certData, certificatePassword, X509KeyStorageFlags.PersistKeySet);
#else
        return new X509Certificate2(certData, certificatePassword, X509KeyStorageFlags.PersistKeySet);
#endif
    }
}
