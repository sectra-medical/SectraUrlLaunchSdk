using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Web;

namespace Sectra.UrlLaunch.Pki;

/// <summary>
/// Main class for managing URL strings used in Sectra's URL launch.
/// </summary>
public static class SectraPkiEncryption {

    public static bool IsPkiEncryption(string encryptedQueryString) {
        var parsedQueryString = HttpUtility.ParseQueryString(encryptedQueryString);
        var seus = parsedQueryString.Get(EncryptedUrlString.SymmetricallyEncryptedUrlStringKey);
        var esp = parsedQueryString.Get(EncryptedUrlString.EncryptedSymmetricPasswordKey);
        var iv = parsedQueryString.Get(EncryptedUrlString.InitializationVectorKey);
        var v = parsedQueryString.Get(EncryptedUrlString.ProtocolVersionKey);
        return !string.IsNullOrEmpty(seus) && !string.IsNullOrEmpty(esp) && !string.IsNullOrEmpty(iv) && !string.IsNullOrEmpty(v);
    }


    public static string Secure(string plainTextQueryString, X509Certificate2 integratingPartyCertificate, X509Certificate2 urlLaunchSystemCertificate) {
        return new UrlLaunchSecurity().Secure(plainTextQueryString, integratingPartyCertificate, urlLaunchSystemCertificate).Serialize();
    }

    public static string Secure(string plainTextQueryString, RSA integratingPartyPrivateKey, RSA urlLaunchSystemPublicKey) {
        return new UrlLaunchSecurity().Secure(plainTextQueryString, integratingPartyPrivateKey, urlLaunchSystemPublicKey).Serialize();
    }

    public static string View(string plainTextQueryString, X509Certificate2 urlLaunchSystemCertificate, X509Certificate2 integratingPartyCertificate) {
        var secureString = EncryptedUrlString.Deserialize(plainTextQueryString);
        return new UrlLaunchSecurity().View(secureString, urlLaunchSystemCertificate, integratingPartyCertificate);
    }

    public static string View(string plainTextQueryString, RSA urlLaunchSystemPrivateKey, RSA integratingPartyPublicKey) {
        var secureString = EncryptedUrlString.Deserialize(plainTextQueryString);
        return new UrlLaunchSecurity().View(secureString, urlLaunchSystemPrivateKey, integratingPartyPublicKey);
    }
}
