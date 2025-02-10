using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Sectra.UrlLaunch.Pki;

/// <summary>
/// Main class for managing URL strings used in Sectra's URL launch.
/// </summary>
internal sealed class UrlLaunchSecurity {
    /// <summary>
    /// The protocol version for this version of the library.
    /// </summary>
    public const ushort ProtocolVersion = 1;

    /// <summary>
    /// Secures the specified plain text string using Sectra's protocol for signing and encrypting URL strings. The protocol is basically:
    /// 1. Sign <paramref name="plainTextString" /> using <paramref name="integratingPartyCertificate" />.
    /// 2. Encrypt <paramref name="plainTextString" /> and the signature using AES with a securely randomly generated key, K_s.
    /// 3. Encrypt K_s using <paramref name="urlLaunchSystemCertificate" />.
    /// 4. Package the result as:
    /// a. The AES encrypted string.
    /// b. The assymetrically encrypted AES key.
    /// c. The initialization vector for the AES algorithm.
    /// </summary>
    /// <param name="plainTextString">The plain text string to be secured.</param>
    /// <param name="integratingPartyCertificate">The integrating party private key.</param>
    /// <param name="urlLaunchSystemCertificate">The URL launch system public key (Sectra's public key).</param>
    /// <returns>
    /// A secure string. This string can be sent over an insecure network.
    /// </returns>
    /// <exception cref="System.ArgumentNullException">
    /// </exception>
    public EncryptedUrlString Secure(string plainTextString, X509Certificate2 integratingPartyCertificate, X509Certificate2 urlLaunchSystemCertificate) {
        if (plainTextString == null) {
            throw new ArgumentNullException(nameof(plainTextString));
        }

        if (integratingPartyCertificate == null) {
            throw new ArgumentNullException(nameof(integratingPartyCertificate));
        }

        if (urlLaunchSystemCertificate == null) {
            throw new ArgumentNullException(nameof(urlLaunchSystemCertificate));
        }

        if (urlLaunchSystemCertificate.GetRSAPublicKey() == null) {
            throw new Exception("URL launch system certificate does not have a public key!");
        }

        if (!integratingPartyCertificate.HasPrivateKey) {
            throw new Exception("Integrating party certificate does not have a private key!");
        }
        return Secure(plainTextString, integratingPartyCertificate.GetRSAPrivateKey()!, urlLaunchSystemCertificate.GetRSAPublicKey()!);
    }

    /// <summary>
    /// Secures the specified plain text string using Sectra's protocol for signing and encrypting URL strings. The protocol is basically:
    /// 1. Sign <paramref name="plainTextString" /> using <paramref name="integratingPartyPrivateKey" />.
    /// 2. Encrypt <paramref name="plainTextString" /> and the signature using AES with a securely randomly generated key, K_s.
    /// 3. Encrypt K_s using <paramref name="urlLaunchSystemPublicKey" />.
    /// 4. Package the result as:
    /// a. The AES encrypted string.
    /// b. The assymetrically encrypted AES key.
    /// c. The initialization vector for the AES algorithm.
    /// </summary>
    /// <param name="plainTextString">The plain text string to be secured.</param>
    /// <param name="integratingPartyPrivateKey">The integrating party private key.</param>
    /// <param name="urlLaunchSystemPublicKey">The URL launch system public key (Sectra's public key).</param>
    /// <returns>
    /// A secure string. This string can be sent over an insecure network.
    /// </returns>
    /// <exception cref="System.ArgumentNullException">
    /// </exception>
    [Obsolete("Use the appropriate version to secure the plain text string, such as the RSA version.")]
    public EncryptedUrlString Secure(string plainTextString, RSA integratingPartyPrivateKey, PublicKey urlLaunchSystemPublicKey) {
        if (plainTextString == null) {
            throw new ArgumentNullException(nameof(plainTextString));
        }

        if (integratingPartyPrivateKey == null) {
            throw new ArgumentNullException(nameof(integratingPartyPrivateKey));
        }

        if (urlLaunchSystemPublicKey == null) {
            throw new ArgumentNullException(nameof(urlLaunchSystemPublicKey));
        }

        return Secure(plainTextString, integratingPartyPrivateKey, (RSA)urlLaunchSystemPublicKey.Key);
    }

    /// <summary>
    /// Secures the specified plain text string using Sectra's protocol for signing and encrypting URL strings. The protocol is basically:
    /// 1. Sign <paramref name="plainTextString" /> using <paramref name="integratingPartyPrivateKey" />.
    /// 2. Encrypt <paramref name="plainTextString" /> and the signature using AES with a securely randomly generated key, K_s.
    /// 3. Encrypt K_s using <paramref name="urlLaunchSystemPublicKey" />.
    /// 4. Package the result as:
    /// a. The AES encrypted string.
    /// b. The assymetrically encrypted AES key.
    /// c. The initialization vector for the AES algorithm.
    /// </summary>
    /// <param name="plainTextString">The plain text string to be secured.</param>
    /// <param name="integratingPartyPrivateKey">The integrating party private key.</param>
    /// <param name="urlLaunchSystemPublicKey">The URL launch system public key (Sectra's public key).</param>
    /// <returns>
    /// A secure string. This string can be sent over an insecure network.
    /// </returns>
    /// <exception cref="System.ArgumentNullException">
    /// </exception>
    public EncryptedUrlString Secure(string plainTextString, RSA integratingPartyPrivateKey, RSA urlLaunchSystemPublicKey) {
        if (plainTextString == null) {
            throw new ArgumentNullException(nameof(plainTextString));
        }

        if (integratingPartyPrivateKey == null) {
            throw new ArgumentNullException(nameof(integratingPartyPrivateKey));
        }

        if (urlLaunchSystemPublicKey == null) {
            throw new ArgumentNullException(nameof(urlLaunchSystemPublicKey));
        }

        var byteString = Encoding.UTF8.GetBytes(plainTextString);
        var signedString = UrlStringSigner.Sign(byteString, integratingPartyPrivateKey);
        var encryptedString = UrlStringEncryptor.Encrypt(signedString, urlLaunchSystemPublicKey);

        encryptedString.ProtocolVersion = ProtocolVersion;

        return encryptedString;
    }

    /// <summary>
    /// Decrypts and verifies the <paramref name="secureString" /> using Sectra's protocol for signing and encrypting URL strings. The protocol is basically the reverse of what is described in <see cref="UrlLaunchSecurity.Secure(string, RSA, PublicKey)" />.
    /// </summary>
    /// <param name="secureString">The secure string to view and verify.</param>
    /// <param name="urlLaunchSystemCertificate">The URL launch system certificate used when encrypting the URL string.</param>
    /// <param name="integratingPartyCertificate">The integrating party certificate used when signing the URL string.</param>
    /// <returns>
    /// A plain text, URL encoded string equal, apart from URL encoding, to what would have been used as the input parameter in <see cref="UrlLaunchSecurity.Secure(string, RSA, PublicKey)" />.
    /// </returns>
    /// <exception cref="System.ArgumentNullException">Thrown if <paramref name="urlLaunchSystemCertificate"/> or <paramref name="integratingPartyCertificate"/> is null.</exception>
    /// <exception cref="System.ArgumentException">Thrown if <paramref name="secureString"/> lacks any of its properties.</exception>
    /// <exception cref="CryptographicException">Thrown if <paramref name="secureString" /> cannot be decrypted using <paramref name="urlLaunchSystemCertificate" /> or if the provided signature cannot be verified using <paramref name="integratingPartyCertificate" />.</exception>
    public string View(EncryptedUrlString secureString, X509Certificate2 urlLaunchSystemCertificate, X509Certificate2 integratingPartyCertificate) {
        if (urlLaunchSystemCertificate == null) {
            throw new ArgumentNullException(nameof(urlLaunchSystemCertificate));
        }

        if (integratingPartyCertificate == null) {
            throw new ArgumentNullException(nameof(integratingPartyCertificate));
        }

        if (!urlLaunchSystemCertificate.HasPrivateKey) {
            throw new Exception("URL launch system certificate does not have a private key!");
        }


        if (integratingPartyCertificate.GetRSAPublicKey() == null) {
            throw new Exception("Integrating party certificate does not have a public key!");
        }

        return View(secureString, urlLaunchSystemCertificate.GetRSAPrivateKey()!, integratingPartyCertificate.GetRSAPublicKey()!);
    }

    /// <summary>
    /// Decrypts and verifies the <paramref name="secureString" /> using Sectra's protocol for signing and encrypting URL strings. The protocol is basically the reverse of what is described in <see cref="UrlLaunchSecurity.Secure(string, RSA, PublicKey)" />.
    /// </summary>
    /// <param name="secureString">The secure string to view and verify.</param>
    /// <param name="urlLaunchSystemPrivateKey">The URL launch system private key for the public key used when encrypting the URL string.</param>
    /// <param name="integratingPartyPublicKey">The integrating party public key for the private key used when signing the URL string.</param>
    /// <returns>
    /// A plain text, URL encoded string equal, apart from URL encoding, to what would have been used as the input parameter in <see cref="UrlLaunchSecurity.Secure(string, RSA, PublicKey)" />.
    /// </returns>
    /// <exception cref="System.ArgumentNullException">Thrown if <paramref name="urlLaunchSystemPrivateKey"/> or <paramref name="integratingPartyPublicKey"/> is null.</exception>
    /// <exception cref="System.ArgumentException">Thrown if <paramref name="secureString"/> lacks any of its properties.</exception>
    /// <exception cref="CryptographicException">Thrown if <paramref name="secureString" /> cannot be decrypted using <paramref name="urlLaunchSystemPrivateKey" /> or if the provided signature cannot be verified using <paramref name="integratingPartyPublicKey" />.</exception>
    [Obsolete("Use the appropriate version to view the secure string, such as the RSA version.")]
    public string View(EncryptedUrlString secureString, RSA urlLaunchSystemPrivateKey, PublicKey integratingPartyPublicKey) {
        if (urlLaunchSystemPrivateKey == null) {
            throw new ArgumentNullException(nameof(urlLaunchSystemPrivateKey));
        }

        if (integratingPartyPublicKey == null) {
            throw new ArgumentNullException(nameof(integratingPartyPublicKey));
        }

        return View(secureString, urlLaunchSystemPrivateKey, (RSA)integratingPartyPublicKey.Key);
    }

    /// <summary>
    /// Decrypts and verifies the <paramref name="secureString" /> using Sectra's protocol for signing and encrypting URL strings. The protocol is basically the reverse of what is described in <see cref="UrlLaunchSecurity.Secure(string, RSA, PublicKey)" />.
    /// </summary>
    /// <param name="secureString">The secure string to view and verify.</param>
    /// <param name="urlLaunchSystemPrivateKey">The URL launch system private key for the public key used when encrypting the URL string.</param>
    /// <param name="integratingPartyPublicKey">The integrating party public key for the private key used when signing the URL string.</param>
    /// <returns>
    /// A plain text, URL encoded string equal, apart from URL encoding, to what would have been used as the input parameter in <see cref="UrlLaunchSecurity.Secure(string, RSA, PublicKey)" />.
    /// </returns>
    /// <exception cref="System.ArgumentNullException">Thrown if <paramref name="urlLaunchSystemPrivateKey"/> or <paramref name="integratingPartyPublicKey"/> is null.</exception>
    /// <exception cref="System.ArgumentException">Thrown if <paramref name="secureString"/> lacks any of its properties.</exception>
    /// <exception cref="CryptographicException">Thrown if <paramref name="secureString" /> cannot be decrypted using <paramref name="urlLaunchSystemPrivateKey" /> or if the provided signature cannot be verified using <paramref name="integratingPartyPublicKey" />.</exception>
    public string View(EncryptedUrlString secureString, RSA urlLaunchSystemPrivateKey, RSA integratingPartyPublicKey) {
        if (urlLaunchSystemPrivateKey == null) {
            throw new ArgumentNullException(nameof(urlLaunchSystemPrivateKey));
        }

        if (integratingPartyPublicKey == null) {
            throw new ArgumentNullException(nameof(integratingPartyPublicKey));
        }

        var signedUrlString = UrlStringEncryptor.Decrypt(secureString, urlLaunchSystemPrivateKey);
        var isValid = UrlStringSigner.Verify(signedUrlString, integratingPartyPublicKey);

        if (!isValid) {
            throw new CryptographicException("Could not verify url string signature.");
        }

        return Encoding.UTF8.GetString(signedUrlString.UrlString);
    }
}
