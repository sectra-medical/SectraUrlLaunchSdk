using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sectra.UrlLaunch.Pki;

internal static class RSACryptoServiceProviderExtensions {
    /// <summary>
    /// Object identifier for sha-256 with rsa encryption (as specified in rfc 7247).
    /// </summary>
    private const string sha256RSAOid = "1.2.840.113549.1.1.11";
    /// <summary>
    /// Object identifier for SHA-512 with RSA encryption (as specified in RFC 7247).
    /// </summary>
    private const string sha512RSAOid = "1.2.840.113549.1.1.13";

    /// <summary>
    /// The signature method identifier/url for rsa-sha256 (as specified in rfc 6931).
    /// </summary>
    public const string XmlDsigRSASHA256Url = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    /// <summary>
    /// The signature method identifier/URL for RSA-SHA512 (as specified in RFC 6931).
    /// </summary>
    public const string XmlDsigRSASHA512Url = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

    /// <summary>
    /// Gets or sets the warn logger action that will be invoked when logging warning messages.
    /// </summary>
    /// <value>
    /// The warn logger.
    /// </value>
    public static Action<string> WarnLogger { get; set; } = message => Console.Error.WriteLine($"{nameof(RSACryptoServiceProviderExtensions)} WARN: {message}");

    /// <summary>
    /// Adds the supported SHA-2 algorithm of the given certificate to the cryptography configuration, when applicable.
    /// </summary>
    public static void AddSha2Algorithm(this X509Certificate2 certificate) {
        if (certificate?.SignatureAlgorithm?.Value == sha256RSAOid) {
            CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA256SignatureDescription), XmlDsigRSASHA256Url);
        } else if (certificate?.SignatureAlgorithm?.Value == sha512RSAOid) {
            CryptoConfig.AddAlgorithm(typeof(RSAPKCS1SHA512SignatureDescription), XmlDsigRSASHA512Url);
        }
    }

    /// <summary>
    /// If the certificate's private key is an rsa cryptographic service provider, this method attempts to
    /// upgrade it to a key that handles both sha-2 and aes. If the upgrade fails the key is returned as is.
    /// </summary>
    public static RSACryptoServiceProvider GetUpgradedCsp(this RSACryptoServiceProvider privateKey) {
        if (Environment.OSVersion.Platform != PlatformID.Win32NT) {
            // GetUpgradedCsp is only available on Windows.
            return privateKey;
        }
#pragma warning disable CA1416
        const int PROV_RSA_AES = 24;
        CspKeyContainerInfo info = privateKey.CspKeyContainerInfo;
        CspParameters cspParameters = new CspParameters(PROV_RSA_AES) {
            KeyContainerName = info.KeyContainerName,
            KeyNumber = (int)info.KeyNumber,
            Flags = CspProviderFlags.UseExistingKey,
        };

        if (info.MachineKeyStore) {
            cspParameters.Flags |= CspProviderFlags.UseMachineKeyStore;
        }

        if (info.ProviderType == PROV_RSA_AES) {
            // Already a PROV_RSA_AES, copy the ProviderName in case it's 3rd party
            cspParameters.ProviderName = info.ProviderName;
        }

        try {
            // 3rd party providers and smart card providers may not handle this upgrade. This will happen if
            // info.ProviderName is not a known-convertible value. In this case, the provider type is correct
            // anyways, so we return the key as is.
            return new RSACryptoServiceProvider(cspParameters);
        }
        catch (CryptographicException ex) {
            WarnLogger($"Key upgrade attempt failed, will use key as is. Reason: {ex.Message}");
            return privateKey;
        }
#pragma warning restore CA1416
    }
}

/// <summary>
/// Used to validate SHA256 signatures
/// </summary>
internal class RSAPKCS1SHA256SignatureDescription : SignatureDescription {
    /// <summary>
    /// Initializes a new instance of the <see cref="RSAPKCS1SHA256SignatureDescription"/> class.
    /// </summary>
    public RSAPKCS1SHA256SignatureDescription() {
        KeyAlgorithm = typeof(RSACryptoServiceProvider).FullName;
#pragma warning disable SYSLIB0021
        DigestAlgorithm = typeof(SHA256CryptoServiceProvider).FullName;
#pragma warning restore SYSLIB0021
        FormatterAlgorithm = typeof(RSAPKCS1SignatureFormatter).FullName;
        DeformatterAlgorithm = typeof(RSAPKCS1SignatureDeformatter).FullName;
    }

    /// <summary>
    /// Creates signature deformatter
    /// </summary>
    /// <param name="key">The key to use in the <see cref="T:System.Security.Cryptography.AsymmetricSignatureDeformatter" />.</param>
    /// <returns>The newly created <see cref="T:System.Security.Cryptography.AsymmetricSignatureDeformatter" /> instance.</returns>
    public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key) {
        var deformatter = new RSAPKCS1SignatureDeformatter(key);
        deformatter.SetHashAlgorithm("SHA256");
        return deformatter;
    }

    /// <summary>
    /// Creates signature formatter
    /// </summary>
    /// <param name="key">The key to use in the <see cref="T:System.Security.Cryptography.AsymmetricSignatureFormatter" />.</param>
    /// <returns>The newly created <see cref="T:System.Security.Cryptography.AsymmetricSignatureFormatter" /> instance.</returns>
    public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key) {
        var formatter = new RSAPKCS1SignatureFormatter(key);
        formatter.SetHashAlgorithm("SHA256");
        return formatter;
    }
}

/// <summary>
/// Used to validate SHA512 signatures
/// </summary>
internal class RSAPKCS1SHA512SignatureDescription : SignatureDescription {
    /// <summary>
    /// Initializes a new instance of the <see cref="RSAPKCS1SHA512SignatureDescription"/> class.
    /// </summary>
    public RSAPKCS1SHA512SignatureDescription() {
        KeyAlgorithm = typeof(RSACryptoServiceProvider).FullName;
#pragma warning disable SYSLIB0021
        DigestAlgorithm = typeof(SHA512CryptoServiceProvider).FullName;
#pragma warning restore SYSLIB0021
        FormatterAlgorithm = typeof(RSAPKCS1SignatureFormatter).FullName;
        DeformatterAlgorithm = typeof(RSAPKCS1SignatureDeformatter).FullName;
    }

    /// <summary>
    /// Creates signature deformatter
    /// </summary>
    /// <param name="key">The key to use in the <see cref="T:System.Security.Cryptography.AsymmetricSignatureDeformatter" />.</param>
    /// <returns>The newly created <see cref="T:System.Security.Cryptography.AsymmetricSignatureDeformatter" /> instance.</returns>
    public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key) {
        var deformatter = new RSAPKCS1SignatureDeformatter(key);
        deformatter.SetHashAlgorithm("SHA512");
        return deformatter;
    }

    /// <summary>
    /// Creates signature formatter
    /// </summary>
    /// <param name="key">The key to use in the <see cref="T:System.Security.Cryptography.AsymmetricSignatureFormatter" />.</param>
    /// <returns>The newly created <see cref="T:System.Security.Cryptography.AsymmetricSignatureFormatter" /> instance.</returns>
    public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key) {
        var formatter = new RSAPKCS1SignatureFormatter(key);
        formatter.SetHashAlgorithm("SHA512");
        return formatter;
    }
}
