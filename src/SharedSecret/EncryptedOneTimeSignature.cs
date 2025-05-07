using System;
using System.Linq;
using System.Text;
#if NET8_0_OR_GREATER
using System.Security.Cryptography;
#endif

namespace Sectra.UrlLaunch.SharedSecret;
internal class EncryptedOneTimeSignature {

    private const int KeyByteSize = 32;

    /// <summary>
    /// Aligned with <see cref="SymmetricEncryption.NonceByteSizeAesGcm"/>
    /// </summary>
    private const int NonceByteSizeAesGcm = 12;

    private const string CipherKeyDomainIdentifier = "sectra/encryptedonetimesignature/cipherkey";
    private const string SignatureKeyDomainIdentifier = "sectra/encryptedonetimesignature/signaturekey";

    /// <summary>
    /// Encrypt data and sign using HMACSHA256 and a symmetric (shared) key
    ///
    /// Pros:
    ///   * Simple and battle proven algorithm
    ///   * Fast
    ///   * Encrypt and sign using a single key
    /// Cons:
    ///   * Since key is shared in two or more locations:
    ///     - it more susceptible to a compromise
    ///     - Weaker Non-repudiation claims: any holder of the key could have signed
    ///       some data
    /// </summary>
    /// <param name="data">data to encrypt sign and pack</param>
    /// <param name="key"></param>
    public static string EncryptAndSign(string data, byte[] key) {
        var cipherText = EncryptAndSign(Encoding.UTF8.GetBytes(data), key);
        return Convert.ToBase64String(cipherText);
    }

    /// <summary>
    /// Encrypt data and sign using HMACSHA256 and a symmetric (shared) key
    ///
    /// Pros:
    ///   * Simple and battle proven algorithm
    ///   * Fast
    ///   * Encrypt and sign using a single key
    /// Cons:
    ///   * Since key is shared in two or more locations:
    ///     - it more susceptible to a compromise
    ///     - Weaker Non-repudiation claims: any holder of the key could have signed
    ///       some data
    /// </summary>
    /// <param name="data">data to encrypt sign and pack</param>
    /// <param name="key"></param>
    public static byte[] EncryptAndSign(byte[] data, byte[] key) {

        var nonce = Rng.GetBytes(NonceByteSizeAesGcm);

        var ephemeralKeys = DeriveKeys(key, nonce);

        var cipherText = SymmetricEncryption.Encrypt(data, ephemeralKeys.CipherKey);

        var signedData = OneTimeSignature.Sign(cipherText, ephemeralKeys.SignatureKey);


        return nonce.Concat(signedData).ToArray();
    }

    /// <summary>
    /// Verify signed data using HMACSHA256 and decrypt
    ///
    /// Used nonces (to enforce one-time usage) will be managed in an in memory shared storage
    /// </summary>
    /// <param name="signedCipherText">signature and encrypted data to verify</param>
    /// <param name="key">symmetric key used to sign the data</param>
    /// <returns>Plaintext data that was signed and encrypted if signature verifies, otherwise exception is thrown</returns>

    public static string VerifyAndDecrypt(string signedCipherText, byte[] key) {
        var plainText = VerifyAndDecrypt(Convert.FromBase64String(signedCipherText), key);
        return Encoding.UTF8.GetString(plainText);
    }

    /// <summary>
    /// Verify signed data using HMACSHA256 and decrypt
    ///
    /// Used nonces (to enforce one-time usage) will be managed in an in memory shared storage
    /// </summary>
    /// <param name="signedCipherText">signature and encrypted data to verify</param>
    /// <param name="key">symmetric key used to sign the data</param>
    /// <returns>Plaintext data that was signed and encrypted if signature verifies, otherwise exception is thrown</returns>

    public static byte[] VerifyAndDecrypt(byte[] signedCipherText, byte[] key) {
        var nonceByteSize = NonceByteSizeAesGcm;

        var nonce = signedCipherText.Take(nonceByteSize);
        var ephemeralKeys = DeriveKeys(key, nonce.ToArray());

        var cipherText = OneTimeSignature.Verify(signedCipherText.Skip(nonceByteSize).ToArray(), ephemeralKeys.SignatureKey);

        return SymmetricEncryption.Decrypt(cipherText, ephemeralKeys.CipherKey);

    }

    private static (byte[] CipherKey, byte[] SignatureKey) DeriveKeys(byte[] key, byte[] nonce) {
#if NET8_0_OR_GREATER
        var cipherKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, key, KeyByteSize, null, Combine(CipherKeyDomainIdentifier, nonce));
        var signatureKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, key, KeyByteSize, null, Combine(SignatureKeyDomainIdentifier, nonce));
#else
        var cipherKey = Hkdf.Derive(key, KeyByteSize, Combine(CipherKeyDomainIdentifier, nonce));
        var signatureKey = Hkdf.Derive(key, KeyByteSize, Combine(SignatureKeyDomainIdentifier, nonce));
#endif
        return (cipherKey, signatureKey);
    }

    private static byte[] Combine(string domainIdentifier, byte[] nonce) {
        return Encoding.UTF8.GetBytes(domainIdentifier).Concat(nonce).ToArray();
    }
}
