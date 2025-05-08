using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Sectra.UrlLaunch.SharedSecret;

/// <summary>
/// Provides easy to use apis for authenticated symmetric encryption 
/// with ciphertext packed in a custom format
/// 
/// The authentication tags and other data required for decryption are
/// automatically packed together in a dense format
/// 
/// NET Standard 2.1 (e.g .NET 6) implementation uses AesGcm (built in auth)
/// NET Standard 2.0 (e.g. NET Framework 4.8) implementation uses Aes (AES-CBC) + HMACSHA256 for auth
/// 
/// </summary>
/// <remarks>
/// NET 6 and NET 4.8 encryption schemes are not compatible
/// </remarks>
internal class SymmetricEncryption {

    private const int KeyByteSize = 32;
    /// <summary>
    /// Size of IV must match BlockSize. In AES block sized is always
    /// 128 bits (https://en.wikipedia.org/wiki/Advanced_Encryption_Standard)
    /// </summary>
    private const int IvByteSize = 16;

    /// <summary>
    /// Match IV size
    /// </summary>
    private const int NonceByteSizeAesCbc = 16;

    /// <summary>
    /// Aes GCM supported nonce size is 12
    /// </summary>
    private const int NonceByteSizeAesGcm = 12;

    private const string CipherKeyDomainIdentifier = "sectra/symmetricencryption/cipherkey";
    private const string CipherIvDomainIdentifier = "sectra/symmetricencryption/cipheriv";
    private const string MacKeyDomainIdentifier = "sectra/symmetricencryption/mackey";

    private enum Format {
        /// <summary>
        /// Version 1 is NET Framework 4.8 compatible but uses a custom
        /// (less efficient) algorithm
        /// </summary>
        Version1 = 1,

        /// <summary>
        /// Version 2 (only NET 6+)
        /// </summary>
        Version2 = 2
    }

    /// <summary>
    /// Return a 32 byte key suitable for use with this class
    /// </summary>
    /// <returns></returns>
    public static byte[] GenerateKey() {
        return Rng.GetBytes(KeyByteSize);
    }

    /// <summary>
    /// Ideally a nonce (number once) should not be randomly chosen as uniqueness
    /// is the important characteristc, not randomness, and there is theoretically
    /// a (very small) chance of getting the same nonce twice.
    /// However, a counter has the problem of not being stateless
    /// which complicates the api and usage introducing risks of
    /// using the api incorrectly and far worse security bugs.
    /// </summary>
    private static byte[] GenerateNonce(int byteSize) {
        return Rng.GetBytes(byteSize);
    }

    /// <summary>
    /// Encrypt a string and return ciphertext in Base64 encoding
    /// </summary>
    public static string Encrypt(string plainText, byte[] key) {
        return Convert.ToBase64String(Encrypt(Encoding.UTF8.GetBytes(plainText), key));
    }

    /// <summary>
    /// Decrypt a base64 ciphertext string and return plaintext string
    /// </summary>
    public static string Decrypt(string cipherTextBase64, byte[] key) {
        return Encoding.UTF8.GetString(Decrypt(Convert.FromBase64String(cipherTextBase64), key));
    }

    /// <summary>
    /// Produces a Message Authentication Code (MAC) over the input
    /// </summary>
    /// <param name="input">input to create MAC over</param>
    /// <param name="macKey">Mac key, should be ephemeral</param>
    /// <returns>MAC over input</returns>
    private static byte[] Mac(Stream input, byte[] macKey) {
        var hmac = new HMACSHA256(macKey);
        return hmac.ComputeHash(input);
    }

    /// <summary>
    /// Derive a cipher key and MAC key from the main key and a nonce
    /// </summary>
    private static (byte[] CipherKey, byte[] CipherIv, byte[] MacKey) DeriveKeys(byte[] key, byte[] nonce) {
#if NET8_0_OR_GREATER
        var cipherKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, key, KeyByteSize, null, Combine(CipherKeyDomainIdentifier, nonce));
        var cipherIv = HKDF.DeriveKey(HashAlgorithmName.SHA256, key, IvByteSize, null, Combine(CipherIvDomainIdentifier, nonce));
        var macKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, key, KeyByteSize, null, Combine(MacKeyDomainIdentifier, nonce));
#else
        var cipherKey = Hkdf.Derive(key, KeyByteSize, Combine(CipherKeyDomainIdentifier, nonce));
        // HKdf.Derive has a minimum output length of 32
        var cipherIv = Hkdf.Derive(key, 32, Combine(CipherIvDomainIdentifier, nonce)).Take(IvByteSize).ToArray();
        var macKey = Hkdf.Derive(key, KeyByteSize, Combine(MacKeyDomainIdentifier, nonce));

#endif
        return (CipherKey: cipherKey, CipherIv: cipherIv, MacKey: macKey);
    }

    private static byte[] Combine(string domainIdentifier, byte[] nonce) {
        return Encoding.UTF8.GetBytes(domainIdentifier).Concat(nonce).ToArray();
    }

    private static byte[] EncryptNetFramework(IEnumerable<byte> plainText, byte[] key) {
        var cipherTextStream = new MemoryStream();
        EncryptNetFramework(new MemoryStream(plainText.ToArray()), cipherTextStream, key);
        return cipherTextStream.ToArray();
    }

    /// <summary>
    /// Read plaintext stream, encrypt, mac and pack, and place result in cipher stream
    /// 
    /// Result is packed in the following format (bytes)
    /// |1      |32 |16   |N         |
    /// |Version|MAC|Nonce|Ciphertext|
    /// but should in general be considered opaque to the caller
    /// 
    /// </summary>
    /// <param name="plainTextStream">Plaintext to encrypt</param>
    /// <param name="cipherTextStream">Resulting ciphertext</param>
    /// <param name="key">Main key</param>
    /// <exception cref="CryptographicException"></exception>
    private static void EncryptNetFramework(Stream plainTextStream, Stream cipherTextStream, byte[] key) {

        if (key.Length < KeyByteSize) {
            throw new CryptographicException("Key is too short. Hint: Use SymmetricEncryption.GenerateKey() to securely generate a random key");
        }

        cipherTextStream.WriteByte((byte)Format.Version1);

        // Even though using the same key for encryption and mac is likely fine
        // https://crypto.stackexchange.com/questions/8081/using-the-same-secret-key-for-encryption-and-authentication-in-a-encrypt-then-ma
        // we take the safe route and derive new keys using HKDF and a nonce

        var nonce = GenerateNonce(NonceByteSizeAesCbc);
        var ephemeralKeys = DeriveKeys(key, nonce);

        // Respect Moxies Cryptography Doom Principle and encrypt-then-mac
        // Also: https://www.iacr.org/archive/crypto2001/21390309.pdf

        // Encrypt
        var cipherText = new MemoryStream();
        RawEncrypt(plainTextStream, cipherText, ephemeralKeys.CipherKey, ephemeralKeys.CipherIv);

        // Then MAC
        cipherText.Position = 0;
        var mac = Mac(cipherText, ephemeralKeys.MacKey);

        // Pack
        cipherTextStream.Write(mac, 0, mac.Length);
        cipherTextStream.Write(nonce, 0, nonce.Length);
        cipherText.Position = 0;
        cipherText.CopyTo(cipherTextStream);
    }

    private static void RawEncrypt(Stream plainText, Stream cipherText, byte[] key, byte[] iv) {
        Aes aes = Aes.Create();
        var encryptor = aes.CreateEncryptor(key, iv);
        var cs = new CryptoStream(cipherText, encryptor, CryptoStreamMode.Write);
        plainText.CopyTo(cs);
        cs.FlushFinalBlock();
    }

    private static byte[] DecryptNetFramework(IEnumerable<byte> cipherText, byte[] key) {
        var plainTextStream = new MemoryStream();
        DecryptNetFramework(new MemoryStream(cipherText.ToArray()), plainTextStream, key);
        return plainTextStream.ToArray();
    }

    /// <summary>
    /// Read ciphertext stream, validate MAC, decrypt and place result in plaintext stream
    /// </summary>
    /// <param name="cipherTextStream">Ciphertext to decrypt</param>
    /// <param name="plainTextStream">Plaintext result</param>
    /// <param name="key">Symmetric key used to encrypt the data</param>
    /// <exception cref="CryptographicException"></exception>
    private static void DecryptNetFramework(Stream cipherTextStream, Stream plainTextStream, byte[] key) {

        if (!cipherTextStream.CanSeek) {
            var memoryStream = new MemoryStream();
            cipherTextStream.CopyTo(memoryStream);
            cipherTextStream = memoryStream;
        }

        // Check version
        var version = cipherTextStream.ReadByte();
        if (version != (int)Format.Version1) {
            throw new NotSupportedException($"Data was encrypted with an unsupported cipher, expected {Format.Version1}, got {version}");
        }

        // Unpack MAC
        var mac = new byte[KeyByteSize];
        cipherTextStream.Read(mac, 0, mac.Length);

        // Unpack Nonce
        var nonce = new byte[NonceByteSizeAesCbc];
        cipherTextStream.Read(nonce, 0, nonce.Length);

        var ephemeralKeys = DeriveKeys(key, nonce);

        // Validate MAC
        var cipherTextStart = cipherTextStream.Position;
        var vMac = Mac(cipherTextStream, ephemeralKeys.MacKey);
        if (!vMac.SequenceEqualConstantTime(mac, KeyByteSize)) {
            throw new CryptographicException($"Failed to authenticate message. Got mac {Convert.ToBase64String(vMac)} expected {Convert.ToBase64String(mac)}");
        }

        cipherTextStream.Position = cipherTextStart;
        RawDecrypt(cipherTextStream, plainTextStream, ephemeralKeys.CipherKey, ephemeralKeys.CipherIv);
    }

    private static void RawDecrypt(Stream cipherText, Stream plainText, byte[] key, byte[] iv) {
        var aes = Aes.Create();
        var decryptor = aes.CreateDecryptor(key, iv);
        using (var cs = new CryptoStream(cipherText, decryptor, CryptoStreamMode.Read)) {
            cs.CopyTo(plainText);
        }
    }

#if NETSTANDARD2_1_OR_GREATER || NET8_0_OR_GREATER

    /// <summary>
    /// Largest possible tag size. See
    /// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
    /// There is correlation between tag size, ciphertext size and how
    /// many decryption calls an attacker would need to leak information
    /// about the key. For small tags and large ciphertext this could
    /// lead to practical attacks
    /// </summary>
    private static int TagByteSize = 16;

    /// <summary>
    /// Read plaintext stream, encrypt, mac and pack, and place result in cipher stream
    ///
    /// Result is packed in the following format (bytes)
    /// |1      |12   |16 |N         |
    /// |Version|Nonce|Tag|ciphertext|
    /// but should in general be considered opaque to the caller
    /// </summary>
    public static void Encrypt(Stream plainTextStream, Stream cipherTextStream, byte[] key) {
        var memoryStream = new MemoryStream();
        plainTextStream.CopyTo(memoryStream);
        var c = Encrypt(memoryStream.ToArray(), key).ToArray();
        cipherTextStream.Write(c, 0, c.Length);
    }

    /// <summary>
    /// Encrypt plaintext using key, mac, and pack
    ///
    /// Result is packed in the following format (bytes)
    /// |1      |12   |16 |N         |
    /// |Version|Nonce|Tag|ciphertext|
    /// but should in general be considered opaque to the caller
    /// </summary>
    public static byte[] Encrypt(ReadOnlySpan<byte> plainText, byte[] key) {
#if NET8_0_OR_GREATER
        AesGcm aes = new(key, TagByteSize);
#else
        AesGcm aes = new(key);
#endif

        var nonce = GenerateNonce(NonceByteSizeAesGcm);
        var cipherText = new byte[plainText.Length];
        var tag = new byte[TagByteSize];

        aes.Encrypt(nonce, plainText, cipherText, tag);

        // Pack nonce, ciphertext and tag
        return (new byte[] { (byte)Format.Version2 }).Concat(nonce).Concat(tag).Concat(cipherText).ToArray();
    }

    //[SupportedOSPlatform("windows")]
    [Obsolete("Only use if cross platform support with .NET Framwork 4.8 is needed")]
    public static byte[] EncryptLegacyNetFramework(IEnumerable<byte> plainText, byte[] key) {
        return EncryptNetFramework(plainText, key);
    }

    //[SupportedOSPlatform("windows")]
    [Obsolete("Only use if cross platform support with .NET Framwork 4.8 is needed")]
    public static string EncryptLegacyNetFramework(string plainText, byte[] key) {
        return Convert.ToBase64String(EncryptLegacyNetFramework(Encoding.UTF8.GetBytes(plainText), key));
    }

    /// <summary>
    /// Read cipher stream, decrypt using key and place decrypted plaintext in plain text stream
    /// </summary>
    public static void Decrypt(Stream cipherTextStream, Stream plainTextStream, byte[] key) {
        var memoryStream = new MemoryStream();
        cipherTextStream.CopyTo(memoryStream);
        var p = Decrypt(memoryStream.ToArray(), key);
        plainTextStream.Write(p, 0, p.Length);
    }

    /// <summary>
    /// Decrypt cipher text using key and return plain text
    /// </summary>
    public static byte[] Decrypt(ReadOnlySpan<byte> cipherText, byte[] key) {
        if (cipherText[0] == (byte)Format.Version1) {
            // Modern .net should be able to decrypt from legacy systems as well.
            return DecryptNetFramework(cipherText.ToArray(), key);
        }
        if (cipherText[0] != (byte)Format.Version2) {
            throw new NotSupportedException($"Data was encrypted with an unsupported cipher, expected {Format.Version2}, got {cipherText[0]}");
        }
        var cipherTextLength = cipherText.Length - NonceByteSizeAesGcm - TagByteSize - 1;
#if NET8_0_OR_GREATER
        AesGcm aes = new(key, TagByteSize);
#else
        AesGcm aes = new(key);
#endif
        var plainText = new byte[cipherTextLength];
        aes.Decrypt(
            cipherText.Slice(1, NonceByteSizeAesGcm),
            cipherText.Slice(1 + NonceByteSizeAesGcm + TagByteSize, cipherTextLength),
            cipherText.Slice(1 + NonceByteSizeAesGcm, TagByteSize),
            plainText);
        return plainText;
    }

    //[SupportedOSPlatform("windows")]
    [Obsolete("Only use if cross platform support with .NET Framwork 4.8 is needed")]
    public static byte[] DecryptLegacyNetFramework(IEnumerable<byte> cipherText, byte[] key) {
        return DecryptNetFramework(cipherText, key);
    }

    //[SupportedOSPlatform("windows")]
    [Obsolete("Only use if cross platform support with .NET Framwork 4.8 is needed")]
    public static string DecryptLegacyNetFramework(string cipherTextBase64, byte[] key) {
        return Encoding.UTF8.GetString(DecryptLegacyNetFramework(Convert.FromBase64String(cipherTextBase64), key));
    }

#elif NETSTANDARD2_0_OR_GREATER
    public static byte[] Encrypt(IEnumerable<byte> plainText, byte[] key) {
        return EncryptNetFramework(plainText, key);
    }
    public static void Encrypt(Stream plainTextStream, Stream cipherTextStream, byte[] key) {
        EncryptNetFramework(plainTextStream, cipherTextStream, key);
    }

    public static byte[] Decrypt(IEnumerable<byte> cipherText, byte[] key) {
        return DecryptNetFramework(cipherText, key);
    }
    public static void Decrypt(Stream cipherTextStream, Stream plainTextStream, byte[] key) {
        DecryptNetFramework(cipherTextStream, plainTextStream, key);
    }

#endif
}