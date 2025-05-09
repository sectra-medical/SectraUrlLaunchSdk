using System;
using System.Linq;
using System.Security.Cryptography;

namespace Sectra.UrlLaunch.Pki;
internal sealed class UrlStringEncryptor {
    /// <summary>
    /// The maximum signature length that is allowed in number of bytes.
    /// </summary>
    public const int MaxSignatureLength = 1024;

    /// <summary>
    /// The number of bytes that the information about the signature length occupies.
    /// </summary>
    public const int SignatureLengthBytes = 4;

    public static EncryptedUrlString Encrypt(SignedUrlString input, RSA key) {

        var signature = input.Signature ?? Array.Empty<byte>();
        var urlString = input.UrlString ?? Array.Empty<byte>();

        if (signature.Length > MaxSignatureLength) {
            throw new ArgumentOutOfRangeException($"Signature length exceeds the allowed length of {MaxSignatureLength}.");
        }

        var signatureLength = BitConverter.GetBytes(signature.Length);

        // Create a combined array with the length of the url string being the first four bytes.
        var payloadAndSignature = new[]
        {
            signatureLength,
            signature,
            urlString,
        }
        .SelectMany(x => x)
        .ToArray();

        var encryptedUrlString = SymmetricalEncryptor.Encrypt(payloadAndSignature, out byte[] symmetricalKey, out byte[] iv);
        var encryptedSymmetricalKey = key.Encrypt(symmetricalKey, RSAEncryptionPadding.OaepSHA1);

        return new EncryptedUrlString {
            SymmetricallyEncryptedUrlString = encryptedUrlString,
            EncryptedSymmetricPassword = encryptedSymmetricalKey,
            InitializationVector = iv,
        };
    }

    public static SignedUrlString Decrypt(EncryptedUrlString input, RSA key) {
        if (input == null) {
            throw new ArgumentNullException(nameof(input));
        }

        if (key == null) {
            throw new ArgumentNullException(nameof(key));
        }

        if (input.EncryptedSymmetricPassword == null || input.SymmetricallyEncryptedUrlString == null || input.InitializationVector == null) {
            throw new ArgumentException($"Properties {nameof(input.EncryptedSymmetricPassword)}, {nameof(input.SymmetricallyEncryptedUrlString)} and {nameof(input.InitializationVector)} of argument '{nameof(input)}' must not be null.");
        }

        byte[]? symmetricalKey = null;
        try {
            symmetricalKey = key.Decrypt(input.EncryptedSymmetricPassword, RSAEncryptionPadding.OaepSHA1);
        }
        catch (CryptographicException ex) {
            throw new CryptographicException("Could not decrypt url string symmetric encryption key.", ex);
        }

        // Decrypt the actual payload url string.
        var decryptedUrlStringAndSignature = SymmetricalEncryptor.Decrypt(
            input.SymmetricallyEncryptedUrlString,
            symmetricalKey,
            input.InitializationVector);

        if (decryptedUrlStringAndSignature.Length < SignatureLengthBytes) {
            throw new ArgumentException("The decrypted data contains no or insufficient signature length information.");
        }

        byte[] signatureLength = new byte[SignatureLengthBytes];
        Array.Copy(decryptedUrlStringAndSignature, signatureLength, SignatureLengthBytes);
        var signatureLengthInt = BitConverter.ToInt32(signatureLength, 0);

        if (signatureLengthInt > MaxSignatureLength) {
            throw new ArgumentOutOfRangeException($"Signature length exceeds the allowed length of {MaxSignatureLength}.");
        }

        if (signatureLengthInt > decryptedUrlStringAndSignature.Length - SignatureLengthBytes) {
            throw new ArgumentException($"The specified signature length of {signatureLengthInt} does not match the length of the signature and url string data of {decryptedUrlStringAndSignature.Length - SignatureLengthBytes}.");
        }

        byte[] signature = new byte[signatureLengthInt];
        Array.Copy(decryptedUrlStringAndSignature, SignatureLengthBytes, signature, 0, signatureLengthInt);

        byte[] urlString = new byte[decryptedUrlStringAndSignature.Length - signatureLengthInt - SignatureLengthBytes];
        Array.Copy(decryptedUrlStringAndSignature, SignatureLengthBytes + signatureLengthInt, urlString, 0, urlString.Length);

        return new SignedUrlString(urlString, signature);
    }
}
