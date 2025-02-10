using System.Security.Cryptography;

namespace Sectra.UrlLaunch.Pki;

internal sealed class UrlStringSigner {

    public static SignedUrlString Sign(byte[] input, RSA key) {
        if (key is RSACryptoServiceProvider rsaCryptoServiceProviderKey) {
            key = rsaCryptoServiceProviderKey.GetUpgradedCsp();
        }
        var signedByteString = key.SignData(input, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return new SignedUrlString(input, signedByteString);
    }

    public static bool Verify(SignedUrlString signedUrlString, RSA key) {
        var valid = key.VerifyData(signedUrlString.UrlString, signedUrlString.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return valid;
    }
}
