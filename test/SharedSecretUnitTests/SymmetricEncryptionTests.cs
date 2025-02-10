#if NET48_OR_GREATER
using System;
#endif
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Sectra.UrlLaunch.SharedSecret;

public class SymmetricEncryptionTests {

    private static string plainTextTestData = "The quick brown fox jumps over the lazy dog";
    private static byte[] key = SymmetricEncryption.GenerateKey();

    [Fact]
    public void SymmetricEncryption_EncryptWithShortKeySize_Fails() {
        var myKey = Encoding.UTF8.GetBytes("supersecret");
        Assert.Throws<CryptographicException>(
            () => SymmetricEncryption.Encrypt(Encoding.UTF8.GetBytes(plainTextTestData), myKey));
    }

    [Fact]
    public void SymmetricEncryption_EncryptThenDecrypt_IsEqual() {
        var cipherText = SymmetricEncryption.Encrypt(Encoding.UTF8.GetBytes(plainTextTestData), key);

        var plainText = Encoding.UTF8.GetString(SymmetricEncryption.Decrypt(cipherText, key).ToArray());
        Assert.Equal(plainTextTestData, plainText);
    }

    [Fact]
    public void SymmetricEncryption_EncryptStringThenDecrypt_IsEqual() {
        var cipherText = SymmetricEncryption.Encrypt(plainTextTestData, key);

        var plainText = SymmetricEncryption.Decrypt(cipherText, key);
        Assert.Equal(plainTextTestData, plainText);
    }

    [Fact]
    public void SymmetricEncryption_EncryptStreamThenDecrypt_IsEqual() {
        var cipherText = SymmetricEncryption.Encrypt(plainTextTestData, key);

        var plainText = SymmetricEncryption.Decrypt(cipherText, key);
        Assert.Equal(plainTextTestData, plainText);
    }

    [Fact]
    public void SymmetricEncryption_EncryptTwiceUsingSameKey_AreNotEqual() {
        var cipherText1 = SymmetricEncryption.Encrypt(plainTextTestData, key);
        var cipherText2 = SymmetricEncryption.Encrypt(plainTextTestData, key);

        Assert.NotEqual(cipherText1, cipherText2);
    }

#if NETSTANDARD2_1_OR_GREATER
    [Fact]
    public void SymmetricEncryption_EncryptNetFrameworkDecryptNet6_Throws() {
        string cipherText = "AdPu52XQAipY2IF436f2T0qZT6yfap4CGgM0PZ+3TO0r3uDlaRe3KVc0yGAWWXxQGIuyY+Z8FAqt2HR27xVwvHORv5b4KL6xXmbbrSV9IbT7dNnq3ivFbyklQwAbkjJL1LDU1hXVLkBrI6yEfKNk0VUqgfusfva6zmKItZfMAfoHekY8GuXG4upwX1bDr4EYkrpiG4ILXTmZ6SiFN2wvCXs=";

        Assert.Throws<NotSupportedException>(() => SymmetricEncryption.Decrypt(cipherText, key));
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    [Obsolete]
    public void SymmetricEncryption_EncryptNetFrameworkDecryptNet6Legacy_Succeeds() {
        // plainTextTestData encrypted on Net 4.8 using key

        string cipherText = "AXZwdyHKl8vV32RAqu+YFWd4gJczYro2xHRNQAWgvPipliDH55EYUbrW7rvhWwIYx3LQjPCqgyF9jynN4htumTryxbUtC0RJ9QRu5v+T7bbJaJkqb0lg9Dm6ZeEIGlH3iQ==";
        byte[] key = Convert.FromBase64String("UTKhAYiVVuemX0BVR05MTvTputqyQUGN2oB2j4ZZShc=");


        var plainText = SymmetricEncryption.DecryptLegacyNetFramework(cipherText, key);
        Assert.Equal(plainTextTestData, plainText);
    }

    [Fact]
    [SupportedOSPlatform("windows")]
    [Obsolete]
    public void SymmetricEncryption_EncryptDecryptLegacyNetFramework_Succeeds() {
        var cipherText = SymmetricEncryption.EncryptLegacyNetFramework(Encoding.UTF8.GetBytes(plainTextTestData), key);
        var plainText = SymmetricEncryption.DecryptLegacyNetFramework(cipherText, key);
        Assert.Equal(plainTextTestData, Encoding.UTF8.GetString(plainText.ToArray()));
    }

    [SupportedOSPlatform("windows")]
    [Fact]
    public void SymmetricEncryption_AesCng_UsesBlockSize128() {
        const int expectedBlockSize = 128;

        Assert.Equal(expectedBlockSize, Aes.Create().BlockSize);
        Assert.Equal(expectedBlockSize, new AesCng().BlockSize);
    }

#endif

#if NET48_OR_GREATER

    [Fact]
    public void SymmetricEncryption_DecryptTamperedMessage_Fails() {
        var cipherText1 = SymmetricEncryption.Encrypt(Encoding.UTF8.GetBytes(plainTextTestData), key);
        var cipherText2 = SymmetricEncryption.Encrypt(Encoding.UTF8.GetBytes(plainTextTestData), key);
        // Tamper by forging a new message from two old (version, mac and nonce from first
        // and ciphertext from second)
        var forged = cipherText1.Take(45).Concat(cipherText2.Skip(45));

        Assert.Throws<CryptographicException>(() => SymmetricEncryption.Decrypt(forged, key));
    }

    [Fact]
    public void SymmetricEncryption_EncryptNet6DecryptNetFramework_Throws() {
        string cipherText = "An4kX/KF8i3+UaG+MQgUHFAjNtPZyUVrmhk5hi+u6l62XmJCkUGFudghBtttRk8p+vi9zx7zbxuDW9NnsI0YazlJPNX8O79S";

        Assert.Throws<NotSupportedException>(() => SymmetricEncryption.Decrypt(cipherText, key));
    }

    [Fact]
    public void SymmetricEncryption_EncryptNet6LegacyDecryptNetFramework_Succeeds() {
        // plainTextTestData encrypted using key on NET6 using EncryptLegacyNetFramework method
        string cipherText = "AYzB8TSRbhdsSudz0RhqciOa/zcU8H7ofC4JqrPfib+eCBzUHXNnRsAJjPp+TtuL3Qj3OhpP2fmO5cudnzUna2sxZixuGP0AvFpD9q3YfgNlEr/Q2hRL+ObFinn4PRCSbg==";
        byte[] key = Convert.FromBase64String("wAx4qO+azccfOP8/PS5z6do5iHW7QxMUmf105Z4xHO0=");

        var plainText = SymmetricEncryption.Decrypt(cipherText, key);
        Assert.Equal(plainTextTestData, plainText);
    }

    [Fact]
    public void SymmetricEncryption_AesCng_UsesBlockSize128() {
        const int expectedBlockSize = 128;

        Assert.Equal(expectedBlockSize, Aes.Create().BlockSize);
        Assert.Equal(expectedBlockSize, new AesCryptoServiceProvider().BlockSize);

        if (Environment.OSVersion.Platform != PlatformID.Win32NT) {
            // In CI environments on Linux Mono is used and does not implement "AesCng"
            return;
        }
        Assert.Equal(expectedBlockSize, new AesCng().BlockSize);
    }

    [Fact]
    public void SymmetricEncryption_DecryptWithTamperedMac_Throws() {
        var cipherText = SymmetricEncryption.Encrypt(Encoding.UTF8.GetBytes(plainTextTestData), key);

        // Second byte is the first byte of Mac
        cipherText[1] ^= cipherText[1];

        var exception = Assert.Throws<CryptographicException>(() => SymmetricEncryption.Decrypt(cipherText, key));
        Assert.Contains("Failed to authenticate message", exception.Message);
    }

    [Fact]
    public void SymmetricEncryption_DecryptWithTamperedNonce_Throws() {
        var cipherText = SymmetricEncryption.Encrypt(Encoding.UTF8.GetBytes(plainTextTestData), key);

        // Skip 33 bytes (1 byte version + 32 bytes Mac)
        cipherText[33] ^= cipherText[33];

        var exception = Assert.Throws<CryptographicException>(() => SymmetricEncryption.Decrypt(cipherText, key));
        Assert.Contains("Failed to authenticate message", exception.Message);
    }

    [Fact]
    public void SymmetricEncryption_DecryptWithTamperedCipherText_Throws() {
        var cipherText = SymmetricEncryption.Encrypt(Encoding.UTF8.GetBytes(plainTextTestData), key);

        // Skip 45 bytes (1 byte version + 32 bytes Mac + 12 byte Nonce)
        cipherText[45] ^= cipherText[45];

        var exception = Assert.Throws<CryptographicException>(() => SymmetricEncryption.Decrypt(cipherText, key));
        Assert.Contains("Failed to authenticate message", exception.Message);
    }

#endif
}
