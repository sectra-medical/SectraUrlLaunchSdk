using NUnit.Framework;
using Sectra.UrlLaunch.SharedSecret;
using System.Security.Cryptography;

namespace Sectra.UrlLaunch.IntegrationTests;

[TestFixture]
public class SectraSharedSecretEncryptionTests {
    private static string plainTextTestData = "The quick brown fox jumps over the lazy dog";
    [Test]
    public void IsSharedSecretEncryption_BackwardCompatibilityCheck() {
        // Arrange
        var encryptedString = "sharedSecretEncryptedUrlQuery=1";

        // Assert
        Assert.That(SectraSharedSecretEncryption.IsSharedSecretEncryption(encryptedString), Is.True);
    }

    [Test]
    public void IsSharedSecretEncryption_DetectsEncryptedLaunchString() {
        // Arrange
        var key = GetKey();

        // Act
        var encryptedString = SectraSharedSecretEncryption.Secure(plainTextTestData, key);

        // Assert
        Assert.That(SectraSharedSecretEncryption.IsSharedSecretEncryption(encryptedString), Is.True);
    }

    [Test]
    public void SharedSecretEncryption_CanSecureAndViewString() {
        // Arrange
        var key = GetKey();

        // Act
        var encryptedString = SectraSharedSecretEncryption.Secure(plainTextTestData, key);
        var decryptedString = SectraSharedSecretEncryption.View(encryptedString, key);

        // Assert
        Assert.That(plainTextTestData, Is.EqualTo(decryptedString));
    }

    private static byte[] GetKey() {
        var rng = RandomNumberGenerator.Create();
        var bytes = new byte[32];
        rng.GetBytes(bytes);
        return bytes;
    }

}