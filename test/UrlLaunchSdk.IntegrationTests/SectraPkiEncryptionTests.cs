using NUnit.Framework;
using Sectra.UrlLaunch.Pki;
using System.Security.Cryptography;

namespace Sectra.UrlLaunch.IntegrationTests;

[TestFixture]
public class SectraPkiEncryptionTests {
    private static string plainTextTestData = "The quick brown fox jumps over the lazy dog";
    [Test]
    public void IsPkiEncryption_BackwardCompatibilityCheck() {
        // Arrange
        var encryptedString = "seus=1&esp=1&iv=1&v=1";

        // Assert
        Assert.That(SectraPkiEncryption.IsPkiEncryption(encryptedString), Is.True);
    }

    [Test]
    public void IsPkiEncryption_DetectsEncryptedLaunchStringUsingKeys() {
        // Arrange
        var integratingPartyKey = RSA.Create(2048);
        var systemKey = RSA.Create(2048);

        // Act
        var encryptedString = SectraPkiEncryption.Secure(plainTextTestData, integratingPartyKey, systemKey);

        // Assert
        Assert.That(SectraPkiEncryption.IsPkiEncryption(encryptedString), Is.True);
    }

    [Test]
    public void IsPkiEncryption_DetectsEncryptedLaunchStringUsingCertificates() {
        // Arrange
        var integratingPartyCert = TestUtils.GetCertificate("integrating_party_test_cert.pfx");
        var systemCert = TestUtils.GetCertificate("url_launch_system_test_cert.pfx");

        // Act
        var encryptedString = SectraPkiEncryption.Secure(plainTextTestData, integratingPartyCert, systemCert);

        // Assert
        Assert.That(SectraPkiEncryption.IsPkiEncryption(encryptedString), Is.True);
    }

    [Test]
    public void SectraPkiEncryption_CanSecureAndViewStringUsingKeys() {
        // Arrange
        var integratingPartyKey = RSA.Create(2048);
        var systemKey = RSA.Create(2048);

        // Act
        var encryptedString = SectraPkiEncryption.Secure(plainTextTestData, integratingPartyKey, systemKey);
        var decryptedString = SectraPkiEncryption.View(encryptedString, systemKey, integratingPartyKey);

        // Assert
        Assert.That(plainTextTestData, Is.EqualTo(decryptedString));
    }

    [Test]
    public void SectraPkiEncryption_CanSecureAndViewStringUsingCertificates() {
        // Arrange
        var integratingPartyCert = TestUtils.GetCertificate("integrating_party_test_cert.pfx");
        var systemCert = TestUtils.GetCertificate("url_launch_system_test_cert.pfx");

        // Act
        var encryptedString = SectraPkiEncryption.Secure(plainTextTestData, integratingPartyCert, systemCert);
        var decryptedString = SectraPkiEncryption.View(encryptedString, systemCert, integratingPartyCert);

        // Assert
        Assert.That(plainTextTestData, Is.EqualTo(decryptedString));
    }

}