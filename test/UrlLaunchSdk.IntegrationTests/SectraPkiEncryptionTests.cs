using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Sectra.UrlLaunch.Pki;

namespace Sectra.UrlLaunch.IntegrationTests;

[TestClass]
public class SectraPkiEncryptionTests {
    private static string plainTextTestData = "The quick brown fox jumps over the lazy dog";
    [TestMethod]
    public void IsPkiEncryption_BackwardCompatibilityCheck() {
        // Arrange
        var encryptedString = "seus=1&esp=1&iv=1&v=1";

        // Assert
        Assert.IsTrue(SectraPkiEncryption.IsPkiEncryption(encryptedString));
    }

    [TestMethod]
    public void IsPkiEncryption_DetectsEncryptedLaunchStringUsingKeys() {
        // Arrange
        var integratingPartyKey = RSA.Create(2048);
        var systemKey = RSA.Create(2048);

        // Act
        var encryptedString = SectraPkiEncryption.Secure(plainTextTestData, integratingPartyKey, systemKey);

        // Assert
        Assert.IsTrue(SectraPkiEncryption.IsPkiEncryption(encryptedString));
    }

    [TestMethod]
    public void IsPkiEncryption_DetectsEncryptedLaunchStringUsingCertificates() {
        // Arrange
        var integratingPartyCert = TestUtils.GetCertificate("integrating_party_test_cert.pfx");
        var systemCert = TestUtils.GetCertificate("url_launch_system_test_cert.pfx");

        // Act
        var encryptedString = SectraPkiEncryption.Secure(plainTextTestData, integratingPartyCert, systemCert);

        // Assert
        Assert.IsTrue(SectraPkiEncryption.IsPkiEncryption(encryptedString));
    }

    [TestMethod]
    public void SectraPkiEncryption_CanSecureAndViewStringUsingKeys() {
        // Arrange
        var integratingPartyKey = RSA.Create(2048);
        var systemKey = RSA.Create(2048);

        // Act
        var encryptedString = SectraPkiEncryption.Secure(plainTextTestData, integratingPartyKey, systemKey);
        var decryptedString = SectraPkiEncryption.View(encryptedString, systemKey, integratingPartyKey);

        // Assert
        Assert.AreEqual(plainTextTestData, decryptedString);
    }

    [TestMethod]
    public void SectraPkiEncryption_CanSecureAndViewStringUsingCertificates() {
        // Arrange
        var integratingPartyCert = TestUtils.GetCertificate("integrating_party_test_cert.pfx");
        var systemCert = TestUtils.GetCertificate("url_launch_system_test_cert.pfx");

        // Act
        var encryptedString = SectraPkiEncryption.Secure(plainTextTestData, integratingPartyCert, systemCert);
        var decryptedString = SectraPkiEncryption.View(encryptedString, systemCert, integratingPartyCert);

        // Assert
        Assert.AreEqual(plainTextTestData, decryptedString);
    }

}
