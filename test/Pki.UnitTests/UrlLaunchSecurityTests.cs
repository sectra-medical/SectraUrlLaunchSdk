using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Sectra.UrlLaunch.Pki;

[TestClass]
public class UrlLaunchSecurityTests {
    [TestMethod]
    public void View_EncryptedStringMissingProperties_ThrowArgumentException_Test() {
        // Arrange
        var testCertificate = TestUtils.GetCertificate();

        var sut = new UrlLaunchSecurity();

        // Act
        // Assert
        Assert.ThrowsExactly<ArgumentException>(() => sut.View(new EncryptedUrlString(), testCertificate.GetRSAPrivateKey()!, testCertificate.GetRSAPublicKey()!));
        Assert.ThrowsExactly<ArgumentException>(() => sut.View(new EncryptedUrlString(), testCertificate, testCertificate));
    }

    [TestMethod]
    public void Secure_ValidCertificate_IncludeCurrentProtocolVersionOfLibrary_Test() {
        // Arrange
        var testCertificate = TestUtils.GetCertificate();

        var sut = new UrlLaunchSecurity();

        // Act
        var secureString = sut.Secure("some string", testCertificate.GetRSAPrivateKey()!, testCertificate.GetRSAPublicKey()!);

        // Assert
        Assert.AreEqual(UrlLaunchSecurity.ProtocolVersion, secureString.ProtocolVersion);
    }

    [TestMethod]
    [Obsolete("Testing obsolete functionality.")]
    public void View_EncryptedStringMissingProperties_ThrowArgumentException_Test_Obsolete() {
        // Arrange
        var testCertificate = TestUtils.GetCertificate();

        var sut = new UrlLaunchSecurity();

        // Act
        // Assert
        Assert.ThrowsExactly<ArgumentException>(() => sut.View(new EncryptedUrlString(), testCertificate.GetRSAPrivateKey()!, testCertificate.PublicKey));
        Assert.ThrowsExactly<ArgumentException>(() => sut.View(new EncryptedUrlString(), testCertificate, testCertificate));
    }

    [TestMethod]
    [Obsolete("Testing obsolete functionality.")]
    public void Secure_ValidCertificate_IncludeCurrentProtocolVersionOfLibrary_Test_Obsolete() {
        // Arrange
        var testCertificate = TestUtils.GetCertificate();

        var sut = new UrlLaunchSecurity();

        // Act
        var secureString = sut.Secure("some string", testCertificate.GetRSAPrivateKey()!, testCertificate.PublicKey);

        // Assert
        Assert.AreEqual(UrlLaunchSecurity.ProtocolVersion, secureString.ProtocolVersion);
    }
}
