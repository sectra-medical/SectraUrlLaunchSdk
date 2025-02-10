using NUnit.Framework;
using System;
using System.Security.Cryptography.X509Certificates;

namespace Sectra.UrlLaunch.Pki;
[TestFixture]
public class UrlLaunchSecurityTests {
    [Test]
    public void View_EncryptedStringMissingProperties_ThrowArgumentException_Test() {
        // Arrange
        var testCertificate = TestUtils.GetCertificate();

        var sut = new UrlLaunchSecurity();

        // Act
        // Assert
        Assert.That(() => sut.View(new EncryptedUrlString(), testCertificate.GetRSAPrivateKey()!, testCertificate.GetRSAPublicKey()!), Throws.ArgumentException);
        Assert.That(() => sut.View(new EncryptedUrlString(), testCertificate, testCertificate), Throws.ArgumentException);
    }

    [Test]
    public void Secure_ValidCertificate_IncludeCurrentProtocolVersionOfLibrary_Test() {
        // Arrange
        var testCertificate = TestUtils.GetCertificate();

        var sut = new UrlLaunchSecurity();

        // Act
        var secureString = sut.Secure("some string", testCertificate.GetRSAPrivateKey()!, testCertificate.GetRSAPublicKey()!);

        // Assert
        Assert.That(secureString.ProtocolVersion, Is.EqualTo(UrlLaunchSecurity.ProtocolVersion));
    }

    [Test]
    [Obsolete("Testing obsolete functionality.")]
    public void View_EncryptedStringMissingProperties_ThrowArgumentException_Test_Obsolete() {
        // Arrange
        var testCertificate = TestUtils.GetCertificate();

        var sut = new UrlLaunchSecurity();

        // Act
        // Assert
        Assert.That(() => sut.View(new EncryptedUrlString(), testCertificate.GetRSAPrivateKey()!, testCertificate.PublicKey), Throws.ArgumentException);
        Assert.That(() => sut.View(new EncryptedUrlString(), testCertificate, testCertificate), Throws.ArgumentException);
    }

    [Test]
    [Obsolete("Testing obsolete functionality.")]
    public void Secure_ValidCertificate_IncludeCurrentProtocolVersionOfLibrary_Test_Obsolete() {
        // Arrange
        var testCertificate = TestUtils.GetCertificate();

        var sut = new UrlLaunchSecurity();

        // Act
        var secureString = sut.Secure("some string", testCertificate.GetRSAPrivateKey()!, testCertificate.PublicKey);

        // Assert
        Assert.That(secureString.ProtocolVersion, Is.EqualTo(UrlLaunchSecurity.ProtocolVersion));
    }
}
