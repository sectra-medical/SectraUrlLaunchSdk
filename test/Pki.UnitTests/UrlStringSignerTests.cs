using NUnit.Framework;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Sectra.UrlLaunch.Pki;
public class UrlStringSignerTests {
    [TestCase("")]
    [TestCase("some input string")]
    [TestCase("some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string")]
    public void Sign_PlainTextString_SignString_Test(string input) {
        // Arrange
        var cert = TestUtils.GetCertificate();
        var privateKey = cert.GetRSAPrivateKey()!;

        // Act
        var result = UrlStringSigner.Sign(Encoding.UTF8.GetBytes(input), privateKey);

        // Assert
        Assert.That(result, Is.Not.EqualTo(input));
    }

    [Test]
    public void Verify_SignedString_Verifies_Test() {
        // Arrange
        var input = "some string";

        var cert = TestUtils.GetCertificate();
        var publicKey = cert.GetRSAPublicKey()!;
        var privateKey = cert.GetRSAPrivateKey()!;

        var signedString = UrlStringSigner.Sign(Encoding.UTF8.GetBytes(input), privateKey);

        // Act
        var result = UrlStringSigner.Verify(signedString, publicKey);

        // Assert
        Assert.That(result, Is.True);
    }
}
