using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Sectra.UrlLaunch.Pki;

[TestClass]
public class UrlStringSignerTests {
    [TestMethod]
    [DataRow("")]
    [DataRow("some input string")]
    [DataRow("some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string")]
    public void Sign_PlainTextString_SignString_Test(string input) {
        // Arrange
        var cert = TestUtils.GetCertificate();
        var privateKey = cert.GetRSAPrivateKey()!;

        // Act
        var result = UrlStringSigner.Sign(Encoding.UTF8.GetBytes(input), privateKey);

        // Assert
        Assert.AreNotEqual<object>(input, result);
    }

    [TestMethod]
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
        Assert.IsTrue(result);
    }
}
