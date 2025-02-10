using NUnit.Framework;
using System.Text;

namespace Sectra.UrlLaunch.Pki;
[TestFixture]
public class SymmetricalEncryptorTests {
    [TestCase("some input")]
    [TestCase("some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string")]
    public void Decrypt_EncryptedString_DecryptsString_Test(string input) {
        // Arrange
        var inputBytes = Encoding.UTF8.GetBytes(input);

        byte[] key, iv;
        var encryptedData = SymmetricalEncryptor.Encrypt(inputBytes, out key, out iv);

        // Act
        var result = SymmetricalEncryptor.Decrypt(encryptedData, key, iv);

        // Assert
        Assert.That(Encoding.UTF8.GetString(result), Is.EqualTo(input));
    }

    [Test]
    public void DecryptStringFromBytes_NullArguments_Throw_Test() {
        // Arrange
        var sut = new SymmetricalEncryptor();

        // Act
        // Assert
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type.
        Assert.That(() => SymmetricalEncryptor.Decrypt(null, new byte[1], new byte[1]), Throws.ArgumentNullException);
        Assert.That(() => SymmetricalEncryptor.Decrypt(new byte[1], null, new byte[1]), Throws.ArgumentNullException);
        Assert.That(() => SymmetricalEncryptor.Decrypt(new byte[1], new byte[1], null), Throws.ArgumentNullException);

        Assert.That(() => SymmetricalEncryptor.Decrypt(new byte[0], new byte[1], new byte[1]), Throws.ArgumentNullException);
        Assert.That(() => SymmetricalEncryptor.Decrypt(new byte[1], new byte[0], new byte[1]), Throws.ArgumentNullException);
        Assert.That(() => SymmetricalEncryptor.Decrypt(new byte[1], new byte[1], new byte[0]), Throws.ArgumentNullException);
#pragma warning restore CS8625 // Cannot convert null literal to non-nullable reference type.
    }
}
