using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Sectra.UrlLaunch.Pki;

[TestClass]
public class SymmetricalEncryptorTests {
    [TestMethod]
    [DataRow("some input")]
    [DataRow("some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string")]
    public void Decrypt_EncryptedString_DecryptsString_Test(string input) {
        // Arrange
        var inputBytes = Encoding.UTF8.GetBytes(input);

        byte[] key, iv;
        var encryptedData = SymmetricalEncryptor.Encrypt(inputBytes, out key, out iv);

        // Act
        var result = SymmetricalEncryptor.Decrypt(encryptedData, key, iv);

        // Assert
        Assert.AreEqual(input, Encoding.UTF8.GetString(result));
    }

    [TestMethod]
    public void DecryptStringFromBytes_NullArguments_Throw_Test() {
        // Arrange
        var sut = new SymmetricalEncryptor();

        // Act
        // Assert
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type.
        Assert.ThrowsExactly<ArgumentNullException>(() => SymmetricalEncryptor.Decrypt(null, new byte[1], new byte[1]));
        Assert.ThrowsExactly<ArgumentNullException>(() => SymmetricalEncryptor.Decrypt(new byte[1], null, new byte[1]));
        Assert.ThrowsExactly<ArgumentNullException>(() => SymmetricalEncryptor.Decrypt(new byte[1], new byte[1], null));

        Assert.ThrowsExactly<ArgumentNullException>(() => SymmetricalEncryptor.Decrypt(new byte[0], new byte[1], new byte[1]));
        Assert.ThrowsExactly<ArgumentNullException>(() => SymmetricalEncryptor.Decrypt(new byte[1], new byte[0], new byte[1]));
        Assert.ThrowsExactly<ArgumentNullException>(() => SymmetricalEncryptor.Decrypt(new byte[1], new byte[1], new byte[0]));
#pragma warning restore CS8625 // Cannot convert null literal to non-nullable reference type.
    }
}
