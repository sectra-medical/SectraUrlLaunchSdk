using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Sectra.UrlLaunch.Pki;

[TestClass]
public class EncryptedUrlStringTests {
    [TestMethod]
    public void Serialize_WithProperties_SerializesIntoUrlEncodedString_Test() {
        // Arrange
        var sut = new EncryptedUrlString {
            SymmetricallyEncryptedUrlString = Encoding.UTF8.GetBytes("a"), // Base 64 encoding of 'a' (UTF8) is 'YQ=='
            EncryptedSymmetricPassword = Encoding.UTF8.GetBytes("b"), // Base 64 encoding of 'b' (UTF8) is 'Yg=='
            InitializationVector = Encoding.UTF8.GetBytes("c"), // Base 64 encoding of 'c' (UTF8) is 'Yw=='
        };

        // Act
        var result = sut.Serialize();

        // Assert
        // Url encoding of '=' is '%3D'
        StringAssert.Contains(result, "YQ%3D%3D");
        StringAssert.Contains(result, "Yg%3D%3D");
        StringAssert.Contains(result, "Yw%3D%3D");
    }


    [TestMethod]
    [DataRow(new byte[0], new byte[0], new byte[0], ushort.MinValue)]
    [DataRow(new byte[] { 0 }, new byte[] { 0 }, new byte[] { 0 }, (ushort)1)]
    [DataRow(new byte[] { 0 }, new byte[] { 0 }, new byte[] { 0 }, ushort.MaxValue)]
    public void Deserialize_SerializedString_Deserializes_Test(byte[] urlString, byte[] password, byte[] iv, ushort protocolVersion) {
        // Arrange
        var input = new EncryptedUrlString {
            SymmetricallyEncryptedUrlString = urlString,
            EncryptedSymmetricPassword = password,
            InitializationVector = iv,
            ProtocolVersion = protocolVersion,
        };

        var serializedString = input.Serialize();

        // Act
        var result = EncryptedUrlString.Deserialize(serializedString);

        // Assert
        CollectionAssert.AreEqual(input.SymmetricallyEncryptedUrlString, result.SymmetricallyEncryptedUrlString);
        CollectionAssert.AreEqual(input.EncryptedSymmetricPassword, result.EncryptedSymmetricPassword);
        CollectionAssert.AreEqual(input.InitializationVector, result.InitializationVector);
        Assert.AreEqual(input.ProtocolVersion, result.ProtocolVersion);
    }

    [TestMethod]
    [DataRow("")]
    public void Deserialize_StringWithMissingProperties_DeserializesWithoutThoseMissingProperties_Test(string input) {
        // Act
        var result = EncryptedUrlString.Deserialize(input);

        // Assert
        Assert.IsNotNull(result);
    }
}
