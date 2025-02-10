using NUnit.Framework;
using System.Text;

namespace Sectra.UrlLaunch.Pki;

[TestFixture]
public class EncryptedUrlStringTests {
    [Test]
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
        Assert.That(result, Does.Contain("YQ%3D%3D"));
        Assert.That(result, Does.Contain("Yg%3D%3D"));
        Assert.That(result, Does.Contain("Yw%3D%3D"));
    }


    [TestCase(new byte[0], new byte[0], new byte[0], ushort.MinValue)]
    [TestCase(new byte[] { 0 }, new byte[] { 0 }, new byte[] { 0 }, (ushort)1)]
    [TestCase(new byte[] { 0 }, new byte[] { 0 }, new byte[] { 0 }, ushort.MaxValue)]
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
        Assert.That(result.SymmetricallyEncryptedUrlString, Is.EqualTo(input.SymmetricallyEncryptedUrlString));
        Assert.That(result.EncryptedSymmetricPassword, Is.EqualTo(input.EncryptedSymmetricPassword));
        Assert.That(result.InitializationVector, Is.EqualTo(input.InitializationVector));
        Assert.That(result.ProtocolVersion, Is.EqualTo(input.ProtocolVersion));
    }

    [TestCase("")]
    public void Deserialize_StringWithMissingProperties_DeserializesWithoutThoseMissingProperties_Test(string input) {
        // Act
        var result = EncryptedUrlString.Deserialize(input);

        // Assert
        Assert.That(result, Is.Not.Null);
    }
}
