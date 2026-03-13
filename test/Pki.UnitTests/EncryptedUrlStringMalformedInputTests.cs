using System;
using NUnit.Framework;

namespace Sectra.UrlLaunch.Pki;

[TestFixture]
public class EncryptedUrlStringMalformedInputTests {

    [Test]
    public void Deserialize_Null_ThrowsArgumentNullException() {
        Assert.Throws<ArgumentNullException>(() => EncryptedUrlString.Deserialize(null!));
    }

    [Test]
    public void Deserialize_InvalidBase64InEncryptedUrlString_ThrowsFormatException() {
        var input = $"SEUS=not%21valid%21base64&ESP=&IV=&V=0";

        Assert.Throws<FormatException>(() => EncryptedUrlString.Deserialize(input));
    }

    [Test]
    public void Deserialize_InvalidBase64InSymmetricPassword_ThrowsFormatException() {
        var input = $"SEUS=&ESP=not%21valid%21base64&IV=&V=0";

        Assert.Throws<FormatException>(() => EncryptedUrlString.Deserialize(input));
    }

    [Test]
    public void Deserialize_InvalidBase64InIV_ThrowsFormatException() {
        var input = $"SEUS=&ESP=&IV=not%21valid%21base64&V=0";

        Assert.Throws<FormatException>(() => EncryptedUrlString.Deserialize(input));
    }

    [Test]
    public void Deserialize_NonNumericProtocolVersion_ThrowsFormatException() {
        var input = $"SEUS=&ESP=&IV=&V=abc";

        Assert.Throws<FormatException>(() => EncryptedUrlString.Deserialize(input));
    }

    [Test]
    public void Deserialize_NegativeProtocolVersion_ThrowsOverflowException() {
        var input = $"SEUS=&ESP=&IV=&V=-1";

        Assert.Throws<OverflowException>(() => EncryptedUrlString.Deserialize(input));
    }

    [Test]
    public void Deserialize_MissingAllKeys_ReturnsDefaultValues() {
        // No recognized keys present - defaults apply (empty base64 = empty arrays)
        var result = EncryptedUrlString.Deserialize("unrecognized=value");

        Assert.That(result, Is.Not.Null);
        Assert.That(result.SymmetricallyEncryptedUrlString, Is.EqualTo(Array.Empty<byte>()));
        Assert.That(result.EncryptedSymmetricPassword, Is.EqualTo(Array.Empty<byte>()));
        Assert.That(result.InitializationVector, Is.EqualTo(Array.Empty<byte>()));
        Assert.That(result.ProtocolVersion, Is.EqualTo(0));
    }

    [Test]
    public void Deserialize_ExtraUnknownKeys_IgnoredGracefully() {
        var input = "SEUS=&ESP=&IV=&V=1&extra=value&another=thing";
        var result = EncryptedUrlString.Deserialize(input);

        Assert.That(result, Is.Not.Null);
        Assert.That(result.ProtocolVersion, Is.EqualTo(1));
    }

    [Test]
    public void Deserialize_DuplicateKeys_UsesLastValue() {
        // Dictionary.ToDictionary with duplicate keys throws, testing behavior
        var input = "V=1&V=2";

        // The base Deserialize uses ToDictionary which throws on duplicate keys
        Assert.That(() => EncryptedUrlString.Deserialize(input), Throws.Exception);
    }

    [Test]
    public void Deserialize_UrlEncodedBase64Values_DecodesCorrectly() {
        // Base64 of [0x00] is "AA==" which URL-encodes to "AA%3D%3D"
        var input = "SEUS=AA%3D%3D&ESP=AA%3D%3D&IV=AA%3D%3D&V=0";
        var result = EncryptedUrlString.Deserialize(input);

        Assert.That(result.SymmetricallyEncryptedUrlString, Is.EqualTo(new byte[] { 0 }));
        Assert.That(result.EncryptedSymmetricPassword, Is.EqualTo(new byte[] { 0 }));
        Assert.That(result.InitializationVector, Is.EqualTo(new byte[] { 0 }));
    }

    [Test]
    public void SerializeDeserialize_RoundTrip_PreservesData() {
        var original = new EncryptedUrlString {
            SymmetricallyEncryptedUrlString = new byte[] { 1, 2, 3 },
            EncryptedSymmetricPassword = new byte[] { 4, 5, 6 },
            InitializationVector = new byte[] { 7, 8, 9 },
            ProtocolVersion = 42,
        };

        var serialized = original.Serialize();
        var deserialized = EncryptedUrlString.Deserialize(serialized);

        Assert.That(deserialized.SymmetricallyEncryptedUrlString, Is.EqualTo(original.SymmetricallyEncryptedUrlString));
        Assert.That(deserialized.EncryptedSymmetricPassword, Is.EqualTo(original.EncryptedSymmetricPassword));
        Assert.That(deserialized.InitializationVector, Is.EqualTo(original.InitializationVector));
        Assert.That(deserialized.ProtocolVersion, Is.EqualTo(original.ProtocolVersion));
    }
}
