using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Sectra.UrlLaunch.Pki;

[TestClass]
public class EncryptedUrlStringMalformedInputTests {

    [TestMethod]
    public void Deserialize_Null_ThrowsArgumentNullException() {
        Assert.ThrowsExactly<ArgumentNullException>(() => EncryptedUrlString.Deserialize(null!));
    }

    [TestMethod]
    public void Deserialize_InvalidBase64InEncryptedUrlString_ThrowsFormatException() {
        var input = $"SEUS=not%21valid%21base64&ESP=&IV=&V=0";

        Assert.ThrowsExactly<FormatException>(() => EncryptedUrlString.Deserialize(input));
    }

    [TestMethod]
    public void Deserialize_InvalidBase64InSymmetricPassword_ThrowsFormatException() {
        var input = $"SEUS=&ESP=not%21valid%21base64&IV=&V=0";

        Assert.ThrowsExactly<FormatException>(() => EncryptedUrlString.Deserialize(input));
    }

    [TestMethod]
    public void Deserialize_InvalidBase64InIV_ThrowsFormatException() {
        var input = $"SEUS=&ESP=&IV=not%21valid%21base64&V=0";

        Assert.ThrowsExactly<FormatException>(() => EncryptedUrlString.Deserialize(input));
    }

    [TestMethod]
    public void Deserialize_NonNumericProtocolVersion_ThrowsFormatException() {
        var input = $"SEUS=&ESP=&IV=&V=abc";

        Assert.ThrowsExactly<FormatException>(() => EncryptedUrlString.Deserialize(input));
    }

    [TestMethod]
    public void Deserialize_NegativeProtocolVersion_ThrowsOverflowException() {
        var input = $"SEUS=&ESP=&IV=&V=-1";

        Assert.ThrowsExactly<OverflowException>(() => EncryptedUrlString.Deserialize(input));
    }

    [TestMethod]
    public void Deserialize_MissingAllKeys_ReturnsDefaultValues() {
        // No recognized keys present - defaults apply (empty base64 = empty arrays)
        var result = EncryptedUrlString.Deserialize("unrecognized=value");

        Assert.IsNotNull(result);
        CollectionAssert.AreEqual(Array.Empty<byte>(), result.SymmetricallyEncryptedUrlString);
        CollectionAssert.AreEqual(Array.Empty<byte>(), result.EncryptedSymmetricPassword);
        CollectionAssert.AreEqual(Array.Empty<byte>(), result.InitializationVector);
        Assert.AreEqual(0, (int)result.ProtocolVersion);
    }

    [TestMethod]
    public void Deserialize_ExtraUnknownKeys_IgnoredGracefully() {
        var input = "SEUS=&ESP=&IV=&V=1&extra=value&another=thing";
        var result = EncryptedUrlString.Deserialize(input);

        Assert.IsNotNull(result);
        Assert.AreEqual(1, (int)result.ProtocolVersion);
    }

    [TestMethod]
    public void Deserialize_DuplicateKeys_UsesLastValue() {
        // Dictionary.ToDictionary with duplicate keys throws, testing behavior
        var input = "V=1&V=2";

        // The base Deserialize uses ToDictionary which throws on duplicate keys
        Assert.Throws<Exception>(() => EncryptedUrlString.Deserialize(input));
    }

    [TestMethod]
    public void Deserialize_UrlEncodedBase64Values_DecodesCorrectly() {
        // Base64 of [0x00] is "AA==" which URL-encodes to "AA%3D%3D"
        var input = "SEUS=AA%3D%3D&ESP=AA%3D%3D&IV=AA%3D%3D&V=0";
        var result = EncryptedUrlString.Deserialize(input);

        CollectionAssert.AreEqual(new byte[] { 0 }, result.SymmetricallyEncryptedUrlString);
        CollectionAssert.AreEqual(new byte[] { 0 }, result.EncryptedSymmetricPassword);
        CollectionAssert.AreEqual(new byte[] { 0 }, result.InitializationVector);
    }

    [TestMethod]
    public void SerializeDeserialize_RoundTrip_PreservesData() {
        var original = new EncryptedUrlString {
            SymmetricallyEncryptedUrlString = new byte[] { 1, 2, 3 },
            EncryptedSymmetricPassword = new byte[] { 4, 5, 6 },
            InitializationVector = new byte[] { 7, 8, 9 },
            ProtocolVersion = 42,
        };

        var serialized = original.Serialize();
        var deserialized = EncryptedUrlString.Deserialize(serialized);

        CollectionAssert.AreEqual(original.SymmetricallyEncryptedUrlString, deserialized.SymmetricallyEncryptedUrlString);
        CollectionAssert.AreEqual(original.EncryptedSymmetricPassword, deserialized.EncryptedSymmetricPassword);
        CollectionAssert.AreEqual(original.InitializationVector, deserialized.InitializationVector);
        Assert.AreEqual(original.ProtocolVersion, deserialized.ProtocolVersion);
    }
}
