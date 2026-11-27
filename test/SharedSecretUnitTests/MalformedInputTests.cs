using System;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Sectra.UrlLaunch.SharedSecret;

[TestClass]
public class MalformedInputTests {

    private static readonly byte[] ValidKey = SymmetricEncryption.GenerateKey();

    // --- OneTimeSignature malformed input ---

    [TestMethod]
    public void OneTimeSignature_Verify_EmptyData_Throws() {
        Assert.Throws<Exception>(
            () => OneTimeSignature.Verify(Array.Empty<byte>(), ValidKey));
    }

    [TestMethod]
    public void OneTimeSignature_Verify_TruncatedData_TooShortForSignature_Throws() {
        // HMAC-SHA256 = 32 bytes, so anything shorter than that can't contain a valid signature
        var truncated = Rng.GetBytes(16);

        Assert.Throws<Exception>(
            () => OneTimeSignature.Verify(truncated, ValidKey));
    }

    [TestMethod]
    public void OneTimeSignature_Verify_TruncatedData_MissingPayload_Throws() {
        // 32 (HMAC) + 8 (timestamp) + 32 (nonce) = 72 bytes minimum for header
        // Provide exactly 72 bytes = valid header but no payload, signature won't match
        var truncated = Rng.GetBytes(72);

        Assert.Throws<Exception>(
            () => OneTimeSignature.Verify(truncated, ValidKey));
    }

    [TestMethod]
    public void OneTimeSignature_Verify_RandomGarbage_Throws() {
        var garbage = Rng.GetBytes(256);

        Assert.Throws<Exception>(
            () => OneTimeSignature.Verify(garbage, ValidKey));
    }

    [TestMethod]
    public void OneTimeSignature_Sign_EmptyPayload_CanBeVerified() {
        var key = Rng.GetBytes(32);
        var signed = OneTimeSignature.Sign(Array.Empty<byte>(), key);
        var result = OneTimeSignature.Verify(signed, key);
        Assert.AreEqual(0, result.Length);
    }

    // --- SymmetricEncryption malformed input ---

    [TestMethod]
    public void SymmetricEncryption_Decrypt_EmptyData_Throws() {
        Assert.Throws<Exception>(
            () => SymmetricEncryption.Decrypt(Array.Empty<byte>(), ValidKey));
    }

    [TestMethod]
    public void SymmetricEncryption_Decrypt_SingleByte_Throws() {
        Assert.Throws<Exception>(
            () => SymmetricEncryption.Decrypt(new byte[] { 0x02 }, ValidKey));
    }

    [TestMethod]
    public void SymmetricEncryption_Decrypt_InvalidVersionByte_Throws() {
        var data = Rng.GetBytes(64);
        data[0] = 0xFF; // Invalid version

        Assert.Throws<Exception>(
            () => SymmetricEncryption.Decrypt(data, ValidKey));
    }

    [TestMethod]
    public void SymmetricEncryption_Decrypt_ValidVersionButCorruptBody_Throws() {
        var data = Rng.GetBytes(64);
        data[0] = 0x02; // Version 2

        Assert.Throws<Exception>(
            () => SymmetricEncryption.Decrypt(data, ValidKey));
    }

    [TestMethod]
    public void SymmetricEncryption_Decrypt_TruncatedCiphertext_Throws() {
        var cipherText = SymmetricEncryption.Encrypt(
            Encoding.UTF8.GetBytes("test data"), ValidKey);

        // Truncate to half length
        var truncated = cipherText.Take(cipherText.Length / 2).ToArray();

        Assert.Throws<Exception>(
            () => SymmetricEncryption.Decrypt(truncated, ValidKey));
    }

    [TestMethod]
    public void SymmetricEncryption_Decrypt_WrongKey_Throws() {
        var cipherText = SymmetricEncryption.Encrypt(
            Encoding.UTF8.GetBytes("test data"), ValidKey);
        var wrongKey = SymmetricEncryption.GenerateKey();

        Assert.Throws<Exception>(
            () => SymmetricEncryption.Decrypt(cipherText, wrongKey));
    }

    [TestMethod]
    public void SymmetricEncryption_Decrypt_EmptyStringBase64_Throws() {
        Assert.Throws<Exception>(
            () => SymmetricEncryption.Decrypt("", ValidKey));
    }

    [TestMethod]
    public void SymmetricEncryption_Decrypt_InvalidBase64_Throws() {
        Assert.Throws<Exception>(
            () => SymmetricEncryption.Decrypt("not-valid-base64!!!", ValidKey));
    }

    // --- EncryptedOneTimeSignature malformed input ---

    [TestMethod]
    public void EncryptedOneTimeSignature_VerifyAndDecrypt_EmptyData_Throws() {
        Assert.Throws<Exception>(
            () => EncryptedOneTimeSignature.VerifyAndDecrypt(Array.Empty<byte>(), ValidKey));
    }

    [TestMethod]
    public void EncryptedOneTimeSignature_VerifyAndDecrypt_RandomGarbage_Throws() {
        var garbage = Rng.GetBytes(256);

        Assert.Throws<Exception>(
            () => EncryptedOneTimeSignature.VerifyAndDecrypt(garbage, ValidKey));
    }

    [TestMethod]
    public void EncryptedOneTimeSignature_VerifyAndDecrypt_InvalidBase64String_Throws() {
        Assert.Throws<Exception>(
            () => EncryptedOneTimeSignature.VerifyAndDecrypt("not-valid-base64!!!", ValidKey));
    }

    [TestMethod]
    public void EncryptedOneTimeSignature_VerifyAndDecrypt_TruncatedData_Throws() {
        var cipherText = EncryptedOneTimeSignature.EncryptAndSign(
            Encoding.UTF8.GetBytes("test"), ValidKey);

        var truncated = cipherText.Take(cipherText.Length / 2).ToArray();

        Assert.Throws<Exception>(
            () => EncryptedOneTimeSignature.VerifyAndDecrypt(truncated, ValidKey));
    }

    // --- SafeExtensions edge cases ---

    [TestMethod]
    public void SequenceEqualConstantTime_BothEmpty_ReturnsTrue() {
        Assert.IsTrue(Array.Empty<byte>().SequenceEqualConstantTime(Array.Empty<byte>(), 0));
    }

    [TestMethod]
    public void SequenceEqualConstantTime_FirstExceedsMaxLength_Throws() {
        var data = new byte[10];
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => data.SequenceEqualConstantTime(new byte[5], 5));
    }

    [TestMethod]
    public void SequenceEqualConstantTime_SecondExceedsMaxLength_Throws() {
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => new byte[5].SequenceEqualConstantTime(new byte[10], 5));
    }

    [TestMethod]
    public void EqualsConstantTime_DifferentLengthStrings_ReturnsFalse() {
        Assert.IsFalse("short".EqualsConstantTime("much longer string", 20));
    }

    [TestMethod]
    public void EqualsConstantTime_EqualStrings_ReturnsTrue() {
        Assert.IsTrue("test".EqualsConstantTime("test", 10));
    }
}
