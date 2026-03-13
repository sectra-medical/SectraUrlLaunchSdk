using System;
using System.Linq;
using System.Text;
using Xunit;

namespace Sectra.UrlLaunch.SharedSecret;

public class MalformedInputTests {

    private static readonly byte[] ValidKey = SymmetricEncryption.GenerateKey();

    // --- OneTimeSignature malformed input ---

    [Fact]
    public void OneTimeSignature_Verify_EmptyData_Throws() {
        Assert.ThrowsAny<Exception>(
            () => OneTimeSignature.Verify(Array.Empty<byte>(), ValidKey));
    }

    [Fact]
    public void OneTimeSignature_Verify_TruncatedData_TooShortForSignature_Throws() {
        // HMAC-SHA256 = 32 bytes, so anything shorter than that can't contain a valid signature
        var truncated = Rng.GetBytes(16);

        Assert.ThrowsAny<Exception>(
            () => OneTimeSignature.Verify(truncated, ValidKey));
    }

    [Fact]
    public void OneTimeSignature_Verify_TruncatedData_MissingPayload_Throws() {
        // 32 (HMAC) + 8 (timestamp) + 32 (nonce) = 72 bytes minimum for header
        // Provide exactly 72 bytes = valid header but no payload, signature won't match
        var truncated = Rng.GetBytes(72);

        Assert.ThrowsAny<Exception>(
            () => OneTimeSignature.Verify(truncated, ValidKey));
    }

    [Fact]
    public void OneTimeSignature_Verify_RandomGarbage_Throws() {
        var garbage = Rng.GetBytes(256);

        Assert.ThrowsAny<Exception>(
            () => OneTimeSignature.Verify(garbage, ValidKey));
    }

    [Fact]
    public void OneTimeSignature_Sign_EmptyPayload_CanBeVerified() {
        var key = Rng.GetBytes(32);
        var signed = OneTimeSignature.Sign(Array.Empty<byte>(), key);
        var result = OneTimeSignature.Verify(signed, key);
        Assert.Empty(result);
    }

    // --- SymmetricEncryption malformed input ---

    [Fact]
    public void SymmetricEncryption_Decrypt_EmptyData_Throws() {
        Assert.ThrowsAny<Exception>(
            () => SymmetricEncryption.Decrypt(Array.Empty<byte>(), ValidKey));
    }

    [Fact]
    public void SymmetricEncryption_Decrypt_SingleByte_Throws() {
        Assert.ThrowsAny<Exception>(
            () => SymmetricEncryption.Decrypt(new byte[] { 0x02 }, ValidKey));
    }

    [Fact]
    public void SymmetricEncryption_Decrypt_InvalidVersionByte_Throws() {
        var data = Rng.GetBytes(64);
        data[0] = 0xFF; // Invalid version

        Assert.ThrowsAny<Exception>(
            () => SymmetricEncryption.Decrypt(data, ValidKey));
    }

    [Fact]
    public void SymmetricEncryption_Decrypt_ValidVersionButCorruptBody_Throws() {
        var data = Rng.GetBytes(64);
        data[0] = 0x02; // Version 2

        Assert.ThrowsAny<Exception>(
            () => SymmetricEncryption.Decrypt(data, ValidKey));
    }

    [Fact]
    public void SymmetricEncryption_Decrypt_TruncatedCiphertext_Throws() {
        var cipherText = SymmetricEncryption.Encrypt(
            Encoding.UTF8.GetBytes("test data"), ValidKey);

        // Truncate to half length
        var truncated = cipherText.Take(cipherText.Length / 2).ToArray();

        Assert.ThrowsAny<Exception>(
            () => SymmetricEncryption.Decrypt(truncated, ValidKey));
    }

    [Fact]
    public void SymmetricEncryption_Decrypt_WrongKey_Throws() {
        var cipherText = SymmetricEncryption.Encrypt(
            Encoding.UTF8.GetBytes("test data"), ValidKey);
        var wrongKey = SymmetricEncryption.GenerateKey();

        Assert.ThrowsAny<Exception>(
            () => SymmetricEncryption.Decrypt(cipherText, wrongKey));
    }

    [Fact]
    public void SymmetricEncryption_Decrypt_EmptyStringBase64_Throws() {
        Assert.ThrowsAny<Exception>(
            () => SymmetricEncryption.Decrypt("", ValidKey));
    }

    [Fact]
    public void SymmetricEncryption_Decrypt_InvalidBase64_Throws() {
        Assert.ThrowsAny<Exception>(
            () => SymmetricEncryption.Decrypt("not-valid-base64!!!", ValidKey));
    }

    // --- EncryptedOneTimeSignature malformed input ---

    [Fact]
    public void EncryptedOneTimeSignature_VerifyAndDecrypt_EmptyData_Throws() {
        Assert.ThrowsAny<Exception>(
            () => EncryptedOneTimeSignature.VerifyAndDecrypt(Array.Empty<byte>(), ValidKey));
    }

    [Fact]
    public void EncryptedOneTimeSignature_VerifyAndDecrypt_RandomGarbage_Throws() {
        var garbage = Rng.GetBytes(256);

        Assert.ThrowsAny<Exception>(
            () => EncryptedOneTimeSignature.VerifyAndDecrypt(garbage, ValidKey));
    }

    [Fact]
    public void EncryptedOneTimeSignature_VerifyAndDecrypt_InvalidBase64String_Throws() {
        Assert.ThrowsAny<Exception>(
            () => EncryptedOneTimeSignature.VerifyAndDecrypt("not-valid-base64!!!", ValidKey));
    }

    [Fact]
    public void EncryptedOneTimeSignature_VerifyAndDecrypt_TruncatedData_Throws() {
        var cipherText = EncryptedOneTimeSignature.EncryptAndSign(
            Encoding.UTF8.GetBytes("test"), ValidKey);

        var truncated = cipherText.Take(cipherText.Length / 2).ToArray();

        Assert.ThrowsAny<Exception>(
            () => EncryptedOneTimeSignature.VerifyAndDecrypt(truncated, ValidKey));
    }

    // --- SafeExtensions edge cases ---

    [Fact]
    public void SequenceEqualConstantTime_BothEmpty_ReturnsTrue() {
        Assert.True(Array.Empty<byte>().SequenceEqualConstantTime(Array.Empty<byte>(), 0));
    }

    [Fact]
    public void SequenceEqualConstantTime_FirstExceedsMaxLength_Throws() {
        var data = new byte[10];
        Assert.Throws<ArgumentOutOfRangeException>(
            () => data.SequenceEqualConstantTime(new byte[5], 5));
    }

    [Fact]
    public void SequenceEqualConstantTime_SecondExceedsMaxLength_Throws() {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new byte[5].SequenceEqualConstantTime(new byte[10], 5));
    }

    [Fact]
    public void EqualsConstantTime_DifferentLengthStrings_ReturnsFalse() {
        Assert.False("short".EqualsConstantTime("much longer string", 20));
    }

    [Fact]
    public void EqualsConstantTime_EqualStrings_ReturnsTrue() {
        Assert.True("test".EqualsConstantTime("test", 10));
    }
}
