using NUnit.Framework;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Sectra.UrlLaunch.Pki;
[TestFixture]
public class UrlStringEncryptorTests {
    [Test]
    public void Decrypt_NullSecureString_ThrowArgumentNullException_Test() {
        // Arrange
        // Act
        // Assert
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type.
        Assert.That(() => UrlStringEncryptor.Decrypt(null, RSA.Create()), Throws.ArgumentNullException);
#pragma warning restore CS8625 // Cannot convert null literal to non-nullable reference type.
    }

    [Test]
    public void Decrypt_NullKey_ThrowsArgumentNullException_Test() {
        // Arrange
        // Act
        // Assert
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type.
        Assert.That(() => UrlStringEncryptor.Decrypt(new EncryptedUrlString(), null), Throws.ArgumentNullException);
#pragma warning restore CS8625 // Cannot convert null literal to non-nullable reference type.
    }

    [Test]
    public void Encrypt_PlainTextString_EncryptString_Test() {
        // Arrange
#pragma warning disable CS8625 // Cannot convert null literal to non-nullable reference type.
        var input = new SignedUrlString(Encoding.UTF8.GetBytes("some url string"), null);
#pragma warning restore CS8625 // Cannot convert null literal to non-nullable reference type.

        // Act
        var result = UrlStringEncryptor.Encrypt(input, RSA.Create());

        // Assert
        Assert.That(result, Is.Not.EqualTo(input));
    }

    [TestCase("", "")]
    [TestCase("test", "")]
    [TestCase(
        "some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string some really long input string",
        "some really long signature some really long signature some really long signature some really long signature some really long signature some really long signature some really long signature some really long signature some really long signature some really long signature some really long signature")]
    public void Decrypt_EncryptedString_ReturnPlainTextString_Test(string inputString, string signature) {
        // Arrange
        var urlStringBytes = Encoding.UTF8.GetBytes(inputString);
        var signatureBytes = Encoding.UTF8.GetBytes(signature);
        var input = new SignedUrlString(urlStringBytes, signatureBytes);

        var cert = TestUtils.GetCertificate();

        var encryptKey = cert.GetRSAPublicKey()!;
        var encryptedString = UrlStringEncryptor.Encrypt(input, encryptKey);

        // Act
        var decryptKey = cert.GetRSAPrivateKey()!;
        var result = UrlStringEncryptor.Decrypt(encryptedString, decryptKey);

        // Assert
        Assert.That(result.UrlString, Is.EqualTo(urlStringBytes));
    }

    [Test]
    public void Encrypt_TooLongSignature_ThrowOutOfRangeException_Test() {
        // Arrange
        var inputString = "some input string";
        // Create a signature with more than the maximum allowed length for the signature.
        var signature = new string(Enumerable.Range(1, UrlStringEncryptor.MaxSignatureLength + 1).Select(_ => 'a').ToArray());

        var urlStringBytes = Encoding.UTF8.GetBytes(inputString);
        var signatureBytes = Encoding.UTF8.GetBytes(signature);
        var input = new SignedUrlString(urlStringBytes, signatureBytes);

        var cert = TestUtils.GetCertificate();
        var encryptKey = cert.GetRSAPublicKey()!;

        // Act
        // Assert
        Assert.That(() => {
            var result = UrlStringEncryptor.Encrypt(input, encryptKey);
            Console.WriteLine(result.Serialize());
        }, Throws.InstanceOf<ArgumentOutOfRangeException>());
    }


    [Test]
    public void Decrypt_TooLongSignature_ThrowOutOfRangeException_Test() {
        // Arrange
        var cert = TestUtils.GetCertificate();

        var input = "SEUS=H%2Fn29d5AMjLPdoAH9FRJNlzkVOp%2Ffsw6nDKK0rWLD63Ej%2Fy1nLuGmY69%2FmWsgzD6YfTZtCdWuBsD0mU%2FfJQIll7eea2XgFUxjWbj8GekrD%2BwK695BBi4HRU5E%2FJVRJz00wdCKMUsvLd3O%2FLlY54UYw%2F7Ir%2BWR%2F400ebz%2FMkKxjx9UnMSrAmXJv0fCXouSRKjQm7fQRmz5348nTTtBlc9IwNBg5g9h44lq%2BlLZkU4IPg59OIfuu5VTqqaDmV8J%2BdpIf77XOaavglQVNoA5QHHRiypMj%2BYSkke%2BoDF1YaZ1cOMZoy7ivqQRa8MJV6EhvCwe%2BfOFjGKrEpD9eY2W7iPtT3gNOnM2j7Ec4HNYzHQYrCjullLCliKmXrOWIr34LM1tT1zfiJ3lo6olPUhB03B7mjIeQhNoOlhNrQqJ6lTdZ%2FNUkPKgGcRYlJKRAAZ9TFSXCiAu26otIFzjgSadp6PawvAdy5UMbMHBXqqV8Ctc8U2hEqbOLFHwnYAvIqDIS%2FIIdyReFM7QbjJi5Yoj6Gn54UFuAU2SKkAfBXcGLhdq6Ou3nXr%2FcZSKK5Sc6aZouzBBJpwdbuUhgKbHlAFathdBsAJP57Vw5GDxRsnaS4TPS9%2F%2BpjHuzmNPBd6Bppro7%2BsE1inhft1NZ9huh31k5WrQCz%2Bzbt1xUVlsiCilEEQ7XYkU7bYB3vXkle0BfUOXh%2BrrPflrxbZ4yM9aN5lMipzdZA3%2BLNX1sfvXsYD00S8dsmlmXLAIWxi7%2BQFMBNvYDvTUaST%2BFlL6A64%2BX1uAZnQjdVCFZ%2BGSbJsHpxf8X7MNWU0ZOhNrUiN%2FU3L7%2F7hXxyzOqeCqcEaGYwXPfQuB0KqEl%2BQNE5U09AqRPyx5EX%2BuQANJ%2FJLYTyk%2FOrI5XDM4FcM7sQOlTX7SkcKv7YmEf1KUGYQydZhMxlRNxBE7nRBPtou4VF0df3l0gYfHNUSVR5N8hgeDB%2B7L4ClZQFXT5HiW097Ka6C74pCdf5kIuiNoXKDS7LvdNipO5Q4AQlS3UBqjpWLjQZpqe3jfWUtIcxUre62HLIzSd%2BPa6UFy2XvDQVTkFWWgDuyG246hfLOI1VDDgK0KZ0xszeE%2FzxYXECKEe8oTPltT%2Bh5Vg2nOGsUmK0%2BUfLwzG7aSLSOM2jvemWUKOaV3uVMK%2BpSw8BwGON4qhQQg0jDL%2FwTTY%2BO3QVrU8SKYIQrMxGBhzzLBFY1EzNntUIp6SyvULZ9feR9bm%2FqSrs%2FVOyUthcLzyfRc%2B%2Fz1Fa2b7dzK0CBnin397jiYja8DUHDxpfQJaxN0xAhqPqCnSHhjJ9o8ZC9TEN7xgQlqLzQRhR47iE8RAk6U%2F3b36zUPylMPQdhfIH9QpPrvObvH2wyxXzijl%2B7GFVpx5lm52a2NRXyrCLUFDjYDs1BMR28&ESP=fMmTO3qrTagi0F4UcjlXLllyM2c9aqmtqi3NEjCuzBJxEXOF3mGIPAxjGit1m%2Fi1vwZSwyeO25YmnNsYcBdKjgnzXUHxhIG0T4e4da4G33Lm5AXXPPxn%2BmvKZ1dSpLfw546T5V26j97Uj2P7griI9MLQhqgLp6sbjWGLWEZYEdnUfGay5HUhZY75BTwWO4aEsXmSMIf4WTBRs0zERil%2FkioQlSHxbRnfirtRPTqmElv3vnMcxTFlvk2w%2B3mdWUGbzVNJOrZvsExqB5g8KholOdR4F1yzkYSMI96cpInpHjkyi5mI5kl8UHM%2Bpm4mPQCMag8%2FghYAZxb3Fy%2BfK7Ymxg%3D%3D&IV=%2FG0w%2BQj1GoLJCMk17wiY1g%3D%3D&V=0";

        var encryptedString = EncryptedUrlString.Deserialize(input);

        var decryptKey = cert.GetRSAPrivateKey()!;

        // Act
        // Assert
        Assert.That(() => UrlStringEncryptor.Decrypt(encryptedString, decryptKey), Throws.InstanceOf<ArgumentOutOfRangeException>(), $"If this test fails, you may have to update the input string. Use the {nameof(Encrypt_TooLongSignature_ThrowOutOfRangeException_Test)} test with the {nameof(ArgumentOutOfRangeException)} line in {nameof(UrlStringEncryptor)}.{nameof(UrlStringEncryptor.Encrypt)} method commented out in order to get the input written to standard out.");
    }

    [TestCase(0)]
    [TestCase(3)]
    public void Decrypt_DecryptedUrlStringAndSignatureWithNoData_ThrowARgumentException_Test(int dataLength) {
        // Arrange
        var cert = TestUtils.GetCertificate();

        var encryptedData = SymmetricalEncryptor.Encrypt(new byte[dataLength], out byte[] key, out byte[] iv);
        var encryptedKey = cert.GetRSAPublicKey()!.Encrypt(key, RSAEncryptionPadding.OaepSHA1);

        var input = new EncryptedUrlString {
            EncryptedSymmetricPassword = encryptedKey,
            InitializationVector = iv,
            SymmetricallyEncryptedUrlString = encryptedData,
        };

        // Act
        // Assert
        Assert.That(() => UrlStringEncryptor.Decrypt(input, cert.GetRSAPrivateKey()!), Throws.ArgumentException);
    }

    [Test]
    public void Decrypt_DecryptedSignatureLengthExceedsLengthOfData_ThrowArgumentException_Test() {
        // Arrange
        var cert = TestUtils.GetCertificate();

        var signatureLengthBytes = BitConverter.GetBytes(1);
        // Normally, this is [<signature length> <signature> <url string>], but
        // now only the signature length specification without any following data.
        var data = signatureLengthBytes;

        byte[] key, iv;
        var encryptedData = SymmetricalEncryptor.Encrypt(data, out key, out iv);
        var encryptedKey = cert.GetRSAPublicKey()!.Encrypt(key, RSAEncryptionPadding.OaepSHA1);

        var input = new EncryptedUrlString {
            EncryptedSymmetricPassword = encryptedKey,
            InitializationVector = iv,
            SymmetricallyEncryptedUrlString = encryptedData,
        };

        // Act
        // Assert
        Assert.That(() => UrlStringEncryptor.Decrypt(input, cert.GetRSAPrivateKey()!), Throws.ArgumentException.With.Message.Contain("signature"));
    }
}
