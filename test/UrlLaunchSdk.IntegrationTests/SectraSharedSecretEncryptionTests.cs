using System;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Sectra.UrlLaunch.SharedSecret;

namespace Sectra.UrlLaunch.IntegrationTests;

[TestClass]
public class SectraSharedSecretEncryptionTests {
    private static string plainTextTestData = "The quick brown fox jumps over the lazy dog";
    private const string base64TestEncryptionKey = "D7qIalCnQzyGrU5sCVZ+HWYcGTihtO32bAuzSiPkTug=";
    private const string encryptedNetFrameworkTextTestData2023 = "sharedSecretEncryptedUrlQuery=Lq2HPvFjISLXCJC6hMp5JQb0EFvlyEHIWIH3FV7JQQie6T6eIngxibJhj6AAID4Wl0zbSJdwyQ5NGgeYg7G7sAPECzBtjuEyREKan0O%2BEFKqmM8GAcYn1hifJMu9U3lfYo1fb88rGn0jzIM1X7RF2cI2jiD4rkQHB21cKWKVM5EB%2Bz9%2Fj1kWwXDkXa03UaZU%2FS6OUjPJenB08hkZrukkKrIm7dqMinD40AUW6y7U3x3lC0215A%3D%3D";
    private const string encryptedNetFrameworkTextTestData2025 = "sharedSecretEncryptedUrlQuery=QBNN5LJLUKuDCsCPlCuc2D6gbEmam1u6kc%2BzmzcVzbznn1ia17ZOMcTpqW8AYDUyA4vdSADhx98k%2BlhAPi7zgdUNpW5qE1CrxaSzKqImMthLm4f9AUDqqmpgb%2BRT6pP6STuui%2Bsn1o%2BuxgYJ4v6f9lfHtjkabSm3td62%2FhP8N2rc9JJlq5t8uSdVBjLwtHNYL2Yr%2F7pSink863QszzWgx3vzZ7j5rGnLAINycFVdiJQT0H1RNw%3D%3D";
#if NET8_0_OR_GREATER
    private const string encryptedTextTestData2023 = "sharedSecretEncryptedUrlQuery=JvI34KTS0p5SvdZNjhswyOax8UHf9sRKfO4Wth%2Fj7KsR1Vy95KTKVzzFoc0AID4Wl0zbSHUZ%2BrSingAmaomF9CwEpE8562DtR%2FOHBXMkx4mWK%2FzJAj7JTOl2uAIsRqlX3PNTuidufcBMSaifhOYqBYt3dSDXBCt8p8lJobV2HyAM2CMM3J4432gEjnS9m7NS9aVUKrChw4BVM4Px";
    private const string encryptedTextTestData2025 = "sharedSecretEncryptedUrlQuery=DGSc2jqpHoY4a0XSmW5R5yjPRODSOFRrQI7Pstpn4c54GuPLy06Y2GTmih8AYDUyA4vdSPhX85ZIYQ%2FhA2U0VLja1bH2hDuJyDpRNraoXtRrQYn5AkvA%2FPxWwKpQZri648w2U5uwcmTcw%2BsXd3sNjO9KqxUo%2BKm7%2F0%2BKLIrWArcRxXpNnonoF%2FyIQ99jxx%2F%2BkfQXELg8sL8kksJg";
#endif

    [ClassInitialize]
    public static void GlobalSetup(TestContext context) {
        DateTimeProvider.Current = new TestDateTimeProvider();
    }

    [ClassCleanup]
    public static void GlobalTeardown() {
        DateTimeProvider.ResetToDefault();
    }

    [TestMethod]
    public void IsSharedSecretEncryption_BackwardCompatibilityCheck() {
        // Arrange
        var encryptedString = "sharedSecretEncryptedUrlQuery=1";

        // Assert
        Assert.IsTrue(SectraSharedSecretEncryption.IsSharedSecretEncryption(encryptedString));
    }

    [TestMethod]
    public void IsSharedSecretEncryption_DetectsEncryptedLaunchString() {
        // Arrange
        var key = GetKey();

        // Act
        var encryptedString = SectraSharedSecretEncryption.Secure(plainTextTestData, key);

        // Assert
        Assert.IsTrue(SectraSharedSecretEncryption.IsSharedSecretEncryption(encryptedString));
    }

    [TestMethod]
    public void SharedSecretEncryption_CanSecureAndViewString() {
        // Arrange
        var key = GetKey();

        // Act
        var encryptedString = SectraSharedSecretEncryption.Secure(plainTextTestData, key);
        var decryptedString = SectraSharedSecretEncryption.View(encryptedString, key);

        // Assert
        Assert.AreEqual(plainTextTestData, decryptedString);
    }

    [TestMethod]
#if NET8_0_OR_GREATER
    [DataRow(encryptedTextTestData2023)]
#endif
    [DataRow(encryptedNetFrameworkTextTestData2023)]
    public void SharedSecretEncryption_CanUnpackNonceAndTimeStampFromOldEncryptedString(string encryptedString) {
        // Arrange
        var key = GetKey(); // Key is not relevant as the decryption will fail earlier due to timestamp as expected

        // Act
        var ex = Assert.ThrowsExactly<ArgumentException>(() => SectraSharedSecretEncryption.View(encryptedString, key));

        // Assert
        StringAssert.StartsWith(ex.Message, "Timestamp too old");
    }

    [TestMethod]
#if NET8_0_OR_GREATER
    [DataRow(encryptedTextTestData2025)]
#endif
    [DataRow(encryptedNetFrameworkTextTestData2025)]
    public void SharedSecretEncryption_CanDecryptVersionCompatibleStrings(string encryptedString) {
        // Arrange
        var key = Convert.FromBase64String(base64TestEncryptionKey);

        // Act
        var decryptedString = SectraSharedSecretEncryption.View(encryptedString, key);

        // Assert
        Assert.AreEqual(plainTextTestData, decryptedString);
    }

    private class TestDateTimeProvider : DateTimeProvider {
        // May the fourth be with you
        private static DateTime testDate = new(2025, 5, 4, 12, 0, 0, DateTimeKind.Utc);

        public override DateTime UtcNow => testDate;

        public static void SetTestDate(DateTime date) {
            testDate = date;
        }
    }

    private static byte[] GetKey() {
        var rng = RandomNumberGenerator.Create();
        var bytes = new byte[32];
        rng.GetBytes(bytes);
        return bytes;
    }

}
