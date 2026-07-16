using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Sectra.UrlLaunch.SharedSecret;

[TestClass]
public class OneTimeSignatureReplayTests {

    private static readonly string PlainText = "The quick brown fox jumps over the lazy dog";

    [TestMethod]
    public void Verify_SameDataTwice_WithSharedNonces_ThrowsOnSecondVerify() {
        var key = Rng.GetBytes(32);
        var nonces = new ConcurrentQueueWrapper<OneTimeSignature.NonceAndTimestamp>();
        var signedData = OneTimeSignature.Sign(Encoding.UTF8.GetBytes(PlainText), key);

        OneTimeSignature.Verify(signedData, key, nonces);

        var ex = Assert.ThrowsExactly<CryptographicException>(
            () => OneTimeSignature.Verify(signedData, key, nonces));
        Assert.AreEqual("Nonce reused, possible replay attack!", ex.Message);
    }

    [TestMethod]
    public void Verify_SameDataTwice_WithSeparateNonceStores_BothSucceed() {
        // Demonstrates the distributed system weakness: separate nonce stores
        // cannot detect replays across process boundaries
        var key = Rng.GetBytes(32);
        var nonces1 = new ConcurrentQueueWrapper<OneTimeSignature.NonceAndTimestamp>();
        var nonces2 = new ConcurrentQueueWrapper<OneTimeSignature.NonceAndTimestamp>();
        var signedData = OneTimeSignature.Sign(Encoding.UTF8.GetBytes(PlainText), key);

        var data1 = OneTimeSignature.Verify(signedData, key, nonces1);
        var data2 = OneTimeSignature.Verify(signedData, key, nonces2);

        Assert.AreEqual(PlainText, Encoding.UTF8.GetString(data1));
        Assert.AreEqual(PlainText, Encoding.UTF8.GetString(data2));
    }

    [TestMethod]
    public void Verify_ExpiredTimestamp_Throws() {
        var key = Rng.GetBytes(32);
        var nonces = new ConcurrentQueueWrapper<OneTimeSignature.NonceAndTimestamp>();

        try {
            // Sign data with a fake DateTimeProvider set to the past
            var oldTime = DateTime.UtcNow.AddSeconds(-60);
            DateTimeProvider.Current = new FakeDateTimeProvider(oldTime);
            var signedData = OneTimeSignature.Sign(Encoding.UTF8.GetBytes(PlainText), key);

            // Restore real time for verification
            DateTimeProvider.ResetToDefault();

            var ex = Assert.ThrowsExactly<ArgumentException>(
                () => OneTimeSignature.Verify(signedData, key, nonces));
            StringAssert.Contains(ex.Message, "Timestamp too old");
        }
        finally {
            DateTimeProvider.ResetToDefault();
        }
    }

    [TestMethod]
    public void Verify_TamperedSignature_Throws() {
        var key = Rng.GetBytes(32);
        var nonces = new ConcurrentQueueWrapper<OneTimeSignature.NonceAndTimestamp>();
        var signedData = OneTimeSignature.Sign(Encoding.UTF8.GetBytes(PlainText), key);

        // Flip a bit in the HMAC signature (first 32 bytes)
        signedData[0] ^= 0xFF;

        Assert.ThrowsExactly<CryptographicException>(
            () => OneTimeSignature.Verify(signedData, key, nonces));
    }

    [TestMethod]
    public void Verify_TamperedPayload_Throws() {
        var key = Rng.GetBytes(32);
        var nonces = new ConcurrentQueueWrapper<OneTimeSignature.NonceAndTimestamp>();
        var signedData = OneTimeSignature.Sign(Encoding.UTF8.GetBytes(PlainText), key);

        // Flip a bit in the payload area (after signature + timestamp + nonce)
        // HMAC=32 bytes, timestamp=8 bytes, nonce=32 bytes = 72 bytes header
        if (signedData.Length > 73) {
            signedData[73] ^= 0xFF;
        }

        Assert.ThrowsExactly<CryptographicException>(
            () => OneTimeSignature.Verify(signedData, key, nonces));
    }

    [TestMethod]
    public void Verify_MultipleDistinctSignatures_AllSucceed() {
        var key = Rng.GetBytes(32);
        var nonces = new ConcurrentQueueWrapper<OneTimeSignature.NonceAndTimestamp>();

        for (var i = 0; i < 10; i++) {
            var signedData = OneTimeSignature.Sign(
                Encoding.UTF8.GetBytes($"message {i}"), key);
            var result = OneTimeSignature.Verify(signedData, key, nonces);
            Assert.AreEqual($"message {i}", Encoding.UTF8.GetString(result));
        }
    }

    private class FakeDateTimeProvider : DateTimeProvider {
        private readonly DateTime fakeUtcNow;
        public FakeDateTimeProvider(DateTime fakeUtcNow) => this.fakeUtcNow = fakeUtcNow;
        public override DateTime UtcNow => fakeUtcNow;
    }

    private class ConcurrentQueueWrapper<T> : IConcurrentQueue<T> {
        private readonly System.Collections.Concurrent.ConcurrentQueue<T> inner = new();
        public int Count => inner.Count;
        public void Enqueue(T item) => inner.Enqueue(item);
        public bool TryDequeue(out T? item) => inner.TryDequeue(out item);
        public bool TryPeek(out T? item) => inner.TryPeek(out item);
        public System.Collections.Generic.IEnumerator<T> GetEnumerator() => inner.GetEnumerator();
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => inner.GetEnumerator();
    }
}
