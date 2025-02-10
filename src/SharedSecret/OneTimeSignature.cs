using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Sectra.UrlLaunch.SharedSecret;

/// <summary>
/// Simplifies signing arbitrary data while preventing
/// replay attacks by using a timestamp and a nonce to make
/// signatures one time verifiable
///
/// Supports different signatures (ECDSA, RSA and HMAC)
///
/// Automatically pacs/unpacks signed data and signature into
/// a custom format to make the api easy to use
///
/// Example use case is when sending data and receiver needs to
/// verify message integrity
///
/// Not suitable when you need to sign once, but verify many times
///
/// If encryption of data is needed, use <see cref="EncryptedOneTimeSignature"/>
/// </summary>
internal class OneTimeSignature {

    private const int NonceByteCount = 32;
    private static readonly IConcurrentQueue<NonceAndTimestamp> SharedUsedNonces = new ConcurrentQueueWrapper<NonceAndTimestamp>();
    private const double MaxSignatureAgeSeconds = 30.0;

    /// <summary>
    /// Implements IConcurrentQueue using a ConcurrentQueue as backing collection
    /// </summary>
    private class ConcurrentQueueWrapper<NonceAndTimeStamp> : IConcurrentQueue<NonceAndTimestamp> {

        ConcurrentQueue<NonceAndTimestamp> innerQueue = new ConcurrentQueue<NonceAndTimestamp>();

        public int Count => innerQueue.Count;

        public void Enqueue(NonceAndTimestamp item) {
            innerQueue.Enqueue(item);
        }

        public IEnumerator<NonceAndTimestamp> GetEnumerator() {
            return innerQueue.GetEnumerator();
        }

        public bool TryDequeue(out NonceAndTimestamp? item) {
            return innerQueue.TryDequeue(out item);
        }

        public bool TryPeek(out NonceAndTimestamp? item) {
            return innerQueue.TryPeek(out item);
        }

        IEnumerator IEnumerable.GetEnumerator() {
            return innerQueue.GetEnumerator();
        }
    }

    /// <summary>
    /// Represents a nonce and corresponding time stamp
    /// </summary>
    public class NonceAndTimestamp {
        private readonly byte[] nonce;
        private readonly DateTime timeStamp;

        public bool Expired => DateTime.UtcNow.Subtract(timeStamp).TotalSeconds > MaxSignatureAgeSeconds;

        public DateTime Timestamp => timeStamp;

        public byte[] Nonce => nonce;

        public NonceAndTimestamp(DateTime timeStamp, byte[] Nonce) {
            this.nonce = Nonce;
            this.timeStamp = timeStamp;
        }
    }

    /// <summary>
    /// Purge nonces that has already expired
    /// These will either fail on verification of timestamp or signature
    /// </summary>
    private static void PurgeExpiredNonces(IConcurrentQueue<NonceAndTimestamp> nonces) {
        while (nonces.TryPeek(out var nonce) && nonce != null && nonce.Expired) {
            nonces.TryDequeue(out _);
        }
    }

    /// <summary>
    /// Pack Timestamp, nonce and data using format
    ///
    /// | 8 bytes   | 32 bytes | N bytes
    /// | Timestamp | Nonce    | data
    ///
    /// </summary>
    /// <returns>Byte array with packed data</returns>
    private static byte[] Pack(byte[] data) {
        return BitConverter.GetBytes(DateTime.UtcNow.ToBinary())
            .Concat(Rng.GetBytes(NonceByteCount))
            .Concat(data).ToArray();
    }

    /// <summary>
    /// Unpack timestamp, nonce and data from packed format
    /// </summary>
    private static (NonceAndTimestamp NonceAndTimestamp, byte[] Data) Unpack(IEnumerable<byte> data) {
        return (new NonceAndTimestamp(
            DateTime.FromBinary(BitConverter.ToInt64(data.Take(sizeof(long)).ToArray(), 0)),
            data.Skip(sizeof(long)).Take(NonceByteCount).ToArray()),
            data.Skip(sizeof(long) + NonceByteCount).ToArray());
    }

    private static bool VerifyTimestamp(DateTime timestamp) {
        return DateTime.UtcNow.Subtract(timestamp).TotalSeconds <= MaxSignatureAgeSeconds;
    }

    /// <summary>
    /// Sign data using HMACSHA256 and a symmetric (shared) key
    ///
    /// Pros:
    ///   * Simple and battle proven algorithm
    ///   * Fast
    /// Cons:
    ///   * Since key is shared in two or more locations:
    ///     - it more susceptible to a compromise
    ///     - Weaker Non-repudiation claims: any holder of the key could have signed
    ///       some data
    /// </summary>
    /// <param name="data">data to sign and pack</param>
    /// <param name="key"></param>
    public static byte[] Sign(byte[] data, byte[] key) {
        var packed = Pack(data);
        var hmac = new HMACSHA256(key);
        var mac = hmac.ComputeHash(packed);
        return mac.Concat(packed).ToArray();
    }

    /// <summary>
    /// Verify signed data using HMACSHA256 and key
    ///
    /// Used nonces (to enforce one-time usage) will be managed in an in memory shared storage
    /// </summary>
    /// <param name="data">signature and signed data</param>
    /// <param name="key">symmetric key used to sign the data</param>
    /// <returns>Plaintext data that was signed if signature verifies, otherwise exception is thrown</returns>
    public static byte[] Verify(
        byte[] data,
        byte[] key) {
        return Verify(data, key, SharedUsedNonces);
    }

    /// <summary>
    /// Verify signed data using HMACSHA256 and key
    /// </summary>
    /// <param name="data">signature and signed data</param>
    /// <param name="key">symmetric key used to sign the data</param>
    /// <param name="usedNonces">Optional backing store for used nonces. Useful e.g. in web farm scenarios</param> 
    /// <returns>Plaintext data that was signed if signature verifies, otherwise exception is thrown</returns>
    public static byte[] Verify(
        byte[] data,
        byte[] key,
        IConcurrentQueue<NonceAndTimestamp> usedNonces) {
        var hmac = new HMACSHA256(key);
        int signatureByteSize = hmac.HashSize / 8;
        return VerifySignature(data, signatureByteSize,
            (signedData, signature) => hmac.ComputeHash(signedData).SequenceEqualConstantTime(signature, signatureByteSize),
            usedNonces);
    }

    /// <summary>
    /// Method to verify a signature. The algorithm works by:
    /// 1. Unpacking the data
    /// 2. Verify timestamp against max age
    /// 3. Verify that Nonce is not reused
    /// 4. Verify signature over timestamp, nonce and data
    /// 5. Purge any expired nonces
    /// 6. Enqueue nonce to protect against reuse
    /// </summary>
    /// <param name="signatureAndSignedData">signature and data to verify</param>
    /// <param name="signatureByteCount">signature length (in bytes)</param>
    /// <param name="Verify">Callback method to perform actual signature verification</param>
    /// <returns>Plaintext data that was signed if signature verifies, otherwise exception is thrown</returns>
    /// <exception cref="CryptographicException">Timestamp expired or nonce reused</exception>
    private static byte[] VerifySignature(byte[] signatureAndSignedData, int signatureByteCount, Func<byte[], byte[], bool> Verify, IConcurrentQueue<NonceAndTimestamp> usedNonces) {
        var signatureBytes = signatureAndSignedData.Take(signatureByteCount).ToArray();
        var signedData = signatureAndSignedData.Skip(signatureByteCount).ToArray();
        var unpacked = Unpack(signedData);

        if (!VerifyTimestamp(unpacked.NonceAndTimestamp.Timestamp)) {
            throw new ArgumentException("Timestamp too old", nameof(unpacked.NonceAndTimestamp.Timestamp));
        }

        if (!VerifyNonce(unpacked.NonceAndTimestamp.Nonce, usedNonces)) {
            throw new CryptographicException("Nonce reused, possible replay attack!");
        }

        if (!Verify(signedData, signatureBytes))
            throw new CryptographicException("Signature verification failed");

        usedNonces.Enqueue(unpacked.NonceAndTimestamp);

        PurgeExpiredNonces(usedNonces);

        return unpacked.Data;
    }

    private static bool VerifyNonce(byte[] newNonce, IConcurrentQueue<NonceAndTimestamp> usedNonces) {
        return !usedNonces.Any(nonce => nonce.Nonce.SequenceEqual(newNonce));
    }
}
