using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Sectra.UrlLaunch.SharedSecret;

#if !NET8_0_OR_GREATER

/// <summary>
/// HMAC-based Key Derivation Function implemented according to
/// https://datatracker.ietf.org/doc/html/rfc5869
///
/// Implemented using HMACSHA256
/// 
/// * Use this method to derive new cryptographically high entropy keys
///   from a given high entopy source key
/// * Don't use this to hash a password for storage. 
///   Instead use <see cref="System.Security.Cryptography.Rfc2898DeriveBytes"/>
///   for that.
/// </summary>
internal class Hkdf {

    /// <summary>
    /// HMACSHA256 outputs 32 bytes
    /// </summary>
    const int HashByteLength = 32;

    /// <summary>
    /// Returns a high entropy key of caller chosen length derived
    /// from the high entropy input key, and optional info
    /// 
    /// * This method assumes input key is of high entropy. 
    ///   If the input key material is of low entropy (e.g. a user chosen
    ///   password), instead use <see cref="Derive(byte[], byte[], int, byte[]?)"/>
    /// * info must be independent of the input key
    /// 
    /// </summary>
    /// <param name="inputKey">Input key</param>
    /// <param name="outputKeyByteLength">Output byte length, 32</param>
    /// <param name="info">Optional associated data. Should be kept small</param>
    /// <returns>Key</returns>
    public static byte[] Derive(byte[] inputKey, int outputKeyByteLength = 32, byte[]? info = null) {
        if (inputKey.Length < HashByteLength) {
            // When using the non-salt variant we require a min length
            throw new ArgumentException($"Minimum input key length is {HashByteLength}");
        }
        // If no salt is given RFC mandates it is set to zeroes
        var salt = Enumerable.Repeat((byte)0, 32).ToArray();
        return Derive(inputKey, salt, outputKeyByteLength, info);
    }

    /// <summary>
    /// Returns a high entropy key of caller chosen length derived
    /// from the low entropy input key, salt and optional info
    /// 
    /// </summary>
    /// <param name="inputKey">Input key</param>
    /// <param name="salt">Salt is used to derive a high entropy PRK from input key</param>
    /// <param name="outputKeyByteLength">Output byte length</param>
    /// <param name="info">Optional associated data. Should be kept small</param>
    /// <returns>Key</returns>
    public static byte[] Derive(byte[] inputKey, byte[] salt, int outputKeyByteLength = 32, byte[]? info = null) {
        var prfKey = Extract(salt, inputKey);
        return Expand(prfKey, outputKeyByteLength, info);
    }

    /// <summary>
    /// This is step 1 of the algorithm as outlined in the RFC
    /// </summary>
    private static byte[] Extract(byte[] salt, byte[] inputKeyMaterial) {
        if (salt.Length < HashByteLength) {
            // See HMAC RFC https://datatracker.ietf.org/doc/html/rfc2104#section-3
            // for rationale on key length (salt is used as HMAC key in Extract method)
            throw new ArgumentException($"Salt must be at least output hash length. Expected > {HashByteLength}, got {salt.Length}");
        }
        var hmac = new HMACSHA256(salt);
        return hmac.ComputeHash(inputKeyMaterial);
    }

    /// <summary>
    /// Step 2 of the algorithm as outlined in the RFC
    /// </summary>
    /// <exception cref="ArgumentException"></exception>
    private static byte[] Expand(byte[] key, int outputKeyByteLength, byte[]? info) {
        if (key.Length != HashByteLength) {
            throw new ArgumentException($"PRF key length must equal {HashByteLength}", nameof(key));
        }
        if (outputKeyByteLength < HashByteLength) {
            throw new ArgumentException($"Minimum output key length is {HashByteLength} bytes", nameof(outputKeyByteLength));
        }
        if (outputKeyByteLength > 255 * HashByteLength) {
            throw new ArgumentException($"Maximum output key length is {255 * HashByteLength}", nameof(outputKeyByteLength));
        }

        int n = Convert.ToInt32(Math.Ceiling((double)outputKeyByteLength / HashByteLength));
        var hmac = new HMACSHA256(key);
        var t = new List<byte[]>();

        // T0
        t.Add(new byte[0]);

        // T1..TN
        for (int i = 1; i <= n; i++) {
            var mac = hmac.ComputeHash(Concat(t.Last(), info, (byte)i));
            t.Add(mac);
        }

        return t.SelectMany(e => e).Take(outputKeyByteLength).ToArray();
    }

    /// <summary>
    /// Return byte array concatenation of all inputs
    /// </summary>
    private static byte[] Concat(byte[] lastHash, byte[]? info, byte n) {
        return lastHash
            .Concat(info ?? new byte[0])
            .Concat(new byte[1] { n })
            .ToArray();
    }
}

#endif
