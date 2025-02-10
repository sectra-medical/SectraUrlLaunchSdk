using System;
using System.IO;
using System.Security.Cryptography;

namespace Sectra.UrlLaunch.Pki;
internal sealed class SymmetricalEncryptor {
    public static byte[] Encrypt(byte[] input, out byte[] key, out byte[] iv) {
        byte[] encrypted;
        using var rijAlg = Aes.Create();
        rijAlg.GenerateKey();
        rijAlg.GenerateIV();

        key = rijAlg.Key;
        iv = rijAlg.IV;

        using var encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);
        using var ms = new MemoryStream();
        using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
        cs.Write(input, 0, input.Length);
        cs.Flush();
        cs.FlushFinalBlock();

        encrypted = ms.ToArray();

        return encrypted;
    }

    public static byte[] Decrypt(byte[] cipherText, byte[] key, byte[] iv) {
        if (cipherText == null || cipherText.Length <= 0) {
            throw new ArgumentNullException(nameof(cipherText));
        }
        if (key == null || key.Length <= 0) {
            throw new ArgumentNullException(nameof(key));
        }
        if (iv == null || iv.Length <= 0) {
            throw new ArgumentNullException(nameof(iv));
        }

        using var rijAlg = Aes.Create();
        rijAlg.Key = key;
        rijAlg.IV = iv;

        using var decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);
        using var msDecrypt = new MemoryStream(cipherText);
        using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
        using var result = new MemoryStream();
        csDecrypt.CopyTo(result);

        return result.ToArray();
    }
}
