using System.Security.Cryptography;

namespace Sectra.UrlLaunch.SharedSecret;
internal class Rng {

    public static byte[] GetBytes(int size) {
        var rng = RandomNumberGenerator.Create();
        var bytes = new byte[size];
        rng.GetBytes(bytes);
        return bytes;
    }
}
