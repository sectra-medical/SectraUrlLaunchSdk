using System.Collections.Generic;
using System.Net;

namespace Sectra.UrlLaunch.Pki;
internal static class Extensions {
    public static string UrlEncodeString(this string source) {
        return WebUtility.UrlEncode(source);
    }

    public static string UrlDecodeString(this string source) {
        return WebUtility.UrlDecode(source);
    }

    public static U ValueOrDefault<T, U>(this IDictionary<T, U> source, T key, U defaultValue) {
        if (source.TryGetValue(key, out var result) && result != null) {
            return result;
        }

        return defaultValue;
    }
}
