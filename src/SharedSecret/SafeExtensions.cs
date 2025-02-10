using System;
using System.Linq;
using System.Text;

namespace Sectra.UrlLaunch.SharedSecret;
internal static class SafeExtensions {
    /// <summary>
    /// Compares two strings for equality in constant time. Should be used for
    /// string comparisons that could be subject to timing attacks
    /// 
    /// A typical use case is comparing a user supplied token
    /// with a stored one for authentication
    /// </summary>
    /// <param name="first">first input string</param>
    /// <param name="second">second input string</param>
    /// <param name="maxExpectedLength">The max expected length of valid strings.
    /// Do NOT set dynamically to length of any of the input strings</param>
    public static bool EqualsConstantTime(this string first, string second, int maxExpectedLength) {
        // More defensive would be to throw exception if any of the strings
        // are ill-formed, however since we just want to do a byte by byte
        // equality check it does not matter and this is still safe
        return SequenceEqualConstantTime(
            Encoding.UTF8.GetBytes(first),
            Encoding.UTF8.GetBytes(second),
            maxExpectedLength);
    }

    /// <summary>
    /// Compare two byte sequences for equality in constant time. Should be used for
    /// comparisons that could be subject to timing attacks
    /// </summary>
    /// <param name="first">first byte sequence</param>
    /// <param name="second">second byte sequence</param>
    /// <param name="maxExpectedLength">The max expected length of valid strings. 
    /// Do NOT set dynamically to length of any of the input strings</param>
    public static bool SequenceEqualConstantTime(this byte[] first, byte[] second, int maxExpectedLength) {

        if (first.Length > maxExpectedLength) {
            throw new ArgumentOutOfRangeException(
                $"{nameof(first)}={first.Length} must not exceed {nameof(maxExpectedLength)}={maxExpectedLength}",
                nameof(first));
        }

        if (second.Length > maxExpectedLength) {
            throw new ArgumentOutOfRangeException(
                $"{nameof(second)}={second.Length} must not exceed {nameof(maxExpectedLength)}={maxExpectedLength}",
                nameof(second));
        }

        // NOTE: This method is deliberately slow by comparing all elements. It pads
        //       both sequences to a fixed max length to not leak any information on
        //       length of source sequence. Do not optimize this code in an unsafe way,
        //       i.e. that would early out. It should run in (near) constant time
        //       on the same hardware, regardless of input.

        const byte padChar = 0x1c;
        first.Concat(Enumerable.Repeat(padChar, maxExpectedLength - first.Length)).ToArray();
        second.Concat(Enumerable.Repeat(padChar, maxExpectedLength - second.Length)).ToArray();

        int differ = 0;
        for (int i = 0; i < first.Length; i++) {
            differ |= first[i] ^ second[i];
        }
        return differ == 0;
    }
}

