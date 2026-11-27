using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Sectra.UrlLaunch.SharedSecret;

[TestClass]
public class SafeExtensionsTests {

    // MSTest's DynamicData cannot pass arguments to the source member, so expose
    // parameterless wrappers with the desired sample counts baked in.
    public static IEnumerable<object[]> RandomByteBuffers => RandomByteBufferMemberData(1000);

    public static IEnumerable<object[]> IntRange => IntRangeMemberData(1000);

    public static IEnumerable<object[]> RandomByteBufferMemberData(int n) {
        foreach (var _ in Enumerable.Range(start: 1, count: n)) {
            var buffer = new byte[4];
            RandomNumberGenerator.Create().GetBytes(buffer);
            yield return new object[] { buffer };
        }
    }

    public static IEnumerable<object[]> IntRangeMemberData(int n) {
        foreach (var i in Enumerable.Range(start: 1, count: n)) {
            yield return new object[] { (short)i };
        }
    }

    [TestMethod]
    [DynamicData(nameof(RandomByteBuffers))]
    public void EqualsConstantTime_WhenStringsAreSame_ReturnsTrue(byte[] buffer) {
        var str = Encoding.UTF8.GetString(buffer);
        var str2 = Encoding.UTF8.GetString(buffer);

        Assert.IsTrue(str.EqualsConstantTime(str2, 128));
    }

    [TestMethod]
    [DynamicData(nameof(IntRange))]
    public void SequenceEqualsConstantTime_WhenDifferent_ReturnsFalse(short i) {

        var source = new byte[] { 0x00, 0x00 };
        var compare = BitConverter.GetBytes(i);

        Assert.IsFalse(source.SequenceEqualConstantTime(compare, 4));
    }

    [TestMethod]
    public void SequenceEqualsConstantTime_WhenLengthLongerThanMax_Throws() {
        var source = new byte[] { 0x00, 0x00 };

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => source.SequenceEqualConstantTime(source, 1));
    }
}
