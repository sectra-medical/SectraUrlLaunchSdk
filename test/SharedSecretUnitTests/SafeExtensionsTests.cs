using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Sectra.UrlLaunch.SharedSecret;

public class SafeExtensionsTests {

    public static IEnumerable<object[]> RandomByteBufferMemberData(int n) {
        foreach (var _ in Enumerable.Range(start: 1, count: n)) {
            byte[] buffer = new byte[4];
            RandomNumberGenerator.Create().GetBytes(buffer);
            yield return new object[] { buffer };
        }
    }

    public static IEnumerable<object[]> IntRangeMemberData(int n) {
        foreach (var i in Enumerable.Range(start: 1, count: n)) {
            yield return new object[] { i };
        }
    }

    [Theory]
    [MemberData(nameof(RandomByteBufferMemberData), 1000)]
    public void EqualsConstantTime_WhenStringsAreSame_ReturnsTrue(byte[] buffer) {
        var str = Encoding.UTF8.GetString(buffer);
        var str2 = Encoding.UTF8.GetString(buffer);

        Assert.True(str.EqualsConstantTime(str2, 128));
    }

    [Theory]
    [MemberData(nameof(IntRangeMemberData), 1000)]
    public void SequenceEqualsConstantTime_WhenDifferent_ReturnsFalse(short i) {

        byte[] source = new byte[] { 0x00, 0x00 };
        byte[] compare = BitConverter.GetBytes(i);

        Assert.False(source.SequenceEqualConstantTime(compare, 4));
    }

    [Fact]
    public void SequenceEqualsConstantTime_WhenLengthLongerThanMax_Throws() {
        byte[] source = new byte[] { 0x00, 0x00 };

        Assert.Throws<ArgumentOutOfRangeException>(() => source.SequenceEqualConstantTime(source, 1));
    }
}
