using System;
using Xunit;

namespace Sectra.UrlLaunch.UrlAccessString;

public class QueryStringMalformedInputTests {

    [Fact]
    public void Parse_EmptyString_ReturnsDefaultParameters() {
        var result = QueryString.Parse("");
        Assert.NotNull(result);
    }

    [Theory]
    [InlineData("no_equals_sign")]
    [InlineData("key_only")]
    [InlineData("missing=val&bad")]
    public void Parse_MalformedKeyValuePair_ThrowsArgumentException(string input) {
        Assert.Throws<ArgumentException>(() => QueryString.Parse(input));
    }

    [Fact]
    public void Parse_UnknownParameter_ThrowsArgumentException() {
        var ex = Assert.Throws<ArgumentException>(
            () => QueryString.Parse("totally_unknown_param=value"));
        Assert.Contains("Unknown parameter", ex.Message);
    }

    [Theory]
    [InlineData("time=notanumber")]
    [InlineData("time=12.34")]
    [InlineData("time=")]
    public void Parse_InvalidTimeValue_Throws(string input) {
        Assert.ThrowsAny<Exception>(() => QueryString.Parse(input));
    }

    [Theory]
    [InlineData("frame_number=0")]
    [InlineData("frame_number=-1")]
    [InlineData("frame_number=abc")]
    [InlineData("frame_number=")]
    public void Parse_InvalidFrameNumber_ThrowsArgumentException(string input) {
        Assert.Throws<ArgumentException>(() => QueryString.Parse(input));
    }

    [Fact]
    public void Parse_StartupPresentation_WrongComponentCount_Throws() {
        // sp parameter expects exactly 3 components separated by ^
        Assert.Throws<ArgumentException>(
            () => QueryString.Parse("sp=one%5Etwo")); // only 2 components
    }

    [Fact]
    public void Parse_StartupPresentation_InvalidGuid_Throws() {
        Assert.ThrowsAny<Exception>(
            () => QueryString.Parse("sp=not-a-guid%5Enot-a-guid%5Ecookie"));
    }

    [Fact]
    public void Parse_PatientName_TooLong_ThrowsArgumentException() {
        var longName = new string('A', 65);
        Assert.Throws<ArgumentException>(
            () => QueryString.Parse($"pat_name={longName}"));
    }

    [Fact]
    public void Parse_PatientName_ControlCharacters_ThrowsArgumentException() {
        Assert.Throws<ArgumentException>(
            () => QueryString.Parse("pat_name=Name%00WithNull"));
    }

    [Fact]
    public void Parse_PatientBirthdate_InvalidDate_ThrowsArgumentException() {
        Assert.Throws<ArgumentException>(
            () => QueryString.Parse("pat_birth=99991301")); // month 13 invalid
    }

    [Fact]
    public void Parse_PatientBirthdate_NonNumeric_ThrowsArgumentException() {
        Assert.Throws<ArgumentException>(
            () => QueryString.Parse("pat_birth=abcdefgh"));
    }

    [Fact]
    public void Parse_PatientSex_Invalid_ThrowsArgumentException() {
        Assert.Throws<ArgumentException>(
            () => QueryString.Parse("pat_sex=X"));
    }

    [Fact]
    public void Parse_ReferringUnit_TooLong_ThrowsArgumentException() {
        var longRef = new string('R', 65);
        Assert.Throws<ArgumentException>(
            () => QueryString.Parse($"ref_unit={longRef}"));
    }

    [Theory]
    [InlineData("cmd=unknown_command")]
    [InlineData("uniview_cmd=unknown_command")]
    [InlineData("uv_layout=unknown_layout")]
    [InlineData("ids7_window_management=unknown")]
    public void Parse_InvalidEnumValue_ThrowsArgumentException(string input) {
        Assert.Throws<ArgumentException>(() => QueryString.Parse(input));
    }

    [Theory]
    [InlineData("login_type=nonexistent")]
    public void Parse_InvalidLoginType_Throws(string input) {
        Assert.ThrowsAny<Exception>(() => QueryString.Parse(input));
    }

    [Fact]
    public void Parse_LimitedAccess_ImpliesNoPatientChange() {
        var result = QueryString.Parse("limited_access=1");
        Assert.False(result.AllowPatientChange);
    }

    [Fact]
    public void Parse_IgnoredParameters_AreSkipped() {
        // key, close_popup, client are ignored
        var result = QueryString.Parse("key=secret&close_popup=1&client=test");
        Assert.NotNull(result);
    }

    [Fact]
    public void Parse_UrlEncodedValues_DecodedCorrectly() {
        var result = QueryString.Parse("pat_id=patient%20with%20spaces");
        Assert.Equal("patient with spaces", result.PatientId);
    }

    [Fact]
    public void Parse_MultipleAccessionNumbers_ParsedAsList() {
        var result = QueryString.Parse("pat_id=p1&acc_no=acc1%5Eacc2%5Eacc3");
        Assert.Equal(3, result.AccessionNumber!.Count);
        Assert.Equal("acc1", result.AccessionNumber[0]);
    }
}
