using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Sectra.UrlLaunch.UrlAccessString;

[TestClass]
public class QueryStringMalformedInputTests {

    [TestMethod]
    public void Parse_EmptyString_ReturnsDefaultParameters() {
        var result = QueryString.Parse("");
        Assert.IsNotNull(result);
    }

    [TestMethod]
    [DataRow("no_equals_sign")]
    [DataRow("key_only")]
    [DataRow("missing=val&bad")]
    public void Parse_MalformedKeyValuePair_ThrowsArgumentException(string input) {
        Assert.ThrowsExactly<ArgumentException>(() => QueryString.Parse(input));
    }

    [TestMethod]
    public void Parse_UnknownParameter_ThrowsArgumentException() {
        var ex = Assert.ThrowsExactly<ArgumentException>(
            () => QueryString.Parse("totally_unknown_param=value"));
        StringAssert.Contains(ex.Message, "Unknown parameter");
    }

    [TestMethod]
    [DataRow("time=notanumber")]
    [DataRow("time=12.34")]
    [DataRow("time=")]
    public void Parse_InvalidTimeValue_Throws(string input) {
        Assert.Throws<Exception>(() => QueryString.Parse(input));
    }

    [TestMethod]
    [DataRow("frame_number=0")]
    [DataRow("frame_number=-1")]
    [DataRow("frame_number=abc")]
    [DataRow("frame_number=")]
    public void Parse_InvalidFrameNumber_ThrowsArgumentException(string input) {
        Assert.ThrowsExactly<ArgumentException>(() => QueryString.Parse(input));
    }

    [TestMethod]
    public void Parse_StartupPresentation_WrongComponentCount_Throws() {
        // sp parameter expects exactly 3 components separated by ^
        Assert.ThrowsExactly<ArgumentException>(
            () => QueryString.Parse("sp=one%5Etwo")); // only 2 components
    }

    [TestMethod]
    public void Parse_StartupPresentation_InvalidGuid_Throws() {
        Assert.Throws<Exception>(
            () => QueryString.Parse("sp=not-a-guid%5Enot-a-guid%5Ecookie"));
    }

    [TestMethod]
    public void Parse_PatientName_TooLong_ThrowsArgumentException() {
        var longName = new string('A', 65);
        Assert.ThrowsExactly<ArgumentException>(
            () => QueryString.Parse($"pat_name={longName}"));
    }

    [TestMethod]
    public void Parse_PatientName_ControlCharacters_ThrowsArgumentException() {
        Assert.ThrowsExactly<ArgumentException>(
            () => QueryString.Parse("pat_name=Name%00WithNull"));
    }

    [TestMethod]
    public void Parse_PatientBirthdate_InvalidDate_ThrowsArgumentException() {
        Assert.ThrowsExactly<ArgumentException>(
            () => QueryString.Parse("pat_birth=99991301")); // month 13 invalid
    }

    [TestMethod]
    public void Parse_PatientBirthdate_NonNumeric_ThrowsArgumentException() {
        Assert.ThrowsExactly<ArgumentException>(
            () => QueryString.Parse("pat_birth=abcdefgh"));
    }

    [TestMethod]
    public void Parse_PatientSex_Invalid_ThrowsArgumentException() {
        Assert.ThrowsExactly<ArgumentException>(
            () => QueryString.Parse("pat_sex=X"));
    }

    [TestMethod]
    public void Parse_ReferringUnit_TooLong_ThrowsArgumentException() {
        var longRef = new string('R', 65);
        Assert.ThrowsExactly<ArgumentException>(
            () => QueryString.Parse($"ref_unit={longRef}"));
    }

    [TestMethod]
    [DataRow("cmd=unknown_command")]
    [DataRow("uniview_cmd=unknown_command")]
    [DataRow("uv_layout=unknown_layout")]
    [DataRow("ids7_window_management=unknown")]
    public void Parse_InvalidEnumValue_ThrowsArgumentException(string input) {
        Assert.ThrowsExactly<ArgumentException>(() => QueryString.Parse(input));
    }

    [TestMethod]
    [DataRow("login_type=nonexistent")]
    public void Parse_InvalidLoginType_Throws(string input) {
        Assert.Throws<Exception>(() => QueryString.Parse(input));
    }

    [TestMethod]
    public void Parse_LimitedAccess_ImpliesNoPatientChange() {
        var result = QueryString.Parse("limited_access=1");
        Assert.IsFalse(result.AllowPatientChange!.Value);
    }

    [TestMethod]
    public void Parse_IgnoredParameters_AreSkipped() {
        // key, close_popup, client are ignored
        var result = QueryString.Parse("key=secret&close_popup=1&client=test");
        Assert.IsNotNull(result);
    }

    [TestMethod]
    public void Parse_UrlEncodedValues_DecodedCorrectly() {
        var result = QueryString.Parse("pat_id=patient%20with%20spaces");
        Assert.AreEqual("patient with spaces", result.PatientId);
    }

    [TestMethod]
    public void Parse_MultipleAccessionNumbers_ParsedAsList() {
        var result = QueryString.Parse("pat_id=p1&acc_no=acc1%5Eacc2%5Eacc3");
        Assert.AreEqual(3, result.AccessionNumber!.Count);
        Assert.AreEqual("acc1", result.AccessionNumber[0]);
    }
}
