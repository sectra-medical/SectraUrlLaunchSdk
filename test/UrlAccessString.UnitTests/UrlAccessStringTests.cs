
using System;
using Xunit;

namespace Sectra.UrlLaunch.UrlAccessString;

public class UrlAccessStringTests {

    [Fact]
    public void UrlAccessString_GetAccessString_EmptyStringHasEmptyResult() {
        // Arrange
        var parameters = new Parameters();

        // Act
        var accessString = QueryString.GetQueryString(parameters);

        // Assert
        Assert.Equal(string.Empty, accessString);
    }

    [Fact]
    public void UrlAccessString_GetAccessString_Time() {
        // Arrange
        var parameters = new Parameters();
        var now = DateTime.UtcNow;
        var nowSince1970 = ((int)(now - new DateTime(1970, 1, 1)).TotalSeconds).ToString();

        // Act
        var accessString = QueryString.GetQueryStringWithCurrentTime(parameters);

        // Assert
        Assert.Equal($"time={nowSince1970}", accessString);
    }

    [Fact]
    public void UrlAccessString_GetAccessString_Parameters() {
        foreach (var kvp in UrlAccessStringTestsData.TestLaunchDictionary) {
            // Arrange & Act
            var expectation = kvp.Key;
            var parameters = kvp.Value;
            var accessString = QueryString.GetQueryString(parameters);

            // Assert
            Assert.Equal(expectation, accessString);
        }
    }

    [Fact]
    public void UrlAccessString_GetAccessString_IDS7_Command() {
        // Arrange
        var parameters = new Parameters {
            Ids7Command = Parameters.Ids7CommandEnum.OpenIpvWindow,
        };

        // Act
        var accessString = QueryString.GetQueryString(parameters);

        // Assert
        Assert.Equal("ids7_cmds=open_ipv_window", accessString);
    }

    [Fact]
    public void UrlAccessString_Parse_Parameters() {
        foreach (var kvp in UrlAccessStringTestsData.TestParseDictionary) {
            // Arrange & Act
            var queryString = kvp.Key;
            var parameters = kvp.Value;
            var accessString = QueryString.Parse(queryString);

            // Assert
            Assert.Equivalent(parameters, accessString);
        }
    }

    [Theory]
    [InlineData("sop_uid=1.2.3")] // Needs patient and exam context
    [InlineData("acc_no=req1")] // Needs patient context
    [InlineData("pat_id=patient&acc_no=req1&exam_id=ex1^ex2")] // Accession numbers and exam id lists needs to be of same length
    [InlineData("uniview_cmd=show_images")] // Needs patient context
    public void UrlAccessString_ParseAndValidate_Parameters(string queryString) {
        // Assert
        Assert.Throws<ArgumentException>(() => QueryString.Parse(queryString, QueryString.Validate));
    }
}
