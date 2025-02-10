
using System;
using System.Collections.Generic;
using System.Linq;

namespace Sectra.UrlLaunch.UrlAccessString;

internal static class QueryStringUtility {
    /// <summary>
    /// Create url launch parameter with key and value (and separator).
    /// </summary>
    /// <param name="key">Url launch string key.</param>
    /// <param name="value">Url launch string value.</param>
    /// <param name="escape">True if <see cref="value"/> should be URL encoded</param>
    public static string CreateUrlParameter(string key, string value, bool escape = true) {
        return $"{EscapeString(key)}={(escape ? EscapeString(value) : value)}";
    }

    /// <summary>
    /// Escapes the specified string.
    /// </summary>
    public static string EscapeString(string str) {
        return System.Web.HttpUtility.UrlEncode(str);
    }

    /// <summary>
    /// Un-escapes the specified string.
    /// </summary>
    public static string UnEscapeString(string str) {
        return System.Web.HttpUtility.UrlDecode(str);
    }

    /// <summary>
    /// Parse enum from string
    /// </summary>
    public static T ParseEnum<T>(string arg) where T : Enum {
        return (T)Enum.Parse(typeof(T), UnEscapeString(arg), ignoreCase: true);
    }

    /// <summary>
    /// Parses a list of arguments separated by the '^' character.
    /// If <paramref name="unescape"/> is true, then <paramref name="arg"/> will be
    /// unescaped before being processed.
    /// </summary>
    public static List<string> ParseList(string arg, bool unescape) {
        string processedArg = unescape ? UnEscapeString(arg) : arg;
        string[] param = processedArg.Split('^');

        return param.Length > 0 ? new List<string>(param) : new List<string> { processedArg };
    }

    /// <summary>
    /// Converts a list of strings to a single string using the specified separator
    /// </summary>
    public static string ListToString(List<string> strList, string separator = "^", bool escape = true) {
        return string.Join(separator, escape ? strList.ConvertAll(EscapeString) : strList);
    }

    /// <summary>
    /// Converts a DateTime object to the query string integer equivalent
    /// </summary>
    public static int TimeToSeconds(DateTime time) {
        var t = time - new DateTime(1970, 1, 1);
        return (int)t.TotalSeconds;
    }

    /// <summary>
    /// Converts query string integer time to a DateTime object
    /// </summary>
    public static DateTime SecondsToTime(string seconds) {
        long secondsSince1970 = long.Parse(seconds);
        var time = new DateTime(1970, 1, 1);
        time = time.AddSeconds(secondsSince1970);
        return time;
    }

    /// <summary>
    /// Check if name is in the DICOM Person Name (PN) format.
    /// </summary>
    public static bool IsPersonName(string str) {
        // Maximum number of characters
        if (str.Length > 64) {
            return false;
        }

        // Forbidden characters
        if (str.Any(c => c == '\\' || char.IsControl(c))) {
            return false;
        }

        // Check number of name components and delimiters.
        // DICOM format: family name complex^given name complex^middle name^name prefix^name suffix
        var parts = str.Split('^');

        // Check max length
        return parts.Length <= 5;
    }

    /// <summary>
    /// Check if date str is in the DICOM Date (DA) format, YYYYMMDD.
    /// Converts similar formats to DA format.
    /// </summary>
    public static bool IsDate(string str, out string date) {
        // Search for invalid characters in date and remove
        // characters of the type '/', '-' and space.
        date = string.Empty;
        foreach (char c in str) {
            if ((c == '-') || (c == ' ') || (c == '/')) {
                continue;
            }

            if (!char.IsDigit(c)) {
                return false;
            }

            date += c;
        }

        // Check string length
        if (date.Length != 8) {
            return false;
        }

        // Check if month is in the interval [1, 12]
        int month = int.Parse(date.Substring(4, 2));
        if (month < 1 || month > 12) {
            return false;
        }

        // Check if day is in the interval [1, 31]
        int day = int.Parse(date.Substring(6, 2));
        if (day < 1 || day > 31) {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Check if argument sex can be interpreted as a valid value
    /// for patient sex according to the DICOM standard.
    /// </summary>
    public static bool IsPatientSex(string str, out string? sex) {
        sex = null;
        if (str.ToLower() == "m" || str.ToLower() == "male" || str.ToLower() == "man") {
            sex = "M";
            return true;
        }

        if (str.ToLower() == "f" || str.ToLower() == "female" || str.ToLower() == "woman" || str.ToLower() == "k" || str.ToLower() == "kvinna") {
            sex = "F";
            return true;
        }

        if (str.ToLower() == "o" || str.ToLower() == "other") {
            sex = "O";
            return true;
        }

        if (str.ToLower() == "empty") {
            sex = "EMPTY";
            return true;
        }

        // Patient sex must be in DICOM format, EMPTY, M, F or O (Empty, Male, Female or Other)
        return false;
    }

    /// <summary>
    /// Check if string is in the DICOM short string (SH) format.
    /// </summary>
    public static bool IsLongString(string str) {
        // Check maximum string length and forbidden characters
        return str.Length <= 64 && str.All(t => t != '\\' && !char.IsControl(t));
    }

    public static Parameters.OrderManagementCommandEnum ParseOMCmd(string OMCommand) => OMCommand switch {
        "schedule_request" => Parameters.OrderManagementCommandEnum.ScheduleRequestExaminations,
        "scheduler_overview" => Parameters.OrderManagementCommandEnum.OpenReferringUnitOverview,
        "create_request" or "" => Parameters.OrderManagementCommandEnum.CreateRequest,
        "search_patient" => Parameters.OrderManagementCommandEnum.SearchPatient,
        "order_overview" => Parameters.OrderManagementCommandEnum.OrderOverview,
        _ => throw new ArgumentException("Unknown Order Management cmd parameter supplied:" + OMCommand),
    };

    public static Parameters.UniViewCommandEnum ParseUniViewCmd(string uniViewCommand) => uniViewCommand.ToLower() switch {
        "show_images" => Parameters.UniViewCommandEnum.ShowImages,
        _ => throw new ArgumentException("Unknown UniView cmd parameter supplied:" + uniViewCommand),
    };

    public static string CreateUniViewCmd(Parameters.UniViewCommandEnum uniViewCommand) => uniViewCommand switch {
        Parameters.UniViewCommandEnum.None => "none",
        Parameters.UniViewCommandEnum.ShowImages => "show_images",
        _ => throw new ArgumentException("Unknown UniView cmd parameter supplied:" + uniViewCommand),
    };

    public static Parameters.UniViewLayoutEnum ParseUniViewLayout(string arg) => arg.ToLower() switch {
        "default" => Parameters.UniViewLayoutEnum.Default,
        "image_and_toolbar" => Parameters.UniViewLayoutEnum.ImageAndToolbar,
        _ => throw new ArgumentException("Unknown UniView layout parameter supplied:" + arg)
    };

    public static string CreateUniViewLayout(Parameters.UniViewLayoutEnum uniViewCommand) => uniViewCommand switch {
        Parameters.UniViewLayoutEnum.Default => "default",
        Parameters.UniViewLayoutEnum.ImageAndToolbar => "image_and_toolbar",
        _ => throw new ArgumentException("Unknown UniView layout parameter supplied:" + uniViewCommand),
    };

    public static string CreateIds7WindowManagement(Parameters.Ids7WindowManagementEnum ids7WindowManagement) => ids7WindowManagement switch {
        Parameters.Ids7WindowManagementEnum.ImageWindow => "image_window",
        Parameters.Ids7WindowManagementEnum.InformationWindow => "information_window",
        Parameters.Ids7WindowManagementEnum.KeepInBackground => "keep_in_background",
        _ => throw new ArgumentException("Unknown IDS7 window management parameter supplied:" + ids7WindowManagement),
    };

    public static Parameters.Ids7WindowManagementEnum ParseIds7WindowManagement(string arg) => arg.ToLower() switch {
        "image_window" => Parameters.Ids7WindowManagementEnum.ImageWindow,
        "information_window" => Parameters.Ids7WindowManagementEnum.InformationWindow,
        "keep_in_background" => Parameters.Ids7WindowManagementEnum.KeepInBackground,
        _ => throw new ArgumentException("Unknown UniView window management parameter supplied:" + arg)
    };

    public static string CreateIds7Command(Parameters.Ids7CommandEnum ids7Command) => ids7Command switch {
        Parameters.Ids7CommandEnum.None => "none",
        Parameters.Ids7CommandEnum.OpenIpvWindow => "open_ipv_window",
        _ => throw new ArgumentException("Unknown IDS7 command parameter supplied:" + ids7Command),
    };
}
