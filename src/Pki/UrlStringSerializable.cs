using System.Collections.Generic;
using System.Linq;

namespace Sectra.UrlLaunch.Pki;
internal abstract class UrlStringSerializable {
    /// <summary>
    /// Serializes the specified properties to a query parameter string.
    /// </summary>
    /// <param name="properties">The properties.</param>
    /// <returns></returns>
    protected string Serialize(IEnumerable<KeyValuePair<string, string>> properties) {
        return string.Join("&", properties.Select(x => $"{x.Key}={x.Value}"));
    }

    /// <summary>
    /// Deserializes the specified query parameter string to a dictionary containing the properties and values contained in it.
    /// </summary>
    /// <param name="input">The input.</param>
    /// <returns></returns>
    protected static Dictionary<string, string> Deserialize(string input) {
        return input.Split('&')
            .Select(x => x.Split('='))
            .Where(pair => pair.Length == 2)
            .ToDictionary(x => x[0], x => x[1]);
    }
}