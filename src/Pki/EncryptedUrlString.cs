using System;
using System.Collections.Generic;

namespace Sectra.UrlLaunch.Pki;

internal class EncryptedUrlString : UrlStringSerializable {
    public const string SymmetricallyEncryptedUrlStringKey = "SEUS";
    public const string EncryptedSymmetricPasswordKey = "ESP";
    public const string InitializationVectorKey = "IV";
    public const string ProtocolVersionKey = "V";

    public byte[]? SymmetricallyEncryptedUrlString { get; init; }

    public byte[]? EncryptedSymmetricPassword { get; init; }

    public byte[]? InitializationVector { get; init; }

    public ushort ProtocolVersion { get; set; }

    /// <summary>
    /// Serializes this instance into a URL query-parameter format with the values being URL encoded.
    /// </summary>
    /// <returns>A string that can be used as query parameters in a URL.</returns>
    public string Serialize() {
        var serializedProperties = new Dictionary<string, string>
        {
            { SymmetricallyEncryptedUrlStringKey, Convert.ToBase64String(this.SymmetricallyEncryptedUrlString ?? Array.Empty<byte>()).UrlEncodeString() },
            { EncryptedSymmetricPasswordKey, Convert.ToBase64String(this.EncryptedSymmetricPassword ?? Array.Empty<byte>()).UrlEncodeString() },
            { InitializationVectorKey, Convert.ToBase64String(this.InitializationVector ?? Array.Empty<byte>()).UrlEncodeString() },
            { ProtocolVersionKey, this.ProtocolVersion.ToString() },
        };

        return this.Serialize(serializedProperties);
    }

    /// <summary>
    /// Deserializes the specified string.
    /// </summary>
    /// <param name="input">The input string in the same format as returned from <see cref="Serialize" />.</param>
    /// <returns></returns>
    /// <exception cref="System.ArgumentNullException"></exception>
    public static new EncryptedUrlString Deserialize(string input) {
        if (input == null) {
            throw new ArgumentNullException(nameof(input));
        }

        var deserializedProperties = UrlStringSerializable.Deserialize(input);

        var instance = new EncryptedUrlString {
            SymmetricallyEncryptedUrlString = Convert.FromBase64String(deserializedProperties.ValueOrDefault(SymmetricallyEncryptedUrlStringKey, string.Empty).UrlDecodeString()),
            EncryptedSymmetricPassword = Convert.FromBase64String(deserializedProperties.ValueOrDefault(EncryptedSymmetricPasswordKey, string.Empty).UrlDecodeString()),
            InitializationVector = Convert.FromBase64String(deserializedProperties.ValueOrDefault(InitializationVectorKey, string.Empty).UrlDecodeString()),
            ProtocolVersion = Convert.ToUInt16(deserializedProperties.ValueOrDefault(ProtocolVersionKey, "0")),
        };

        return instance;
    }
}
