
using System;

namespace Sectra.UrlLaunch.UrlAccessString;

/// <summary>
/// Data container for startup presentation parameters.
/// </summary>
public record StartupPresentationData {
    /// <summary>
    /// Representing an empty guid during serialization/launch
    /// </summary>
    public const string EmptyGuidString = "null";

    /// <summary>
    /// Constructor.
    /// </summary>
    public StartupPresentationData(Guid displayUnitGuid, Guid databaseGuid, string baseRpCookie) {
        this.DisplayUnitGuid = displayUnitGuid;
        this.DatabaseGuid = databaseGuid;
        this.BaseRpCookie = baseRpCookie;
    }

    /// <summary>
    /// Returns the display unit guid parameter.
    /// </summary>
    public Guid DisplayUnitGuid { get; private set; }

    /// <summary>
    /// Returns the database guid parameter.
    /// </summary>
    public Guid DatabaseGuid { get; private set; }

    /// <summary>
    /// Returns the base rp cookie parameter.
    /// </summary>
    public string BaseRpCookie { get; private set; }
}
