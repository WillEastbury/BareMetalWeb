namespace BareMetalWeb.Data;

/// <summary>
/// Well-known setting IDs stored in the <see cref="AppSetting"/> object store.
/// These replace direct reads from the configuration file so settings can be
/// managed at runtime without a deployment.
/// </summary>
public static class WellKnownSettings
{
    /// <summary>The display name of the application.</summary>
    public const string AppName = "app.name";

    /// <summary>The company name shown in the application header/footer.</summary>
    public const string AppCompany = "app.company";

    /// <summary>The copyright year or statement shown in the application footer.</summary>
    public const string AppCopyright = "app.copyright";
}
