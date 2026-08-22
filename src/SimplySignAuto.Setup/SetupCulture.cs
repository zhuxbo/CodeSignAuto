using System.Globalization;
using System.Resources;

namespace SimplySignAuto.Setup;

internal static class SetupCulture
{
    public const string ChineseName = "zh-CN";
    public const string EnglishName = "en-US";

    private static readonly ResourceManager Strings = new(
        "SimplySignAuto.Setup.Resources.SetupStrings",
        typeof(SetupCulture).Assembly);

    public static CultureInfo ResolveDefault(CultureInfo windowsUiCulture)
    {
        ArgumentNullException.ThrowIfNull(windowsUiCulture);
        return ResolveSelection(
            windowsUiCulture.TwoLetterISOLanguageName.Equals("zh", StringComparison.OrdinalIgnoreCase)
                ? ChineseName
                : EnglishName);
    }

    public static CultureInfo ResolveSelection(string cultureName) => cultureName switch
    {
        ChineseName => CultureInfo.GetCultureInfo(ChineseName),
        EnglishName => CultureInfo.GetCultureInfo(EnglishName),
        _ => throw new ArgumentException("setup_culture_unsupported", nameof(cultureName)),
    };

    public static string GetString(string key, CultureInfo culture)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentNullException.ThrowIfNull(culture);
        var selected = ResolveSelection(culture.Name);
        return Strings.GetString(key, selected) is { Length: > 0 } value
            ? value
            : throw new InvalidOperationException($"setup_resource_missing:{key}");
    }

    public static string Format(string key, CultureInfo culture, params object?[] arguments) =>
        string.Format(culture, GetString(key, culture), arguments);

    public static string DescribeError(
        string code,
        CultureInfo culture,
        string? autoLogonAccount = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        var resourceKey = ReadPrimaryCode(code) switch
        {
            "required_runtime_missing" => "ErrorRequiredRuntimeMissing",
            "simplysign_desktop_missing" => "ErrorSimplySignDesktopMissing",
            "simplysign_pkcs11_missing" => "ErrorSimplySignPkcs11Missing",
            "os_unsupported" => "ErrorOsUnsupported",
            "desktop_experience_required" => "ErrorDesktopExperienceRequired",
            "architecture_unsupported" => "ErrorArchitectureUnsupported",
            "elevation_required" or "administrator_required" => "ErrorAdministratorRequired",
            "domain_controller_unsupported" => "ErrorDomainControllerUnsupported",
            "autologon_conflict" => "ErrorAutoLogonConflict",
            "autologon_plaintext_password_present" => "ErrorAutoLogonPlaintextPasswordPresent",
            "autologon_cleanup_owned_state" => "ErrorAutoLogonCleanupOwnedState",
            "autologon_cleanup_state_uncertain" => "ErrorAutoLogonCleanupStateUncertain",
            "autologon_cleanup_busy" => "ErrorAutoLogonCleanupBusy",
            "autologon_cleanup_failed" => "ErrorAutoLogonCleanupFailed",
            "install_media_target_exists" => "ErrorInstallMediaTargetExists",
            _ => "ErrorGeneric",
        };
        var reason = resourceKey == "ErrorAutoLogonConflict"
            ? Format(
                resourceKey,
                culture,
                autoLogonAccount ?? GetString("AutoLogonAccountUnknown", culture))
            : GetString(resourceKey, culture);
        return reason + Environment.NewLine + Environment.NewLine +
            Format("ErrorCodeFormat", culture, code);
    }

    public static string ReadPrimaryCode(string code)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        var separator = code.IndexOf(' ', StringComparison.Ordinal);
        return separator > 0 ? code[..separator] : code;
    }
}
