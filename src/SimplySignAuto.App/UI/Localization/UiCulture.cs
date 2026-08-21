using System.Globalization;
using System.Resources;

namespace SimplySignAuto.App.UI.Localization;

public static class UiCulture
{
    public const string ChineseName = "zh-CN";
    public const string EnglishName = "en-US";

    private static readonly ResourceManager Strings = new(
        "SimplySignAuto.App.UI.Resources.UiStrings",
        typeof(UiCulture).Assembly);

    public static CultureInfo ResolveDefault(CultureInfo systemUiCulture)
    {
        ArgumentNullException.ThrowIfNull(systemUiCulture);
        return ResolveSelection(
            systemUiCulture.TwoLetterISOLanguageName.Equals("zh", StringComparison.OrdinalIgnoreCase)
                ? ChineseName
                : EnglishName);
    }

    public static CultureInfo ResolveSelection(string cultureName) => cultureName switch
    {
        ChineseName => CultureInfo.GetCultureInfo(ChineseName),
        EnglishName => CultureInfo.GetCultureInfo(EnglishName),
        _ => throw new ArgumentException("ui_culture_unsupported", nameof(cultureName)),
    };

    public static void Apply(CultureInfo culture)
    {
        ArgumentNullException.ThrowIfNull(culture);
        var selected = ResolveSelection(culture.Name);
        CultureInfo.CurrentCulture = selected;
        CultureInfo.CurrentUICulture = selected;
        CultureInfo.DefaultThreadCurrentCulture = selected;
        CultureInfo.DefaultThreadCurrentUICulture = selected;
    }

    public static string GetString(string key, CultureInfo culture)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentNullException.ThrowIfNull(culture);
        var selected = ResolveSelection(culture.Name);
        return Strings.GetString(key, selected) is { Length: > 0 } value
            ? value
            : throw new InvalidOperationException($"ui_resource_missing:{key}");
    }
}
