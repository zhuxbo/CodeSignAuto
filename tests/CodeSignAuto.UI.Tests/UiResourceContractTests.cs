using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace CodeSignAuto.UI.Tests;

public sealed class UiResourceContractTests
{
    [Fact]
    public void Chinese_and_English_resources_have_identical_nonempty_keys()
    {
        var root = RepositoryRoot();
        var neutral = ReadResources(Path.Combine(
            root,
            "src",
            "CodeSignAuto.App",
            "UI",
            "Resources",
            "UiStrings.resx"));
        var english = ReadResources(Path.Combine(
            root,
            "src",
            "CodeSignAuto.App",
            "UI",
            "Resources",
            "UiStrings.en-US.resx"));

        Assert.Equal(neutral.Keys.Order(), english.Keys.Order());
        Assert.All(neutral.Values, value => Assert.False(string.IsNullOrWhiteSpace(value)));
        Assert.All(english.Values, value => Assert.False(string.IsNullOrWhiteSpace(value)));
        Assert.All(neutral.Keys, key => Assert.Equal(
            CompositeFormat.Parse(neutral[key]).MinimumArgumentCount,
            CompositeFormat.Parse(english[key]).MinimumArgumentCount));
        Assert.Contains("NavigationOverview", neutral.Keys);
        Assert.Contains("QuickSignChooseFile", neutral.Keys);
        Assert.Contains("JobsSaveCopy", neutral.Keys);
        Assert.Contains("ActivationImportTitle", neutral.Keys);
        Assert.Contains("ServiceSettingsEditTitle", neutral.Keys);
        Assert.Contains("TrayOpenConsole", neutral.Keys);
        Assert.Contains("ConfirmRelogin", neutral.Keys);
    }

    [Fact]
    public void User_visible_UI_sources_do_not_hardcode_Chinese_copy()
    {
        var uiRoot = Path.Combine(
            RepositoryRoot(),
            "src",
            "CodeSignAuto.App",
            "UI");
        var offenders = Directory.EnumerateFiles(uiRoot, "*", SearchOption.AllDirectories)
            .Where(path => Path.GetExtension(path) is ".cs" or ".xaml")
            .Where(path => Regex.IsMatch(File.ReadAllText(path), "[\\p{IsCJKUnifiedIdeographs}]"))
            .Select(path => Path.GetRelativePath(uiRoot, path))
            .Order()
            .ToArray();

        Assert.Empty(offenders);
    }

    [Fact]
    public void Every_XAML_UI_string_reference_exists_in_both_resources()
    {
        var root = RepositoryRoot();
        var uiRoot = Path.Combine(root, "src", "CodeSignAuto.App", "UI");
        var resources = ReadResources(Path.Combine(uiRoot, "Resources", "UiStrings.resx"));
        var references = Directory.EnumerateFiles(uiRoot, "*.xaml", SearchOption.AllDirectories)
            .SelectMany(path => Regex.Matches(
                    File.ReadAllText(path),
                    "\\{localization:UiString (?<key>[A-Za-z][A-Za-z0-9]+)\\}")
                .Select(match => match.Groups["key"].Value))
            .Distinct(StringComparer.Ordinal)
            .Order()
            .ToArray();

        Assert.NotEmpty(references);
        Assert.All(references, key => Assert.True(resources.ContainsKey(key), key));
    }

    [Fact]
    public void Every_CSharp_UI_string_reference_exists_in_both_resources()
    {
        var root = RepositoryRoot();
        var uiRoot = Path.Combine(root, "src", "CodeSignAuto.App", "UI");
        var resources = ReadResources(Path.Combine(uiRoot, "Resources", "UiStrings.resx"));
        var references = Directory.EnumerateFiles(uiRoot, "*.cs", SearchOption.AllDirectories)
            .SelectMany(path => Regex.Matches(
                    File.ReadAllText(path),
                    "UiCulture\\.(?:Text|Format)\\(\"(?<key>[A-Za-z][A-Za-z0-9]+)\"")
                .Select(match => match.Groups["key"].Value))
            .Distinct(StringComparer.Ordinal)
            .Order()
            .ToArray();

        Assert.NotEmpty(references);
        Assert.All(references, key => Assert.True(resources.ContainsKey(key), key));
    }

    private static IReadOnlyDictionary<string, string> ReadResources(string path) =>
        XDocument.Load(path)
            .Root!
            .Elements("data")
            .ToDictionary(
                element => element.Attribute("name")!.Value,
                element => element.Element("value")?.Value ?? string.Empty,
                StringComparer.Ordinal);

    private static string RepositoryRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory);
             directory is not null;
             directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "CodeSignAuto.sln")))
            {
                return directory.FullName;
            }
        }

        throw new DirectoryNotFoundException("repository_root_not_found");
    }
}

internal static class UiTestCultureInitializer
{
    [ModuleInitializer]
    internal static void Initialize()
    {
        var culture = CultureInfo.GetCultureInfo("zh-CN");
        CultureInfo.DefaultThreadCurrentCulture = culture;
        CultureInfo.DefaultThreadCurrentUICulture = culture;
    }
}

internal sealed class UiTestCultureScope : IDisposable
{
    private readonly CultureInfo _originalCulture = CultureInfo.CurrentCulture;
    private readonly CultureInfo _originalUiCulture = CultureInfo.CurrentUICulture;

    public UiTestCultureScope(string cultureName)
    {
        var culture = CultureInfo.GetCultureInfo(cultureName);
        CultureInfo.CurrentCulture = culture;
        CultureInfo.CurrentUICulture = culture;
    }

    public void Dispose()
    {
        CultureInfo.CurrentCulture = _originalCulture;
        CultureInfo.CurrentUICulture = _originalUiCulture;
    }
}
