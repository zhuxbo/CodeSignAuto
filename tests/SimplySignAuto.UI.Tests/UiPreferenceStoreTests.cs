using System.Globalization;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using SimplySignAuto.App.UI.Localization;

namespace SimplySignAuto.UI.Tests;

public sealed class UiPreferenceStoreTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        $"SimplySignAuto-UiPreference-{Guid.NewGuid():N}");

    [Theory]
    [InlineData("zh-CN", "zh-CN")]
    [InlineData("zh-TW", "zh-CN")]
    [InlineData("en-US", "en-US")]
    [InlineData("fr-FR", "en-US")]
    public async Task Missing_preference_uses_supported_system_language(
        string systemCulture,
        string expected)
    {
        var store = CreateStore();

        var selected = await store.LoadAsync(
            CultureInfo.GetCultureInfo(systemCulture),
            CancellationToken.None);

        Assert.Equal(expected, selected.Name);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("{\"culture\":\"zh-CN\",\"extra\":true}")]
    [InlineData("{\"culture\":\"zh-CN\",\"culture\":\"en-US\"}")]
    [InlineData("{\"culture\":\"fr-FR\"}")]
    [InlineData("{\"culture\":null}")]
    [InlineData("[]")]
    [InlineData("not-json")]
    public async Task Existing_preference_is_parsed_strictly(string json)
    {
        Directory.CreateDirectory(_directory);
        await File.WriteAllTextAsync(Path.Combine(_directory, "ui.json"), json);
        var store = CreateStore();

        var error = await Assert.ThrowsAsync<InvalidDataException>(() =>
            store.LoadAsync(CultureInfo.GetCultureInfo("zh-CN"), CancellationToken.None));

        Assert.Equal("ui_preference_invalid", error.Message);
    }

    [Theory]
    [InlineData("zh-CN")]
    [InlineData("en-US")]
    public async Task Save_atomically_writes_only_the_selected_supported_culture(string cultureName)
    {
        var store = CreateStore();

        await store.SaveAsync(cultureName, CancellationToken.None);

        var path = Path.Combine(_directory, "ui.json");
        using var document = JsonDocument.Parse(await File.ReadAllTextAsync(path));
        var property = Assert.Single(document.RootElement.EnumerateObject());
        Assert.Equal("culture", property.Name);
        Assert.Equal(cultureName, property.Value.GetString());
        Assert.Empty(Directory.EnumerateFiles(_directory, "*.tmp"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("zh-TW")]
    [InlineData("fr-FR")]
    public async Task Save_rejects_unsupported_cultures(string cultureName)
    {
        var store = CreateStore();

        await Assert.ThrowsAsync<ArgumentException>(() =>
            store.SaveAsync(cultureName, CancellationToken.None));

        Assert.False(File.Exists(Path.Combine(_directory, "ui.json")));
    }

    [Fact]
    public async Task Windows_save_protects_the_file_for_the_current_user_and_local_system()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var store = CreateStore();
        await store.SaveAsync(UiCulture.ChineseName, CancellationToken.None);

        using var identity = WindowsIdentity.GetCurrent();
        var currentUser = Assert.IsType<SecurityIdentifier>(identity.User);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var security = new FileInfo(Path.Combine(_directory, "ui.json")).GetAccessControl();
        Assert.True(security.AreAccessRulesProtected);
        Assert.Equal(currentUser, security.GetOwner(typeof(SecurityIdentifier)));
        var rules = security.GetAccessRules(
                includeExplicit: true,
                includeInherited: false,
                typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .ToArray();
        Assert.Equal(2, rules.Length);
        Assert.All(rules, rule =>
        {
            Assert.Equal(AccessControlType.Allow, rule.AccessControlType);
            Assert.Equal(FileSystemRights.FullControl, rule.FileSystemRights);
            var principal = (SecurityIdentifier)rule.IdentityReference;
            Assert.True(principal == currentUser || principal == system);
        });
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private UiPreferenceStore CreateStore() =>
        new(Path.Combine(_directory, "ui.json"));
}
