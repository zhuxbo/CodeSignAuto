using CodeSignAuto.App.Manual;
using System.Security.AccessControl;
using System.Security.Principal;

namespace CodeSignAuto.UI.Tests;

public sealed class ManualSettingsTests : IDisposable
{
    private readonly string _root = Path.Combine(
        Path.GetTempPath(),
        $"CodeSignAuto-ManualSettings-{Guid.NewGuid():N}");

    [Fact]
    public async Task Missing_settings_use_168_and_boundaries_round_trip()
    {
        var store = CreateStore();

        Assert.Equal(168, (await store.LoadAsync(default)).RetentionHours);
        await store.SaveAsync(0, default);
        Assert.Equal(0, (await CreateStore().LoadAsync(default)).RetentionHours);
        await store.SaveAsync(168, default);
        Assert.Equal(168, (await CreateStore().LoadAsync(default)).RetentionHours);
    }

    [Theory]
    [InlineData("{\"schemaVersion\":1,\"retentionHours\":168,\"extra\":true}")]
    [InlineData("{\"schemaVersion\":1,\"retentionHours\":168,\"retentionHours\":0}")]
    [InlineData("{\"schemaVersion\":2,\"retentionHours\":168}")]
    [InlineData("{\"schemaVersion\":1,\"retentionHours\":169}")]
    public async Task Invalid_or_non_exact_schema_is_rejected(string json)
    {
        var store = CreateStore();
        Directory.CreateDirectory(Path.GetDirectoryName(store.Path)!);
        await File.WriteAllTextAsync(store.Path, json);

        var error = await Assert.ThrowsAsync<InvalidDataException>(() => store.LoadAsync(default));

        Assert.Equal("manual_settings_invalid", error.Message);
        Assert.Equal(168, store.CurrentRetentionHours);
    }

    [Fact]
    public void Default_path_is_separate_from_ui_preferences()
    {
        Assert.Equal(
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "CodeSignAuto",
                "manual",
                "settings.json"),
            ManualSettingsStore.DefaultPath);
    }

    [Fact]
    public async Task Windows_save_is_current_user_and_system_only()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var store = CreateStore();
        await store.SaveAsync(168, default);

        using var identity = WindowsIdentity.GetCurrent();
        var currentUser = Assert.IsType<SecurityIdentifier>(identity.User);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var security = new FileInfo(store.Path).GetAccessControl();
        Assert.True(security.AreAccessRulesProtected);
        Assert.Equal(currentUser, security.GetOwner(typeof(SecurityIdentifier)));
        var rules = security.GetAccessRules(true, false, typeof(SecurityIdentifier))
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

    private ManualSettingsStore CreateStore() =>
        new(Path.Combine(_root, "manual", "settings.json"));

    public void Dispose()
    {
        if (Directory.Exists(_root))
        {
            Directory.Delete(_root, recursive: true);
        }
    }
}
