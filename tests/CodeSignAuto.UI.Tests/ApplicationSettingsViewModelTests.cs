using System.Globalization;
using CodeSignAuto.App.UI.Localization;
using CodeSignAuto.App.UI.ViewModels;
using CodeSignAuto.App.Manual;

namespace CodeSignAuto.UI.Tests;

public sealed class ApplicationSettingsViewModelTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        $"CodeSignAuto-ApplicationSettings-{Guid.NewGuid():N}");

    [Fact]
    public async Task Save_persists_selection_and_requires_restart_without_changing_runtime_culture()
    {
        var originalCulture = CultureInfo.CurrentCulture;
        var originalUiCulture = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentCulture = CultureInfo.GetCultureInfo("zh-CN");
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("zh-CN");
            var store = new UiPreferenceStore(Path.Combine(_directory, "ui.json"));
            var viewModel = new ApplicationSettingsViewModel(store);
            viewModel.SelectedCultureName = UiCulture.EnglishName;

            await viewModel.SaveAsync(CancellationToken.None);

            Assert.Equal(UiCulture.EnglishName, (await store.LoadAsync(
                CultureInfo.GetCultureInfo("zh-CN"),
                CancellationToken.None)).Name);
            Assert.True(viewModel.RestartRequired);
            Assert.Equal("语言设置已保存。重启 CodeSignAuto 后生效。", viewModel.StatusText);
            Assert.Equal("zh-CN", CultureInfo.CurrentCulture.Name);
            Assert.Equal("zh-CN", CultureInfo.CurrentUICulture.Name);
        }
        finally
        {
            CultureInfo.CurrentCulture = originalCulture;
            CultureInfo.CurrentUICulture = originalUiCulture;
        }
    }

    [Fact]
    public void English_runtime_uses_current_culture_for_complete_settings_copy()
    {
        var originalUiCulture = CultureInfo.CurrentUICulture;
        try
        {
            CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo("en-US");
            var viewModel = new ApplicationSettingsViewModel(
                new UiPreferenceStore(Path.Combine(_directory, "ui.json")));

            Assert.Equal("Application settings", viewModel.PageTitle);
            Assert.Equal("Interface language", viewModel.LanguageLabel);
            Assert.Equal("Save", viewModel.SaveButtonText);
            Assert.Equal(["Simplified Chinese", "English"],
                viewModel.Languages.Select(option => option.DisplayName).ToArray());
        }
        finally
        {
            CultureInfo.CurrentUICulture = originalUiCulture;
        }
    }

    [Fact]
    public async Task Manual_settings_show_and_persist_retention_separately_from_ui_language()
    {
        var uiStore = new UiPreferenceStore(Path.Combine(_directory, "ui.json"));
        var manualStore = new ManualSettingsStore(Path.Combine(_directory, "manual", "settings.json"));
        await manualStore.LoadAsync(CancellationToken.None);
        var viewModel = new ApplicationSettingsViewModel(
            uiStore,
            displayCulture: null,
            manualSettings: manualStore)
        {
            RetentionHoursText = "0",
        };

        await viewModel.SaveAsync(CancellationToken.None);

        Assert.True(viewModel.IsManualMode);
        Assert.Equal(0, manualStore.CurrentRetentionHours);
        Assert.Equal(0, (await new ManualSettingsStore(manualStore.Path)
            .LoadAsync(CancellationToken.None)).RetentionHours);
        Assert.Equal("结果将永久保留；此设置只影响之后创建的任务。", viewModel.RetentionStatusText);
    }

    [Fact]
    public async Task Invalid_manual_retention_does_not_mutate_either_settings_file()
    {
        var uiPath = Path.Combine(_directory, "invalid", "ui.json");
        var manualStore = new ManualSettingsStore(Path.Combine(_directory, "invalid", "manual", "settings.json"));
        await manualStore.LoadAsync(CancellationToken.None);
        var viewModel = new ApplicationSettingsViewModel(
            new UiPreferenceStore(uiPath),
            displayCulture: null,
            manualSettings: manualStore)
        {
            SelectedCultureName = UiCulture.EnglishName,
            RetentionHoursText = "169",
        };

        await viewModel.SaveAsync(CancellationToken.None);

        Assert.Equal(168, manualStore.CurrentRetentionHours);
        Assert.False(File.Exists(uiPath));
        Assert.Equal("请输入 0 至 168 的整数。", viewModel.RetentionStatusText);
        Assert.False(viewModel.RestartRequired);
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}
