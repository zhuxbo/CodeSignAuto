using System.Globalization;
using SimplySignAuto.App.UI.Localization;
using SimplySignAuto.App.UI.ViewModels;

namespace SimplySignAuto.UI.Tests;

public sealed class ApplicationSettingsViewModelTests : IDisposable
{
    private readonly string _directory = Path.Combine(
        Path.GetTempPath(),
        $"SimplySignAuto-ApplicationSettings-{Guid.NewGuid():N}");

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
            Assert.Equal("语言设置已保存。重启 SimplySignAuto 后生效。", viewModel.StatusText);
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

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }
}
