using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using SimplySignAuto.App.UI.Localization;

namespace SimplySignAuto.App.UI.ViewModels;

public sealed record UiLanguageOption(string CultureName, string DisplayName);

public sealed class ApplicationSettingsViewModel : INotifyPropertyChanged
{
    private readonly UiPreferenceStore _store;
    private readonly CultureInfo _displayCulture;
    private string _selectedCultureName;
    private bool _restartRequired;

    public ApplicationSettingsViewModel(
        UiPreferenceStore store,
        CultureInfo? displayCulture = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _displayCulture = displayCulture is null
            ? UiCulture.ResolveDefault(CultureInfo.CurrentUICulture)
            : UiCulture.ResolveSelection(displayCulture.Name);
        _selectedCultureName = _displayCulture.Name;
        Languages =
        [
            new(UiCulture.ChineseName, Text("LanguageChinese")),
            new(UiCulture.EnglishName, Text("LanguageEnglish")),
        ];
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public IReadOnlyList<UiLanguageOption> Languages { get; }

    public string PageTitle => Text("ApplicationSettingsTitle");

    public string Description => Text("ApplicationSettingsDescription");

    public string LanguageLabel => Text("InterfaceLanguageLabel");

    public string SaveButtonText => Text("SaveButton");

    public string StatusAreaAutomationName => Text("ApplicationSettingsStatusArea");

    public string? StatusText => RestartRequired ? Text("RestartRequired") : null;

    public string SelectedCultureName
    {
        get => _selectedCultureName;
        set
        {
            UiCulture.ResolveSelection(value);
            if (SetField(ref _selectedCultureName, value))
            {
                RestartRequired = false;
            }
        }
    }

    public bool RestartRequired
    {
        get => _restartRequired;
        private set
        {
            if (SetField(ref _restartRequired, value))
            {
                OnPropertyChanged(nameof(StatusText));
            }
        }
    }

    public async Task SaveAsync(CancellationToken cancellationToken = default)
    {
        await _store.SaveAsync(SelectedCultureName, cancellationToken);
        RestartRequired = true;
    }

    private string Text(string key) => UiCulture.GetString(key, _displayCulture);

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }

        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
