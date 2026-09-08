using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using CodeSignAuto.App.Manual;
using CodeSignAuto.App.UI.Localization;

namespace CodeSignAuto.App.UI.ViewModels;

public sealed record UiLanguageOption(string CultureName, string DisplayName);

public sealed class ApplicationSettingsViewModel : INotifyPropertyChanged
{
    private readonly UiPreferenceStore _store;
    private readonly ManualSettingsStore? _manualSettings;
    private readonly CultureInfo _displayCulture;
    private string _selectedCultureName;
    private string _retentionHoursText;
    private string? _retentionStatusText;
    private bool _restartRequired;

    public ApplicationSettingsViewModel(
        UiPreferenceStore store,
        CultureInfo? displayCulture = null)
        : this(store, displayCulture, null)
    {
    }

    internal ApplicationSettingsViewModel(
        UiPreferenceStore store,
        CultureInfo? displayCulture,
        ManualSettingsStore? manualSettings = null)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _manualSettings = manualSettings;
        _displayCulture = displayCulture is null
            ? UiCulture.Current
            : UiCulture.ResolveSelection(displayCulture.Name);
        _selectedCultureName = _displayCulture.Name;
        _retentionHoursText = (_manualSettings?.CurrentRetentionHours ?? ManualSettings.DefaultRetentionHours)
            .ToString(CultureInfo.InvariantCulture);
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

    public bool IsManualMode => _manualSettings is not null;

    public string RetentionLabel => Text("ManualRetentionHours");

    public string RetentionDescription => Text("ManualRetentionDescription");

    public string RetentionHoursText
    {
        get => _retentionHoursText;
        set
        {
            if (SetField(ref _retentionHoursText, value))
            {
                RetentionStatusText = null;
            }
        }
    }

    public string? RetentionStatusText
    {
        get => _retentionStatusText;
        private set => SetField(ref _retentionStatusText, value);
    }

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
        int? retentionHours = null;
        if (_manualSettings is not null)
        {
            if (!int.TryParse(
                    RetentionHoursText,
                    NumberStyles.None,
                    CultureInfo.InvariantCulture,
                    out var parsed) || parsed is < 0 or > 168)
            {
                RetentionStatusText = Text("ManualRetentionInvalid");
                return;
            }

            retentionHours = parsed;
        }

        if (_manualSettings is not null && retentionHours is { } validRetention)
        {
            await _manualSettings.SaveAsync(validRetention, cancellationToken);
            RetentionStatusText = validRetention == 0
                ? Text("ManualRetentionSavedForever")
                : string.Format(
                    _displayCulture,
                    Text("ManualRetentionSavedHours"),
                    validRetention);
        }

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
