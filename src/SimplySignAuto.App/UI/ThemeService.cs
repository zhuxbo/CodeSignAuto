namespace SimplySignAuto.App.UI;

public enum ShellTheme
{
    Light,
    Dark,
    HighContrast,
}

public interface IThemeSettingsSource : IDisposable
{
    event EventHandler? Changed;

    bool HighContrast { get; }

    bool? AppsUseLightTheme { get; }
}

public interface IThemeResourceApplier
{
    void Apply(ShellTheme theme);
}

public static class ThemeResourceUris
{
    private const string Light = "/SimplySignAuto;component/UI/Themes/Colors.Light.xaml";
    private const string Dark = "/SimplySignAuto;component/UI/Themes/Colors.Dark.xaml";

    public static Uri For(ShellTheme theme) => new(
        theme switch
        {
            ShellTheme.Light => Light,
            ShellTheme.Dark => Dark,
            _ => throw new ArgumentOutOfRangeException(nameof(theme)),
        },
        UriKind.Relative);
}

public sealed class ThemeService : IDisposable
{
    private readonly IThemeSettingsSource _settings;
    private readonly IThemeResourceApplier _resources;
    private bool _disposed;

    public ThemeService(IThemeSettingsSource settings, IThemeResourceApplier resources)
    {
        _settings = settings ?? throw new ArgumentNullException(nameof(settings));
        _resources = resources ?? throw new ArgumentNullException(nameof(resources));
        Current = SelectSafely();
        _resources.Apply(Current);
        _settings.Changed += HandleSettingsChanged;
    }

    public ShellTheme Current { get; private set; }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _settings.Changed -= HandleSettingsChanged;
        _settings.Dispose();
    }

    private void HandleSettingsChanged(object? sender, EventArgs args)
    {
        if (_disposed)
        {
            return;
        }

        var selected = SelectSafely();
        if (selected == Current)
        {
            return;
        }

        Current = selected;
        _resources.Apply(selected);
    }

    private ShellTheme SelectSafely()
    {
        try
        {
            if (_settings.HighContrast)
            {
                return ShellTheme.HighContrast;
            }

            return _settings.AppsUseLightTheme == false
                ? ShellTheme.Dark
                : ShellTheme.Light;
        }
        catch (Exception error) when (
            error is IOException
                or UnauthorizedAccessException
                or InvalidOperationException
                or System.Security.SecurityException)
        {
            return ShellTheme.Light;
        }
    }
}

#if SIMPLYSIGN_WPF
internal sealed class WindowsThemeSettingsSource : IThemeSettingsSource
{
    private bool _disposed;

    public WindowsThemeSettingsSource()
    {
        System.Windows.SystemParameters.StaticPropertyChanged += HandleSystemPropertyChanged;
        Microsoft.Win32.SystemEvents.UserPreferenceChanged += HandleUserPreferenceChanged;
    }

    public event EventHandler? Changed;

    public bool HighContrast
    {
        get
        {
            try
            {
                return System.Windows.SystemParameters.HighContrast;
            }
            catch (Exception error) when (
                error is InvalidOperationException or System.Security.SecurityException)
            {
                return false;
            }
        }
    }

    public bool? AppsUseLightTheme
    {
        get
        {
            try
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
                    writable: false);
                return key?.GetValue("AppsUseLightTheme") switch
                {
                    int value => value != 0,
                    long value => value != 0,
                    _ => null,
                };
            }
            catch (Exception error) when (
                error is IOException
                    or UnauthorizedAccessException
                    or System.Security.SecurityException)
            {
                return null;
            }
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        System.Windows.SystemParameters.StaticPropertyChanged -= HandleSystemPropertyChanged;
        Microsoft.Win32.SystemEvents.UserPreferenceChanged -= HandleUserPreferenceChanged;
    }

    private void HandleSystemPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs args) =>
        Changed?.Invoke(this, EventArgs.Empty);

    private void HandleUserPreferenceChanged(
        object sender,
        Microsoft.Win32.UserPreferenceChangedEventArgs args) =>
        Changed?.Invoke(this, EventArgs.Empty);
}

internal sealed class WpfThemeResourceApplier : IThemeResourceApplier
{
    private System.Windows.ResourceDictionary? _current;

    public void Apply(ShellTheme theme)
    {
        var application = System.Windows.Application.Current
            ?? throw new InvalidOperationException("desktop_application_missing");
        if (!application.Dispatcher.CheckAccess())
        {
            application.Dispatcher.Invoke(() => Apply(theme));
            return;
        }

        var dictionary = theme switch
        {
            ShellTheme.Light or ShellTheme.Dark => FromSource(ThemeResourceUris.For(theme)),
            ShellTheme.HighContrast => CreateHighContrast(),
            _ => throw new ArgumentOutOfRangeException(nameof(theme)),
        };
        if (_current is not null)
        {
            application.Resources.MergedDictionaries.Remove(_current);
        }

        application.Resources.MergedDictionaries.Insert(0, dictionary);
        _current = dictionary;
    }

    private static System.Windows.ResourceDictionary FromSource(Uri source) => new()
    {
        Source = source,
    };

    private static System.Windows.ResourceDictionary CreateHighContrast()
    {
        var dictionary = new System.Windows.ResourceDictionary
        {
            ["ShellBackgroundBrush"] = System.Windows.SystemColors.WindowBrush,
            ["SurfaceBrush"] = System.Windows.SystemColors.ControlBrush,
            ["SidebarBackgroundBrush"] = System.Windows.SystemColors.WindowBrush,
            ["PrimaryBrush"] = System.Windows.SystemColors.HighlightBrush,
            ["PrimaryForegroundBrush"] = System.Windows.SystemColors.HighlightTextBrush,
            ["TextPrimaryBrush"] = System.Windows.SystemColors.WindowTextBrush,
            ["TextSecondaryBrush"] = System.Windows.SystemColors.GrayTextBrush,
            ["BorderBrush"] = System.Windows.SystemColors.ActiveBorderBrush,
            ["SelectionBrush"] = System.Windows.SystemColors.HighlightBrush,
            ["SuccessBrush"] = System.Windows.SystemColors.WindowTextBrush,
            ["WarningBrush"] = System.Windows.SystemColors.WindowTextBrush,
            ["ErrorBrush"] = System.Windows.SystemColors.WindowTextBrush,
        };
        return dictionary;
    }
}
#endif
