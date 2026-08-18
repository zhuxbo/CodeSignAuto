using SimplySignAuto.App.UI;

namespace SimplySignAuto.UI.Tests;

public sealed class ThemeAndTrayTests
{
    [Theory]
    [InlineData(ShellTheme.Light, "/SimplySignAuto;component/UI/Themes/Colors.Light.xaml")]
    [InlineData(ShellTheme.Dark, "/SimplySignAuto;component/UI/Themes/Colors.Dark.xaml")]
    public void Theme_dictionary_uri_is_assembly_qualified_and_rooted(
        ShellTheme theme,
        string expected)
    {
        Assert.Equal(expected, ThemeResourceUris.For(theme).OriginalString);
    }

    [Theory]
    [InlineData(true, true, ShellTheme.HighContrast)]
    [InlineData(false, false, ShellTheme.Dark)]
    [InlineData(false, true, ShellTheme.Light)]
    [InlineData(false, null, ShellTheme.Light)]
    public void Theme_selection_prefers_high_contrast_and_falls_back_safely(
        bool highContrast,
        bool? useLightTheme,
        ShellTheme expected)
    {
        using var source = new MutableThemeSettings(highContrast, useLightTheme);
        var applier = new RecordingThemeApplier();
        using var service = new ThemeService(source, applier);

        Assert.Equal(expected, service.Current);
        Assert.Equal(expected, Assert.Single(applier.Applied));
    }

    [Fact]
    public void Theme_changes_are_applied_once_and_subscriptions_are_removed_on_dispose()
    {
        using var source = new MutableThemeSettings(highContrast: false, useLightTheme: true);
        var applier = new RecordingThemeApplier();
        var service = new ThemeService(source, applier);

        source.Change(highContrast: false, useLightTheme: false);
        source.Change(highContrast: true, useLightTheme: false);
        service.Dispose();
        source.Change(highContrast: false, useLightTheme: true);

        Assert.Equal([ShellTheme.Light, ShellTheme.Dark, ShellTheme.HighContrast], applier.Applied);
        Assert.Equal(0, source.SubscriberCount);
    }

    [Fact]
    public void Tray_menu_has_the_fixed_order_and_status_is_not_color_only()
    {
        var platform = new RecordingTrayPlatform();
        var window = new RecordingWindow();
        var viewModel = new ShellViewModel(
            new FixedActiveJobState(ActiveJobState.Unknown),
            window,
            new RecordingAgentLifetime());
        using var controller = new TrayIconController(platform, viewModel, window);

        Assert.Equal(
            ["打开控制台", "退出程序"],
            platform.Entries.Select(entry => entry.Text).ToArray());
        Assert.Equal("○ 尚未检查", platform.StatusText);
    }

    [Fact]
    public async Task Tray_commands_operate_the_real_shell_contract_and_dispose_once()
    {
        var platform = new RecordingTrayPlatform();
        var window = new RecordingWindow();
        var lifetime = new RecordingAgentLifetime();
        var viewModel = new ShellViewModel(
            new FixedActiveJobState(ActiveJobState.None),
            window,
            lifetime);
        var controller = new TrayIconController(platform, viewModel, window);

        await controller.HandleCommandAsync(TrayCommand.OpenConsole, CancellationToken.None);
        await controller.HandleCommandAsync(TrayCommand.Recheck, CancellationToken.None);
        await controller.HandleCommandAsync(TrayCommand.OpenRecentJobs, CancellationToken.None);
        await controller.HandleCommandAsync(TrayCommand.Exit, CancellationToken.None);
        controller.Dispose();
        controller.Dispose();

        Assert.True(window.WasShown);
        Assert.Contains("状态检查将在后续任务接入", window.Notices);
        Assert.Contains("最近任务将在任务页接入", window.Notices);
        Assert.Equal(0, lifetime.StopCalls);
        Assert.Equal(1, platform.DisposeCalls);
        Assert.Equal(0, platform.SubscriberCount);
    }

    private sealed class MutableThemeSettings(bool highContrast, bool? useLightTheme) : IThemeSettingsSource
    {
        private EventHandler? _changed;

        public bool HighContrast { get; private set; } = highContrast;

        public bool? AppsUseLightTheme { get; private set; } = useLightTheme;

        public int SubscriberCount => _changed?.GetInvocationList().Length ?? 0;

        public event EventHandler? Changed
        {
            add => _changed += value;
            remove => _changed -= value;
        }

        public void Change(bool highContrast, bool? useLightTheme)
        {
            HighContrast = highContrast;
            AppsUseLightTheme = useLightTheme;
            _changed?.Invoke(this, EventArgs.Empty);
        }

        public void Dispose()
        {
        }
    }

    private sealed class RecordingThemeApplier : IThemeResourceApplier
    {
        public List<ShellTheme> Applied { get; } = [];

        public void Apply(ShellTheme theme) => Applied.Add(theme);
    }

    private sealed class RecordingTrayPlatform : ITrayIconPlatform
    {
        private EventHandler<TrayCommandEventArgs>? _commandInvoked;

        public IReadOnlyList<TrayMenuEntry> Entries { get; private set; } = [];

        public string? StatusText { get; private set; }

        public int DisposeCalls { get; private set; }

        public int SubscriberCount => _commandInvoked?.GetInvocationList().Length ?? 0;

        public event EventHandler<TrayCommandEventArgs>? CommandInvoked
        {
            add => _commandInvoked += value;
            remove => _commandInvoked -= value;
        }

        public void Initialize(IReadOnlyList<TrayMenuEntry> entries, string statusText)
        {
            Entries = entries;
            StatusText = statusText;
        }

        public void SetStatus(string statusText) => StatusText = statusText;

        public void Dispose() => DisposeCalls++;
    }

    private sealed class FixedActiveJobState(ActiveJobState state) : IActiveJobStateSource
    {
        public ActiveJobState Current => state;
    }

    private sealed class RecordingAgentLifetime : IDesktopAgentLifetime
    {
        public int StopCalls { get; private set; }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            StopCalls++;
            return Task.CompletedTask;
        }
    }

    private sealed class RecordingWindow : IWindowController
    {
        public bool WasShown { get; private set; }

        public List<string> Notices { get; } = [];

        public void ShowRestoreActivate() => WasShown = true;

        public void Hide()
        {
        }

        public void CloseForExit()
        {
        }

        public void ShowNotice(string message) => Notices.Add(message);
    }
}
