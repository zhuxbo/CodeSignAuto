using System.ComponentModel;
using System.Runtime.CompilerServices;
using CodeSignAuto.Agent.Ipc;
using CodeSignAuto.Agent.LocalJobs;
using CodeSignAuto.App.Commands;
using CodeSignAuto.App.Manual;
using CodeSignAuto.App.UI.Localization;
using CodeSignAuto.App.UI.Status;
using CodeSignAuto.App.UI.ViewModels;

namespace CodeSignAuto.App.UI;

public enum ActiveJobState
{
    Unknown,
    None,
    Active,
}

public enum WindowCloseDisposition
{
    Hide,
    AllowSystemShutdown,
}

public enum ExitRequestResult
{
    Refused,
    Exiting,
}

public interface IActiveJobStateSource
{
    ActiveJobState Current { get; }
}

public interface IDesktopAgentLifetime
{
    Task StopAsync(CancellationToken cancellationToken);
}

public interface IWindowController
{
    void ShowRestoreActivate();

    void Hide();

    void CloseForExit();

    void ShowNotice(string message);

    bool ConfirmRelogin() => false;

    bool ConfirmClearOtp() => false;
}

public sealed class DesktopShutdownCoordinator
{
    private int _started;

    public bool HasStarted => Volatile.Read(ref _started) != 0;

    public bool TryBegin() => Interlocked.CompareExchange(ref _started, 1, 0) == 0;

    public bool TryBegin(Action action)
    {
        ArgumentNullException.ThrowIfNull(action);
        if (!TryBegin())
        {
            return false;
        }

        action();
        return true;
    }

    public bool TryRun(Action action)
    {
        ArgumentNullException.ThrowIfNull(action);
        if (HasStarted)
        {
            return false;
        }

        action();
        return true;
    }
}

public sealed class ShutdownAwareWindowController : IWindowController
{
    private readonly DesktopShutdownCoordinator _shutdown;
    private readonly IWindowController _target;

    public ShutdownAwareWindowController(
        DesktopShutdownCoordinator shutdown,
        IWindowController target)
    {
        _shutdown = shutdown ?? throw new ArgumentNullException(nameof(shutdown));
        _target = target ?? throw new ArgumentNullException(nameof(target));
    }

    public void ShowRestoreActivate() => _shutdown.TryRun(_target.ShowRestoreActivate);

    public void Hide() => _shutdown.TryRun(_target.Hide);

    public void CloseForExit() => _shutdown.TryBegin(_target.CloseForExit);

    public void ShowNotice(string message)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(message);
        _shutdown.TryRun(() => _target.ShowNotice(message));
    }

    public bool ConfirmRelogin() => !_shutdown.HasStarted && _target.ConfirmRelogin();

    public bool ConfirmClearOtp() => !_shutdown.HasStarted && _target.ConfirmClearOtp();
}

public sealed class UnknownActiveJobStateSource : IActiveJobStateSource
{
    public ActiveJobState Current => ActiveJobState.Unknown;
}

public sealed class ManagementActiveJobStateSource : IActiveJobStateSource
{
    private readonly IAgentManagementClient _management;

    public ManagementActiveJobStateSource(IAgentManagementClient management) =>
        _management = management ?? throw new ArgumentNullException(nameof(management));

    public ActiveJobState Current => _management.LatestSnapshot switch
    {
        null => ActiveJobState.Unknown,
        { ActiveJobCount: > 0 } => ActiveJobState.Active,
        { CurrentJob: not null } => ActiveJobState.Active,
        _ => ActiveJobState.None,
    };
}

public sealed class OverviewActiveJobStateSource(OverviewViewModel overview) : IActiveJobStateSource
{
    public ActiveJobState Current => overview.Snapshot switch
    {
        null => ActiveJobState.Unknown,
        { ActiveJobCount: > 0 } => ActiveJobState.Active,
        { CurrentJob: not null } => ActiveJobState.Active,
        _ => ActiveJobState.None,
    };
}

public sealed class WindowReloginConfirmation : IReloginConfirmation
{
    private readonly IWindowController _window;
    private readonly IUiDispatcher _dispatcher;

    public WindowReloginConfirmation(
        IWindowController window,
        IUiDispatcher? dispatcher = null)
    {
        _window = window ?? throw new ArgumentNullException(nameof(window));
        _dispatcher = dispatcher ?? InlineAppUiDispatcher.Instance;
    }

    public async Task<bool> ConfirmAsync(CancellationToken cancellationToken)
    {
        var confirmed = false;
        await _dispatcher.InvokeAsync(
            () => confirmed = _window.ConfirmRelogin(),
            cancellationToken).ConfigureAwait(false);
        return confirmed;
    }
}

public sealed class WindowOtpClearConfirmation : IOtpClearConfirmation
{
    private readonly IWindowController _window;
    private readonly IUiDispatcher _dispatcher;

    public WindowOtpClearConfirmation(
        IWindowController window,
        IUiDispatcher? dispatcher = null)
    {
        _window = window ?? throw new ArgumentNullException(nameof(window));
        _dispatcher = dispatcher ?? InlineAppUiDispatcher.Instance;
    }

    public async Task<bool> ConfirmAsync(CancellationToken cancellationToken)
    {
        var confirmed = false;
        await _dispatcher.InvokeAsync(
            () => confirmed = _window.ConfirmClearOtp(),
            cancellationToken).ConfigureAwait(false);
        return confirmed;
    }
}

public static class DesktopShellComposition
{
    public static ShellViewModel Create(
        IAgentRunner agentRunner,
        IActiveJobStateSource fallbackActiveJobs,
        IWindowController window,
        IDesktopAgentLifetime agentLifetime) =>
        Create(
            agentRunner,
            fallbackActiveJobs,
            window,
            agentLifetime,
            InlineAppUiDispatcher.Instance);

    public static ShellViewModel Create(
        IAgentRunner agentRunner,
        IActiveJobStateSource fallbackActiveJobs,
        IWindowController window,
        IDesktopAgentLifetime agentLifetime,
        IUiDispatcher dispatcher,
        AgentConfiguration? configuration = null) =>
        Create(
            agentRunner,
            fallbackActiveJobs,
            window,
            agentLifetime,
            dispatcher,
            configuration,
            InstallationMode.Service,
            manualSettings: null);

    internal static ShellViewModel Create(
        IAgentRunner agentRunner,
        IActiveJobStateSource fallbackActiveJobs,
        IWindowController window,
        IDesktopAgentLifetime agentLifetime,
        IUiDispatcher dispatcher,
        AgentConfiguration? configuration,
        InstallationMode mode,
        ManualSettingsStore? manualSettings)
    {
        ArgumentNullException.ThrowIfNull(agentRunner);
        ArgumentNullException.ThrowIfNull(dispatcher);
        if (agentRunner is IDesktopManagementSource managementSource)
        {
            return configuration is not null && agentRunner is IDesktopLocalJobSource localSource
                ? new ShellViewModel(
                    managementSource.Management,
                    localSource.LocalJobs,
                    configuration,
                    new WindowReloginConfirmation(window, dispatcher),
                    window,
                    agentLifetime,
                    dispatcher,
                    terminalJobs: null,
                    clipboard: null,
                    serviceConfigurationEditor: null,
                    serviceSettingsDialogs: null,
                    uiPreferenceStore: null,
                    mode: mode,
                    manualSettings: manualSettings)
                : new ShellViewModel(
                    managementSource.Management,
                    new WindowReloginConfirmation(window, dispatcher),
                    window,
                    agentLifetime,
                    dispatcher);
        }

        return new ShellViewModel(fallbackActiveJobs, window, agentLifetime, dispatcher);
    }
}

public sealed class ShellViewModel : INotifyPropertyChanged, IDisposable
{

    private readonly object _exitSync = new();
    private readonly IWindowController _window;
    private readonly IUiDispatcher _dispatcher;
    private readonly IActiveJobStateSource _activeJobs;
    private readonly IDesktopAgentLifetime _agentLifetime;
    private readonly InstallationMode _mode;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly IReadOnlyList<NavigationPage> _pages;
    private NavigationPage _currentPage;
    private Task<ExitRequestResult>? _exitTask;
    private int _disposed;

    public ShellViewModel(
        IActiveJobStateSource activeJobs,
        IWindowController window,
        IDesktopAgentLifetime agentLifetime,
        IUiDispatcher? dispatcher = null)
        : this(activeJobs, window, agentLifetime, dispatcher, InstallationMode.Service)
    {
    }

    internal ShellViewModel(
        IActiveJobStateSource activeJobs,
        IWindowController window,
        IDesktopAgentLifetime agentLifetime,
        IUiDispatcher? dispatcher,
        InstallationMode mode)
    {
        _activeJobs = activeJobs ?? throw new ArgumentNullException(nameof(activeJobs));
        _window = window ?? throw new ArgumentNullException(nameof(window));
        _agentLifetime = agentLifetime ?? throw new ArgumentNullException(nameof(agentLifetime));
        _dispatcher = dispatcher ?? InlineAppUiDispatcher.Instance;
        _mode = mode;
        ApplicationSettings = new ApplicationSettingsViewModel(new UiPreferenceStore());
        _pages = CreatePages(null, null, null, null, null, ApplicationSettings, _mode);
        _currentPage = _pages[0];
    }

    public ShellViewModel(
        IAgentManagementClient management,
        IReloginConfirmation confirmation,
        IWindowController window,
        IDesktopAgentLifetime agentLifetime,
        IUiDispatcher? dispatcher = null)
        : this(management, confirmation, window, agentLifetime, dispatcher, null)
    {
    }

    internal ShellViewModel(
        IAgentManagementClient management,
        IReloginConfirmation confirmation,
        IWindowController window,
        IDesktopAgentLifetime agentLifetime,
        IUiDispatcher? dispatcher,
        ITerminalJobFeed? terminalJobs)
    {
        ArgumentNullException.ThrowIfNull(management);
        _activeJobs = new ManagementActiveJobStateSource(management);
        _window = window ?? throw new ArgumentNullException(nameof(window));
        _agentLifetime = agentLifetime ?? throw new ArgumentNullException(nameof(agentLifetime));
        _dispatcher = dispatcher ?? InlineAppUiDispatcher.Instance;
        _mode = InstallationMode.Service;
        Overview = new OverviewViewModel(management, confirmation, OpenJobs, _dispatcher);
        if (management is IAgentAdministrationClient administration)
        {
            TerminalJobs = terminalJobs ?? new TerminalJobFeed(administration);
        }
        Overview.PropertyChanged += HandleOverviewPropertyChanged;
        ApplicationSettings = new ApplicationSettingsViewModel(new UiPreferenceStore());
        _pages = CreatePages(Overview, null, null, null, null, ApplicationSettings, _mode);
        _currentPage = _pages[0];
    }

    public ShellViewModel(
        IAgentManagementClient management,
        ILocalJobClient localJobs,
        AgentConfiguration configuration,
        IReloginConfirmation confirmation,
        IWindowController window,
        IDesktopAgentLifetime agentLifetime,
        IUiDispatcher? dispatcher = null)
        : this(
            management,
            localJobs,
            confirmation,
            window,
            agentLifetime,
            dispatcher,
            null)
    {
        ArgumentNullException.ThrowIfNull(configuration);
    }

    internal ShellViewModel(
        IAgentManagementClient management,
        ILocalJobClient localJobs,
        AgentConfiguration configuration,
        IReloginConfirmation confirmation,
        IWindowController window,
        IDesktopAgentLifetime agentLifetime,
        IUiDispatcher? dispatcher,
        ITerminalJobFeed? terminalJobs,
        IClipboardService? clipboard = null,
        IServiceConfigurationEditor? serviceConfigurationEditor = null,
        IServiceSettingsDialogService? serviceSettingsDialogs = null,
        UiPreferenceStore? uiPreferenceStore = null,
        InstallationMode mode = InstallationMode.Service,
        ManualSettingsStore? manualSettings = null)
        : this(
            management,
            localJobs,
            confirmation,
            window,
            agentLifetime,
            dispatcher,
            terminalJobs,
            clipboard,
            serviceConfigurationEditor,
            serviceSettingsDialogs,
            uiPreferenceStore,
            mode,
            manualSettings)
    {
        ArgumentNullException.ThrowIfNull(configuration);
    }

    public ShellViewModel(
        IAgentManagementClient management,
        ILocalJobClient localJobs,
        IReloginConfirmation confirmation,
        IWindowController window,
        IDesktopAgentLifetime agentLifetime,
        IUiDispatcher? dispatcher = null)
        : this(
            management,
            localJobs,
            confirmation,
            window,
            agentLifetime,
            dispatcher,
            null)
    {
    }

    internal ShellViewModel(
        IAgentManagementClient management,
        ILocalJobClient localJobs,
        IReloginConfirmation confirmation,
        IWindowController window,
        IDesktopAgentLifetime agentLifetime,
        IUiDispatcher? dispatcher,
        ITerminalJobFeed? terminalJobs,
        IClipboardService? clipboard = null,
        IServiceConfigurationEditor? serviceConfigurationEditor = null,
        IServiceSettingsDialogService? serviceSettingsDialogs = null,
        UiPreferenceStore? uiPreferenceStore = null,
        InstallationMode mode = InstallationMode.Service,
        ManualSettingsStore? manualSettings = null)
    {
        ArgumentNullException.ThrowIfNull(management);
        ArgumentNullException.ThrowIfNull(localJobs);
        _activeJobs = new ManagementActiveJobStateSource(management);
        _window = window ?? throw new ArgumentNullException(nameof(window));
        _agentLifetime = agentLifetime ?? throw new ArgumentNullException(nameof(agentLifetime));
        _dispatcher = dispatcher ?? InlineAppUiDispatcher.Instance;
        _mode = mode;
        Overview = new OverviewViewModel(management, confirmation, OpenJobs, _dispatcher);
        if (management is IAgentAdministrationClient administration)
        {
            var desktopClipboard = clipboard ?? new DesktopClipboardService();
            TerminalJobs = terminalJobs ?? new TerminalJobFeed(administration);
            Jobs = new JobsViewModel(administration, localJobs, _dispatcher, TerminalJobs);
            Activation = new ActivationViewModel(
                management,
                administration,
                desktopClipboard,
                confirmation,
                new WindowOtpClearConfirmation(window, _dispatcher),
                _dispatcher,
                administration as ILocalTotpCodeProvider);
            if (_mode == InstallationMode.Service)
            {
                ServiceSettings = new ServiceSettingsViewModel(
                    administration,
                    serviceConfigurationEditor ?? UnavailableServiceConfigurationEditor.Instance,
                    serviceSettingsDialogs ?? UnavailableServiceSettingsDialogService.Instance,
                    desktopClipboard,
                    _dispatcher);
            }
        }
        QuickSign = new QuickSignViewModel(
            localJobs,
            management,
            OpenJob,
            _dispatcher,
            TerminalJobs);

        Overview.PropertyChanged += HandleOverviewPropertyChanged;
        ApplicationSettings = new ApplicationSettingsViewModel(
            uiPreferenceStore ?? new UiPreferenceStore(),
            displayCulture: null,
            manualSettings: _mode == InstallationMode.Manual ? manualSettings : null);
        _pages = CreatePages(
            Overview,
            QuickSign,
            Jobs,
            Activation,
            ServiceSettings,
            ApplicationSettings,
            _mode);
        _currentPage = _pages[0];
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public IReadOnlyList<NavigationPage> Pages => _pages;

    public OverviewViewModel? Overview { get; }

    public QuickSignViewModel? QuickSign { get; }

    public JobsViewModel? Jobs { get; }

    public ActivationViewModel? Activation { get; }

    public ServiceSettingsViewModel? ServiceSettings { get; }

    public ApplicationSettingsViewModel ApplicationSettings { get; }

    internal ITerminalJobFeed? TerminalJobs { get; }

    public Guid? SelectedJobId { get; private set; }

    public string FooterVersionText =>
        ApplicationVersion.ReadDisplay(typeof(Program).Assembly);

    public string OverallStatusText => Overview?.Status?.Overall switch
    {
        OverallReadiness.Ready => UiCulture.Text("OverallReady"),
        OverallReadiness.Partial => UiCulture.Text("OverallPartial"),
        OverallReadiness.ActionRequired => UiCulture.Text("OverallActionRequired"),
        _ => UiCulture.Text("OverallNotChecked"),
    };

    public string OverallStatusIcon => Overview?.Status?.Overall switch
    {
        OverallReadiness.Ready => "✓",
        OverallReadiness.Partial => "!",
        OverallReadiness.ActionRequired => "×",
        _ => "○",
    };

    public string OverallStatusAutomationName =>
        UiCulture.Format("OverallStatusAutomation", OverallStatusText);

    public NavigationPage CurrentPage
    {
        get => _currentPage;
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            if (!ReferenceEquals(_currentPage, value))
            {
                if (ReferenceEquals(_currentPage.Content, Activation))
                {
                    Activation?.DeactivateTotp();
                }

                _currentPage = value;
                OnPropertyChanged();
            }
        }
    }

    public WindowCloseDisposition HandleCloseRequested(bool isSystemShutdown)
    {
        if (isSystemShutdown)
        {
            return WindowCloseDisposition.AllowSystemShutdown;
        }

        Activation?.DeactivateTotp();
        _window.Hide();
        return WindowCloseDisposition.Hide;
    }

    public Task<ExitRequestResult> RequestExitAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_mode == InstallationMode.Manual &&
            (QuickSign?.HasActiveJob == true || _activeJobs.Current != ActiveJobState.None))
        {
            return RefuseManualExitAsync();
        }

        lock (_exitSync)
        {
            return _exitTask ??= ExitOnceAsync();
        }
    }

    private async Task<ExitRequestResult> ExitOnceAsync()
    {
        if (_mode == InstallationMode.Manual)
        {
            await _agentLifetime.StopAsync(CancellationToken.None).ConfigureAwait(false);
        }

        await InvokeUiAsync(_window.CloseForExit).ConfigureAwait(false);
        return ExitRequestResult.Exiting;
    }

    private async Task<ExitRequestResult> RefuseManualExitAsync()
    {
        await InvokeUiAsync(
            () => _window.ShowNotice(UiCulture.Text("ManualExitActiveJob")))
            .ConfigureAwait(false);
        return ExitRequestResult.Refused;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        if (Overview is not null)
        {
            Overview.PropertyChanged -= HandleOverviewPropertyChanged;
            Overview.Dispose();
        }

        QuickSign?.Dispose();
        Jobs?.Dispose();
        Activation?.Dispose();
        ServiceSettings?.Dispose();
        TerminalJobs?.Dispose();

        _lifetime.Cancel();
    }

    private static IReadOnlyList<NavigationPage> CreatePages(
        OverviewViewModel? overview,
        QuickSignViewModel? quickSign,
        JobsViewModel? jobs,
        ActivationViewModel? activation,
        ServiceSettingsViewModel? serviceSettings,
        ApplicationSettingsViewModel applicationSettings,
        InstallationMode mode)
    {
        var pages = new List<NavigationPage>
        {
            new(UiCulture.Text("NavigationOverview"), "●", UiCulture.Text("NavigationOverviewPlaceholder"), overview),
            new(
                UiCulture.Text(mode == InstallationMode.Manual
                    ? "NavigationManualSign"
                    : "NavigationQuickSign"),
                "✎",
                UiCulture.Text("NavigationQuickSignPlaceholder"),
                quickSign),
            new(UiCulture.Text("NavigationJobs"), "≡", UiCulture.Text("NavigationJobsPlaceholder"), jobs),
            new(UiCulture.Text("NavigationActivation"), "◆", UiCulture.Text("NavigationActivationPlaceholder"), activation),
        };
        if (mode == InstallationMode.Service)
        {
            pages.Add(new NavigationPage(
                UiCulture.Text("NavigationServiceSettings"),
                "⚙",
                UiCulture.Text("NavigationServiceSettingsPlaceholder"),
                serviceSettings));
        }

        pages.Add(new NavigationPage(applicationSettings.PageTitle, "⚙", string.Empty, applicationSettings));
        return pages.AsReadOnly();
    }

    private void OpenJobs() => _ = InvokeUiAsync(() => CurrentPage = Pages[2]);

    private void OpenJob(Guid jobId) => _ = InvokeUiAsync(() =>
    {
        SelectedJobId = jobId;
        OnPropertyChanged(nameof(SelectedJobId));
        CurrentPage = Pages[2];
    });

    private void HandleOverviewPropertyChanged(object? sender, PropertyChangedEventArgs eventArgs)
    {
        if (eventArgs.PropertyName is nameof(OverviewViewModel.Status) or null)
        {
            OnPropertyChanged(nameof(OverallStatusText));
            OnPropertyChanged(nameof(OverallStatusIcon));
            OnPropertyChanged(nameof(OverallStatusAutomationName));
        }
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    private async Task InvokeUiAsync(Action action)
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        try
        {
            await _dispatcher.InvokeAsync(() =>
            {
                if (Volatile.Read(ref _disposed) == 0)
                {
                    action();
                }
            }, _lifetime.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
        }
        catch (ObjectDisposedException) when (Volatile.Read(ref _disposed) != 0)
        {
        }
        catch (InvalidOperationException) when (Volatile.Read(ref _disposed) != 0)
        {
        }
    }
}
