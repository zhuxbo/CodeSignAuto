using System.ComponentModel;
using System.Runtime.CompilerServices;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.Agent.LocalJobs;
using SimplySignAuto.App.Commands;
using SimplySignAuto.App.UI.Status;
using SimplySignAuto.App.UI.ViewModels;

namespace SimplySignAuto.App.UI;

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
        AgentConfiguration? configuration = null)
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
                    dispatcher)
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
    {
        ArgumentNullException.ThrowIfNull(activeJobs);
        _window = window ?? throw new ArgumentNullException(nameof(window));
        ArgumentNullException.ThrowIfNull(agentLifetime);
        _dispatcher = dispatcher ?? InlineAppUiDispatcher.Instance;
        _pages = CreatePages(null, null, null, null, null);
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
        _window = window ?? throw new ArgumentNullException(nameof(window));
        ArgumentNullException.ThrowIfNull(agentLifetime);
        _dispatcher = dispatcher ?? InlineAppUiDispatcher.Instance;
        Overview = new OverviewViewModel(management, confirmation, OpenJobs, _dispatcher);
        if (management is IAgentAdministrationClient administration)
        {
            TerminalJobs = terminalJobs ?? new TerminalJobFeed(administration);
        }
        Overview.PropertyChanged += HandleOverviewPropertyChanged;
        _pages = CreatePages(Overview, null, null, null, null);
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
        IServiceSettingsDialogService? serviceSettingsDialogs = null)
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
            serviceSettingsDialogs)
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
        IServiceSettingsDialogService? serviceSettingsDialogs = null)
    {
        ArgumentNullException.ThrowIfNull(management);
        ArgumentNullException.ThrowIfNull(localJobs);
        _window = window ?? throw new ArgumentNullException(nameof(window));
        ArgumentNullException.ThrowIfNull(agentLifetime);
        _dispatcher = dispatcher ?? InlineAppUiDispatcher.Instance;
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
            ServiceSettings = new ServiceSettingsViewModel(
                administration,
                serviceConfigurationEditor ?? UnavailableServiceConfigurationEditor.Instance,
                serviceSettingsDialogs ?? UnavailableServiceSettingsDialogService.Instance,
                desktopClipboard,
                _dispatcher);
        }
        QuickSign = new QuickSignViewModel(
            localJobs,
            management,
            OpenJob,
            _dispatcher,
            TerminalJobs);

        Overview.PropertyChanged += HandleOverviewPropertyChanged;
        _pages = CreatePages(Overview, QuickSign, Jobs, Activation, ServiceSettings);
        _currentPage = _pages[0];
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public IReadOnlyList<NavigationPage> Pages => _pages;

    public OverviewViewModel? Overview { get; }

    public QuickSignViewModel? QuickSign { get; }

    public JobsViewModel? Jobs { get; }

    public ActivationViewModel? Activation { get; }

    public ServiceSettingsViewModel? ServiceSettings { get; }

    internal ITerminalJobFeed? TerminalJobs { get; }

    public Guid? SelectedJobId { get; private set; }

    public string FooterVersionText =>
        ApplicationVersion.ReadDisplay(typeof(Program).Assembly);

    public string OverallStatusText => Overview?.Status?.Overall switch
    {
        OverallReadiness.Ready => "签名服务已就绪",
        OverallReadiness.Partial => "部分签名能力可用",
        OverallReadiness.ActionRequired => "需要处理",
        _ => "尚未检查",
    };

    public string OverallStatusIcon => Overview?.Status?.Overall switch
    {
        OverallReadiness.Ready => "✓",
        OverallReadiness.Partial => "!",
        OverallReadiness.ActionRequired => "×",
        _ => "○",
    };

    public string OverallStatusAutomationName => $"服务状态：{OverallStatusText}";

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
        lock (_exitSync)
        {
            return _exitTask ??= ExitOnceAsync();
        }
    }

    private async Task<ExitRequestResult> ExitOnceAsync()
    {
        await InvokeUiAsync(_window.CloseForExit).ConfigureAwait(false);
        return ExitRequestResult.Exiting;
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
        ServiceSettingsViewModel? serviceSettings) =>
    [
        new("概览", "●", "概览信息将在状态检查后显示。", overview),
        new("快速签名", "✎", "请选择本机文件进行签名。", quickSign),
        new("签名任务", "≡", "任务列表将在服务连接后显示。", jobs),
        new("激活凭证", "◆", "激活凭证状态将在后续版本启用。", activation),
        new("服务设置", "⚙", "服务设置将在后续版本启用。", serviceSettings),
    ];

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
