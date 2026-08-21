using System.Runtime.ExceptionServices;
using SimplySignAuto.Agent;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.Agent.Sessions;
using SimplySignAuto.Agent.Diagnostics;
using SimplySignAuto.App.Commands;
using SimplySignAuto.App.Control;
using SimplySignAuto.App.UI.ViewModels;
using SimplySignAuto.App.UI.Views;
using SimplySignAuto.App.UI.Localization;
using SimplySignAuto.Agent.LocalJobs;
using SimplySignAuto.Core.Security;
using SimplySignAuto.Service;

namespace SimplySignAuto.App.UI;

public interface IDesktopRuntime : IAsyncDisposable
{
    IWindowController Window { get; }

    IUiDispatcher Dispatcher { get; }

    Task InitializeAsync(ShellViewModel viewModel, CancellationToken cancellationToken);

    Task<int> RunAsync(bool showInitially, CancellationToken cancellationToken);

    void RequestShutdown();
}

public interface IDesktopRuntimeFactory
{
    IDesktopRuntime Create(string? uiTestTrayIdentity = null);
}

public interface IAgentLifetimeFactory
{
    IOwnedAgentLifetime Create();
}

public sealed class WindowsAgentLifetimeFactory : IAgentLifetimeFactory
{
    public IOwnedAgentLifetime Create() => new WindowsAgentLifetime();
}

public interface IDesktopSigningUserIdentity
{
    string GetCurrentSid();
}

public sealed class WindowsDesktopSigningUserIdentity : IDesktopSigningUserIdentity
{
    public string GetCurrentSid()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new ActivationException("activation_windows_required");
        }

        return GetWindowsSid();
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static string GetWindowsSid()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var sid = identity.User?.Value;
            if (!CanonicalWindowsSid.IsValid(sid))
            {
                throw new ActivationException("activation_identity_invalid");
            }

            return sid!;
        }
        catch (ActivationException)
        {
            throw;
        }
        catch (Exception error) when (
            error is UnauthorizedAccessException
                or InvalidOperationException
                or System.Security.SecurityException)
        {
            throw new ActivationException("activation_identity_invalid");
        }
    }
}

public sealed class DeferredShutdownGate
{
    private readonly object _sync = new();
    private Action? _target;
    private bool _requested;
    private bool _delivered;

    public void Attach(Action target)
    {
        ArgumentNullException.ThrowIfNull(target);
        Action? deliver = null;
        lock (_sync)
        {
            if (_target is not null)
            {
                throw new InvalidOperationException("shutdown_target_already_attached");
            }

            _target = target;
            if (_requested && !_delivered)
            {
                _delivered = true;
                deliver = target;
            }
        }

        deliver?.Invoke();
    }

    public void Request()
    {
        Action? deliver = null;
        lock (_sync)
        {
            _requested = true;
            if (_target is not null && !_delivered)
            {
                _delivered = true;
                deliver = _target;
            }
        }

        deliver?.Invoke();
    }
}

public sealed class DesktopOwnedLifetimes : IDesktopAgentLifetime
{
    private readonly object _sync = new();
    private readonly IActivationServer _activationServer;
    private readonly ActivationCommandHandler _activationHandler;
    private readonly IAgentRunner _agentRunner;
    private readonly IAgentLifetime _agentLifetime;
    private readonly AgentConfiguration _configuration;
    private readonly TaskCompletionSource _deliberateShutdown =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Task _systemShutdown;
    private CancellationTokenSource? _activationCancellation;
    private CancellationTokenSource? _agentCancellation;
    private Task? _activationTask;
    private Task? _agentTask;
    private Task? _stopTask;
    private bool _started;
    private bool _stopRequested;

    public DesktopOwnedLifetimes(
        IActivationServer activationServer,
        ActivationCommandHandler activationHandler,
        IAgentRunner agentRunner,
        AgentConfiguration configuration,
        IAgentLifetime? agentLifetime = null)
    {
        _activationServer = activationServer ?? throw new ArgumentNullException(nameof(activationServer));
        _activationHandler = activationHandler ?? throw new ArgumentNullException(nameof(activationHandler));
        _agentRunner = agentRunner ?? throw new ArgumentNullException(nameof(agentRunner));
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _agentLifetime = agentLifetime ?? NeverShutdownAgentLifetime.Instance;
        _systemShutdown = WaitForCancellationAsync(_agentLifetime.ShutdownRequested);
    }

    public Task ActivationCompletion => _activationTask ?? Task.CompletedTask;

    public Task AgentCompletion => _agentTask ?? Task.CompletedTask;

    public Task DeliberateShutdown => _deliberateShutdown.Task;

    public Task SystemShutdown => _systemShutdown;

    public bool IsSystemShutdownRequested => _agentLifetime.ShutdownRequested.IsCancellationRequested;

    public void Start()
    {
        lock (_sync)
        {
            if (_stopRequested)
            {
                throw new InvalidOperationException("desktop_lifetime_stopped");
            }

            if (_started)
            {
                throw new InvalidOperationException("desktop_lifetime_already_started");
            }

            _started = true;
            _activationCancellation = new CancellationTokenSource();
            _activationTask = _activationServer.RunAsync(
                _activationHandler,
                _activationCancellation.Token);
            _agentCancellation = new CancellationTokenSource();
            _agentTask = _agentRunner is IDesktopAgentRunner desktopAgentRunner
                ? desktopAgentRunner.RunAsync(
                    _configuration,
                    _agentLifetime,
                    _agentCancellation.Token)
                : _agentRunner.RunAsync(_configuration, _agentCancellation.Token);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            _stopRequested = true;
            _deliberateShutdown.TrySetResult();
            return _stopTask ??= StopOnceAsync();
        }
    }

    private async Task StopOnceAsync()
    {
        var activationCancellation = _activationCancellation;
        var activationTask = _activationTask;
        Exception? failure = null;
        if (activationCancellation is not null)
        {
            try
            {
                activationCancellation.Cancel();
            }
            catch (Exception error)
            {
                failure = error;
            }

            var activationFailure = await CaptureCompletionFailureAsync(
                activationTask,
                activationCancellation).ConfigureAwait(false);
            failure ??= activationFailure;
        }

        var agentCancellation = _agentCancellation;
        var agentTask = _agentTask;
        if (agentCancellation is not null)
        {
            try
            {
                agentCancellation.Cancel();
            }
            catch (Exception error)
            {
                failure ??= error;
            }

            var agentFailure = await CaptureCompletionFailureAsync(
                agentTask,
                agentCancellation).ConfigureAwait(false);
            failure ??= agentFailure;
        }

        try
        {
            activationCancellation?.Dispose();
        }
        catch (Exception error)
        {
            failure ??= error;
        }

        try
        {
            agentCancellation?.Dispose();
        }
        catch (Exception error)
        {
            failure ??= error;
        }

        if (failure is not null)
        {
            ExceptionDispatchInfo.Capture(failure).Throw();
        }
    }

    private static async Task<Exception?> CaptureCompletionFailureAsync(
        Task? task,
        CancellationTokenSource cancellation)
    {
        if (task is null)
        {
            return null;
        }

        try
        {
            await task.ConfigureAwait(false);
            return null;
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            return null;
        }
        catch (Exception error)
        {
            return error;
        }
    }

    private static async Task WaitForCancellationAsync(CancellationToken cancellationToken)
    {
        if (!cancellationToken.CanBeCanceled)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan).ConfigureAwait(false);
            return;
        }

        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }

    private sealed class NeverShutdownAgentLifetime : IAgentLifetime
    {
        public static NeverShutdownAgentLifetime Instance { get; } = new();

        public CancellationToken ShutdownRequested => CancellationToken.None;
    }
}

public sealed class DesktopApplication
{
    private readonly IAgentConfigurationLoader _configurationLoader;
    private readonly IDesktopSigningUserIdentity _signingIdentity;
    private readonly ISingleInstanceActivator _singleInstance;
    private readonly IAgentRunner _agentRunner;
    private readonly IDesktopRuntimeFactory _runtimeFactory;
    private readonly IActiveJobStateSource _activeJobs;
    private readonly IAgentLifetimeFactory _agentLifetimeFactory;

    public DesktopApplication()
        : this(Console.Error)
    {
    }

    internal DesktopApplication(TextWriter diagnosticWriter)
        : this(
            new AgentConfigurationLoader(),
            new WindowsDesktopSigningUserIdentity(),
            new SingleInstanceActivator(),
            new DefaultAgentRunner(diagnosticWriter),
            new WpfDesktopRuntimeFactory(),
            new UnknownActiveJobStateSource(),
            new WindowsAgentLifetimeFactory())
    {
    }

    public DesktopApplication(
        IAgentConfigurationLoader configurationLoader,
        IDesktopSigningUserIdentity signingIdentity,
        ISingleInstanceActivator singleInstance,
        IAgentRunner agentRunner,
        IDesktopRuntimeFactory runtimeFactory,
        IActiveJobStateSource activeJobs,
        IAgentLifetimeFactory? agentLifetimeFactory = null)
    {
        _configurationLoader = configurationLoader ?? throw new ArgumentNullException(nameof(configurationLoader));
        _signingIdentity = signingIdentity ?? throw new ArgumentNullException(nameof(signingIdentity));
        _singleInstance = singleInstance ?? throw new ArgumentNullException(nameof(singleInstance));
        _agentRunner = agentRunner ?? throw new ArgumentNullException(nameof(agentRunner));
        _runtimeFactory = runtimeFactory ?? throw new ArgumentNullException(nameof(runtimeFactory));
        _activeJobs = activeJobs ?? throw new ArgumentNullException(nameof(activeJobs));
        _agentLifetimeFactory = agentLifetimeFactory ?? new WindowsAgentLifetimeFactory();
    }

    public async Task<int> ExecuteAsync(
        bool showInitially,
        TextWriter error,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(error);
        try
        {
            var signingUserSid = _signingIdentity.GetCurrentSid();
            return await _singleInstance.RunSingleAsync(
                signingUserSid,
                (server, token) => StartOwnedInstanceAsync(
                    signingUserSid,
                    server,
                    showInitially,
                    token),
                cancellationToken).ConfigureAwait(false);
        }
        catch (AgentConfigurationException configurationError)
        {
            return await ReportDesktopFailureAsync(
                error,
                "desktop_configuration",
                configurationError.Code,
                configurationError).ConfigureAwait(false);
        }
        catch (ActivationException activationError)
        {
            return await ReportDesktopFailureAsync(
                error,
                "desktop_activation",
                activationError.Code,
                activationError).ConfigureAwait(false);
        }
        catch (AgentStartupException startupError)
        {
            return await ReportDesktopFailureAsync(
                error,
                "desktop_agent_startup",
                startupError.Code,
                startupError).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return 0;
        }
        catch (OperationCanceledException cancellationError)
        {
            return await ReportDesktopFailureAsync(
                error,
                "desktop_execute",
                "desktop_start_failed",
                cancellationError).ConfigureAwait(false);
        }
        catch (Exception desktopError)
        {
            return await ReportDesktopFailureAsync(
                error,
                "desktop_execute",
                "desktop_start_failed",
                desktopError).ConfigureAwait(false);
        }
    }

    private static async Task<int> ReportDesktopFailureAsync(
        TextWriter writer,
        string stage,
        string stableCode,
        Exception error)
    {
        new TextWriterAgentDiagnosticSink(writer).Safe().Report(
            new AgentDiagnostic(stage, stableCode, error));
        try
        {
            await writer.WriteLineAsync(stableCode).ConfigureAwait(false);
        }
        catch (Exception)
        {
        }

        return 1;
    }

    private async Task<int> StartOwnedInstanceAsync(
        string signingUserSid,
        IActivationServer activationServer,
        bool showInitially,
        CancellationToken cancellationToken)
    {
        var configuration = await _configurationLoader.LoadAsync(cancellationToken).ConfigureAwait(false);
        if (!string.Equals(configuration.SigningUserSid, signingUserSid, StringComparison.Ordinal))
        {
            throw new AgentConfigurationException("agent_configuration_invalid");
        }

        return await RunOwnedAsync(
            configuration,
            activationServer,
            showInitially,
            cancellationToken).ConfigureAwait(false);
    }

    private async Task<int> RunOwnedAsync(
        AgentConfiguration configuration,
        IActivationServer activationServer,
        bool showInitially,
        CancellationToken cancellationToken)
    {
        using var agentLifetime = _agentLifetimeFactory.Create();
        await using var runtime = _runtimeFactory.Create();
        DesktopOwnedLifetimes? lifetimes = null;
        try
        {
            var placeholderLifetime = new DeferredDesktopAgentLifetime();
            using var viewModel = DesktopShellComposition.Create(
                _agentRunner,
                _activeJobs,
                runtime.Window,
                placeholderLifetime,
                runtime.Dispatcher,
                configuration);
            await runtime.InitializeAsync(viewModel, cancellationToken).ConfigureAwait(false);

            var activationHandler = new ActivationCommandHandler(runtime.Dispatcher, runtime.Window);
            lifetimes = new DesktopOwnedLifetimes(
                activationServer,
                activationHandler,
                _agentRunner,
                configuration,
                agentLifetime);
            lifetimes.Start();
            placeholderLifetime.Attach(lifetimes);

            var runTask = runtime.RunAsync(showInitially, cancellationToken);
            var completed = await Task.WhenAny(
                runTask,
                lifetimes.DeliberateShutdown,
                lifetimes.SystemShutdown,
                lifetimes.AgentCompletion,
                lifetimes.ActivationCompletion).ConfigureAwait(false);
            if (lifetimes.IsSystemShutdownRequested)
            {
                if (!runTask.IsCompleted)
                {
                    runtime.RequestShutdown();
                }

                try
                {
                    await lifetimes.AgentCompletion.ConfigureAwait(false);
                }
                catch (OperationCanceledException cancellationError) when (
                    cancellationError.CancellationToken == agentLifetime.ShutdownRequested)
                {
                }

                return await runTask.ConfigureAwait(false);
            }

            if (completed == runTask)
            {
                return await runTask.ConfigureAwait(false);
            }

            if (completed == lifetimes.DeliberateShutdown || lifetimes.DeliberateShutdown.IsCompleted)
            {
                await lifetimes.StopAsync(CancellationToken.None).ConfigureAwait(false);
                return await runTask.ConfigureAwait(false);
            }

            Exception failure;
            if (completed == lifetimes.AgentCompletion)
            {
                failure = await CaptureFailureAsync(
                    lifetimes.AgentCompletion,
                    new IOException("agent_stopped")).ConfigureAwait(false);
            }
            else
            {
                failure = await CaptureFailureAsync(
                    lifetimes.ActivationCompletion,
                    new IOException("activation_server_stopped")).ConfigureAwait(false);
            }

            await runtime.Dispatcher.InvokeAsync(runtime.RequestShutdown, CancellationToken.None)
                .ConfigureAwait(false);
            await runTask.ConfigureAwait(false);
            ExceptionDispatchInfo.Capture(failure).Throw();
            throw new InvalidOperationException("desktop_unreachable");
        }
        finally
        {
            if (lifetimes is not null)
            {
                await lifetimes.StopAsync(CancellationToken.None).ConfigureAwait(false);
            }
        }
    }

    private static async Task<Exception> CaptureFailureAsync(Task task, Exception completedError)
    {
        try
        {
            await task.ConfigureAwait(false);
            return completedError;
        }
        catch (Exception error)
        {
            return error;
        }
    }

    private sealed class DeferredDesktopAgentLifetime : IDesktopAgentLifetime
    {
        private IDesktopAgentLifetime? _inner;

        public void Attach(IDesktopAgentLifetime lifetime)
        {
            if (Interlocked.CompareExchange(ref _inner, lifetime, null) is not null)
            {
                throw new InvalidOperationException("desktop_lifetime_already_attached");
            }
        }

        public Task StopAsync(CancellationToken cancellationToken) =>
            (_inner ?? throw new InvalidOperationException("desktop_lifetime_not_started"))
                .StopAsync(cancellationToken);
    }
}

public sealed class AdminDesktopApplication
{
    private readonly IDesktopSigningUserIdentity _identity;
    private readonly ISingleInstanceActivator _singleInstance;
    private readonly IDesktopRuntimeFactory _runtimeFactory;

    public AdminDesktopApplication(TextWriter diagnosticWriter)
        : this(
            new WindowsDesktopSigningUserIdentity(),
            new SingleInstanceActivator(),
            new WpfDesktopRuntimeFactory())
    {
        ArgumentNullException.ThrowIfNull(diagnosticWriter);
    }

    public AdminDesktopApplication(
        IDesktopSigningUserIdentity identity,
        ISingleInstanceActivator singleInstance,
        IDesktopRuntimeFactory runtimeFactory)
    {
        _identity = identity ?? throw new ArgumentNullException(nameof(identity));
        _singleInstance = singleInstance ?? throw new ArgumentNullException(nameof(singleInstance));
        _runtimeFactory = runtimeFactory ?? throw new ArgumentNullException(nameof(runtimeFactory));
    }

    public async Task<int> ExecuteAsync(
        bool showInitially,
        TextWriter error,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(error);
        try
        {
            var administratorSid = _identity.GetCurrentSid();
            return await _singleInstance.RunSingleAsync(
                administratorSid,
                (activation, token) => RunOwnedAsync(
                    activation,
                    showInitially,
                    token),
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return 0;
        }
        catch (Exception failure) when (
            failure is ActivationException or ManagementUnavailableException or
                IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            new TextWriterAgentDiagnosticSink(error).Safe().Report(
                new AgentDiagnostic("admin_desktop", "admin_control_start_failed", failure));
            await error.WriteLineAsync("admin_control_start_failed").ConfigureAwait(false);
            return 1;
        }
    }

    private async Task<int> RunOwnedAsync(
        IActivationServer activationServer,
        bool showInitially,
        CancellationToken cancellationToken)
    {
        using var control = new AdminControlClient();
        await using var localJobs = new LocalJobClient(
            control,
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "SimplySignAuto",
                "spool"));
        await using var runtime = _runtimeFactory.Create();
        var settingsDialogs = runtime as IServiceSettingsDialogServiceProvider
            ?? throw new InvalidOperationException("service_settings_dialog_unavailable");
        var settingsEditor = new ServiceConfigurationEditor(new WindowsConfigureServicePlatform());
        using var viewModel = new ShellViewModel(
            control,
            localJobs,
            new WindowReloginConfirmation(runtime.Window, runtime.Dispatcher),
            runtime.Window,
            DetachedControlConsoleLifetime.Instance,
            runtime.Dispatcher,
            terminalJobs: null,
            clipboard: null,
            serviceConfigurationEditor: settingsEditor,
            serviceSettingsDialogs: settingsDialogs.ServiceSettingsDialogs,
            uiPreferenceStore: new UiPreferenceStore());
        await runtime.InitializeAsync(viewModel, cancellationToken).ConfigureAwait(false);

        using var activationCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        var activationHandler = new ActivationCommandHandler(runtime.Dispatcher, runtime.Window);
        var activationTask = activationServer.RunAsync(
            activationHandler,
            activationCancellation.Token);
        var runTask = runtime.RunAsync(showInitially, cancellationToken);
        try
        {
            var completed = await Task.WhenAny(runTask, activationTask).ConfigureAwait(false);
            if (completed == activationTask && !cancellationToken.IsCancellationRequested)
            {
                await activationTask.ConfigureAwait(false);
                runtime.RequestShutdown();
            }

            return await runTask.ConfigureAwait(false);
        }
        finally
        {
            activationCancellation.Cancel();
            try
            {
                await activationTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (activationCancellation.IsCancellationRequested)
            {
            }
        }
    }

    private sealed class DetachedControlConsoleLifetime : IDesktopAgentLifetime
    {
        public static DetachedControlConsoleLifetime Instance { get; } = new();

        public Task StopAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }
    }
}

public sealed class WpfDesktopRuntimeFactory : IDesktopRuntimeFactory
{
    private readonly bool _isolatedUiTestMode;

    public WpfDesktopRuntimeFactory(bool isolatedUiTestMode = false) =>
        _isolatedUiTestMode = isolatedUiTestMode;

    public IDesktopRuntime Create(string? uiTestTrayIdentity = null) =>
        new WpfDesktopRuntime(_isolatedUiTestMode, uiTestTrayIdentity);
}

#if !SIMPLYSIGN_WPF
internal sealed class WpfDesktopRuntime :
    IDesktopRuntime,
    IServiceSettingsDialogServiceProvider
{
    public WpfDesktopRuntime(bool isolatedUiTestMode = false, string? uiTestTrayIdentity = null)
    {
    }

    public IWindowController Window => throw new PlatformNotSupportedException("WPF requires Windows.");

    public IUiDispatcher Dispatcher => throw new PlatformNotSupportedException("WPF requires Windows.");

    public IServiceSettingsDialogService ServiceSettingsDialogs =>
        UnavailableServiceSettingsDialogService.Instance;

    public Task InitializeAsync(ShellViewModel viewModel, CancellationToken cancellationToken) =>
        throw new PlatformNotSupportedException("WPF requires Windows.");

    public Task<int> RunAsync(bool showInitially, CancellationToken cancellationToken) =>
        throw new PlatformNotSupportedException("WPF requires Windows.");

    public void RequestShutdown() => throw new PlatformNotSupportedException("WPF requires Windows.");

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}
#endif

#if SIMPLYSIGN_WPF
public partial class DesktopWpfApplication : System.Windows.Application
{
    public DesktopWpfApplication() => InitializeComponent();
}

internal sealed class WpfDesktopRuntime :
    IDesktopRuntime,
    IServiceSettingsDialogServiceProvider
{
    private readonly DesktopShutdownCoordinator _shutdown = new();
    private readonly DeferredWindowController _windowTarget = new();
    private readonly IWindowController _window;
    private readonly DeferredUiDispatcher _dispatcher = new();
    private readonly TaskCompletionSource _ready = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<int> _runCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _disposeRequested = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _disposeCompletion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly DeferredShutdownGate _shutdownGate = new();
    private readonly DeferredServiceSettingsDialogService _serviceSettingsDialogs = new();
    private readonly Testing.UiTestOwnedDirectory? _isolatedDirectory;
    private readonly string? _uiTestTrayIdentity;
    private ShellViewModel? _viewModel;
    private System.Threading.Thread? _thread;
    private DesktopWpfApplication? _application;
    private MainWindow? _mainWindow;
    private int _initialized;
    private int _disposed;

    public WpfDesktopRuntime(bool isolatedUiTestMode = false, string? uiTestTrayIdentity = null)
    {
        if (uiTestTrayIdentity is not null &&
            (!isolatedUiTestMode || !Testing.UiTestTrayIdentity.IsValid(uiTestTrayIdentity)))
        {
            throw new ArgumentException("ui_test_tray_identity_invalid", nameof(uiTestTrayIdentity));
        }

        _window = new ShutdownAwareWindowController(_shutdown, _windowTarget);
        _isolatedDirectory = isolatedUiTestMode ? Testing.UiTestOwnedDirectory.Create() : null;
        _uiTestTrayIdentity = uiTestTrayIdentity;
    }

    public IWindowController Window => _window;

    public IUiDispatcher Dispatcher => _dispatcher;

    public IServiceSettingsDialogService ServiceSettingsDialogs => _serviceSettingsDialogs;

    public async Task InitializeAsync(ShellViewModel viewModel, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(viewModel);
        if (Interlocked.Exchange(ref _initialized, 1) != 0)
        {
            throw new InvalidOperationException("desktop_runtime_already_initialized");
        }

        _viewModel = viewModel;
        _thread = new System.Threading.Thread(RunWpfThread)
        {
            IsBackground = false,
            Name = "SimplySignAuto Desktop UI",
        };
        _thread.SetApartmentState(System.Threading.ApartmentState.STA);
        _thread.Start();
        await _ready.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        if (viewModel.Overview is { } overview)
        {
            await overview.RefreshAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task<int> RunAsync(bool showInitially, CancellationToken cancellationToken)
    {
        await _ready.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        if (showInitially)
        {
            await _dispatcher.InvokeAsync(_window.ShowRestoreActivate, cancellationToken).ConfigureAwait(false);
        }

        using var registration = cancellationToken.Register(RequestShutdown);
        return await _runCompletion.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
    }

    public void RequestShutdown()
    {
        if (_shutdown.TryBegin())
        {
            _shutdownGate.Request();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            await _disposeCompletion.Task.ConfigureAwait(false);
            return;
        }

        if (_thread is null)
        {
            _isolatedDirectory?.Dispose();
            _disposeCompletion.TrySetResult();
            return;
        }

        RequestShutdown();
        _disposeRequested.TrySetResult();
        await _disposeCompletion.Task.ConfigureAwait(false);
        _isolatedDirectory?.Dispose();
    }

    private void RunWpfThread()
    {
        ThemeService? theme = null;
        TrayIconController? tray = null;
        var readyPublished = false;
        try
        {
            var application = new DesktopWpfApplication();
            _application = application;
            theme = new ThemeService(new WindowsThemeSettingsSource(), new WpfThemeResourceApplier());
            var mainWindow = _isolatedDirectory is null
                ? new MainWindow()
                : new MainWindow(new WindowPlacementStore(
                    Path.Combine(_isolatedDirectory.Path, "window.json"),
                    new WindowsScreenWorkAreaSource()));
            _mainWindow = mainWindow;
            _serviceSettingsDialogs.SetTarget(new WpfServiceSettingsDialogService(mainWindow));
            mainWindow.Initialize(_viewModel ?? throw new InvalidOperationException("desktop_view_model_missing"));
            _windowTarget.SetTarget(mainWindow);
            _dispatcher.SetTarget(new WpfUiDispatcher(application.Dispatcher));
            _shutdownGate.Attach(() => application.Dispatcher.BeginInvoke(() =>
            {
                mainWindow.PrepareForShutdown();
                application.Shutdown();
            }));
            tray = new TrayIconController(
                new WindowsNotifyIconPlatform(_uiTestTrayIdentity),
                _viewModel,
                _window,
                _dispatcher);
            application.SessionEnding += HandleSessionEnding;
            readyPublished = _ready.TrySetResult();
            var exitCode = application.Run();
            _shutdown.TryBegin();
            _runCompletion.TrySetResult(exitCode);
        }
        catch (Exception error)
        {
            _ready.TrySetException(error);
            _runCompletion.TrySetException(error);
        }
        finally
        {
            if (readyPublished)
            {
                _disposeRequested.Task.GetAwaiter().GetResult();
            }

            if (_application is not null)
            {
                _application.SessionEnding -= HandleSessionEnding;
            }

            _serviceSettingsDialogs.ClearTarget();
            tray?.Dispose();
            theme?.Dispose();
            _mainWindow = null;
            _application = null;
            _disposeCompletion.TrySetResult();
        }
    }

    private void HandleSessionEnding(object? sender, System.Windows.SessionEndingCancelEventArgs args)
    {
        _shutdown.TryBegin();
        _mainWindow?.PrepareForShutdown();
    }

    private sealed class WpfUiDispatcher(System.Windows.Threading.Dispatcher dispatcher) : IUiDispatcher
    {
        public Task InvokeAsync(Action action, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(action);
            cancellationToken.ThrowIfCancellationRequested();
            if (dispatcher.CheckAccess())
            {
                action();
                return Task.CompletedTask;
            }

            return dispatcher.InvokeAsync(
                action,
                System.Windows.Threading.DispatcherPriority.Send,
                cancellationToken).Task;
        }
    }

    private sealed class DeferredUiDispatcher : IUiDispatcher
    {
        private IUiDispatcher? _target;

        public void SetTarget(IUiDispatcher target)
        {
            if (Interlocked.CompareExchange(ref _target, target, null) is not null)
            {
                throw new InvalidOperationException("desktop_dispatcher_already_initialized");
            }
        }

        public Task InvokeAsync(Action action, CancellationToken cancellationToken) =>
            (_target ?? throw new InvalidOperationException("desktop_dispatcher_not_initialized"))
                .InvokeAsync(action, cancellationToken);
    }

    private sealed class DeferredWindowController : IWindowController
    {
        private IWindowController? _target;

        public void SetTarget(IWindowController target)
        {
            if (Interlocked.CompareExchange(ref _target, target, null) is not null)
            {
                throw new InvalidOperationException("desktop_window_already_initialized");
            }
        }

        public void ShowRestoreActivate() => Target.ShowRestoreActivate();

        public void Hide() => Target.Hide();

        public void CloseForExit() => Target.CloseForExit();

        public void ShowNotice(string message) => Target.ShowNotice(message);

        public bool ConfirmRelogin() => Target.ConfirmRelogin();

        public bool ConfirmClearOtp() => Target.ConfirmClearOtp();

        private IWindowController Target =>
            _target ?? throw new InvalidOperationException("desktop_window_not_initialized");
    }
}
#endif
