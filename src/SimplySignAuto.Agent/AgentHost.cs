using System.Runtime.InteropServices;
using System.Reflection;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.Agent.Security;
using SimplySignAuto.Agent.Sessions;
using SimplySignAuto.Agent.Diagnostics;
using SimplySignAuto.Agent.Signing;
using SimplySignAuto.Agent.SimplySign;
using SimplySignAuto.Core.Versioning;
using SimplySignAuto.Protocol;

namespace SimplySignAuto.Agent;

public sealed record AgentReadiness(string OtpStatus);

public interface IAgentInstanceLock : IDisposable;

public interface IAgentInstanceLockFactory
{
    IAgentInstanceLock? TryAcquire(string mutexName);
}

public interface IAgentPipeSession
{
    Task CurrentJobCompletion { get; }

    Task RunAsync(
        InteractiveSessionInfo session,
        AgentReadiness readiness,
        CancellationToken cancellationToken);

    void StopAcceptingNewJobs();
}

public interface IAgentPipeSessionFactory
{
    IAgentPipeSession Create(InteractiveSessionInfo session);
}

public interface IAgentLifetime
{
    CancellationToken ShutdownRequested { get; }
}

public interface IOwnedAgentLifetime : IAgentLifetime, IDisposable;

public interface IAgentSessionEndingSignal : IDisposable
{
    event EventHandler? SessionEnding;
}

public interface IAgentShutdownWaiter
{
    Task WaitAsync(Task currentJobCompletion, TimeSpan timeout, CancellationToken cancellationToken);
}

public interface IAgentReconnectDelay
{
    Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken);
}

public sealed class SystemAgentReconnectDelay : IAgentReconnectDelay
{
    public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
        Task.Delay(delay, cancellationToken);
}

public sealed class AgentHost
{
    public static readonly TimeSpan ShutdownTimeout = TimeSpan.FromSeconds(60);
    public static readonly TimeSpan ReconnectDelay = TimeSpan.FromSeconds(1);

    private readonly InteractiveSessionGuard _sessionGuard;
    private readonly IOtpStore _otpStore;
    private readonly IAgentInstanceLockFactory _instanceLocks;
    private readonly IAgentPipeSessionFactory _pipeSessions;
    private readonly IAgentLifetime _lifetime;
    private readonly IAgentShutdownWaiter _shutdownWaiter;
    private readonly IAgentReconnectDelay? _reconnectDelay;
    private readonly IAgentDiagnosticSink _diagnostics;

    public AgentHost(
        InteractiveSessionGuard sessionGuard,
        IOtpStore otpStore,
        IAgentInstanceLockFactory instanceLocks,
        IAgentPipeSession pipeSession,
        IAgentLifetime lifetime,
        IAgentShutdownWaiter shutdownWaiter)
    {
        _sessionGuard = sessionGuard ?? throw new ArgumentNullException(nameof(sessionGuard));
        _otpStore = otpStore ?? throw new ArgumentNullException(nameof(otpStore));
        _instanceLocks = instanceLocks ?? throw new ArgumentNullException(nameof(instanceLocks));
        _pipeSessions = new FixedAgentPipeSessionFactory(
            pipeSession ?? throw new ArgumentNullException(nameof(pipeSession)));
        _lifetime = lifetime ?? throw new ArgumentNullException(nameof(lifetime));
        _shutdownWaiter = shutdownWaiter ?? throw new ArgumentNullException(nameof(shutdownWaiter));
        _reconnectDelay = null;
        _diagnostics = NullAgentDiagnosticSink.Instance;
    }

    public AgentHost(
        InteractiveSessionGuard sessionGuard,
        IOtpStore otpStore,
        IAgentInstanceLockFactory instanceLocks,
        IAgentPipeSessionFactory pipeSessions,
        IAgentLifetime lifetime,
        IAgentShutdownWaiter shutdownWaiter)
        : this(
            sessionGuard,
            otpStore,
            instanceLocks,
            pipeSessions,
            lifetime,
            shutdownWaiter,
            new SystemAgentReconnectDelay())
    {
    }

    public AgentHost(
        InteractiveSessionGuard sessionGuard,
        IOtpStore otpStore,
        IAgentInstanceLockFactory instanceLocks,
        IAgentPipeSessionFactory pipeSessions,
        IAgentLifetime lifetime,
        IAgentShutdownWaiter shutdownWaiter,
        IAgentReconnectDelay reconnectDelay,
        IAgentDiagnosticSink? diagnostics = null)
    {
        _sessionGuard = sessionGuard ?? throw new ArgumentNullException(nameof(sessionGuard));
        _otpStore = otpStore ?? throw new ArgumentNullException(nameof(otpStore));
        _instanceLocks = instanceLocks ?? throw new ArgumentNullException(nameof(instanceLocks));
        _pipeSessions = pipeSessions ?? throw new ArgumentNullException(nameof(pipeSessions));
        _lifetime = lifetime ?? throw new ArgumentNullException(nameof(lifetime));
        _shutdownWaiter = shutdownWaiter ?? throw new ArgumentNullException(nameof(shutdownWaiter));
        _reconnectDelay = reconnectDelay ?? throw new ArgumentNullException(nameof(reconnectDelay));
        _diagnostics = diagnostics.Safe();
    }

    public async Task RunAsync(string expectedUserSid, CancellationToken cancellationToken)
    {
        var session = _sessionGuard.ValidateCurrentProcess(expectedUserSid);
        cancellationToken.ThrowIfCancellationRequested();
        if (_lifetime.ShutdownRequested.IsCancellationRequested)
        {
            return;
        }

        using var shutdown = CancellationTokenSource.CreateLinkedTokenSource(
            _lifetime.ShutdownRequested,
            cancellationToken);
        var mutexName = $"Local\\SimplySignAuto.Agent.{session.UserSid}";
        using var instanceLock = _instanceLocks.TryAcquire(mutexName)
            ?? throw new AgentStartupException("agent_already_running");
        cancellationToken.ThrowIfCancellationRequested();
        if (_lifetime.ShutdownRequested.IsCancellationRequested)
        {
            return;
        }

        AgentReadiness readiness;
        try
        {
            readiness = await LoadReadinessAsync(shutdown.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return;
        }

        cancellationToken.ThrowIfCancellationRequested();
        if (_lifetime.ShutdownRequested.IsCancellationRequested)
        {
            return;
        }

        while (!shutdown.IsCancellationRequested)
        {
            var pipeSession = _pipeSessions.Create(session);
            try
            {
                await RunPipeSessionAsync(
                    pipeSession,
                    session,
                    readiness,
                    shutdown,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (Exception error) when (
                _reconnectDelay is not null && error is not OperationCanceledException)
            {
                _diagnostics.Report(new AgentDiagnostic(
                    "agent_pipe_session",
                    "agent_connection_failed",
                    error));
            }
            finally
            {
                await DisposePipeSessionAsync(pipeSession).ConfigureAwait(false);
            }

            if (_reconnectDelay is null || shutdown.IsCancellationRequested)
            {
                return;
            }

            try
            {
                await _reconnectDelay.DelayAsync(ReconnectDelay, shutdown.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return;
            }
        }
    }

    private async Task RunPipeSessionAsync(
        IAgentPipeSession pipeSession,
        InteractiveSessionInfo session,
        AgentReadiness readiness,
        CancellationTokenSource shutdown,
        CancellationToken cancellationToken)
    {
        using var connectionCancellation = new CancellationTokenSource();
        var acceptingStopped = 0;
        void StopAcceptingNewJobsOnce()
        {
            if (Interlocked.Exchange(ref acceptingStopped, 1) == 0)
            {
                pipeSession.StopAcceptingNewJobs();
            }
        }

        using var shutdownRegistration = shutdown.Token.Register(StopAcceptingNewJobsOnce);
        if (shutdown.IsCancellationRequested)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return;
        }

        var connection = pipeSession.RunAsync(session, readiness, connectionCancellation.Token);
        if (shutdown.IsCancellationRequested)
        {
            StopAcceptingNewJobsOnce();
            await CancelAndJoinConnectionAsync(connection, connectionCancellation).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            return;
        }

        var shutdownRequested = WaitForCancellationAsync(shutdown.Token);
        var completed = await Task.WhenAny(connection, shutdownRequested).ConfigureAwait(false);
        if (completed == connection)
        {
            shutdownRegistration.Dispose();
            StopAcceptingNewJobsOnce();
            await CancelAndJoinConnectionAsync(connection, connectionCancellation).ConfigureAwait(false);
            return;
        }

        StopAcceptingNewJobsOnce();
        try
        {
            await _shutdownWaiter
                .WaitAsync(pipeSession.CurrentJobCompletion, ShutdownTimeout, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            await CancelAndJoinConnectionAsync(connection, connectionCancellation).ConfigureAwait(false);
        }
    }

    private sealed class FixedAgentPipeSessionFactory(IAgentPipeSession pipeSession) : IAgentPipeSessionFactory
    {
        public IAgentPipeSession Create(InteractiveSessionInfo session) => pipeSession;
    }

    private static async ValueTask DisposePipeSessionAsync(IAgentPipeSession pipeSession)
    {
        switch (pipeSession)
        {
            case IAsyncDisposable asyncDisposable:
                await asyncDisposable.DisposeAsync().ConfigureAwait(false);
                break;
            case IDisposable disposable:
                disposable.Dispose();
                break;
        }
    }

    private static async Task CancelAndJoinConnectionAsync(
        Task connection,
        CancellationTokenSource connectionCancellation)
    {
        connectionCancellation.Cancel();
        try
        {
            await connection.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (connectionCancellation.IsCancellationRequested)
        {
        }
    }

    private async Task<AgentReadiness> LoadReadinessAsync(CancellationToken cancellationToken)
    {
        try
        {
            _ = await _otpStore.LoadAsync(cancellationToken).ConfigureAwait(false);
            return new AgentReadiness("ready");
        }
        catch (OtpStoreException error)
        {
            return new AgentReadiness(error.Code);
        }
    }

    private static Task WaitForCancellationAsync(CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return Task.CompletedTask;
        }

        return Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ContinueWith(
            static _ => { },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }
}

public sealed class LocalAgentInstanceLockFactory : IAgentInstanceLockFactory
{
    public IAgentInstanceLock? TryAcquire(string mutexName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(mutexName);
        if (!OperatingSystem.IsWindows())
        {
            throw new AgentStartupException("agent_not_interactive");
        }

        var mutex = new Mutex(initiallyOwned: false, mutexName, out var createdNew);
        if (!createdNew)
        {
            mutex.Dispose();
            return null;
        }

        return new LocalAgentInstanceLock(mutex);
    }

    private sealed class LocalAgentInstanceLock(Mutex mutex) : IAgentInstanceLock
    {
        private Mutex? _mutex = mutex;

        public void Dispose()
        {
            var mutexToRelease = Interlocked.Exchange(ref _mutex, null);
            if (mutexToRelease is null)
            {
                return;
            }

            mutexToRelease.Dispose();
        }
    }
}

public sealed class SystemAgentShutdownWaiter : IAgentShutdownWaiter
{
    public async Task WaitAsync(
        Task currentJobCompletion,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(currentJobCompletion);
        var timeoutTask = Task.Delay(timeout, cancellationToken);
        if (await Task.WhenAny(currentJobCompletion, timeoutTask).ConfigureAwait(false) == currentJobCompletion)
        {
            await currentJobCompletion.ConfigureAwait(false);
            return;
        }

        await timeoutTask.ConfigureAwait(false);
    }
}

public sealed class AgentPipeSession : IAgentPipeSession
{
    private static readonly HashSet<string> SupportedCapabilities = new(StringComparer.Ordinal)
    {
        "authenticode", "pdf",
    };
    private readonly AgentPipeClient _client;
    private readonly PrepareSignJobCommandHandler _commandHandler;
    private readonly IReadOnlyList<string> _capabilities;
    private readonly CapabilityProbeCache? _capabilityCache;
    private readonly AgentStartupPreparationCache? _startupPreparation;
    private readonly IAgentControlCommandHandler? _controlCommands;

    public AgentPipeSession(
        AgentPipeClient client,
        SignJobCommandHandler commandHandler,
        IReadOnlyList<string> capabilities,
        CapabilityProbeCache? capabilityCache = null)
        : this(
            client,
            async (command, progress, token) => new JobTerminalPublication(
                await commandHandler(command, progress, token).ConfigureAwait(false)),
            capabilities,
            capabilityCache)
    {
        ArgumentNullException.ThrowIfNull(commandHandler);
    }

    public AgentPipeSession(
        AgentPipeClient client,
        PrepareSignJobCommandHandler commandHandler,
        IReadOnlyList<string> capabilities,
        CapabilityProbeCache? capabilityCache = null,
        AgentStartupPreparationCache? startupPreparation = null,
        IAgentControlCommandHandler? controlCommands = null)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
        _commandHandler = commandHandler ?? throw new ArgumentNullException(nameof(commandHandler));
        ArgumentNullException.ThrowIfNull(capabilities);
        if (capabilities.Count == 0 ||
            capabilities.Any(capability => !SupportedCapabilities.Contains(capability)) ||
            capabilities.Distinct(StringComparer.Ordinal).Count() != capabilities.Count)
        {
            throw new ArgumentException("Agent capabilities are invalid.", nameof(capabilities));
        }

        _capabilities = capabilities.ToArray();
        _capabilityCache = capabilityCache;
        _startupPreparation = startupPreparation;
        _controlCommands = controlCommands;
    }

    public AgentPipeSession(AgentPipeClient client, SigningWorker worker)
        : this(
            client,
            (command, progress, cancellationToken) => worker.PreparePublicationAsync(command, progress, cancellationToken),
            worker.Capabilities)
    {
        ArgumentNullException.ThrowIfNull(worker);
    }

    public Task CurrentJobCompletion => _client.CurrentJobCompletion;

    public async Task RunAsync(
        InteractiveSessionInfo session,
        AgentReadiness readiness,
        CancellationToken cancellationToken)
    {
        var hello = new AgentHello(
            LengthPrefixedJsonProtocol.ProtocolVersion,
            Environment.ProcessId,
            session.SessionId,
            session.UserSid,
            ReadProductIdentity(typeof(AgentHost).Assembly),
            _capabilities);
        await _client.RunWithPublicationAsync(
            hello,
            () => _capabilityCache?.CreateHeartbeat(_client.CurrentJobId) ?? new AgentHeartbeat(
                    session.SessionId,
                    "not_checked",
                    readiness.OtpStatus,
                    "not_checked",
                    "not_checked",
                    _client.CurrentJobId,
                    null,
                    CapabilitySnapshot.NotConfigured(),
                    CapabilitySnapshot.NotConfigured(),
                    1),
            _commandHandler,
            cancellationToken,
            _startupPreparation,
            _controlCommands).ConfigureAwait(false);
    }

    private static string ReadProductIdentity(Assembly assembly)
    {
        var informational = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion;
        return ProductVersion.TryParse(informational, out var version)
            ? version!.Identity
            : throw new InvalidOperationException("product_version_invalid");
    }

    public void StopAcceptingNewJobs()
    {
        _client.StopAcceptingNewJobs();
    }

}

public enum AgentConsoleControlType : uint
{
    CtrlC = 0,
    CtrlBreak = 1,
    CtrlClose = 2,
    CtrlLogoff = 5,
    CtrlShutdown = 6,
}

public static class AgentConsoleControlPolicy
{
    public static bool ShouldHandle(AgentConsoleControlType controlType) =>
        controlType is AgentConsoleControlType.CtrlC
            or AgentConsoleControlType.CtrlBreak
            or AgentConsoleControlType.CtrlClose;
}

public sealed partial class WindowsAgentLifetime : IOwnedAgentLifetime
{
    private readonly CancellationTokenSource _shutdown = new();
    private readonly EventHandler _processExitHandler;
    private readonly IAgentSessionEndingSignal _sessionEndingSignal;
    private ConsoleControlHandler? _consoleControlHandler;
    private bool _disposed;

    public WindowsAgentLifetime()
        : this(OperatingSystem.IsWindows()
            ? new WindowsSessionEndingSignal()
            : new EmptySessionEndingSignal())
    {
    }

    public WindowsAgentLifetime(IAgentSessionEndingSignal sessionEndingSignal)
    {
        _sessionEndingSignal = sessionEndingSignal ?? throw new ArgumentNullException(nameof(sessionEndingSignal));
        _sessionEndingSignal.SessionEnding += HandleSessionEnding;
        _processExitHandler = (_, _) => RequestShutdown();
        AppDomain.CurrentDomain.ProcessExit += _processExitHandler;
        if (OperatingSystem.IsWindows())
        {
            _consoleControlHandler = HandleConsoleControl;
            if (!SetConsoleCtrlHandler(_consoleControlHandler, add: true))
            {
                AppDomain.CurrentDomain.ProcessExit -= _processExitHandler;
                _sessionEndingSignal.SessionEnding -= HandleSessionEnding;
                _sessionEndingSignal.Dispose();
                _consoleControlHandler = null;
                _shutdown.Dispose();
                throw new AgentStartupException("agent_shutdown_handler_failed");
            }
        }
    }

    public CancellationToken ShutdownRequested => _shutdown.Token;

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        AppDomain.CurrentDomain.ProcessExit -= _processExitHandler;
        _sessionEndingSignal.SessionEnding -= HandleSessionEnding;
        _sessionEndingSignal.Dispose();
        if (OperatingSystem.IsWindows() && _consoleControlHandler is not null)
        {
            _ = SetConsoleCtrlHandler(_consoleControlHandler, add: false);
            _consoleControlHandler = null;
        }

        _shutdown.Dispose();
    }

    private void HandleSessionEnding(object? sender, EventArgs args) => RequestShutdown();

    private bool HandleConsoleControl(AgentConsoleControlType controlType)
    {
        if (AgentConsoleControlPolicy.ShouldHandle(controlType))
        {
            RequestShutdown();
            return true;
        }

        return false;
    }

    private void RequestShutdown()
    {
        if (!_disposed)
        {
            _shutdown.Cancel();
        }
    }

    private delegate bool ConsoleControlHandler(AgentConsoleControlType controlType);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetConsoleCtrlHandler(
        ConsoleControlHandler? handler,
        [MarshalAs(UnmanagedType.Bool)] bool add);

    private sealed class EmptySessionEndingSignal : IAgentSessionEndingSignal
    {
        public event EventHandler? SessionEnding
        {
            add { }
            remove { }
        }

        public void Dispose()
        {
        }
    }
}
