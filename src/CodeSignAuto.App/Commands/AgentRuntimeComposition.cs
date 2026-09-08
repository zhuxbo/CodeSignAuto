using CodeSignAuto.Agent;
using CodeSignAuto.Agent.Ipc;
using CodeSignAuto.Agent.LocalJobs;
using CodeSignAuto.Agent.Security;
using CodeSignAuto.Agent.Sessions;
using CodeSignAuto.Agent.Signing;
using CodeSignAuto.Agent.SimplySign;
using CodeSignAuto.Agent.Diagnostics;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Core.Security;
using CodeSignAuto.App.Tools;

namespace CodeSignAuto.App.Commands;

internal sealed record AgentSigningBackends(
    IAuthenticodeSigner? AuthenticodeSigner,
    IPdfSigner? PdfSigner,
    ISimplySignSessionManager Controller,
    IDisposable Lifetime,
    IInstalledPdfToolResolver? PdfToolResolver = null);

internal interface IAgentSigningBackendFactory
{
    AgentSigningBackends Create(
        AgentConfiguration configuration,
        InteractiveSessionInfo session,
        IOtpStore otpStore);
}

internal sealed class AgentRuntimePipeSessionFactory : IAgentPipeSessionFactory, IDisposable, IAsyncDisposable
{
    private readonly AgentConfiguration _configuration;
    private readonly IOtpStore _otpStore;
    private readonly IAgentSigningBackendFactory _backends;
    private readonly Func<AgentPipeClient> _clients;
    private readonly AgentManagementBridge? _managementBridge;
    private readonly TimeProvider _healthTimeProvider;
    private readonly bool _startHealthMonitor;
    private readonly IAgentDiagnosticSink _diagnostics;
    private readonly AgentPipeClient? _managedClient;
    private readonly LocalJobClient? _managedLocalJobs;
    private readonly object _runtimeSync = new();
    private readonly object _disposeSync = new();
    private SharedAgentRuntime? _runtime;
    private Task? _disposeTask;
    private int _disposed;

    public AgentRuntimePipeSessionFactory(
        AgentConfiguration configuration,
        IOtpStore otpStore,
        IAgentSigningBackendFactory backends,
        Func<AgentPipeClient> clients,
        AgentManagementBridge? managementBridge = null,
        TimeProvider? healthTimeProvider = null,
        bool startHealthMonitor = true,
        IAgentDiagnosticSink? diagnostics = null)
    {
        _configuration = AgentConfigurationLoader.Validate(configuration);
        _otpStore = otpStore ?? throw new ArgumentNullException(nameof(otpStore));
        _backends = backends ?? throw new ArgumentNullException(nameof(backends));
        _clients = clients ?? throw new ArgumentNullException(nameof(clients));
        _managementBridge = managementBridge;
        _healthTimeProvider = healthTimeProvider ?? TimeProvider.System;
        _startHealthMonitor = startHealthMonitor;
        _diagnostics = diagnostics.Safe();
        if (_managementBridge is not null)
        {
            _managedClient = _clients();
            _managedLocalJobs = new LocalJobClient(_managedClient, _configuration.SpoolPath);
        }
    }

    public AgentRuntimePipeSessionFactory(AgentConfiguration configuration, IOtpStore otpStore)
        : this(configuration, otpStore, new DefaultAgentSigningBackendFactory(), () => new AgentPipeClient())
    {
    }

    public AgentRuntimePipeSessionFactory(
        AgentConfiguration configuration,
        IOtpStore otpStore,
        AgentManagementBridge managementBridge)
        : this(configuration, otpStore, managementBridge, NullAgentDiagnosticSink.Instance)
    {
    }

    public AgentRuntimePipeSessionFactory(
        AgentConfiguration configuration,
        IOtpStore otpStore,
        AgentManagementBridge managementBridge,
        IAgentDiagnosticSink diagnostics)
        : this(
            configuration,
            otpStore,
            new DefaultAgentSigningBackendFactory(diagnostics),
            () => new AgentPipeClient(),
            managementBridge ?? throw new ArgumentNullException(nameof(managementBridge)),
            diagnostics: diagnostics)
    {
    }

    public IAgentPipeSession Create(InteractiveSessionInfo session)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        ArgumentNullException.ThrowIfNull(session);
        var runtime = GetOrCreateRuntime(session);
        var client = _managedClient ?? _clients();
        if (_managementBridge is null)
        {
            return new OwnedAgentPipeSession(
                new AgentPipeSession(client, runtime.Worker));
        }

        var managementSession = new LiveAgentManagementSession(
            client,
            runtime.Cache!,
            _otpStore,
            _healthTimeProvider);
        return new OwnedAgentPipeSession(
            new AgentPipeSession(
                client,
                new PrepareSignJobCommandHandler((command, progress, cancellationToken) =>
                    managementSession.PrepareSigningPublicationAsync(
                        token => runtime.Worker.PreparePublicationAsync(command, progress, token),
                        cancellationToken)),
                runtime.Worker.Capabilities,
                runtime.Cache,
                runtime.StartupPreparation,
                managementSession),
            _managementBridge,
            managementSession,
            _managedLocalJobs);
    }

    public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();

    public ValueTask DisposeAsync()
    {
        Task disposeTask;
        TaskCompletionSource? completion = null;
        lock (_disposeSync)
        {
            if (_disposeTask is null)
            {
                completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                _disposeTask = completion.Task;
                Volatile.Write(ref _disposed, 1);
            }

            disposeTask = _disposeTask;
        }

        if (completion is not null)
        {
            _ = CompleteDisposeAsync(completion);
        }

        return new ValueTask(disposeTask);
    }

    private async Task CompleteDisposeAsync(TaskCompletionSource completion)
    {
        try
        {
            if (_managedLocalJobs is not null)
            {
                await _managedLocalJobs.DisposeAsync().ConfigureAwait(false);
            }

            SharedAgentRuntime? runtime;
            lock (_runtimeSync)
            {
                runtime = _runtime;
                _runtime = null;
            }

            runtime?.Dispose();

            completion.TrySetResult();
        }
        catch (Exception error)
        {
            completion.TrySetException(error);
        }
    }

    private SharedAgentRuntime GetOrCreateRuntime(InteractiveSessionInfo session)
    {
        lock (_runtimeSync)
        {
            if (_runtime is not null)
            {
                if (_runtime.SessionId != session.SessionId ||
                    !string.Equals(_runtime.UserSid, session.UserSid, StringComparison.Ordinal))
                {
                    throw new AgentConfigurationException("agent_configuration_invalid");
                }

                return _runtime;
            }

            var backends = _backends.Create(_configuration, session, _otpStore);
            try
            {
                var worker = new SigningWorker(
                    backends.AuthenticodeSigner,
                    backends.PdfSigner,
                    backends.Controller,
                    _configuration.SpoolPath);
                CapabilityProbeCache? cache = null;
                if (_managementBridge is not null)
                {
                    cache = new CapabilityProbeCache(
                        backends.Controller,
                        session.SessionId,
                        _configuration.Authenticode is not null,
                        _configuration.Pdf is not null,
                        _diagnostics,
                        backends.PdfToolResolver);
                }

                _runtime = new SharedAgentRuntime(
                    session.SessionId,
                    session.UserSid,
                    worker,
                    cache,
                    cache is null
                        ? null
                        : new AgentStartupPreparationCache(
                            (command, token) => _managementBridge!.PrepareStartupAsync(command, token),
                            _diagnostics),
                    cache is null || !_startHealthMonitor
                        ? null
                        : new SimplySignHealthMonitor(
                            backends.Controller,
                            _healthTimeProvider),
                    backends.Lifetime);
                return _runtime;
            }
            catch
            {
                backends.Lifetime.Dispose();
                throw;
            }
        }
    }

    private sealed class OwnedAgentPipeSession : IAgentPipeSession, IDisposable, IAsyncDisposable
    {
        private readonly IAgentPipeSession _inner;
        private readonly AgentManagementBridge? _managementBridge;
        private readonly IAgentManagementSession? _managementSession;
        private readonly ILocalJobClient? _localJobs;
        private readonly object _disposeSync = new();
        private Task? _disposeTask;

        public OwnedAgentPipeSession(
            IAgentPipeSession inner,
            AgentManagementBridge? managementBridge = null,
            IAgentManagementSession? managementSession = null,
            ILocalJobClient? localJobs = null)
        {
            _inner = inner;
            _managementBridge = managementBridge;
            _managementSession = managementSession;
            _localJobs = localJobs;
        }

        public Task CurrentJobCompletion => _inner.CurrentJobCompletion;

        public async Task RunAsync(
            InteractiveSessionInfo session,
            AgentReadiness readiness,
            CancellationToken cancellationToken)
        {
            using var lease = _managementBridge is not null && _managementSession is not null
                ? _managementBridge.Attach(_managementSession, _localJobs)
                : null;
            await _inner.RunAsync(session, readiness, cancellationToken).ConfigureAwait(false);
        }

        public void StopAcceptingNewJobs() => _inner.StopAcceptingNewJobs();

        public void Dispose() => DisposeAsync().AsTask().GetAwaiter().GetResult();

        public ValueTask DisposeAsync()
        {
            Task disposeTask;
            TaskCompletionSource? completion = null;
            lock (_disposeSync)
            {
                if (_disposeTask is null)
                {
                    completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                    _disposeTask = completion.Task;
                }

                disposeTask = _disposeTask;
            }

            if (completion is not null)
            {
                _ = CompleteDisposeAsync(completion);
            }

            return new ValueTask(disposeTask);
        }

        private async Task CompleteDisposeAsync(TaskCompletionSource completion)
        {
            try
            {
                switch (_managementSession)
                {
                    case IAsyncDisposable asyncDisposable:
                        await asyncDisposable.DisposeAsync().ConfigureAwait(false);
                        break;
                    case IDisposable disposable:
                        disposable.Dispose();
                        break;
                }

                completion.TrySetResult();
            }
            catch (Exception error)
            {
                completion.TrySetException(error);
            }
        }
    }

    private sealed class SharedAgentRuntime(
        int sessionId,
        string userSid,
        SigningWorker worker,
        CapabilityProbeCache? cache,
        AgentStartupPreparationCache? startupPreparation,
        SimplySignHealthMonitor? healthMonitor,
        IDisposable lifetime) : IDisposable
    {
        private IDisposable? _lifetime = lifetime;
        private SimplySignHealthMonitor? _healthMonitor = healthMonitor;

        public int SessionId { get; } = sessionId;
        public string UserSid { get; } = userSid;
        public SigningWorker Worker { get; } = worker;
        public CapabilityProbeCache? Cache { get; } = cache;
        public AgentStartupPreparationCache? StartupPreparation { get; } = startupPreparation;

        public void Dispose()
        {
            try
            {
                Interlocked.Exchange(ref _healthMonitor, null)?.Dispose();
            }
            finally
            {
                try
                {
                    StartupPreparation?.Dispose();
                }
                finally
                {
                    try
                    {
                        Cache?.Dispose();
                    }
                    finally
                    {
                        Interlocked.Exchange(ref _lifetime, null)?.Dispose();
                    }
                }
            }
        }
    }

}

internal sealed class DefaultAgentSigningBackendFactory : IAgentSigningBackendFactory
{
    private static readonly TimeSpan SigningTimeout = TimeSpan.FromMinutes(2);
    private readonly IAgentDiagnosticSink _diagnostics;

    public DefaultAgentSigningBackendFactory(IAgentDiagnosticSink? diagnostics = null) =>
        _diagnostics = diagnostics.Safe();

    public AgentSigningBackends Create(
        AgentConfiguration configuration,
        InteractiveSessionInfo session,
        IOtpStore otpStore)
    {
        configuration = AgentConfigurationLoader.Validate(configuration);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(otpStore);

        var runner = new ProcessRunner();
        var processSource = new WindowsSimplySignProcessSource();
        var programFilesRoot = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (!Path.IsPathFullyQualified(programFilesRoot))
        {
            throw new AgentConfigurationException("agent_configuration_invalid");
        }

        var productExecutable = ResolveProductExecutable(programFilesRoot);
        var otpDirectory = Path.GetDirectoryName(otpStore.Path)
            ?? throw new AgentConfigurationException("agent_configuration_invalid");
        var probe = new SimplySignProbe(
            runner,
            processSource,
            productExecutable,
            Path.Combine(otpDirectory, "probe"),
            session,
            _diagnostics);
        var catalog = new CertificateCatalog(
            probe,
            configuration.Pkcs11ModulePath,
            diagnostics: _diagnostics);
        var controller = new SimplySignController(
            probe,
            runner,
            processSource,
            otpStore,
            new SystemSimplySignClock(),
            session,
            configuration.SimplySignDesktopPath,
            _diagnostics);
        var operationGate = new SigningOperationGate();
        var manager = new SimplySignSessionManager(
            controller,
            operationGate,
            catalog);
        var lifetime = new SimplySignRuntimeLifetime(manager, operationGate, controller);

        try
        {
            IAuthenticodeSigner? authenticodeSigner = null;
            if (configuration.Authenticode is { } authenticode)
            {
                var profile = AuthenticodeSigningProfile.Create(
                    authenticode.SignToolPath,
                    authenticode.TimestampUrl);
                authenticodeSigner = new AuthenticodeSigner(
                    runner,
                    new WindowsAuthenticodeSignatureReader(),
                    profile,
                    configuration.SpoolPath,
                    new ControlledFileCopier(),
                    new AuthenticodeFileValidator(),
                    SigningTimeout);
            }

            IPdfSigner? pdfSigner = null;
            IInstalledPdfToolResolver? pdfToolResolver = null;
            if (configuration.Pdf is { } pdf)
            {
                var profile = PdfSigningProfile.Create(pdf.TimestampUrl);
                pdfToolResolver = CreatePdfToolResolver(
                    configuration,
                    programFilesRoot);
                pdfSigner = new PdfSigner(
                    runner,
                    profile,
                    configuration.SpoolPath,
                    SigningTimeout,
                    pdfToolResolver);
            }

            return new AgentSigningBackends(
                authenticodeSigner,
                pdfSigner,
                manager,
                lifetime,
                pdfToolResolver);
        }
        catch
        {
            lifetime.Dispose();
            throw;
        }
    }

    internal static string ResolveProductExecutable(string programFilesRoot)
    {
        if (string.IsNullOrWhiteSpace(programFilesRoot) ||
            !Path.IsPathFullyQualified(programFilesRoot))
        {
            throw new AgentConfigurationException("agent_configuration_invalid");
        }

        return Path.GetFullPath(Path.Combine(
            programFilesRoot,
            "CodeSignAuto",
            "CodeSignAuto.exe"));
    }

    internal static IInstalledPdfToolResolver CreatePdfToolResolver(
        AgentConfiguration configuration,
        string? programFilesRoot = null)
    {
        configuration = AgentConfigurationLoader.Validate(configuration);
        programFilesRoot ??= Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (!Path.IsPathFullyQualified(programFilesRoot))
        {
            throw new AgentConfigurationException("agent_configuration_invalid");
        }

        return new WindowsInstalledPdfToolResolver(programFilesRoot);
    }

    private sealed class SimplySignRuntimeLifetime(
        SimplySignSessionManager manager,
        SigningOperationGate operationGate,
        SimplySignController controller) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
            {
                return;
            }

            try
            {
                manager.Dispose();
            }
            finally
            {
                try
                {
                    operationGate.Dispose();
                }
                finally
                {
                    controller.Dispose();
                }
            }
        }
    }
}
