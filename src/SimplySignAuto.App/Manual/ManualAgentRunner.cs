using Microsoft.Extensions.Logging.Abstractions;
using SimplySignAuto.Agent;
using SimplySignAuto.Agent.Diagnostics;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.Agent.LocalJobs;
using SimplySignAuto.Agent.Security;
using SimplySignAuto.Agent.Sessions;
using SimplySignAuto.Agent.Signing;
using SimplySignAuto.Agent.SimplySign;
using SimplySignAuto.App.Commands;
using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Core.Security;
using SimplySignAuto.Service.Api;
using SimplySignAuto.Service.Jobs;

namespace SimplySignAuto.App.Manual;

internal sealed record ManualRuntimePaths(
    string DataRoot,
    string DatabasePath,
    string SpoolPath,
    string OtpPath)
{
    public static ManualRuntimePaths Default => ForDataRoot(Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SimplySignAuto",
        "manual"));

    public static ManualRuntimePaths ForDataRoot(string dataRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataRoot);
        var root = Path.GetFullPath(dataRoot);
        return new ManualRuntimePaths(
            root,
            Path.Combine(root, "jobs.db"),
            Path.Combine(root, "spool"),
            Path.Combine(root, "otp.dat"));
    }
}

internal sealed class ManualAgentConfigurationLoader : IAgentConfigurationLoader
{
    private readonly InstallationReceipt _receipt;
    private readonly ManualRuntimePaths _paths;
    private readonly Func<SetupPreflightResult> _inspectPrerequisites;

    public ManualAgentConfigurationLoader(
        InstallationReceipt receipt,
        ManualRuntimePaths paths,
        Func<SetupPreflightResult>? inspectPrerequisites = null)
    {
        _receipt = InstallationReceiptValidator.Validate(receipt);
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _inspectPrerequisites = inspectPrerequisites ??
            WindowsSetupPreflight.InspectSigningPrerequisites;
        if (_receipt.Mode != InstallationMode.Manual ||
            !string.Equals(_receipt.UserDataRoot, _paths.DataRoot, PathComparison()))
        {
            throw new AgentConfigurationException("installation_receipt_invalid");
        }
    }

    public Task<AgentConfiguration> LoadAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var prerequisites = _inspectPrerequisites();
            return Task.FromResult(AgentConfigurationLoader.Validate(new AgentConfiguration(
                _receipt.SigningUserSid,
                _paths.SpoolPath,
                prerequisites.SimplySignDesktopPath,
                prerequisites.Pkcs11ModulePath,
                prerequisites.SignToolPath is null
                    ? null
                    : new AgentAuthenticodeConfiguration(prerequisites.SignToolPath),
                new AgentPdfConfiguration())));
        }
        catch (SetupException error)
        {
            throw new AgentConfigurationException(error.Code, error);
        }
    }

    private static StringComparison PathComparison() =>
        OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
}

internal sealed class ManualAgentRunner :
    IAgentRunner,
    IDesktopAgentRunner,
    IDesktopManagementSource,
    IDesktopLocalJobSource
{
    public const int DefaultRetentionHours = 168;

    private readonly ManualRuntimePaths _paths;
    private readonly IOtpStore _otpStore;
    private readonly IAgentSigningBackendFactory _backends;
    private readonly Func<string, InteractiveSessionInfo> _sessionResolver;
    private readonly Func<string, ISpoolAclPolicy> _spoolAclPolicyFactory;
    private readonly ILocalLeaseProtector _leaseProtector;
    private readonly TimeProvider _timeProvider;
    private readonly IAgentDiagnosticSink _diagnostics;
    private readonly AgentManagementBridge _management;
    private readonly int _retentionHours;
    private readonly ManualSettingsStore? _settingsStore;
    private int _started;

    public ManualAgentRunner(TextWriter? diagnosticWriter = null)
        : this(ManualRuntimePaths.Default, new ManualSettingsStore(), diagnosticWriter)
    {
    }

    internal ManualAgentRunner(
        ManualRuntimePaths paths,
        ManualSettingsStore settingsStore,
        TextWriter? diagnosticWriter = null)
    {
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _settingsStore = settingsStore ?? throw new ArgumentNullException(nameof(settingsStore));
        _otpStore = new DpapiOtpStore(_paths.OtpPath);
        _diagnostics = new TextWriterAgentDiagnosticSink(diagnosticWriter ?? Console.Error).Safe();
        _backends = new DefaultAgentSigningBackendFactory(_diagnostics);
        _sessionResolver = expectedSid =>
            new InteractiveSessionGuard().ValidateCurrentProcess(expectedSid);
        _spoolAclPolicyFactory = signingUserSid => new WindowsSpoolAclPolicy(signingUserSid);
        _leaseProtector = new WindowsLocalLeaseProtector();
        _timeProvider = TimeProvider.System;
        _retentionHours = DefaultRetentionHours;
        _management = new AgentManagementBridge(
            otpStore: _otpStore,
            timeProvider: _timeProvider);
    }

    internal ManualAgentRunner(
        ManualRuntimePaths paths,
        IOtpStore otpStore,
        IAgentSigningBackendFactory backends,
        Func<string, InteractiveSessionInfo> sessionResolver,
        Func<string, ISpoolAclPolicy> spoolAclPolicyFactory,
        ILocalLeaseProtector leaseProtector,
        TimeProvider timeProvider,
        int retentionHours = DefaultRetentionHours,
        IAgentDiagnosticSink? diagnostics = null)
    {
        _paths = paths ?? throw new ArgumentNullException(nameof(paths));
        _otpStore = otpStore ?? throw new ArgumentNullException(nameof(otpStore));
        _backends = backends ?? throw new ArgumentNullException(nameof(backends));
        _sessionResolver = sessionResolver ?? throw new ArgumentNullException(nameof(sessionResolver));
        _spoolAclPolicyFactory = spoolAclPolicyFactory ??
            throw new ArgumentNullException(nameof(spoolAclPolicyFactory));
        _leaseProtector = leaseProtector ?? throw new ArgumentNullException(nameof(leaseProtector));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _ = new JobRetentionPolicy(retentionHours);
        _retentionHours = retentionHours;
        _settingsStore = null;
        _diagnostics = diagnostics.Safe();
        _management = new AgentManagementBridge(
            otpStore: _otpStore,
            timeProvider: _timeProvider);
    }

    public IAgentManagementClient Management => _management;

    public ILocalJobClient LocalJobs => _management;

    public Task RunAsync(
        AgentConfiguration configuration,
        CancellationToken cancellationToken) =>
        RunOnceAsync(configuration, cancellationToken);

    public async Task RunAsync(
        AgentConfiguration configuration,
        IAgentLifetime lifetime,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(lifetime);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken,
            lifetime.ShutdownRequested);
        await RunOnceAsync(configuration, linked.Token).ConfigureAwait(false);
    }

    private async Task RunOnceAsync(
        AgentConfiguration configuration,
        CancellationToken cancellationToken)
    {
        if (Interlocked.CompareExchange(ref _started, 1, 0) != 0)
        {
            throw new InvalidOperationException("manual_runner_already_started");
        }

        try
        {
            configuration = AgentConfigurationLoader.Validate(configuration);
            if (_settingsStore is not null)
            {
                await _settingsStore.LoadAsync(cancellationToken).ConfigureAwait(false);
            }

            EnsureRuntimePaths();
            var session = _sessionResolver(configuration.SigningUserSid);
            if (!string.Equals(
                    session.UserSid,
                    configuration.SigningUserSid,
                    StringComparison.Ordinal))
            {
                throw new AgentConfigurationException("agent_configuration_invalid");
            }

            var manualConfiguration = configuration with { SpoolPath = _paths.SpoolPath };
            var backends = _backends.Create(manualConfiguration, session, _otpStore);
            using var backendLifetime = backends.Lifetime;
            if (backends.PdfToolResolver is not null)
            {
                _ = await DefaultAgentRunner.ResolveOptionalPdfToolAtStartupAsync(
                        manualConfiguration,
                        backends.PdfToolResolver,
                        cancellationToken)
                    .ConfigureAwait(false);
            }

            var worker = new SigningWorker(
                backends.AuthenticodeSigner,
                backends.PdfSigner,
                backends.Controller,
                _paths.SpoolPath);
            using var cache = new CapabilityProbeCache(
                backends.Controller,
                session.SessionId,
                manualConfiguration.Authenticode is not null,
                manualConfiguration.Pdf is not null,
                _diagnostics,
                backends.PdfToolResolver);
            using var jobs = new SqliteJobStore(_paths.DatabasePath);
            var spool = new SpoolStore(
                _paths.SpoolPath,
                _spoolAclPolicyFactory(session.UserSid));
            var notifier = new JobCompletionNotifier(jobs);
            await using var transport = new InProcessSigningTransport(
                worker,
                session,
                worker.Capabilities,
                _timeProvider);
            using var dispatcher = new JobDispatcher(jobs, spool, transport, notifier);
            var localCoordinator = new LocalJobUploadCoordinator(
                jobs,
                spool,
                dispatcher,
                _timeProvider,
                session.UserSid,
                _leaseProtector,
                retentionHours: _retentionHours,
                retentionHoursProvider: _settingsStore is null
                    ? null
                    : () => _settingsStore.CurrentRetentionHours);
            var managementProvider = new ServiceManagementSnapshotProvider(jobs, _timeProvider);
            transport.Configure(localCoordinator, managementProvider);
            using var cleanup = new JobCleanupService(
                jobs,
                spool,
                notifier,
                _timeProvider,
                NullLogger<JobCleanupService>.Instance,
                localCoordinator);

            await jobs.RecoverManualInterruptedAsync(cancellationToken).ConfigureAwait(false);
            await cleanup.StartAsync(cancellationToken).ConfigureAwait(false);
            await cleanup.CleanupExpiredAsync(cancellationToken).ConfigureAwait(false);
            transport.Connect();

            await using var localJobs = new LocalJobClient(transport, _paths.SpoolPath);
            await using var managementSession = new LiveAgentManagementSession(
                transport,
                cache,
                _otpStore,
                _timeProvider);
            using var managementLease = _management.Attach(managementSession, localJobs);
            using var runtimeCancellation = new CancellationTokenSource();
            var dispatcherTask = dispatcher.RunAsync(runtimeCancellation.Token);
            try
            {
                await WaitForStopAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                await localJobs.DisposeAsync().ConfigureAwait(false);
                transport.StopAcceptingNewJobs();
                await transport.DrainAsync(CancellationToken.None).ConfigureAwait(false);
                await WaitForDispatchSettlementAsync(jobs, dispatcherTask).ConfigureAwait(false);

                runtimeCancellation.Cancel();
                await dispatcherTask.ConfigureAwait(false);
                await cleanup.StopAsync(CancellationToken.None).ConfigureAwait(false);
            }
        }
        finally
        {
            _management.Dispose();
        }
    }

    private void EnsureRuntimePaths()
    {
        EnsureDirectory(_paths.DataRoot);
        EnsureDirectory(_paths.SpoolPath);
        if (NoFollowFile.InspectPathEntry(_paths.DatabasePath) is not (
                NoFollowPathEntryKind.Missing or NoFollowPathEntryKind.RegularFile))
        {
            throw new AgentConfigurationException("agent_configuration_invalid");
        }

        if (!string.Equals(_otpStore.Path, _paths.OtpPath, PathComparison()))
        {
            throw new AgentConfigurationException("agent_configuration_invalid");
        }
    }

    private static void EnsureDirectory(string path)
    {
        var kind = NoFollowFile.InspectPathEntry(path);
        if (kind == NoFollowPathEntryKind.Missing)
        {
            Directory.CreateDirectory(path);
            kind = NoFollowFile.InspectPathEntry(path);
        }

        if (kind != NoFollowPathEntryKind.Directory)
        {
            throw new AgentConfigurationException("agent_configuration_invalid");
        }
    }

    private static async Task WaitForStopAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }

    private static async Task WaitForDispatchSettlementAsync(
        IJobStore jobs,
        Task dispatcherTask)
    {
        while (true)
        {
            if (dispatcherTask.IsCompleted)
            {
                await dispatcherTask.ConfigureAwait(false);
            }

            var queue = await jobs.GetQueueSnapshotAsync(CancellationToken.None).ConfigureAwait(false);
            if (queue.Active == 0)
            {
                return;
            }

            await Task.Delay(10).ConfigureAwait(false);
        }
    }

    private static StringComparison PathComparison() =>
        OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;
}
