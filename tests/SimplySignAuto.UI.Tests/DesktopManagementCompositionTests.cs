using SimplySignAuto.Agent;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.Agent.LocalJobs;
using SimplySignAuto.App.Commands;
using SimplySignAuto.App.UI;
using SimplySignAuto.App.UI.Status;
using SimplySignAuto.Core.Jobs;
using SimplySignAuto.Core.Otp;
using SimplySignAuto.Protocol;

namespace SimplySignAuto.UI.Tests;

public sealed class DesktopManagementCompositionTests
{
    [Fact]
    public void Default_runner_exposes_the_production_management_bridge()
    {
        var runner = new DefaultAgentRunner();

        var source = Assert.IsAssignableFrom<IDesktopManagementSource>(runner);

        Assert.IsType<AgentManagementBridge>(source.Management);
    }

    [Fact]
    public async Task Local_login_value_provider_reads_the_current_user_store_only_when_requested()
    {
        var profile = new OtpauthProfile(
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
            "SHA256",
            6,
            30,
            "Certum",
            "operator@example.test");
        var store = new StoredOtpStore(profile);
        var now = DateTimeOffset.FromUnixTimeSeconds(59);
        using var bridge = new AgentManagementBridge(
            otpStore: store,
            timeProvider: new FixedTimeProvider(now));
        var provider = Assert.IsAssignableFrom<ILocalTotpCodeProvider>(bridge);

        Assert.Equal(0, store.LoadCalls);
        var current = await provider.GenerateCurrentAsync(default);

        Assert.Equal(1, store.LoadCalls);
        Assert.Equal(6, current.Code.Length);
        Assert.All(current.Code, digit => Assert.InRange(digit, '0', '9'));
        Assert.Equal(1, current.RemainingSeconds);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(60), current.ExpiresAtUtc);
        Assert.Equal(string.Empty, current.ToString());
    }

    [Fact]
    public void Default_runner_exposes_the_same_production_bridge_for_management_and_local_jobs()
    {
        var runner = new DefaultAgentRunner();

        var management = Assert.IsAssignableFrom<IDesktopManagementSource>(runner);
        var local = Assert.IsAssignableFrom<IDesktopLocalJobSource>(runner);

        Assert.Same(management.Management, local.LocalJobs);
        Assert.IsType<AgentManagementBridge>(local.LocalJobs);
    }

    [Fact]
    public void Production_shell_replaces_quick_sign_placeholder_with_the_same_runner_local_client()
    {
        using var fixture = new ConfigurationFixture();
        var bridge = new AgentManagementBridge();
        var runner = new LocalManagementRunner(bridge);
        using var shell = DesktopShellComposition.Create(
            runner,
            new FixedActiveJobStateSource(ActiveJobState.None),
            new RecordingWindow(),
            new RecordingLifetime(),
            InlineTestDispatcher.Instance,
            fixture.Configuration);

        Assert.NotNull(shell.QuickSign);
        Assert.Same(shell.QuickSign, shell.Pages[1].Content);
    }

    [Fact]
    public void Production_shell_replaces_all_management_placeholders_with_the_same_runner_bridge_and_local_client()
    {
        using var fixture = new ConfigurationFixture();
        var bridge = new AgentManagementBridge(otpStore: new MemoryOtpStore());
        var runner = new LocalManagementRunner(bridge);
        using var shell = DesktopShellComposition.Create(
            runner,
            new FixedActiveJobStateSource(ActiveJobState.None),
            new RecordingWindow(),
            new RecordingLifetime(),
            InlineTestDispatcher.Instance,
            fixture.Configuration);

        Assert.Same(shell.Jobs, shell.Pages[2].Content);
        Assert.Same(shell.Activation, shell.Pages[3].Content);
        Assert.Same(shell.ServiceSettings, shell.Pages[4].Content);
        Assert.Same(bridge, shell.Jobs!.AdministrationClient);
        Assert.Same(bridge, shell.Jobs.LocalJobClient);
        Assert.Same(bridge, shell.Activation!.ManagementClient);
        Assert.Same(bridge, shell.Activation.AdministrationClient);
        Assert.Same(bridge, shell.ServiceSettings!.AdministrationClient);
        Assert.Same(InlineTestDispatcher.Instance, shell.Jobs.Dispatcher);
        Assert.Same(InlineTestDispatcher.Instance, shell.Activation.Dispatcher);
        Assert.Same(InlineTestDispatcher.Instance, shell.ServiceSettings.Dispatcher);
    }

    [Fact]
    public async Task Admin_shell_uses_one_snapshot_for_overview_and_tray_but_exit_is_detached()
    {
        var client = new MutableManagementClient(Snapshot(active: 1));
        var runner = new ManagementRunner(client);
        var window = new RecordingWindow();
        var lifetime = new RecordingLifetime();
        using var shell = DesktopShellComposition.Create(
            runner,
            new FixedActiveJobStateSource(ActiveJobState.None),
            window,
            lifetime);
        var platform = new RecordingTrayPlatform();
        using var tray = new TrayIconController(platform, shell, window);

        Assert.NotNull(shell.Overview);
        Assert.Same(shell.Overview, shell.Pages[0].Content);
        Assert.Equal("签名服务已就绪", shell.OverallStatusText);
        Assert.Equal("✓ 签名服务已就绪", platform.StatusText);
        Assert.Equal(
            ExitRequestResult.Exiting,
            await shell.RequestExitAsync(CancellationToken.None));
        Assert.Equal(0, lifetime.StopCalls);

        client.Publish(Snapshot(active: 0, authenticodeReady: false));

        Assert.Equal("部分签名能力可用", shell.OverallStatusText);
        Assert.Equal("! 部分签名能力可用", platform.StatusText);
        await tray.HandleCommandAsync(TrayCommand.Recheck, CancellationToken.None);
        Assert.Equal(1, client.RefreshCalls);
        await tray.HandleCommandAsync(TrayCommand.OpenRecentJobs, CancellationToken.None);
        Assert.Equal("签名任务", shell.CurrentPage.Title);

        client.FailRefresh = true;
        await tray.HandleCommandAsync(TrayCommand.Recheck, CancellationToken.None);

        Assert.Equal("需要处理", shell.OverallStatusText);
        Assert.Equal(ExitRequestResult.Exiting, await shell.RequestExitAsync(CancellationToken.None));
        Assert.Equal(0, lifetime.StopCalls);
    }

    [Fact]
    public async Task Admin_console_exit_does_not_refresh_login_or_stop_background_agent()
    {
        var client = new InitialUnknownManagementClient(Snapshot(active: 0, authenticodeReady: false));
        var window = new RecordingWindow();
        var lifetime = new RecordingLifetime();
        using var shell = DesktopShellComposition.Create(
            new ManagementRunner(client),
            new FixedActiveJobStateSource(ActiveJobState.Unknown),
            window,
            lifetime);

        var result = await shell.RequestExitAsync(CancellationToken.None);

        Assert.Equal(ExitRequestResult.Exiting, result);
        Assert.Equal(0, client.RefreshCalls);
        Assert.Equal(0, client.ReloginCalls);
        Assert.Equal(0, lifetime.StopCalls);
    }

    [Fact]
    public async Task Manual_exit_refuses_an_accepted_local_job_after_selecting_another_file_with_stale_snapshot()
    {
        using var fixture = new ConfigurationFixture();
        var management = new MutableManagementClient(Snapshot(active: 0));
        var localJobs = new ImmediateLocalJobClient();
        var window = new RecordingWindow();
        var lifetime = new RecordingLifetime();
        using var shell = DesktopShellComposition.Create(
            new LocalSourceRunner(management, localJobs),
            new FixedActiveJobStateSource(ActiveJobState.None),
            window,
            lifetime,
            InlineTestDispatcher.Instance,
            fixture.Configuration,
            InstallationMode.Manual,
            manualSettings: null);
        await shell.QuickSign!.SelectFileAsync(fixture.WriteSource());
        Assert.Equal(localJobs.JobId, await shell.QuickSign.SubmitAsync(default));
        await shell.QuickSign.SelectFileAsync(fixture.WriteSource("replacement.exe"));
        Assert.Null(shell.QuickSign.AcceptedJobId);

        var result = await shell.RequestExitAsync(default);

        Assert.Equal(ExitRequestResult.Refused, result);
        Assert.Equal(0, management.RefreshCalls);
        Assert.Equal(0, lifetime.StopCalls);
        Assert.Equal("签名任务正在进行，完成后才能退出程序。", window.LastNotice);
    }

    [Fact]
    public async Task Worker_snapshot_marshals_shell_and_tray_status_and_disposal_prevents_dead_dispatcher_access()
    {
        var dispatcher = new GuardedDispatcher();
        var client = new MutableManagementClient(Snapshot(active: 0));
        var window = new RecordingWindow();
        var shell = DesktopShellComposition.Create(
            new ManagementRunner(client),
            new FixedActiveJobStateSource(ActiveJobState.None),
            window,
            new RecordingLifetime(),
            dispatcher);
        var platform = new RecordingTrayPlatform(dispatcher);
        var tray = new TrayIconController(platform, shell, window, dispatcher);
        var shellMutationContexts = new List<bool>();
        shell.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName is nameof(ShellViewModel.OverallStatusText)
                or nameof(ShellViewModel.OverallStatusIcon))
            {
                shellMutationContexts.Add(dispatcher.IsDispatching);
            }
        };

        await Task.Run(() => client.Publish(Snapshot(active: 0, authenticodeReady: false)));

        Assert.NotEmpty(shellMutationContexts);
        Assert.All(shellMutationContexts, Assert.True);
        Assert.NotEmpty(platform.SetStatusContexts);
        Assert.All(platform.SetStatusContexts, Assert.True);
        tray.Dispose();
        shell.Dispose();
        dispatcher.MarkDead();
        await Task.Run(() => client.Publish(Snapshot(active: 0)));
        Assert.Equal(0, dispatcher.CallsAfterDead);
    }

    private static ManagementSnapshot Snapshot(int active, bool authenticodeReady = true) =>
        new(
            ManagementSnapshot.CurrentVersion,
            new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero),
            Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            true,
            true,
            7,
            7,
            1_000,
            true,
            7,
            authenticodeReady ? Ready() : NotReady(),
            Ready(),
            0,
            active,
            active == 0
                ? null
                : new CurrentJobSnapshot(
                    Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
                    "authenticode",
                    "signing",
                    "signing",
                    new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero),
                    2),
            [],
            1,
            [
                new CertificateSummary(
                    "Synthetic", "52A1B4C9",
                    DateTimeOffset.Parse("2025-01-01T00:00:00Z"),
                    DateTimeOffset.Parse("2027-01-01T00:00:00Z"),
                    authenticodeReady, true, true, null),
            ]);

    private static CapabilitySnapshot Ready() =>
        ProtocolV3TestFixtures.Ready();

    private static CapabilitySnapshot NotReady() =>
        ProtocolV3TestFixtures.TokenMissing();

    private sealed class ManagementRunner(IAgentManagementClient management) :
        IAgentRunner,
        IDesktopManagementSource
    {
        public IAgentManagementClient Management { get; } = management;

        public Task RunAsync(AgentConfiguration configuration, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class LocalManagementRunner(AgentManagementBridge bridge) :
        IAgentRunner,
        IDesktopManagementSource,
        IDesktopLocalJobSource
    {
        public IAgentManagementClient Management => bridge;

        public ILocalJobClient LocalJobs => bridge;

        public Task RunAsync(AgentConfiguration configuration, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class LocalSourceRunner(
        IAgentManagementClient management,
        ILocalJobClient localJobs) :
        IAgentRunner,
        IDesktopManagementSource,
        IDesktopLocalJobSource
    {
        public IAgentManagementClient Management { get; } = management;

        public ILocalJobClient LocalJobs { get; } = localJobs;

        public Task RunAsync(AgentConfiguration configuration, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class ConfigurationFixture : IDisposable
    {
        private readonly string _root = Path.Combine(Path.GetTempPath(), "SimplySignAuto.Tests", Guid.NewGuid().ToString("N"));

        public ConfigurationFixture()
        {
            Configuration = new AgentConfiguration(
                "S-1-5-21-1000-2000-3000-4000",
                Path.Combine(_root, "spool"),
                Path.Combine(_root, "SimplySignDesktop.exe"),
                Path.Combine(_root, "pkcs11.dll"),
                new AgentAuthenticodeConfiguration(Path.Combine(_root, "signtool.exe")),
                null);
        }

        public AgentConfiguration Configuration { get; }

        public string WriteSource(string fileName = "source.exe")
        {
            Directory.CreateDirectory(_root);
            var path = Path.Combine(_root, fileName);
            File.WriteAllBytes(path, "MZ-manual-exit"u8.ToArray());
            return path;
        }

        public void Dispose()
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
    }

    private sealed class InlineTestDispatcher : IUiDispatcher
    {
        public static InlineTestDispatcher Instance { get; } = new();

        public Task InvokeAsync(Action action, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            action();
            return Task.CompletedTask;
        }
    }

    private sealed class MemoryOtpStore : SimplySignAuto.Agent.Security.IOtpStore
    {
        public string Path => "memory";

        public Task SaveAsync(SimplySignAuto.Core.Otp.OtpauthProfile profile, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<SimplySignAuto.Core.Otp.OtpauthProfile> LoadAsync(CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    private sealed class StoredOtpStore(OtpauthProfile profile) : SimplySignAuto.Agent.Security.IOtpStore
    {
        public string Path => "memory";
        public int LoadCalls { get; private set; }

        public Task SaveAsync(OtpauthProfile value, CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task<OtpauthProfile> LoadAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LoadCalls++;
            return Task.FromResult(profile);
        }
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class MutableManagementClient(ManagementSnapshot snapshot) : IAgentManagementClient
    {
        public event EventHandler? SnapshotChanged;

        public ManagementSnapshot? LatestSnapshot { get; private set; } = snapshot;

        public int RefreshCalls { get; private set; }

        public bool FailRefresh { get; set; }

        public Task<ManagementSnapshot> RefreshAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RefreshCalls++;
            if (FailRefresh)
            {
                throw new ManagementUnavailableException(
                    Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc"));
            }

            return Task.FromResult(LatestSnapshot!);
        }

        public Task<ManagementSnapshot> ReloginAsync(CancellationToken cancellationToken) =>
            RefreshAsync(cancellationToken);

        public void Publish(ManagementSnapshot value)
        {
            LatestSnapshot = value;
            SnapshotChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    private sealed class InitialUnknownManagementClient(ManagementSnapshot refreshSnapshot) : IAgentManagementClient
    {
        public event EventHandler? SnapshotChanged;

        public ManagementSnapshot? LatestSnapshot { get; private set; }

        public int RefreshCalls { get; private set; }

        public int ReloginCalls { get; private set; }

        public Task<ManagementSnapshot> RefreshAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RefreshCalls++;
            LatestSnapshot = refreshSnapshot;
            SnapshotChanged?.Invoke(this, EventArgs.Empty);
            return Task.FromResult(refreshSnapshot);
        }

        public Task<ManagementSnapshot> ReloginAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ReloginCalls++;
            return Task.FromResult(refreshSnapshot);
        }
    }

    private sealed class FixedActiveJobStateSource(ActiveJobState state) : IActiveJobStateSource
    {
        public ActiveJobState Current => state;
    }

    private sealed class RecordingLifetime : IDesktopAgentLifetime
    {
        public int StopCalls { get; private set; }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            StopCalls++;
            return Task.CompletedTask;
        }
    }

    private sealed class RecordingWindow : IWindowController
    {
        public string? LastNotice { get; private set; }

        public void ShowRestoreActivate() { }
        public void Hide() { }
        public void CloseForExit() { }
        public void ShowNotice(string message) => LastNotice = message;
    }

    private sealed class ImmediateLocalJobClient : ILocalJobClient
    {
        public Guid JobId { get; } = Guid.Parse("dddddddd-dddd-dddd-dddd-dddddddddddd");

        public Task<Guid> CreateAndUploadAsync(
            string path,
            SigningParameters parameters,
            IProgress<LocalCopyProgress>? progress,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(JobId);
        }

        public Task SaveSignedCopyAsync(
            Guid jobId,
            string destinationPath,
            bool overwrite,
            CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public void ReleaseAcceptedSource(Guid jobId) { }
    }

    private sealed class RecordingTrayPlatform(GuardedDispatcher? dispatcher = null) : ITrayIconPlatform
    {
        public event EventHandler<TrayCommandEventArgs>? CommandInvoked { add { } remove { } }

        public string? StatusText { get; private set; }
        public List<bool> SetStatusContexts { get; } = [];

        public void Initialize(IReadOnlyList<TrayMenuEntry> entries, string statusText) =>
            StatusText = statusText;

        public void SetStatus(string statusText)
        {
            SetStatusContexts.Add(dispatcher?.IsDispatching ?? true);
            StatusText = statusText;
        }

        public void Dispose() { }
    }

    private sealed class GuardedDispatcher : IUiDispatcher
    {
        private readonly AsyncLocal<int> _depth = new();
        private int _dead;

        public bool IsDispatching => _depth.Value > 0;
        public int CallsAfterDead { get; private set; }

        public Task InvokeAsync(Action action, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Volatile.Read(ref _dead) != 0)
            {
                CallsAfterDead++;
                throw new ObjectDisposedException(nameof(GuardedDispatcher));
            }

            _depth.Value++;
            try
            {
                action();
            }
            finally
            {
                _depth.Value--;
            }

            return Task.CompletedTask;
        }

        public void MarkDead() => Volatile.Write(ref _dead, 1);
    }
}
