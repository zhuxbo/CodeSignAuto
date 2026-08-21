using System.Collections.Concurrent;
using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.App.UI;
using SimplySignAuto.App.UI.Status;
using SimplySignAuto.App.UI.ViewModels;
using SimplySignAuto.Protocol;

namespace SimplySignAuto.UI.Tests;

public sealed class OverviewViewModelTests
{
    [Fact]
    public async Task Serialized_refresh_keeps_refreshing_true_and_newer_result_wins()
    {
        var client = new QueueManagementClient();
        var viewModel = new OverviewViewModel(client, new AlwaysConfirm(), () => { });
        var first = viewModel.RefreshAsync(default);
        await client.WaitForCallsAsync(1);
        var second = viewModel.RefreshAsync(default);
        Assert.True(viewModel.IsRefreshing);
        Assert.Equal(1, client.RefreshCalls);
        client.CompleteNext(Snapshot(Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), queued: 1));
        await client.WaitForCallsAsync(2);
        Assert.True(viewModel.IsRefreshing);
        client.CompleteNext(Snapshot(Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), queued: 2));

        await Task.WhenAll(first, second);

        Assert.False(viewModel.IsRefreshing);
        Assert.Equal(2, viewModel.Snapshot!.QueuedJobCount);
        Assert.Equal(Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), viewModel.Snapshot.ConnectionId);
    }

    [Fact]
    public async Task Cancellation_preserves_the_previous_complete_snapshot_and_status()
    {
        var prior = Snapshot(Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
        var client = new QueueManagementClient(prior);
        var viewModel = new OverviewViewModel(client, new AlwaysConfirm(), () => { });
        await viewModel.RefreshAsync(default);
        using var cancellation = new CancellationTokenSource();
        client.BlockNext = true;
        var refresh = viewModel.RefreshAsync(cancellation.Token);
        await client.WaitForCallsAsync(2);
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => refresh);

        Assert.Equal(prior, viewModel.Snapshot);
        Assert.Equal(OverallReadiness.Ready, viewModel.Status!.Overall);
        Assert.False(viewModel.IsRefreshing);
    }

    [Fact]
    public async Task Service_unavailable_exposes_only_stable_code_and_correlation()
    {
        var correlation = Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc");
        var client = new ThrowingManagementClient(new ManagementUnavailableException(correlation));
        var viewModel = new OverviewViewModel(client, new AlwaysConfirm(), () => { });

        await viewModel.RefreshAsync(default);

        Assert.Equal(OverallReadiness.ActionRequired, viewModel.Status!.Overall);
        Assert.Equal(["service_unavailable"], viewModel.Status.Reasons);
        Assert.Equal(correlation, viewModel.Status.CorrelationId);
        Assert.Null(viewModel.Snapshot);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(0)]
    public async Task Relogin_is_disabled_for_active_or_unknown_state_and_never_calls_controller(int mode)
    {
        var client = new QueueManagementClient();
        var viewModel = new OverviewViewModel(client, new AlwaysConfirm(), () => { });
        if (mode == 1)
        {
            client.Enqueue(Snapshot(
                Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
                active: 1,
                current: CurrentJob()));
            await viewModel.RefreshAsync(default);
        }

        var result = await viewModel.ReloginAsync(default);

        Assert.False(result);
        Assert.Equal(0, client.ReloginCalls);
    }

    [Fact]
    public async Task Login_refreshes_an_already_ready_session_without_relogin()
    {
        var initial = Snapshot(Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
        var refreshed = Snapshot(Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"));
        var client = new QueueManagementClient(initial, refreshed);
        var confirmation = new AlwaysConfirm();
        using var viewModel = new OverviewViewModel(client, confirmation, () => { });
        await viewModel.RefreshAsync(default);

        var result = await viewModel.LoginAsync(default);

        Assert.True(result);
        Assert.Equal(2, client.RefreshCalls);
        Assert.Equal(0, confirmation.Calls);
        Assert.Equal(0, client.ReloginCalls);
        Assert.Equal(refreshed, viewModel.Snapshot);
    }

    [Fact]
    public async Task Login_without_a_running_process_relogs_in_without_a_cleanup_confirmation()
    {
        var refreshed = LoginRequiredSnapshot(Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
        var after = Snapshot(Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"));
        var client = new QueueManagementClient(refreshed) { ReloginResult = after };
        var confirmation = new AlwaysConfirm();
        using var viewModel = new OverviewViewModel(client, confirmation, () => { });

        Assert.True(viewModel.LoginCommand.CanExecute(null));

        var result = await viewModel.LoginAsync(default);

        Assert.True(result);
        Assert.Equal(1, client.RefreshCalls);
        Assert.Equal(0, confirmation.Calls);
        Assert.Equal(1, client.ReloginCalls);
        Assert.Equal(after, viewModel.Snapshot);
        Assert.Equal("退出", viewModel.LoginButtonText);
    }

    [Fact]
    public async Task Login_cleans_a_current_session_residue_without_a_confirmation()
    {
        var initial = LoginRequiredSnapshot(
            Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            processSessionId: 7);
        var refreshed = LoginRequiredSnapshot(
            Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            processSessionId: 7);
        var after = Snapshot(Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc"));
        var client = new QueueManagementClient(initial, refreshed) { ReloginResult = after };
        var confirmation = new AlwaysConfirm();
        using var viewModel = new OverviewViewModel(client, confirmation, () => { });
        await viewModel.RefreshAsync(default);

        var result = await viewModel.LoginAsync(default);

        Assert.True(result);
        Assert.Equal(2, client.RefreshCalls);
        Assert.Equal(0, confirmation.Calls);
        Assert.Equal(1, client.ReloginCalls);
        Assert.Equal(after, viewModel.Snapshot);
    }

    [Fact]
    public async Task Login_confirms_before_cleaning_a_process_from_another_session()
    {
        var refreshed = LoginRequiredSnapshot(
            Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            processSessionId: 8);
        var after = Snapshot(Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"));
        var client = new QueueManagementClient(refreshed) { ReloginResult = after };
        var confirmation = new AlwaysConfirm();
        using var viewModel = new OverviewViewModel(client, confirmation, () => { });

        Assert.True(await viewModel.LoginAsync(default));

        Assert.Equal(1, confirmation.Calls);
        Assert.Equal(1, client.ReloginCalls);
    }

    [Fact]
    public async Task Ready_login_button_logs_out_without_deleting_the_saved_activation()
    {
        var ready = Snapshot(Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
        var loggedOut = LoginRequiredSnapshot(Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"));
        var client = new QueueManagementClient(ready) { LogoutResult = loggedOut };
        using var viewModel = new OverviewViewModel(client, new AlwaysConfirm(), () => { });
        await viewModel.RefreshAsync(default);

        Assert.True(viewModel.IsLoggedIn);
        Assert.Equal("退出", viewModel.LoginButtonText);
        viewModel.LoginCommand.Execute(null);
        await client.LogoutObserved.Task.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal(1, client.LogoutCalls);
        Assert.Equal(0, client.ReloginCalls);
        Assert.False(viewModel.IsLoggedIn);
        Assert.Equal("登录", viewModel.LoginButtonText);
    }

    [Fact]
    public async Task Current_session_process_uses_logout_even_when_signing_capability_is_unavailable()
    {
        var running = LoginRequiredSnapshot(
            Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            processSessionId: 7);
        var loggedOut = LoginRequiredSnapshot(Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"));
        var client = new QueueManagementClient(running) { LogoutResult = loggedOut };
        using var viewModel = new OverviewViewModel(client, new AlwaysConfirm(), () => { });
        await viewModel.RefreshAsync(default);

        Assert.False(viewModel.IsLoggedIn);
        Assert.Equal("退出", viewModel.LoginButtonText);
        viewModel.LoginCommand.Execute(null);
        await client.LogoutObserved.Task.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal(1, client.LogoutCalls);
        Assert.Equal(0, client.ReloginCalls);
        Assert.Equal("登录", viewModel.LoginButtonText);
    }

    [Fact]
    public async Task Confirmed_relogin_with_no_active_job_calls_management_once_and_applies_new_probe_snapshot()
    {
        var before = Snapshot(Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
        var after = Snapshot(Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"));
        var client = new QueueManagementClient(before) { ReloginResult = after };
        var confirmation = new AlwaysConfirm();
        var viewModel = new OverviewViewModel(client, confirmation, () => { });
        await viewModel.RefreshAsync(default);

        var result = await viewModel.ReloginAsync(default);

        Assert.True(result);
        Assert.Equal(1, confirmation.Calls);
        Assert.Equal(1, client.ReloginCalls);
        Assert.Equal(after, viewModel.Snapshot);
    }

    [Fact]
    public async Task Relogin_rechecks_idle_state_after_a_serialized_refresh_closes_the_race()
    {
        var idle = Snapshot(Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
        var client = new QueueManagementClient(idle);
        var confirmation = new AlwaysConfirm();
        using var viewModel = new OverviewViewModel(client, confirmation, () => { });
        await viewModel.RefreshAsync(default);
        client.BlockNext = true;
        var refresh = viewModel.RefreshAsync(default);
        await client.WaitForCallsAsync(2);

        var relogin = viewModel.ReloginAsync(default);
        await confirmation.WaitForCallsAsync(1);
        client.CompleteNext(Snapshot(
            Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
            active: 1,
            current: CurrentJob()));

        await refresh;
        Assert.False(await relogin);
        Assert.Equal(0, client.ReloginCalls);
        Assert.False(viewModel.CanRelogin);
    }

    [Fact]
    public async Task Relogin_management_loss_returns_false_and_exposes_only_stable_correlation()
    {
        var idle = Snapshot(Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
        var correlation = Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc");
        var client = new QueueManagementClient(idle)
        {
            ReloginError = new ManagementUnavailableException(correlation),
        };
        using var viewModel = new OverviewViewModel(client, new AlwaysConfirm(), () => { });
        await viewModel.RefreshAsync(default);

        var result = await viewModel.ReloginAsync(default);

        Assert.False(result);
        Assert.Null(viewModel.Snapshot);
        Assert.Equal(["service_unavailable"], viewModel.Status!.Reasons);
        Assert.Equal($"关联编号：{correlation:D}", viewModel.CorrelationText);
        Assert.True(viewModel.HasDiagnostics);
    }

    [Fact]
    public async Task Action_required_snapshot_has_deterministic_nonsecret_presentation()
    {
        var snapshot = ProblemSnapshot();
        var client = new QueueManagementClient(snapshot);
        using var viewModel = new OverviewViewModel(client, new AlwaysConfirm(), () => { });

        await viewModel.RefreshAsync(default);

        Assert.Equal("进程诊断：未运行", viewModel.SimplySignStatusText);
        Assert.Equal("×", viewModel.SimplySignStatusIcon);
        Assert.Equal("不可用", viewModel.AuthenticodeStatusText);
        Assert.Equal("×", viewModel.AuthenticodeStatusIcon);
        Assert.Equal("不可用", viewModel.PdfStatusText);
        Assert.Equal("×", viewModel.PdfStatusIcon);
        Assert.Equal("排队 3 · 执行中 1", viewModel.QueueStatusText);
        Assert.Equal("PDF 文档签名 · 正在验证 · 已运行 5 秒", viewModel.CurrentJobText);
        Assert.Equal(["SimplySign 未运行"], viewModel.ReasonMessages);
        Assert.True(viewModel.HasDiagnostics);
    }

    [Theory]
    [InlineData(null, true)]
    [InlineData("pdf_support_not_installed", false)]
    [InlineData("pdf_helper_tampered", true)]
    public async Task Pdf_card_is_visible_only_when_the_extension_is_installed_or_needs_repair(
        string? pdfFailureCode,
        bool expectedVisible)
    {
        var snapshot = Snapshot(
            Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            pdf: pdfFailureCode is null ? Ready() : PdfFailure(pdfFailureCode));
        var client = new QueueManagementClient(snapshot);
        using var viewModel = new OverviewViewModel(client, new AlwaysConfirm(), () => { });

        await viewModel.RefreshAsync(default);

        Assert.Equal(expectedVisible, viewModel.PdfExtensionVisible);
    }

    [Fact]
    public void Open_jobs_command_uses_the_existing_shell_navigation_callback()
    {
        var opened = 0;
        var viewModel = new OverviewViewModel(
            new QueueManagementClient(),
            new AlwaysConfirm(),
            () => opened++);

        viewModel.OpenJobsCommand.Execute(null);

        Assert.Equal(1, opened);
    }

    [Fact]
    public async Task Worker_refresh_completion_updates_every_observable_property_inside_the_ui_dispatcher()
    {
        var dispatcher = new GuardedDispatcher();
        var client = new QueueManagementClient { BlockNext = true };
        using var viewModel = new OverviewViewModel(
            client,
            new AlwaysConfirm(),
            () => { },
            dispatcher);
        var mutationContexts = new List<bool>();
        viewModel.PropertyChanged += (_, _) => mutationContexts.Add(dispatcher.IsDispatching);
        var refresh = viewModel.RefreshAsync(default);
        await client.WaitForCallsAsync(1);

        await Task.Run(() => client.CompleteNext(
            Snapshot(Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), queued: 2)));
        await refresh.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.NotEmpty(mutationContexts);
        Assert.All(mutationContexts, Assert.True);
        Assert.True(dispatcher.Calls > 0);
    }

    [Fact]
    public async Task Disposed_overview_ignores_worker_completion_without_touching_a_dead_dispatcher()
    {
        var dispatcher = new GuardedDispatcher();
        var client = new QueueManagementClient { BlockNext = true };
        var viewModel = new OverviewViewModel(
            client,
            new AlwaysConfirm(),
            () => { },
            dispatcher);
        var refresh = viewModel.RefreshAsync(default);
        await client.WaitForCallsAsync(1);
        viewModel.Dispose();
        dispatcher.MarkDead();

        await Task.Run(() => client.CompleteNext(
            Snapshot(Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))));
        await refresh.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal(0, dispatcher.CallsAfterDead);
    }

    private static CurrentJobSnapshot CurrentJob() =>
        new(
            Guid.Parse("dddddddd-dddd-dddd-dddd-dddddddddddd"),
            "authenticode",
            "signing",
            "signing",
            new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero),
            5);

    private static ManagementSnapshot Snapshot(
        Guid connectionId,
        int queued = 0,
        int active = 0,
        CurrentJobSnapshot? current = null,
        CapabilitySnapshot? pdf = null) =>
        new(
            ManagementSnapshot.CurrentVersion,
            new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero),
            connectionId,
            true,
            true,
            7,
            7,
            1_000,
            true,
            7,
            Ready(),
            pdf ?? Ready(),
            queued,
            active,
            current,
            [],
            1,
            [Summary("Universal", "52A1B4C9", true, true)]);

    private static ManagementSnapshot ProblemSnapshot()
    {
        var notConfigured = new CapabilitySnapshot(
            false, false, false, null, false, false, null,
            false, false, null, false, "not_configured");
        var tokenMissing = ProtocolV3TestFixtures.TokenMissing();
        var now = new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero);
        return new ManagementSnapshot(
            ManagementSnapshot.CurrentVersion,
            now,
            Guid.Parse("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"),
            true,
            true,
            7,
            7,
            1_000,
            false,
            null,
            notConfigured,
            tokenMissing,
            3,
            1,
            new CurrentJobSnapshot(
                Guid.Parse("dddddddd-dddd-dddd-dddd-dddddddddddd"),
                "pdf",
                "verifying",
                "verifying",
                now.AddSeconds(-5),
                5),
            [],
            1,
            []);
    }

    private static ManagementSnapshot LoginRequiredSnapshot(
        Guid connectionId,
        int? processSessionId = null)
    {
        var now = new DateTimeOffset(2026, 8, 8, 0, 0, 0, TimeSpan.Zero);
        return new ManagementSnapshot(
            ManagementSnapshot.CurrentVersion,
            now,
            connectionId,
            true,
            true,
            7,
            7,
            1_000,
            processSessionId is not null,
            processSessionId,
            CapabilitySnapshot.NotConfigured(),
            CapabilitySnapshot.NotConfigured(),
            0,
            0,
            null,
            [],
            1,
            []);
    }

    private static CertificateSummary Summary(
        string commonName,
        string serial,
        bool authenticode,
        bool pdf) =>
        new(
            commonName,
            serial,
            DateTimeOffset.Parse("2025-01-01T00:00:00Z"),
            DateTimeOffset.Parse("2027-01-01T00:00:00Z"),
            authenticode,
            pdf,
            true,
            null);

    private static CapabilitySnapshot Ready() =>
        ProtocolV3TestFixtures.Ready();

    private static CapabilitySnapshot PdfFailure(string reasonCode)
    {
        var ready = Ready();
        return new CapabilitySnapshot(
            ready.Configured,
            ready.TokenPresent,
            ready.TokenMatches,
            ready.TokenSuffix,
            ready.CertificatePresent,
            ready.CertificateMatches,
            ready.CertificateSuffix,
            ready.PrivateKeyPresent,
            ready.PrivateKeyMatches,
            ready.PrivateKeySuffix,
            ready: false,
            reasonCode,
            ready.CertificateNotAfterUtc,
            ready.CertificateThumbprintSuffix,
            ready.Session);
    }

    private sealed class AlwaysConfirm : IReloginConfirmation
    {
        public int Calls { get; private set; }

        public Task<bool> ConfirmAsync(CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(true);
        }

        public async Task WaitForCallsAsync(int expected)
        {
            for (var attempt = 0; attempt < 1_000 && Calls < expected; attempt++)
            {
                await Task.Yield();
            }

            Assert.Equal(expected, Calls);
        }
    }

    private sealed class ThrowingManagementClient(Exception error) : IAgentManagementClient
    {
        public event EventHandler? SnapshotChanged { add { } remove { } }
        public ManagementSnapshot? LatestSnapshot => null;
        public Task<ManagementSnapshot> RefreshAsync(CancellationToken cancellationToken) =>
            Task.FromException<ManagementSnapshot>(error);
        public Task<ManagementSnapshot> ReloginAsync(CancellationToken cancellationToken) =>
            Task.FromException<ManagementSnapshot>(error);
    }

    private sealed class QueueManagementClient : IAgentManagementClient
    {
        private readonly ConcurrentQueue<ManagementSnapshot> _queued = [];
        private readonly ConcurrentQueue<TaskCompletionSource<ManagementSnapshot>> _pending = [];
        private int _refreshCalls;

        public QueueManagementClient(params ManagementSnapshot[] snapshots)
        {
            foreach (var snapshot in snapshots)
            {
                _queued.Enqueue(snapshot);
            }
        }

        public event EventHandler? SnapshotChanged;
        public ManagementSnapshot? LatestSnapshot { get; private set; }
        public int RefreshCalls => Volatile.Read(ref _refreshCalls);
        public int ReloginCalls { get; private set; }
        public int LogoutCalls { get; private set; }
        public bool BlockNext { get; set; }
        public ManagementSnapshot? ReloginResult { get; set; }
        public ManagementSnapshot? LogoutResult { get; set; }
        public Exception? ReloginError { get; set; }
        public TaskCompletionSource LogoutObserved { get; } = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<ManagementSnapshot> RefreshAsync(CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _refreshCalls);
            if (!BlockNext && _queued.TryDequeue(out var queued))
            {
                LatestSnapshot = queued;
                SnapshotChanged?.Invoke(this, EventArgs.Empty);
                return Task.FromResult(queued);
            }

            var completion = new TaskCompletionSource<ManagementSnapshot>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            _pending.Enqueue(completion);
            return completion.Task.WaitAsync(cancellationToken);
        }

        public Task<ManagementSnapshot> ReloginAsync(CancellationToken cancellationToken)
        {
            ReloginCalls++;
            if (ReloginError is not null)
            {
                return Task.FromException<ManagementSnapshot>(ReloginError);
            }

            return Task.FromResult(ReloginResult ?? throw new InvalidOperationException("No relogin result."));
        }

        public Task<ManagementSnapshot> LogoutAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LogoutCalls++;
            LatestSnapshot = LogoutResult ?? throw new InvalidOperationException("No logout result.");
            SnapshotChanged?.Invoke(this, EventArgs.Empty);
            LogoutObserved.TrySetResult();
            return Task.FromResult(LatestSnapshot);
        }

        public void Enqueue(ManagementSnapshot snapshot) => _queued.Enqueue(snapshot);

        public void CompleteNext(ManagementSnapshot snapshot)
        {
            Assert.True(_pending.TryDequeue(out var completion));
            completion.TrySetResult(snapshot);
        }

        public async Task WaitForCallsAsync(int expected)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (RefreshCalls < expected)
            {
                await Task.Delay(1, timeout.Token);
            }

            Assert.Equal(expected, RefreshCalls);
        }
    }

    private sealed class GuardedDispatcher : IUiDispatcher
    {
        private readonly AsyncLocal<int> _depth = new();
        private int _dead;

        public bool IsDispatching => _depth.Value > 0;
        public int Calls { get; private set; }
        public int CallsAfterDead { get; private set; }

        public Task InvokeAsync(Action action, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(action);
            cancellationToken.ThrowIfCancellationRequested();
            if (Volatile.Read(ref _dead) != 0)
            {
                CallsAfterDead++;
                throw new ObjectDisposedException(nameof(GuardedDispatcher));
            }

            Calls++;
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
