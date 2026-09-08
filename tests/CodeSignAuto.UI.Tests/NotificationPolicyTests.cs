using CodeSignAuto.Agent;
using CodeSignAuto.Agent.Ipc;
using CodeSignAuto.Agent.LocalJobs;
using CodeSignAuto.App.Commands;
using CodeSignAuto.App.UI;
using CodeSignAuto.App.UI.Status;
using CodeSignAuto.App.UI.ViewModels;
using CodeSignAuto.Core.Jobs;
using CodeSignAuto.Protocol;
using Xunit;

namespace CodeSignAuto.UI.Tests;

public sealed class NotificationPolicyTests
{
    [Fact]
    public void Initial_unavailable_partial_and_initial_terminal_jobs_establish_a_silent_baseline()
    {
        var policy = new NotificationPolicy();
        var initial = Job("local", "failed", "pdf_sign_failed", 1);

        var notifications = policy.Evaluate(
            null,
            Status(OverallReadiness.ActionRequired, "service_unavailable"),
            [Event(1, initial)]);
        var partial = policy.Evaluate(
            Status(OverallReadiness.ActionRequired, "service_unavailable"),
            Status(OverallReadiness.Partial),
            [Event(1, initial)]);

        Assert.Empty(notifications);
        Assert.Empty(partial);
    }

    [Fact]
    public void Ready_to_unavailable_is_deduplicated_for_thirty_minutes_and_clock_rollback_fails_closed()
    {
        var time = new MutableTimeProvider(new DateTimeOffset(2026, 8, 9, 0, 0, 0, TimeSpan.Zero));
        var policy = new NotificationPolicy(time);
        var ready = Status(OverallReadiness.Ready);
        var unavailable = Status(OverallReadiness.ActionRequired, "service_unavailable");

        Assert.Single(policy.Evaluate(ready, unavailable, null));
        time.Advance(TimeSpan.FromMinutes(29));
        Assert.Empty(policy.Evaluate(ready, unavailable, null));
        time.Advance(TimeSpan.FromMinutes(1));
        Assert.Single(policy.Evaluate(ready, unavailable, null));
        time.Set(new DateTimeOffset(2026, 8, 8, 23, 59, 0, TimeSpan.Zero));
        Assert.Empty(policy.Evaluate(ready, unavailable, null));
    }

    [Fact]
    public void Recovery_to_ready_clears_unavailable_suppression_immediately()
    {
        var time = new MutableTimeProvider(new DateTimeOffset(2026, 8, 9, 0, 0, 0, TimeSpan.Zero));
        var policy = new NotificationPolicy(time);
        var ready = Status(OverallReadiness.Ready);
        var unavailable = Status(OverallReadiness.ActionRequired, "agent_unavailable");

        Assert.Single(policy.Evaluate(ready, unavailable, null));
        Assert.Empty(policy.Evaluate(unavailable, ready, null));
        time.Advance(TimeSpan.FromSeconds(1));

        Assert.Single(policy.Evaluate(ready, unavailable, null));
    }

    [Fact]
    public void Only_local_success_and_any_failure_notify_once_without_original_name()
    {
        var policy = new NotificationPolicy();
        policy.Evaluate(null, Status(OverallReadiness.Ready), []);
        var localSuccess = Job("local", "succeeded", null, 2);
        var apiSuccess = Job("api", "succeeded", null, 3);
        var apiFailure = Job("api", "failed", "pdf_sign_failed", 4);
        var expired = Job("local", "expired", "job_expired", 5);

        var first = policy.Evaluate(
            Status(OverallReadiness.Ready),
            Status(OverallReadiness.Ready),
            [Event(2, localSuccess), Event(3, apiSuccess), Event(4, apiFailure), Event(5, expired)]);
        var replay = policy.Evaluate(
            Status(OverallReadiness.Ready),
            Status(OverallReadiness.Ready),
            [Event(4, apiFailure), Event(2, localSuccess)]);

        Assert.Equal(2, first.Count);
        Assert.Contains(first, item => item.Kind == TrayNotificationKind.LocalJobSucceeded);
        Assert.Contains(first, item => item.Kind == TrayNotificationKind.JobFailed);
        Assert.All(first, item => Assert.DoesNotContain("secret-input.pdf", item.Message, StringComparison.Ordinal));
        Assert.Empty(replay);
    }

    [Fact]
    public void More_than_one_thousand_same_timestamp_events_notify_once_with_constant_memory()
    {
        var policy = new NotificationPolicy();
        policy.Evaluate(null, Status(OverallReadiness.Ready), []);
        var completed = DateTimeOffset.Parse("2026-08-09T00:00:00Z");
        var jobs = Enumerable.Range(10, 1_005)
            .Select((index, offset) => Event(
                offset + 1,
                JobAt(Guid.Parse($"00000000-0000-0000-0000-{index:D12}"), completed)))
            .ToArray();

        var first = policy.Evaluate(Status(OverallReadiness.Ready), Status(OverallReadiness.Ready), jobs);
        var replay = policy.Evaluate(
            Status(OverallReadiness.Ready),
            Status(OverallReadiness.Ready),
            [jobs[0]]);

        Assert.Equal(1_005, first.Count);
        Assert.Equal(0, policy.TrackedTerminalJobCount);
        Assert.Empty(replay);
    }

    [Fact]
    public void Terminal_watermark_accepts_reverse_guid_at_same_timestamp_once()
    {
        var policy = new NotificationPolicy();
        var completed = DateTimeOffset.Parse("2026-08-09T00:00:00Z");
        var baseline = JobAt(Guid.Parse("00000000-0000-0000-0000-000000000002"), completed);
        var newerTie = JobAt(Guid.Parse("00000000-0000-0000-0000-000000000003"), completed);
        var reverseGuidTie = JobAt(Guid.Parse("00000000-0000-0000-0000-000000000001"), completed);

        policy.Evaluate(Status(OverallReadiness.Ready), Status(OverallReadiness.Ready), [Event(1, baseline)]);
        var emitted = policy.Evaluate(Status(OverallReadiness.Ready), Status(OverallReadiness.Ready), [Event(2, newerTie)]);
        var reverse = policy.Evaluate(Status(OverallReadiness.Ready), Status(OverallReadiness.Ready), [Event(3, reverseGuidTie)]);
        var replay = policy.Evaluate(Status(OverallReadiness.Ready), Status(OverallReadiness.Ready), [Event(3, reverseGuidTie), Event(2, newerTie)]);

        Assert.Single(emitted);
        Assert.Single(reverse);
        Assert.Empty(replay);
    }

    [Fact]
    public void Old_sequence_does_not_replay_after_a_large_same_timestamp_batch()
    {
        var policy = new NotificationPolicy();
        var completed = DateTimeOffset.Parse("2026-08-09T00:00:00Z");
        var baseline = JobAt(Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff"), completed);
        policy.Evaluate(Status(OverallReadiness.Ready), Status(OverallReadiness.Ready), [Event(1, baseline)]);
        var sameTimestamp = Enumerable.Range(1, 1_000)
            .Select(index => Event(
                index + 1,
                JobAt(Guid.Parse($"00000000-0000-0000-0000-{index:D12}"), completed)))
            .ToArray();

        policy.Evaluate(Status(OverallReadiness.Ready), Status(OverallReadiness.Ready), sameTimestamp);
        var replay = policy.Evaluate(
            Status(OverallReadiness.Ready),
            Status(OverallReadiness.Ready),
            [Event(1, baseline)]);

        Assert.Equal(0, policy.TrackedTerminalJobCount);
        Assert.Empty(replay);
    }

    [Fact]
    public void Tray_displays_feed_notification_on_dispatcher_and_dispose_stops_callbacks()
    {
        var oldFailure = Job("api", "failed", "pdf_sign_failed", 1);
        var newFailure = Job("local", "failed", "pdf_sign_failed", 2);
        var backend = new AdministrationBackend(Snapshot(), [oldFailure]);
        var feed = new ControllableTerminalFeed();
        var dispatcher = new GuardedDispatcher();
        var platform = new RecordingTrayPlatform(dispatcher);
        var window = new NullWindow();
        using var shell = new ShellViewModel(
            backend,
            backend,
            Configuration(),
            new ConfirmRelogin(),
            window,
            new NullLifetime(),
            dispatcher,
            feed);
        var tray = new TrayIconController(platform, shell, window, dispatcher);

        feed.PublishInitial([Event(1, oldFailure)]);
        feed.Publish([Event(2, newFailure)]);

        var shown = Assert.Single(platform.Notifications);
        Assert.Equal(TrayNotificationKind.JobFailed, shown.Notification.Kind);
        Assert.True(shown.WasDispatched);
        tray.Dispose();
        feed.Publish([Event(3, Job("api", "failed", "pdf_sign_failed", 3))]);
        Assert.Single(platform.Notifications);
    }

    [Fact]
    public async Task Terminal_feed_backpressures_until_the_tray_consumes_the_published_page()
    {
        var backend = new AdministrationBackend(Snapshot(), []);
        var feed = new ControllableTerminalFeed();
        var dispatcher = new BlockingDispatcher();
        var platform = new PlainRecordingTrayPlatform();
        var window = new NullWindow();
        using var shell = new ShellViewModel(
            backend,
            backend,
            Configuration(),
            new ConfirmRelogin(),
            window,
            new NullLifetime(),
            dispatcher,
            feed);
        using var tray = new TrayIconController(platform, shell, window, dispatcher);
        feed.PublishInitial([]);
        dispatcher.Block();

        var publish = Task.Run(() => feed.Publish([
            Event(1, Job("api", "failed", "pdf_sign_failed", 1)),
        ]));
        await dispatcher.InvocationStarted.Task.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.False(publish.IsCompleted);
        dispatcher.Release();
        await publish.WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Single(platform.Notifications);
    }

    [Fact]
    public async Task Production_terminal_feed_notifies_while_window_is_hidden_and_jobs_page_was_never_loaded()
    {
        var oldFailure = Job("api", "failed", "pdf_sign_failed", 1);
        var localSuccess = Job("local", "succeeded", null, 2);
        var apiFailure = Job("api", "failed", "pdf_sign_failed", 3);
        var backend = new TerminalFeedBackend(
            Snapshot(),
            [Event(1, oldFailure)],
            [Event(2, apiFailure), Event(3, localSuccess)]);
        var delay = new ManualTerminalFeedDelay();
        using var feed = new TerminalJobFeed(backend, delay, TimeSpan.FromSeconds(5));
        await backend.FirstPageServed.Task.WaitAsync(TimeSpan.FromSeconds(1));
        var dispatcher = new GuardedDispatcher();
        var platform = new RecordingTrayPlatform(dispatcher);
        var window = new NullWindow();
        using var shell = new ShellViewModel(
            backend,
            backend,
            Configuration(),
            new ConfirmRelogin(),
            window,
            new NullLifetime(),
            dispatcher,
            feed);
        using var tray = new TrayIconController(platform, shell, window, dispatcher);

        Assert.False(shell.Jobs!.HasLoadedPage);
        window.Hide();
        delay.ReleaseFirstDelay();
        await platform.TwoNotifications.Task.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal(
            [TrayNotificationKind.JobFailed, TrayNotificationKind.LocalJobSucceeded],
            platform.Notifications.Select(item => item.Notification.Kind).ToArray());
        Assert.All(platform.Notifications, shown => Assert.True(shown.WasDispatched));
        Assert.Equal(0, backend.GeneralPageCalls);
    }

    [Fact]
    public async Task Terminal_feed_updates_quick_sign_and_loaded_jobs_without_manual_refresh_or_navigation()
    {
        var jobId = Guid.Parse("11111111-2222-3333-4444-555555555555");
        var queued = Job(jobId, "local", "queued", null, 2);
        var succeeded = Job(jobId, "local", "succeeded", null, 3);
        var backend = new AdministrationBackend(Snapshot(), [queued], jobId);
        var feed = new ControllableTerminalFeed();
        var source = Path.Combine(
            Path.GetTempPath(),
            $"CodeSignAuto-terminal-feed-{Guid.NewGuid():N}.exe");
        await File.WriteAllBytesAsync(source, "MZ-terminal-feed"u8.ToArray());
        try
        {
            using var shell = new ShellViewModel(
                backend,
                backend,
                Configuration(),
                new ConfirmRelogin(),
                new NullWindow(),
                new NullLifetime(),
                new GuardedDispatcher(),
                feed);
            await shell.QuickSign!.SelectFileAsync(source);
            Assert.Equal(jobId, await shell.QuickSign.SubmitAsync(default));
            await shell.Jobs!.RefreshAsync(default);
            Assert.Equal("已提交，正在签名任务页中跟踪", shell.QuickSign.StatusText);
            Assert.Equal("排队中", Assert.Single(shell.Jobs.Items).StateText);

            feed.Publish([Event(1, succeeded)]);

            Assert.Equal("签名已完成，请在签名任务中保存", shell.QuickSign.StatusText);
            var completed = Assert.Single(shell.Jobs.Items);
            Assert.Equal("已完成", completed.StateText);
            Assert.True(completed.HasResult);
            Assert.Equal(1, backend.PageCalls);
        }
        finally
        {
            File.Delete(source);
        }
    }

    [Fact]
    public async Task Terminal_feed_commits_each_successful_page_and_resumes_after_the_next_page_disconnects()
    {
        var first = Event(1, Job("api", "failed", "pdf_sign_failed", 1));
        var second = Event(2, Job("api", "failed", "pdf_sign_failed", 2));
        var backend = new DisconnectingTerminalFeedBackend(Snapshot(), first, second);
        var delay = new StepTerminalFeedDelay();
        using var feed = new TerminalJobFeed(backend, delay, TimeSpan.FromSeconds(5));
        await backend.WaitForCallAsync(1).WaitAsync(TimeSpan.FromSeconds(1));

        var policy = new NotificationPolicy();
        var notified = new List<string>();
        feed.ItemsChanged += (_, _) =>
        {
            var notifications = policy.Evaluate(
                Status(OverallReadiness.Ready),
                Status(OverallReadiness.Ready),
                feed.Items);
            notified.AddRange(notifications.Select(static item => item.Message));
        };
        policy.Evaluate(null, Status(OverallReadiness.Ready), feed.Items);

        delay.Release();
        await backend.WaitForCallAsync(2).WaitAsync(TimeSpan.FromSeconds(1));
        await WaitUntilAsync(() => feed.Items.Select(static item => item.Sequence).SequenceEqual([1]));

        delay.Release();
        await backend.WaitForCallAsync(3).WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Equal([1L], feed.Items.Select(static item => item.Sequence).ToArray());

        delay.Release();
        await backend.WaitForCallAsync(4).WaitAsync(TimeSpan.FromSeconds(1));
        await WaitUntilAsync(() => feed.Items.Select(static item => item.Sequence).SequenceEqual([2, 1]));

        Assert.Equal(2, notified.Count);
        Assert.Contains(first.Item.JobId.ToString("N")[^8..].ToUpperInvariant(), notified[0], StringComparison.Ordinal);
        Assert.Contains(second.Item.JobId.ToString("N")[^8..].ToUpperInvariant(), notified[1], StringComparison.Ordinal);
    }

    [Fact]
    public void Delayed_initial_terminal_feed_establishes_a_silent_baseline_before_notifying_new_jobs()
    {
        var oldFailure = Job("api", "failed", "pdf_sign_failed", 1);
        var newFailure = Job("api", "failed", "pdf_sign_failed", 2);
        var backend = new AdministrationBackend(Snapshot(), []);
        var feed = new ControllableTerminalFeed();
        var dispatcher = new GuardedDispatcher();
        var platform = new RecordingTrayPlatform(dispatcher);
        var window = new NullWindow();
        using var shell = new ShellViewModel(
            backend,
            backend,
            Configuration(),
            new ConfirmRelogin(),
            window,
            new NullLifetime(),
            dispatcher,
            feed);
        using var tray = new TrayIconController(platform, shell, window, dispatcher);

        feed.PublishInitial([Event(1, oldFailure)]);
        Assert.Empty(platform.Notifications);

        feed.Publish([Event(2, newFailure), Event(1, oldFailure)]);
        Assert.Equal(TrayNotificationKind.JobFailed, Assert.Single(platform.Notifications).Notification.Kind);
    }

    private static OverallStatus Status(OverallReadiness readiness, params string[] reasons) =>
        new(readiness, reasons);

    private static JobPageItem Job(string source, string state, string? errorCode, int second)
        => Job(Guid.NewGuid(), source, state, errorCode, second);

    private static JobPageItem Job(
        Guid jobId,
        string source,
        string state,
        string? errorCode,
        int second)
    {
        var completed = new DateTimeOffset(2026, 8, 9, 0, 0, 0, TimeSpan.Zero).AddSeconds(second);
        return new JobPageItem(
            jobId,
            source,
            "pdf",
            state,
            "secret-input.pdf",
            completed.AddSeconds(-1),
            state == "queued" ? null : completed.AddMilliseconds(-500),
            state is "succeeded" or "failed" or "expired" ? completed : null,
            errorCode,
            Guid.NewGuid(),
            state == "succeeded");
    }

    private static JobPageItem JobAt(Guid jobId, DateTimeOffset completed) => new(
        jobId,
        "api",
        "pdf",
        "failed",
        "secret-input.pdf",
        completed.AddSeconds(-1),
        completed.AddMilliseconds(-500),
        completed,
        "pdf_sign_failed",
        Guid.NewGuid(),
        false);

    private static TerminalJobEventItem Event(long sequence, JobPageItem item) => new(sequence, item);

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(1));
        while (!condition())
        {
            await Task.Delay(1, timeout.Token);
        }
    }

    private sealed class MutableTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = utcNow;

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan value) => _utcNow += value;

        public void Set(DateTimeOffset value) => _utcNow = value;
    }

    private static ManagementSnapshot Snapshot()
    {
        var ready = ProtocolV3TestFixtures.Ready();
        return new ManagementSnapshot(
            1,
            DateTimeOffset.Parse("2026-08-09T00:00:00Z"),
            Guid.NewGuid(),
            true,
            true,
            7,
            7,
            10,
            true,
            7,
            ready,
            ready,
            0,
            0,
            null,
            [],
            1,
            [
                new CertificateSummary(
                    "Universal",
                    "52A1B4C9",
                    DateTimeOffset.Parse("2026-01-01T00:00:00Z"),
                    DateTimeOffset.Parse("2027-01-01T00:00:00Z"),
                    true,
                    true,
                    true,
                    null),
            ]);
    }

    private static AgentConfiguration Configuration()
    {
        var root = Path.Combine(Path.GetTempPath(), "simplysign-notification-tests");
        return new AgentConfiguration(
            "S-1-5-21-1000-2000-3000-4000",
            Path.Combine(root, "spool"),
            Path.Combine(root, "SimplySignDesktop.exe"),
            Path.Combine(root, "pkcs11.dll"),
            new AgentAuthenticodeConfiguration(Path.Combine(root, "signtool.exe")),
            null);
    }

    private sealed class AdministrationBackend(
        ManagementSnapshot snapshot,
        IReadOnlyList<JobPageItem> pageItems,
        Guid? jobId = null) :
        IAgentManagementClient,
        IAgentAdministrationClient,
        ILocalJobClient
    {
        public event EventHandler? SnapshotChanged { add { } remove { } }

        public ManagementSnapshot? LatestSnapshot { get; } = snapshot;

        public IReadOnlyList<JobPageItem> PageItems { get; set; } = pageItems;

        public int PageCalls { get; private set; }

        public Task<ManagementSnapshot> RefreshAsync(CancellationToken cancellationToken) =>
            Task.FromResult(LatestSnapshot!);

        public Task<ManagementSnapshot> ReloginAsync(CancellationToken cancellationToken) =>
            Task.FromResult(LatestSnapshot!);

        public Task<JobPageResponse> GetJobPageAsync(JobPageCursor? cursor, CancellationToken cancellationToken)
        {
            PageCalls++;
            return Task.FromResult(new JobPageResponse(Guid.NewGuid(), PageItems, null, null, null));
        }

        public Task<ServiceSettingsSummary> GetServiceSettingsAsync(CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task SaveOtpAsync(CodeSignAuto.Core.Otp.OtpauthProfile profile, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<Guid> CreateAndUploadAsync(
            string path,
            SigningParameters parameters,
            IProgress<LocalCopyProgress>? progress,
            CancellationToken cancellationToken) => Task.FromResult(
                jobId ?? throw new NotSupportedException());

        public Task SaveSignedCopyAsync(
            Guid jobId,
            string destinationPath,
            bool overwrite,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public void ReleaseAcceptedSource(Guid jobId)
        {
        }
    }

    private sealed class GuardedDispatcher : IUiDispatcher
    {
        public bool IsDispatching { get; private set; }

        public Task InvokeAsync(Action action, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            IsDispatching = true;
            try
            {
                action();
            }
            finally
            {
                IsDispatching = false;
            }

            return Task.CompletedTask;
        }
    }

    private sealed class BlockingDispatcher : IUiDispatcher
    {
        private readonly object _sync = new();
        private TaskCompletionSource? _release;

        public TaskCompletionSource InvocationStarted { get; private set; } =
            CompletedSource();

        public async Task InvokeAsync(Action action, CancellationToken cancellationToken)
        {
            TaskCompletionSource? release;
            TaskCompletionSource started;
            lock (_sync)
            {
                release = _release;
                started = InvocationStarted;
            }

            if (release is not null)
            {
                started.TrySetResult();
                await release.Task.WaitAsync(cancellationToken);
            }

            action();
        }

        public void Block()
        {
            lock (_sync)
            {
                _release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                InvocationStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            }
        }

        public void Release()
        {
            lock (_sync)
            {
                _release?.TrySetResult();
                _release = null;
            }
        }

        private static TaskCompletionSource CompletedSource()
        {
            var source = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            source.SetResult();
            return source;
        }
    }

    private sealed class RecordingTrayPlatform(GuardedDispatcher dispatcher) : ITrayIconPlatform
    {
        public event EventHandler<TrayCommandEventArgs>? CommandInvoked { add { } remove { } }

        public List<(TrayNotification Notification, bool WasDispatched)> Notifications { get; } = [];
        public TaskCompletionSource TwoNotifications { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void Initialize(IReadOnlyList<TrayMenuEntry> entries, string statusText)
        {
        }

        public void SetStatus(string statusText)
        {
        }

        public void ShowNotification(TrayNotification notification)
        {
            Notifications.Add((notification, dispatcher.IsDispatching));
            if (Notifications.Count == 2)
            {
                TwoNotifications.TrySetResult();
            }
        }

        public void Dispose()
        {
        }
    }

    private sealed class PlainRecordingTrayPlatform : ITrayIconPlatform
    {
        public event EventHandler<TrayCommandEventArgs>? CommandInvoked { add { } remove { } }
        public List<TrayNotification> Notifications { get; } = [];
        public void Initialize(IReadOnlyList<TrayMenuEntry> entries, string statusText) { }
        public void SetStatus(string statusText) { }
        public void ShowNotification(TrayNotification notification) => Notifications.Add(notification);
        public void Dispose() { }
    }

    private sealed class NullWindow : IWindowController
    {
        public void ShowRestoreActivate() { }
        public void Hide() { }
        public void CloseForExit() { }
        public void ShowNotice(string message) { }
    }

    private sealed class NullLifetime : IDesktopAgentLifetime
    {
        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed class ConfirmRelogin : IReloginConfirmation
    {
        public Task<bool> ConfirmAsync(CancellationToken cancellationToken) => Task.FromResult(true);
    }

    private sealed class ManualTerminalFeedDelay : ITerminalJobFeedDelay
    {
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _calls;

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
            Interlocked.Increment(ref _calls) == 1
                ? _release.Task.WaitAsync(cancellationToken)
                : Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);

        public void ReleaseFirstDelay() => _release.TrySetResult();
    }

    private sealed class StepTerminalFeedDelay : ITerminalJobFeedDelay
    {
        private readonly SemaphoreSlim _steps = new(0);

        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) =>
            _steps.WaitAsync(cancellationToken);

        public void Release() => _steps.Release();
    }

    private sealed class ControllableTerminalFeed : ITerminalJobFeed
    {
        public event EventHandler? ItemsChanged;
        public IReadOnlyList<TerminalJobEventItem> Items { get; private set; } = [];
        public bool HasCompletedInitialPoll { get; private set; }

        public void PublishInitial(IReadOnlyList<TerminalJobEventItem> items)
        {
            HasCompletedInitialPoll = true;
            Publish(items);
        }

        public void Publish(IReadOnlyList<TerminalJobEventItem> items)
        {
            Items = items;
            ItemsChanged?.Invoke(this, EventArgs.Empty);
        }

        public void Dispose() { }
    }

    private sealed class TerminalFeedBackend(
        ManagementSnapshot snapshot,
        params IReadOnlyList<TerminalJobEventItem>[] pages) :
        IAgentManagementClient,
        IAgentAdministrationClient,
        ILocalJobClient
    {
        private readonly Queue<IReadOnlyList<TerminalJobEventItem>> _pages = new(pages);
        private readonly ManagementSnapshot _snapshot = snapshot;

        public event EventHandler? SnapshotChanged { add { } remove { } }
        public ManagementSnapshot? LatestSnapshot => _snapshot;
        public TaskCompletionSource FirstPageServed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int GeneralPageCalls { get; private set; }

        public Task<ManagementSnapshot> RefreshAsync(CancellationToken cancellationToken) =>
            Task.FromResult(_snapshot);

        public Task<ManagementSnapshot> ReloginAsync(CancellationToken cancellationToken) =>
            Task.FromResult(_snapshot);

        public Task<JobPageResponse> GetJobPageAsync(JobPageCursor? cursor, CancellationToken cancellationToken)
        {
            GeneralPageCalls++;
            throw new InvalidOperationException("terminal_feed_must_not_scan_general_pages");
        }

        public Task<TerminalJobDeltaResponse> GetTerminalJobDeltaAsync(
            TerminalJobWatermark? watermark,
            TerminalJobCursor? cursor,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var items = _pages.Count == 0 ? Array.Empty<TerminalJobEventItem>() : _pages.Dequeue();
            FirstPageServed.TrySetResult();
            var observed = items
                .Select(static item => item.Sequence)
                .Append(watermark?.Sequence ?? 0)
                .Max();
            var nextWatermark = new TerminalJobWatermark(observed);
            return Task.FromResult(new TerminalJobDeltaResponse(
                Guid.NewGuid(), items, null, nextWatermark, null, null));
        }

        public Task<ServiceSettingsSummary> GetServiceSettingsAsync(CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task SaveOtpAsync(CodeSignAuto.Core.Otp.OtpauthProfile profile, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<Guid> CreateAndUploadAsync(
            string path,
            SigningParameters parameters,
            IProgress<LocalCopyProgress>? progress,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task SaveSignedCopyAsync(
            Guid jobId,
            string destinationPath,
            bool overwrite,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public void ReleaseAcceptedSource(Guid jobId) { }
    }

    private sealed class DisconnectingTerminalFeedBackend(
        ManagementSnapshot snapshot,
        TerminalJobEventItem first,
        TerminalJobEventItem second) :
        IAgentManagementClient,
        IAgentAdministrationClient,
        ILocalJobClient
    {
        private readonly SemaphoreSlim _calls = new(0);
        private int _callCount;

        public event EventHandler? SnapshotChanged { add { } remove { } }
        public ManagementSnapshot? LatestSnapshot => snapshot;

        public Task WaitForCallAsync(int expected) => WaitAsync(expected);

        public Task<ManagementSnapshot> RefreshAsync(CancellationToken cancellationToken) =>
            Task.FromResult(snapshot);

        public Task<ManagementSnapshot> ReloginAsync(CancellationToken cancellationToken) =>
            Task.FromResult(snapshot);

        public Task<JobPageResponse> GetJobPageAsync(JobPageCursor? cursor, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("terminal_feed_must_not_scan_general_pages");

        public Task<TerminalJobDeltaResponse> GetTerminalJobDeltaAsync(
            TerminalJobWatermark? watermark,
            TerminalJobCursor? cursor,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var call = Interlocked.Increment(ref _callCount);
            _calls.Release();
            return call switch
            {
                1 => Task.FromResult(new TerminalJobDeltaResponse(
                    Guid.NewGuid(), [], null, new TerminalJobWatermark(0), null, null)),
                2 => Task.FromResult(new TerminalJobDeltaResponse(
                    Guid.NewGuid(), [first], new TerminalJobCursor(1, 2), new TerminalJobWatermark(2), null, null)),
                3 => Task.FromException<TerminalJobDeltaResponse>(new IOException("simulated_disconnect")),
                4 => Task.FromResult(new TerminalJobDeltaResponse(
                    Guid.NewGuid(), [second], null, new TerminalJobWatermark(2), null, null)),
                _ => Task.FromResult(new TerminalJobDeltaResponse(
                    Guid.NewGuid(), [], null, new TerminalJobWatermark(2), null, null)),
            };
        }

        public Task<ServiceSettingsSummary> GetServiceSettingsAsync(CancellationToken cancellationToken) =>
            throw new NotSupportedException();

        public Task SaveOtpAsync(CodeSignAuto.Core.Otp.OtpauthProfile profile, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public Task<Guid> CreateAndUploadAsync(
            string path,
            SigningParameters parameters,
            IProgress<LocalCopyProgress>? progress,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public Task SaveSignedCopyAsync(
            Guid jobId,
            string destinationPath,
            bool overwrite,
            CancellationToken cancellationToken) => throw new NotSupportedException();

        public void ReleaseAcceptedSource(Guid jobId) { }

        private async Task WaitAsync(int expected)
        {
            while (Volatile.Read(ref _callCount) < expected)
            {
                await _calls.WaitAsync();
            }
        }
    }
}
