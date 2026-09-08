using CodeSignAuto.Agent.Signing;
using CodeSignAuto.Agent.SimplySign;
using CodeSignAuto.Core.Otp;
using CodeSignAuto.Protocol;
using Xunit;

namespace CodeSignAuto.Agent.Tests;

public sealed class SimplySignHealthMonitorTests
{
    [Fact]
    public async Task Health_tick_only_checks_and_never_logs_in_or_refreshes_catalog()
    {
        var driver = new HealthDriver();
        var catalog = new HealthCatalog();
        await using var manager = new SimplySignSessionManager(driver, new SigningOperationGate(), catalog);
        await using var monitor = new SimplySignHealthMonitor(manager, TimeProvider.System);

        Assert.True(await monitor.TickAsync(default));

        Assert.True(driver.ProcessChecks > 0);
        Assert.Equal(0, driver.LoginCalls);
        Assert.Equal(0, catalog.RefreshCalls);
    }

    [Fact]
    public async Task Expired_idle_session_is_not_refreshed_by_timer()
    {
        var driver = new HealthDriver
        {
            ProcessState = new SimplySignProcessState(false, null),
        };
        var catalog = new HealthCatalog();
        await using var manager = new SimplySignSessionManager(driver, new SigningOperationGate(), catalog);
        await using var monitor = new SimplySignHealthMonitor(manager, TimeProvider.System);

        _ = await monitor.TickAsync(default);

        Assert.Equal(0, driver.LoginCalls);
        Assert.Equal(0, catalog.RefreshCalls);
        Assert.Null(catalog.Current);
    }

    [Fact]
    public async Task Starts_immediately_then_checks_only_on_each_fixed_five_minute_boundary()
    {
        var time = new ControllableTimeProvider(DateTimeOffset.Parse("2026-08-09T00:00:00Z"));
        var manager = new RecordingManager();
        await using var monitor = new SimplySignHealthMonitor(manager, time);
        await manager.WaitForHealthCallsAsync(1);

        time.Advance(TimeSpan.FromMinutes(5) - TimeSpan.FromSeconds(1));
        await Task.Yield();
        Assert.Equal(1, manager.HealthCalls);

        time.Advance(TimeSpan.FromSeconds(1));
        await manager.WaitForHealthCallsAsync(2);
        Assert.Equal(2, manager.HealthCalls);

        time.Advance(TimeSpan.FromMinutes(5));
        await manager.WaitForHealthCallsAsync(3);
        Assert.Equal(3, manager.HealthCalls);
    }

    [Fact]
    public async Task Global_session_is_checked_once_per_health_tick()
    {
        var manager = new RecordingManager();
        await using var monitor = new SimplySignHealthMonitor(manager, TimeProvider.System);

        await manager.WaitForHealthCallsAsync(1);

        Assert.Equal(1, manager.ProbeCalls);
    }

    [Fact]
    public async Task Busy_signing_gate_skips_health_without_queueing_or_entering_probe()
    {
        await using var gate = new SigningOperationGate();
        var manager = new RecordingManager(gate);
        await using var signing = await gate.AcquireAsync(default);
        await using var monitor = new SimplySignHealthMonitor(manager, TimeProvider.System);
        await manager.WaitForHealthCallsAsync(1);

        Assert.Equal(0, manager.ProbeCalls);
        Assert.False(manager.LastHealthRan);

        await signing.DisposeAsync();
        Assert.True(await monitor.TickAsync(default));
        Assert.Equal(1, manager.ProbeCalls);
        Assert.True(manager.LastHealthRan);
    }

    [Fact]
    public async Task Dispose_cancels_and_joins_a_running_startup_check()
    {
        var manager = new RecordingManager { BlockHealth = true };
        var monitor = new SimplySignHealthMonitor(manager, TimeProvider.System);
        await manager.HealthEntered.Task.WaitAsync(TimeSpan.FromSeconds(1));

        var disposing = monitor.DisposeAsync().AsTask();
        await manager.HealthExited.Task.WaitAsync(TimeSpan.FromSeconds(1));
        await disposing.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.True(manager.HealthExited.Task.IsCompletedSuccessfully);
    }

    private sealed class RecordingManager : ISimplySignSessionManager
    {
        private readonly ISigningOperationGate? _gate;
        private TaskCompletionSource<int> _healthChanged = NewHealthSource();
        private int _healthCalls;

        public RecordingManager(ISigningOperationGate? gate = null) => _gate = gate;

        public event EventHandler<SimplySignSessionSnapshot>? SnapshotChanged { add { } remove { } }

        public int HealthCalls => Volatile.Read(ref _healthCalls);
        public int ProbeCalls { get; private set; }
        public bool LastHealthRan { get; private set; }
        public bool BlockHealth { get; init; }
        public TaskCompletionSource HealthEntered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource HealthExited { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task<SimplySignSessionSnapshot> CheckAsync(
            SessionTrigger trigger,
            CancellationToken cancellationToken)
        {
            var calls = Interlocked.Increment(ref _healthCalls);
            _healthChanged.TrySetResult(calls);
            if (BlockHealth)
            {
                HealthEntered.TrySetResult();
                try
                {
                    await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                }
                finally
                {
                    HealthExited.TrySetResult();
                }
            }

            if (_gate is null)
            {
                ProbeCalls++;
                LastHealthRan = true;
                return Ready();
            }

            LastHealthRan = await _gate.TryRunHealthCheckAsync(
                _ =>
                {
                    ProbeCalls++;
                    return Task.CompletedTask;
                },
                cancellationToken);
            return Ready();
        }

        public async Task WaitForHealthCallsAsync(int expected)
        {
            while (HealthCalls < expected)
            {
                var source = _healthChanged;
                await source.Task.WaitAsync(TimeSpan.FromSeconds(1));
                Interlocked.CompareExchange(ref _healthChanged, NewHealthSource(), source);
            }
        }

        public SimplySignSessionSnapshot GetSnapshot() => Ready();
        public SimplySignCapabilityGroup GetCapabilityGroup() => throw new NotSupportedException();
        public Task<SimplySignSessionSnapshot> PrepareStartupAsync(CancellationToken cancellationToken) =>
            Task.FromResult(Ready());
        public Task<SimplySignSessionSnapshot> EnsureReadyAsync(
            SessionTrigger trigger,
            CancellationToken cancellationToken) => Task.FromResult(Ready());
        public Task<IReadySignLease> AcquireReadySignLeaseAsync(CancellationToken cancellationToken) =>
            throw new NotSupportedException();
        public void Invalidate()
        {
        }
        public void Dispose()
        {
        }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;

        private static TaskCompletionSource<int> NewHealthSource() =>
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        private static SimplySignSessionSnapshot Ready()
        {
            var now = DateTimeOffset.Parse("2026-08-09T00:00:00Z");
            return new SimplySignSessionSnapshot(
                SimplySignSessionState.Ready,
                1,
                now,
                now,
                7,
                true,
                true,
                true,
                true,
                true,
                true,
                true,
                "ready",
                0,
                null);
        }
    }

    private sealed class HealthCatalog : ICertificateCatalog
    {
        public CertificateCatalogSnapshot? Current { get; private set; }
        public IReadOnlyList<CertificateDisplaySummary> DisplaySummaries => [];
        public int RefreshCalls { get; private set; }

        public Task<CertificateCatalogSnapshot> RefreshAsync(CancellationToken cancellationToken)
        {
            RefreshCalls++;
            throw new SigningException("certificate_catalog_unavailable");
        }

        public SigningCertificate Resolve(string serialNumber, SigningKind kind) =>
            throw new NotSupportedException();

        public void Invalidate() => Current = null;
    }

    private sealed class HealthDriver : ISimplySignSessionDriver
    {
        public int VerifiedSessionId => 7;
        public DateTimeOffset UtcNow => DateTimeOffset.UnixEpoch;
        public int ProcessChecks { get; private set; }
        public int LoginCalls { get; private set; }
        public SimplySignProcessState ProcessState { get; init; } = new(true, 7);

        public SimplySignProcessState CheckProcessOnly()
        {
            ProcessChecks++;
            return ProcessState;
        }

        public Task<ProbeResult> ProbeAsync(CertificateAlias alias, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("health_catalog_probe_forbidden");

        public Task CloseAsync(CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<OtpauthProfile> LoadOtpAsync(CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<long> StartLoginAsync(OtpauthProfile profile, CancellationToken cancellationToken)
        {
            LoginCalls++;
            throw new InvalidOperationException("health_login_forbidden");
        }
        public Task WaitForCounterAfterAsync(OtpauthProfile profile, long priorCounter, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
        public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    private sealed class ControllableTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private readonly Lock _lock = new();
        private readonly List<ControlledTimer> _timers = [];
        private DateTimeOffset _now = now;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override DateTimeOffset GetUtcNow()
        {
            lock (_lock)
            {
                return _now;
            }
        }

        public override long GetTimestamp() => GetUtcNow().UtcTicks;

        public override ITimer CreateTimer(
            TimerCallback callback,
            object? state,
            TimeSpan dueTime,
            TimeSpan period)
        {
            ArgumentNullException.ThrowIfNull(callback);
            var timer = new ControlledTimer(this, callback, state, dueTime, period);
            lock (_lock)
            {
                _timers.Add(timer);
            }

            return timer;
        }

        public void Advance(TimeSpan elapsed)
        {
            List<(TimerCallback Callback, object? State)> callbacks = [];
            lock (_lock)
            {
                _now += elapsed;
                foreach (var timer in _timers.ToArray())
                {
                    timer.CollectDueCallbacks(_now, callbacks);
                }
            }

            foreach (var (callback, state) in callbacks)
            {
                callback(state);
            }
        }

        private sealed class ControlledTimer : ITimer
        {
            private readonly ControllableTimeProvider _owner;
            private readonly TimerCallback _callback;
            private readonly object? _state;
            private DateTimeOffset? _dueAt;
            private TimeSpan _period;
            private bool _disposed;

            public ControlledTimer(
                ControllableTimeProvider owner,
                TimerCallback callback,
                object? state,
                TimeSpan dueTime,
                TimeSpan period)
            {
                _owner = owner;
                _callback = callback;
                _state = state;
                _period = period;
                _dueAt = DueAt(owner._now, dueTime);
            }

            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                lock (_owner._lock)
                {
                    if (_disposed)
                    {
                        return false;
                    }

                    _period = period;
                    _dueAt = DueAt(_owner._now, dueTime);
                    return true;
                }
            }

            public void Dispose()
            {
                lock (_owner._lock)
                {
                    _disposed = true;
                    _owner._timers.Remove(this);
                }
            }

            public ValueTask DisposeAsync()
            {
                Dispose();
                return ValueTask.CompletedTask;
            }

            public void CollectDueCallbacks(
                DateTimeOffset current,
                List<(TimerCallback Callback, object? State)> callbacks)
            {
                if (_disposed || _dueAt is null || current < _dueAt)
                {
                    return;
                }

                callbacks.Add((_callback, _state));
                _dueAt = _period is { Ticks: > 0 } && _period != Timeout.InfiniteTimeSpan
                    ? current + _period
                    : null;
            }

            private static DateTimeOffset? DueAt(DateTimeOffset current, TimeSpan dueTime) =>
                dueTime == Timeout.InfiniteTimeSpan ? null : current + dueTime;
        }
    }
}
