using SimplySignAuto.Agent.Security;
using SimplySignAuto.Agent.Sessions;
using SimplySignAuto.Agent.Diagnostics;
using SimplySignAuto.Core.Otp;
using Xunit;

namespace SimplySignAuto.Agent.Tests;

public sealed class AgentHostTests
{
    private const string ExpectedSid = "S-1-5-21-1000-2000-3000-4000";

    [Fact]
    public async Task Starts_in_session_then_dpapi_then_pipe_order()
    {
        var events = new List<string>();
        var lifetime = new FakeAgentLifetime();
        var locks = new RecordingInstanceLockFactory(events);
        var pipe = new RecordingPipeSession(events);
        var host = CreateHost(events, lifetime, locks, pipe);

        var run = host.RunAsync(ExpectedSid, CancellationToken.None);
        await pipe.WaitUntilConnectedAsync();
        lifetime.RequestShutdown();
        await run;

        Assert.Equal(["session", "mutex", "otp", "pipe", "stop", "wait:60", "disconnect", "unlock"], events);
        Assert.Equal(7, pipe.Session?.SessionId);
        Assert.Equal(ExpectedSid, pipe.Session?.UserSid);
        Assert.Equal("ready", pipe.Readiness?.OtpStatus);
        Assert.Equal($"Local\\SimplySignAuto.Agent.{ExpectedSid}", locks.RequestedName);
    }

    [Fact]
    public async Task Pre_requested_shutdown_validates_session_but_does_not_load_otp_or_connect_pipe()
    {
        var events = new List<string>();
        var lifetime = new FakeAgentLifetime();
        lifetime.RequestShutdown();
        var pipe = new RecordingPipeSession(events);
        var host = CreateHost(
            events,
            lifetime,
            new RecordingInstanceLockFactory(events),
            pipe);

        await host.RunAsync(ExpectedSid, CancellationToken.None);

        Assert.Equal(["session"], events);
        Assert.Null(pipe.Session);
    }

    [Fact]
    public async Task Pre_cancelled_caller_validates_session_then_exits_without_otp_or_pipe()
    {
        var events = new List<string>();
        using var callerCancellation = new CancellationTokenSource();
        callerCancellation.Cancel();
        var pipe = new RecordingPipeSession(events);
        var host = CreateHost(
            events,
            new FakeAgentLifetime(),
            new RecordingInstanceLockFactory(events),
            pipe);

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            host.RunAsync(ExpectedSid, callerCancellation.Token));

        Assert.Equal(["session"], events);
        Assert.Null(pipe.Session);
    }

    [Fact]
    public async Task Shutdown_requested_while_loading_otp_does_not_connect_pipe()
    {
        var events = new List<string>();
        var lifetime = new FakeAgentLifetime();
        var pipe = new RecordingPipeSession(events);
        var host = CreateHost(
            events,
            lifetime,
            new RecordingInstanceLockFactory(events),
            pipe,
            new ShutdownRequestingOtpStore(events, lifetime));

        await host.RunAsync(ExpectedSid, CancellationToken.None);

        Assert.Equal(["session", "mutex", "otp", "unlock"], events);
        Assert.Null(pipe.Session);
    }

    [Fact]
    public async Task Shutdown_racing_with_pipe_creation_stops_and_joins_without_grace_wait()
    {
        var events = new List<string>();
        var lifetime = new FakeAgentLifetime();
        var pipe = new RecordingPipeSession(
            events,
            onRun: lifetime.RequestShutdown,
            attemptDispatchAfterOnRun: true);
        var host = CreateHost(
            events,
            lifetime,
            new RecordingInstanceLockFactory(events),
            pipe);

        await host.RunAsync(ExpectedSid, CancellationToken.None);

        Assert.Equal(
            ["session", "mutex", "otp", "pipe", "stop", "dispatch-blocked", "disconnect", "unlock"],
            events);
    }

    [Fact]
    public async Task Missing_otp_is_readiness_and_does_not_skip_session_validation_or_pipe_connection()
    {
        var events = new List<string>();
        var lifetime = new FakeAgentLifetime();
        var pipe = new RecordingPipeSession(events);
        var host = CreateHost(
            events,
            lifetime,
            new RecordingInstanceLockFactory(events),
            pipe,
            new RecordingOtpStore(events, "otp_missing"));

        var run = host.RunAsync(ExpectedSid, CancellationToken.None);
        await pipe.WaitUntilConnectedAsync();
        lifetime.RequestShutdown();
        await run;

        Assert.Equal("otp_missing", pipe.Readiness?.OtpStatus);
        Assert.True(events.IndexOf("session") < events.IndexOf("otp"));
        Assert.True(events.IndexOf("otp") < events.IndexOf("pipe"));
    }

    [Fact]
    public async Task Rejects_second_instance_before_dpapi_or_pipe_and_reports_stable_code()
    {
        var events = new List<string>();
        var locks = new RecordingInstanceLockFactory(events) { RefuseAcquisition = true };
        var pipe = new RecordingPipeSession(events);
        var host = CreateHost(events, new FakeAgentLifetime(), locks, pipe);

        var error = await Assert.ThrowsAsync<AgentStartupException>(() =>
            host.RunAsync(ExpectedSid, CancellationToken.None));

        Assert.Equal("agent_already_running", error.Code);
        Assert.Equal(["session", "mutex"], events);
        Assert.Null(pipe.Session);
    }

    [Fact]
    public async Task Rejects_wrong_user_before_mutex_dpapi_or_pipe()
    {
        var events = new List<string>();
        var guard = new InteractiveSessionGuard(new RecordingSessionSource(
            events,
            new InteractiveSessionState(7, "S-1-5-21-1000-2000-3000-4001", true)));
        var host = new AgentHost(
            guard,
            new RecordingOtpStore(events),
            new RecordingInstanceLockFactory(events),
            new RecordingPipeSession(events),
            new FakeAgentLifetime(),
            new ImmediateShutdownWaiter(events));

        var error = await Assert.ThrowsAsync<AgentStartupException>(() =>
            host.RunAsync(ExpectedSid, CancellationToken.None));

        Assert.Equal("agent_wrong_user", error.Code);
        Assert.Equal(["session"], events);
    }

    [Fact]
    public async Task Shutdown_stops_new_jobs_waits_at_most_sixty_seconds_then_disconnects()
    {
        var events = new List<string>();
        var lifetime = new FakeAgentLifetime();
        var pipe = new RecordingPipeSession(events, currentJobCompleted: false);
        var waiter = new ImmediateShutdownWaiter(events);
        var locks = new RecordingInstanceLockFactory(events);
        var host = CreateHost(events, lifetime, locks, pipe, waiter: waiter);

        var run = host.RunAsync(ExpectedSid, CancellationToken.None);
        await pipe.WaitUntilConnectedAsync();
        lifetime.RequestShutdown();
        await run;

        Assert.Same(pipe.CurrentJobCompletion, waiter.WaitedFor);
        Assert.Equal(TimeSpan.FromSeconds(60), waiter.Timeout);
        Assert.True(events.IndexOf("stop") < events.IndexOf("wait:60"));
        Assert.True(events.IndexOf("wait:60") < events.IndexOf("disconnect"));
        Assert.True(locks.LastLock?.Disposed);
    }

    [Fact]
    public async Task Releases_mutex_when_pipe_startup_fails()
    {
        var events = new List<string>();
        var locks = new RecordingInstanceLockFactory(events);
        var pipe = new RecordingPipeSession(events) { StartupError = new IOException("pipe unavailable") };
        var host = CreateHost(events, new FakeAgentLifetime(), locks, pipe);

        await Assert.ThrowsAsync<IOException>(() => host.RunAsync(ExpectedSid, CancellationToken.None));

        Assert.True(locks.LastLock?.Disposed);
        Assert.Equal("unlock", events[^1]);
    }

    [Fact]
    public async Task Reconnects_after_pipe_eof_only_after_session_is_joined_and_disposed()
    {
        var events = new List<string>();
        var lifetime = new FakeAgentLifetime();
        var first = new ReconnectablePipeSession(events, "pipe:1");
        var second = new ReconnectablePipeSession(events, "pipe:2");
        var sessions = new QueuePipeSessionFactory(events, first, second);
        var delay = new ControlledReconnectDelay(events);
        var host = CreateReconnectHost(events, lifetime, sessions, delay);

        var run = host.RunAsync(ExpectedSid, CancellationToken.None);
        await first.Connected.Task.WaitAsync(TimeSpan.FromSeconds(1));
        first.EndFromService();
        await delay.Started.Task.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal(
            ["session", "mutex", "otp", "create:1", "pipe:1", "stop:pipe:1", "dispose:pipe:1", "reconnect-delay"],
            events);

        delay.Continue();
        await second.Connected.Task.WaitAsync(TimeSpan.FromSeconds(1));
        lifetime.RequestShutdown();
        await run.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal(2, sessions.Calls);
        Assert.Contains("dispose:pipe:2", events);
        Assert.Equal("unlock", events[^1]);
    }

    [Fact]
    public async Task Shutdown_during_reconnect_delay_does_not_create_another_session()
    {
        var events = new List<string>();
        var lifetime = new FakeAgentLifetime();
        var first = new ReconnectablePipeSession(events, "pipe:1");
        var sessions = new QueuePipeSessionFactory(events, first);
        var delay = new ControlledReconnectDelay(events);
        var host = CreateReconnectHost(events, lifetime, sessions, delay);

        var run = host.RunAsync(ExpectedSid, CancellationToken.None);
        await first.Connected.Task.WaitAsync(TimeSpan.FromSeconds(1));
        first.EndFromService();
        await delay.Started.Task.WaitAsync(TimeSpan.FromSeconds(1));
        lifetime.RequestShutdown();
        await run.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal(1, sessions.Calls);
        Assert.Equal("unlock", events[^1]);
    }

    [Fact]
    public async Task Transport_failure_stops_joins_and_disposes_before_reconnecting()
    {
        var events = new List<string>();
        var lifetime = new FakeAgentLifetime();
        var first = new ReconnectablePipeSession(events, "pipe:1");
        var second = new ReconnectablePipeSession(events, "pipe:2");
        var sessions = new QueuePipeSessionFactory(events, first, second);
        var delay = new ControlledReconnectDelay(events);
        var host = CreateReconnectHost(events, lifetime, sessions, delay);

        var run = host.RunAsync(ExpectedSid, CancellationToken.None);
        await first.Connected.Task.WaitAsync(TimeSpan.FromSeconds(1));
        first.FailFromService(new IOException("synthetic transport failure"));
        await delay.Started.Task.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal("stop:pipe:1", events[^3]);
        Assert.Equal("dispose:pipe:1", events[^2]);
        Assert.Equal("reconnect-delay", events[^1]);

        delay.Continue();
        await second.Connected.Task.WaitAsync(TimeSpan.FromSeconds(1));
        lifetime.RequestShutdown();
        await run.WaitAsync(TimeSpan.FromSeconds(1));

        Assert.Equal(2, sessions.Calls);
    }

    [Fact]
    public async Task Transport_failure_reports_full_exception_before_reconnecting()
    {
        var events = new List<string>();
        var lifetime = new FakeAgentLifetime();
        var first = new ReconnectablePipeSession(events, "pipe:1");
        var second = new ReconnectablePipeSession(events, "pipe:2");
        var sessions = new QueuePipeSessionFactory(events, first, second);
        var delay = new ControlledReconnectDelay(events);
        var diagnostics = new RecordingAgentDiagnosticSink();
        var guard = new InteractiveSessionGuard(new RecordingSessionSource(
            events,
            new InteractiveSessionState(7, ExpectedSid, true)));
        var host = new AgentHost(
            guard,
            new RecordingOtpStore(events),
            new RecordingInstanceLockFactory(events),
            sessions,
            lifetime,
            new ImmediateShutdownWaiter(events),
            delay,
            diagnostics);
        var expected = new IOException("pipe path=C:\\ProgramData\\SimplySignAuto line=170");

        var run = host.RunAsync(ExpectedSid, CancellationToken.None);
        await first.Connected.Task.WaitAsync(TimeSpan.FromSeconds(1));
        first.FailFromService(expected);
        await delay.Started.Task.WaitAsync(TimeSpan.FromSeconds(1));

        var diagnostic = Assert.Single(diagnostics.Diagnostics);
        Assert.Equal("agent_pipe_session", diagnostic.Stage);
        Assert.Equal("agent_connection_failed", diagnostic.StableCode);
        Assert.Same(expected, diagnostic.Exception);
        lifetime.RequestShutdown();
        await run.WaitAsync(TimeSpan.FromSeconds(1));
    }

    [Fact]
    public async Task Cancels_and_joins_pipe_when_shutdown_wait_is_cancelled()
    {
        var events = new List<string>();
        var lifetime = new FakeAgentLifetime();
        var pipe = new RecordingPipeSession(events, currentJobCompleted: false);
        var host = CreateHost(
            events,
            lifetime,
            new RecordingInstanceLockFactory(events),
            pipe,
            waiter: new CancellingShutdownWaiter());

        var run = host.RunAsync(ExpectedSid, CancellationToken.None);
        await pipe.WaitUntilConnectedAsync();
        lifetime.RequestShutdown();

        await Assert.ThrowsAsync<OperationCanceledException>(() => run);
        await pipe.WaitUntilDisconnectedAsync().WaitAsync(TimeSpan.FromSeconds(1));
        Assert.Equal("disconnect", events[^2]);
        Assert.Equal("unlock", events[^1]);
    }

    [WindowsFact]
    public void Windows_local_mutex_rejects_a_second_owner_for_the_same_sid()
    {
        var factory = new LocalAgentInstanceLockFactory();
        using var first = factory.TryAcquire(ExpectedSid);
        using var second = factory.TryAcquire(ExpectedSid);

        Assert.NotNull(first);
        Assert.Null(second);
    }

    [WindowsFact]
    public async Task Windows_local_mutex_lease_can_be_disposed_from_a_different_thread()
    {
        var factory = new LocalAgentInstanceLockFactory();
        var lease = await Task.Run(() => factory.TryAcquire(ExpectedSid));

        Assert.NotNull(lease);
        lease.Dispose();
        using var replacement = factory.TryAcquire(ExpectedSid);
        Assert.NotNull(replacement);
    }

    [Fact]
    public void Windows_lifetime_requests_shutdown_when_session_ending_is_signaled()
    {
        var sessionEnding = new FakeSessionEndingSignal();
        using var lifetime = new WindowsAgentLifetime(sessionEnding);

        sessionEnding.Raise();

        Assert.True(lifetime.ShutdownRequested.IsCancellationRequested);
    }

    [Theory]
    [InlineData(AgentConsoleControlType.CtrlC, true)]
    [InlineData(AgentConsoleControlType.CtrlBreak, true)]
    [InlineData(AgentConsoleControlType.CtrlClose, true)]
    [InlineData(AgentConsoleControlType.CtrlLogoff, false)]
    [InlineData(AgentConsoleControlType.CtrlShutdown, false)]
    public void Console_control_policy_handles_only_console_close_signals(
        AgentConsoleControlType controlType,
        bool expectedHandled)
    {
        Assert.Equal(expectedHandled, AgentConsoleControlPolicy.ShouldHandle(controlType));
    }

    [WindowsFact]
    public void Windows_session_ending_monitor_can_start_and_stop_its_hidden_window()
    {
        using var signal = new WindowsSessionEndingSignal();
    }

    private static AgentHost CreateHost(
        List<string> events,
        FakeAgentLifetime lifetime,
        RecordingInstanceLockFactory locks,
        RecordingPipeSession pipe,
        IOtpStore? otpStore = null,
        IAgentShutdownWaiter? waiter = null)
    {
        var guard = new InteractiveSessionGuard(new RecordingSessionSource(
            events,
            new InteractiveSessionState(7, ExpectedSid, true)));
        return new AgentHost(
            guard,
            otpStore ?? new RecordingOtpStore(events),
            locks,
            pipe,
            lifetime,
            waiter ?? new ImmediateShutdownWaiter(events));
    }

    private static AgentHost CreateReconnectHost(
        List<string> events,
        FakeAgentLifetime lifetime,
        IAgentPipeSessionFactory sessions,
        IAgentReconnectDelay delay)
    {
        var guard = new InteractiveSessionGuard(new RecordingSessionSource(
            events,
            new InteractiveSessionState(7, ExpectedSid, true)));
        return new AgentHost(
            guard,
            new RecordingOtpStore(events),
            new RecordingInstanceLockFactory(events),
            sessions,
            lifetime,
            new ImmediateShutdownWaiter(events),
            delay);
    }

    private sealed class RecordingSessionSource(
        List<string> events,
        InteractiveSessionState state) : IInteractiveSessionSource
    {
        public InteractiveSessionState ReadCurrent()
        {
            events.Add("session");
            return state;
        }
    }

    private sealed class RecordingOtpStore(List<string> events, string? errorCode = null) : IOtpStore
    {
        public string Path => "otp.dat";

        public Task SaveAsync(OtpauthProfile profile, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<OtpauthProfile> LoadAsync(CancellationToken cancellationToken = default)
        {
            events.Add("otp");
            if (errorCode is not null)
            {
                throw new OtpStoreException(errorCode);
            }

            return Task.FromResult(new OtpauthProfile(
                "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
                "SHA256",
                6,
                30,
                "Certum",
                "test"));
        }
    }

    private sealed class ShutdownRequestingOtpStore(
        List<string> events,
        FakeAgentLifetime lifetime) : IOtpStore
    {
        public string Path => "otp.dat";

        public Task SaveAsync(OtpauthProfile profile, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<OtpauthProfile> LoadAsync(CancellationToken cancellationToken = default)
        {
            events.Add("otp");
            lifetime.RequestShutdown();
            return Task.FromResult(new OtpauthProfile(
                "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
                "SHA256",
                6,
                30,
                "Certum",
                "test"));
        }
    }

    private sealed class RecordingInstanceLockFactory(List<string> events) : IAgentInstanceLockFactory
    {
        public bool RefuseAcquisition { get; init; }
        public string? RequestedName { get; private set; }
        public RecordingInstanceLock? LastLock { get; private set; }

        public IAgentInstanceLock? TryAcquire(string mutexName)
        {
            events.Add("mutex");
            RequestedName = mutexName;
            if (RefuseAcquisition)
            {
                return null;
            }

            LastLock = new RecordingInstanceLock(events);
            return LastLock;
        }
    }

    private sealed class RecordingInstanceLock(List<string> events) : IAgentInstanceLock
    {
        public bool Disposed { get; private set; }

        public void Dispose()
        {
            if (!Disposed)
            {
                Disposed = true;
                events.Add("unlock");
            }
        }
    }

    private sealed class RecordingPipeSession : IAgentPipeSession
    {
        private readonly List<string> _events;
        private readonly TaskCompletionSource _connected = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _currentJob = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _disconnected = new(TaskCreationOptions.RunContinuationsAsynchronously);

        private readonly Action? _onRun;
        private readonly bool _attemptDispatchAfterOnRun;
        private int _acceptingNewJobs = 1;

        public RecordingPipeSession(
            List<string> events,
            bool currentJobCompleted = true,
            Action? onRun = null,
            bool attemptDispatchAfterOnRun = false)
        {
            _events = events;
            _onRun = onRun;
            _attemptDispatchAfterOnRun = attemptDispatchAfterOnRun;
            if (currentJobCompleted)
            {
                _currentJob.TrySetResult();
            }
        }

        public Exception? StartupError { get; init; }
        public InteractiveSessionInfo? Session { get; private set; }
        public AgentReadiness? Readiness { get; private set; }
        public Task CurrentJobCompletion => _currentJob.Task;

        public async Task RunAsync(
            InteractiveSessionInfo session,
            AgentReadiness readiness,
            CancellationToken cancellationToken)
        {
            _events.Add("pipe");
            Session = session;
            Readiness = readiness;
            _connected.TrySetResult();
            _onRun?.Invoke();
            if (_attemptDispatchAfterOnRun)
            {
                _events.Add(Volatile.Read(ref _acceptingNewJobs) == 0
                    ? "dispatch-blocked"
                    : "dispatch-accepted");
            }

            if (StartupError is not null)
            {
                throw StartupError;
            }

            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                _events.Add("disconnect");
                _disconnected.TrySetResult();
            }
        }

        public void StopAcceptingNewJobs()
        {
            if (Interlocked.Exchange(ref _acceptingNewJobs, 0) != 0)
            {
                _events.Add("stop");
            }
        }

        public Task WaitUntilConnectedAsync() => _connected.Task;

        public Task WaitUntilDisconnectedAsync() => _disconnected.Task;
    }

    private sealed class QueuePipeSessionFactory(
        List<string> events,
        params ReconnectablePipeSession[] sessions) : IAgentPipeSessionFactory
    {
        private readonly Queue<ReconnectablePipeSession> _sessions = new(sessions);

        public int Calls { get; private set; }

        public IAgentPipeSession Create(InteractiveSessionInfo session)
        {
            Calls++;
            events.Add($"create:{Calls}");
            return _sessions.Dequeue();
        }
    }

    private sealed class ReconnectablePipeSession(
        List<string> events,
        string name) : IAgentPipeSession, IDisposable
    {
        private readonly TaskCompletionSource _ended = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Connected { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task CurrentJobCompletion => Task.CompletedTask;

        public async Task RunAsync(
            InteractiveSessionInfo session,
            AgentReadiness readiness,
            CancellationToken cancellationToken)
        {
            events.Add(name);
            Connected.TrySetResult();
            await _ended.Task.WaitAsync(cancellationToken);
        }

        public void StopAcceptingNewJobs() => events.Add($"stop:{name}");

        public void EndFromService() => _ended.TrySetResult();

        public void FailFromService(Exception error) => _ended.TrySetException(error);

        public void Dispose() => events.Add($"dispose:{name}");
    }

    private sealed class ControlledReconnectDelay(List<string> events) : IAgentReconnectDelay
    {
        private readonly TaskCompletionSource _continue = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            Assert.InRange(delay, TimeSpan.FromMilliseconds(1), TimeSpan.FromSeconds(5));
            events.Add("reconnect-delay");
            Started.TrySetResult();
            await _continue.Task.WaitAsync(cancellationToken);
        }

        public void Continue() => _continue.TrySetResult();
    }

    private sealed class FakeAgentLifetime : IAgentLifetime
    {
        private readonly CancellationTokenSource _shutdown = new();

        public CancellationToken ShutdownRequested => _shutdown.Token;

        public void RequestShutdown() => _shutdown.Cancel();
    }

    private sealed class ImmediateShutdownWaiter(List<string> events) : IAgentShutdownWaiter
    {
        public Task? WaitedFor { get; private set; }
        public TimeSpan Timeout { get; private set; }

        public Task WaitAsync(Task currentJobCompletion, TimeSpan timeout, CancellationToken cancellationToken)
        {
            WaitedFor = currentJobCompletion;
            Timeout = timeout;
            events.Add($"wait:{timeout.TotalSeconds:0}");
            return Task.CompletedTask;
        }
    }

    private sealed class CancellingShutdownWaiter : IAgentShutdownWaiter
    {
        public Task WaitAsync(Task currentJobCompletion, TimeSpan timeout, CancellationToken cancellationToken) =>
            Task.FromException(new OperationCanceledException("shutdown cancelled"));
    }

    private sealed class FakeSessionEndingSignal : IAgentSessionEndingSignal
    {
        public event EventHandler? SessionEnding;

        public bool Disposed { get; private set; }

        public void Dispose() => Disposed = true;

        public void Raise() => SessionEnding?.Invoke(this, EventArgs.Empty);
    }
}
