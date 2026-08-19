using SimplySignAuto.Agent.Security;
using SimplySignAuto.Agent.Diagnostics;
using SimplySignAuto.Agent.Sessions;
using SimplySignAuto.Agent.Signing;
using SimplySignAuto.Agent.SimplySign;
using SimplySignAuto.Core.Otp;
using SimplySignAuto.Protocol;
using Xunit;

namespace SimplySignAuto.Agent.Tests;

public sealed class SimplySignControllerTests
{
    private const int AgentSessionId = 7;
    private static readonly CertificateAlias Alias = new(
        "document",
        TestPaths.Controlled("pkcs11.dll"),
        2,
        "TOKEN-SERIAL-01",
        "c0ffee01",
        "decafbad");

    [Fact]
    public async Task Already_ready_performs_no_close_no_login_and_does_not_load_otp()
    {
        var probe = new DelegateProbe((_, _) => ProbeResult.ReadyFor(AgentSessionId));
        var runner = new CapturingRunner();
        var otpStore = new FakeOtpStore();
        var controller = CreateController(probe, runner, otpStore: otpStore);

        var result = await controller.EnsureReadyAsync(Alias, CancellationToken.None);

        Assert.True(result.Ready);
        Assert.Empty(runner.Arguments);
        Assert.Equal(0, otpStore.LoadCalls);
    }

    [Theory]
    [MemberData(nameof(NotReadyStates))]
    public async Task A_process_or_credential_state_that_is_not_strictly_ready_triggers_close_and_login(
        ProbeResult initial)
    {
        var calls = 0;
        var probe = new DelegateProbe((_, _) =>
            Task.FromResult(calls++ == 0 ? initial : ProbeResult.ReadyFor(AgentSessionId)));
        var runner = new CapturingRunner();
        var controller = CreateController(probe, runner);

        var result = await controller.EnsureReadyAsync(Alias, CancellationToken.None);

        Assert.True(result.Ready);
        Assert.Equal("/close", Assert.Single(runner.Arguments[0]));
        AssertAutologinArguments(runner.DetachedArguments[0]);
    }

    [Fact]
    public async Task Autologin_uses_the_account_from_the_loaded_otp_profile()
    {
        var account = $"synthetic-account-{Guid.NewGuid():N}";
        var calls = 0;
        var runner = new CapturingRunner();
        var controller = CreateController(
            new DelegateProbe((_, _) =>
                Task.FromResult(calls++ == 0
                    ? ProbeResult.NotReadyFor(AgentSessionId, "token_missing")
                    : ProbeResult.ReadyFor(AgentSessionId))),
            runner,
            otpStore: new FakeOtpStore(account));

        var result = await controller.EnsureReadyAsync(Alias, CancellationToken.None);

        Assert.True(result.Ready);
        AssertAutologinArguments(Assert.Single(runner.DetachedArguments), account);
    }

    [Fact]
    public async Task Close_waits_only_for_the_verified_agent_session_and_for_at_most_fifteen_seconds()
    {
        var clock = new ManualClock(DateTimeOffset.UnixEpoch);
        var processSource = new FakeProcessSource([AgentSessionId]);
        var controller = CreateController(
            new DelegateProbe((_, _) => ProbeResult.NotReadyFor(AgentSessionId, "token_missing")),
            new CapturingRunner(),
            clock,
            processSource);

        var error = await Assert.ThrowsAsync<SimplySignException>(() =>
            controller.EnsureReadyAsync(Alias, CancellationToken.None));

        Assert.Equal("simplysign_close_timeout", error.Code);
        Assert.Equal(TimeSpan.FromSeconds(15), clock.TotalDelay);
        Assert.All(processSource.RequestedSessionIds, id => Assert.Equal(AgentSessionId, id));
    }

    [Fact]
    public async Task Close_does_not_wait_for_a_process_in_another_session()
    {
        var clock = new ManualClock(DateTimeOffset.UnixEpoch);
        var processSource = new FakeProcessSource([11]);
        var runner = new CapturingRunner
        {
            BeforeStartDetached = () => processSource.RunningSessions = [AgentSessionId],
        };
        var calls = 0;
        var controller = CreateController(
            new DelegateProbe((_, _) =>
                Task.FromResult(calls++ == 0
                    ? ProbeResult.NotReadyFor(AgentSessionId, "process_session_mismatch", processRunning: true, processSessionId: 0)
                    : ProbeResult.ReadyFor(AgentSessionId))),
            runner,
            clock,
            processSource);

        var result = await controller.EnsureReadyAsync(Alias, CancellationToken.None);

        Assert.True(result.Ready);
        Assert.Equal(TimeSpan.FromSeconds(1), clock.TotalDelay);
    }

    [Fact]
    public async Task Otp_below_three_seconds_waits_for_next_counter()
    {
        var clock = new ManualClock(DateTimeOffset.UnixEpoch + TimeSpan.FromSeconds(27.5));
        var runner = new CapturingRunner();
        var calls = 0;
        var controller = CreateController(
            new DelegateProbe((_, _) =>
                Task.FromResult(calls++ == 0
                    ? ProbeResult.NotReadyFor(AgentSessionId, "token_missing")
                    : ProbeResult.ReadyFor(AgentSessionId))),
            runner,
            clock);

        await controller.EnsureReadyAsync(Alias, CancellationToken.None);

        Assert.Equal(TimeSpan.FromSeconds(2.5), clock.Delays[0]);
        Assert.Equal(TimeSpan.FromSeconds(3.5), clock.TotalDelay);
        Assert.Equal(["/autologin", "user", "119246"], runner.DetachedArguments[0]);
    }

    [Fact]
    public async Task Otp_with_three_seconds_remaining_is_used()
    {
        var clock = new ManualClock(DateTimeOffset.UnixEpoch + TimeSpan.FromSeconds(27));
        var runner = new CapturingRunner();
        var calls = 0;
        var controller = CreateController(
            new DelegateProbe((_, _) =>
                Task.FromResult(calls++ == 0
                    ? ProbeResult.NotReadyFor(AgentSessionId, "token_missing")
                    : ProbeResult.ReadyFor(AgentSessionId))),
            runner,
            clock);

        await controller.EnsureReadyAsync(Alias, CancellationToken.None);

        Assert.Equal(TimeSpan.FromSeconds(1), clock.Delays[0]);
        Assert.Equal(["/autologin", "user", "920136"], runner.DetachedArguments[0]);
    }

    [Fact]
    public async Task First_failed_login_window_retries_once_with_a_new_current_code()
    {
        var clock = new ManualClock(DateTimeOffset.UnixEpoch);
        var runner = new CapturingRunner();
        var probeCalls = 0;
        var controller = CreateController(
            new DelegateProbe((_, _) => Task.FromResult(
                probeCalls++ >= 31
                    ? ProbeResult.ReadyFor(AgentSessionId)
                    : ProbeResult.NotReadyFor(AgentSessionId, "token_missing"))),
            runner,
            clock);

        var result = await controller.EnsureReadyAsync(Alias, CancellationToken.None);

        Assert.True(result.Ready);
        var loginCalls = runner.DetachedArguments.ToArray();
        Assert.Equal(2, loginCalls.Length);
        Assert.Equal("user", loginCalls[0][1]);
        Assert.Equal("user", loginCalls[1][1]);
        Assert.NotEqual(loginCalls[0][2], loginCalls[1][2]);
        Assert.Equal(3, loginCalls[0].Count);
        Assert.Equal(3, loginCalls[1].Count);
        Assert.Equal(2, runner.DetachedArguments.Count);
    }

    [Fact]
    public async Task Autologin_uses_detached_start_and_a_launch_failure_maps_to_the_stable_missing_exe_code()
    {
        var runner = new CapturingRunner
        {
            DetachedResult = ProcessLaunchResult.Failed("SimplySignDesktop.exe", "process_launch_failed", TimeSpan.Zero),
        };
        var controller = CreateController(
            new DelegateProbe((_, _) => ProbeResult.NotReadyFor(AgentSessionId, "token_missing")),
            runner);

        var error = await Assert.ThrowsAsync<SimplySignException>(() =>
            controller.EnsureReadyAsync(Alias, CancellationToken.None));

        Assert.Equal("simplysign_exe_missing", error.Code);
        Assert.Single(runner.DetachedArguments);
        AssertAutologinArguments(runner.DetachedArguments[0]);
        Assert.DoesNotContain(runner.Arguments, args => args[0] == "/autologin");
    }

    [Fact]
    public async Task Autologin_launch_diagnostic_keeps_native_failure_and_redacts_the_loaded_profile_secret()
    {
        const string secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
        var native = new System.ComponentModel.Win32Exception(5, $"denied path=C:\\SimplySignDesktop.exe secret={secret}");
        var runner = new CapturingRunner
        {
            DetachedResult = ProcessLaunchResult.Failed(
                "SimplySignDesktop.exe",
                "process_launch_failed",
                TimeSpan.Zero,
                native),
        };
        var output = new StringWriter();
        var controller = CreateController(
            new DelegateProbe((_, _) => ProbeResult.NotReadyFor(AgentSessionId, "token_missing")),
            runner,
            diagnostics: new TextWriterAgentDiagnosticSink(output));

        var error = await Assert.ThrowsAsync<SimplySignException>(() =>
            controller.EnsureReadyAsync(Alias, CancellationToken.None));

        Assert.Equal("simplysign_exe_missing", error.Code);
        var diagnostic = output.ToString();
        Assert.DoesNotContain(secret, diagnostic, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("stage=simplysign_login_launch", diagnostic, StringComparison.Ordinal);
        Assert.Contains("message=denied path=C:\\SimplySignDesktop.exe", diagnostic, StringComparison.Ordinal);
        Assert.Contains("win32_error=5", diagnostic, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Second_failed_window_returns_one_stable_sanitized_failure()
    {
        var runner = new CapturingRunner();
        var controller = CreateController(
            new DelegateProbe((_, _) => ProbeResult.NotReadyFor(AgentSessionId, "TOKEN-SERIAL-01")),
            runner,
            new ManualClock(DateTimeOffset.UnixEpoch));

        var error = await Assert.ThrowsAsync<SimplySignException>(() =>
            controller.EnsureReadyAsync(Alias, CancellationToken.None));

        Assert.Equal("simplysign_login_failed", error.Code);
        Assert.DoesNotContain("TOKEN-SERIAL-01", error.Message, StringComparison.Ordinal);
        Assert.Equal(2, runner.DetachedArguments.Count);
    }

    [Fact]
    public async Task Caller_cancellation_stops_polling_promptly()
    {
        using var cancellation = new CancellationTokenSource();
        var clock = new CancellingClock(cancellation);
        var controller = CreateController(
            new DelegateProbe((_, _) => ProbeResult.NotReadyFor(AgentSessionId, "token_missing")),
            new CapturingRunner(),
            clock);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            controller.EnsureReadyAsync(Alias, cancellation.Token));
        Assert.Equal(1, clock.DelayCalls);
    }

    [Fact]
    public async Task Concurrent_ready_requests_are_serialized()
    {
        var probe = new BlockingProbe(AgentSessionId);
        var controller = CreateController(probe, new CapturingRunner());

        var first = controller.EnsureReadyAsync(Alias, CancellationToken.None);
        await probe.FirstEntered;
        var second = controller.EnsureReadyAsync(Alias, CancellationToken.None);
        await Task.Yield();

        Assert.Equal(1, probe.Calls);
        probe.Release();
        await Task.WhenAll(first, second);
        Assert.Equal(1, probe.MaximumConcurrency);
    }

    [Fact]
    public async Task Read_only_probe_never_closes_logs_in_or_loads_otp()
    {
        var probe = new DelegateProbe((_, _) =>
            ProbeResult.NotReadyFor(AgentSessionId, "token_missing", processRunning: true));
        var runner = new CapturingRunner();
        var otpStore = new FakeOtpStore();
        var controller = CreateController(probe, runner, otpStore: otpStore);

        var result = await controller.ProbeAsync(Alias, default);

        Assert.False(result.Ready);
        Assert.Empty(runner.Arguments);
        Assert.Empty(runner.DetachedArguments);
        Assert.Equal(0, otpStore.LoadCalls);
    }

    [Fact]
    public async Task Explicit_relogin_forces_close_and_autologin_even_when_current_probe_would_be_ready()
    {
        var probe = new DelegateProbe((_, _) => ProbeResult.ReadyFor(AgentSessionId));
        var runner = new CapturingRunner();
        var otpStore = new FakeOtpStore();
        var controller = CreateController(probe, runner, otpStore: otpStore);

        var result = await controller.ReloginAsync(Alias, default);

        Assert.True(result.Ready);
        Assert.Equal(["/close"], Assert.Single(runner.Arguments));
        AssertAutologinArguments(Assert.Single(runner.DetachedArguments));
        Assert.Equal(1, otpStore.LoadCalls);
    }

    [Fact]
    public async Task Read_only_probe_waits_on_the_same_gate_as_signing_readiness()
    {
        var probe = new BlockingProbe(AgentSessionId);
        var controller = CreateController(probe, new CapturingRunner());
        var signing = controller.EnsureReadyAsync(Alias, default);
        await probe.FirstEntered;

        var management = controller.ProbeAsync(Alias, default);
        await Task.Yield();

        Assert.Equal(1, probe.Calls);
        probe.Release();
        await Task.WhenAll(signing, management);
        Assert.Equal(1, probe.MaximumConcurrency);
    }

    public static TheoryData<ProbeResult> NotReadyStates => new()
    {
        ProbeResult.NotReadyFor(AgentSessionId, "token_missing", processRunning: true),
        ProbeResult.NotReadyFor(AgentSessionId, "certificate_missing", processRunning: true, tokenPresent: true),
        ProbeResult.NotReadyFor(AgentSessionId, "private_key_missing", processRunning: true, tokenPresent: true, certificatePresent: true),
        ProbeResult.NotReadyFor(AgentSessionId, "token_identifier_mismatch", processRunning: true, tokenPresent: true, certificatePresent: true, privateKeyPresent: true, tokenIdentifierMatches: false),
        ProbeResult.NotReadyFor(AgentSessionId, "certificate_identifier_mismatch", processRunning: true, tokenPresent: true, certificatePresent: true, privateKeyPresent: true, certificateIdentifierMatches: false),
    };

    private static void AssertAutologinArguments(
        IReadOnlyList<string> arguments,
        string expectedAccount = "user")
    {
        Assert.Equal(3, arguments.Count);
        Assert.Equal("/autologin", arguments[0]);
        Assert.Equal(expectedAccount, arguments[1]);
        Assert.Equal(6, arguments[2].Length);
        Assert.All(arguments[2], value => Assert.True(char.IsAsciiDigit(value)));
    }

    private static ManagementHarness CreateController(
        ISimplySignProbe probe,
        IProcessRunner runner,
        ISimplySignClock? clock = null,
        ISimplySignProcessSource? processSource = null,
        IOtpStore? otpStore = null,
        IAgentDiagnosticSink? diagnostics = null)
    {
        var driver = new SimplySignController(
            probe,
            runner,
            processSource ?? new DefaultProcessSource(),
            otpStore ?? new FakeOtpStore(),
            clock ?? new ManualClock(DateTimeOffset.UnixEpoch),
            new InteractiveSessionInfo(AgentSessionId, "S-1-5-21-1000", "1000"),
            TestPaths.Controlled("SimplySignDesktop.exe"),
            diagnostics);
        return new ManagementHarness(
            new SimplySignSessionManager(driver, new SigningOperationGate(), new ProbeCatalog(probe)));
    }

    private sealed class ManagementHarness(SimplySignSessionManager manager)
    {
        public async Task<SimplySignSessionSnapshot> EnsureReadyAsync(
            CertificateAlias alias,
            CancellationToken cancellationToken)
        {
            var snapshot = await manager.EnsureReadyAsync(
                SessionTrigger.BeforeSign,
                cancellationToken);
            return snapshot.State == SimplySignSessionState.Failed
                ? throw new SimplySignException("simplysign_login_failed")
                : snapshot;
        }

        public Task<SimplySignSessionSnapshot> ProbeAsync(
            CertificateAlias alias,
            CancellationToken cancellationToken) =>
            manager.CheckAsync(SessionTrigger.ManualRefresh, cancellationToken);

        public async Task<SimplySignSessionSnapshot> ReloginAsync(
            CertificateAlias alias,
            CancellationToken cancellationToken)
        {
            var snapshot = await manager.EnsureReadyAsync(
                SessionTrigger.ManualRelogin,
                cancellationToken);
            return snapshot.State == SimplySignSessionState.Failed
                ? throw new SimplySignException("simplysign_login_failed")
                : snapshot;
        }
    }

    private sealed class ProbeCatalog(ISimplySignProbe probe) : ICertificateCatalog
    {
        private long _generation;

        public CertificateCatalogSnapshot? Current { get; private set; }
        public IReadOnlyList<CertificateDisplaySummary> DisplaySummaries => [];

        public async Task<CertificateCatalogSnapshot> RefreshAsync(CancellationToken cancellationToken)
        {
            var result = await probe.ProbeAsync(Alias, cancellationToken);
            if (!result.Ready)
            {
                throw new SigningException("certificate_catalog_unavailable");
            }

            Current = new CertificateCatalogSnapshot(
                ++_generation,
                DateTimeOffset.UnixEpoch + TimeSpan.FromTicks(_generation),
                new Dictionary<string, IReadOnlyList<SigningCertificate>>(StringComparer.Ordinal));
            return Current;
        }

        public SigningCertificate Resolve(string serialNumber, SigningKind kind) =>
            throw new NotSupportedException();

        public void Invalidate() => Current = null;
    }

    private sealed class DefaultProcessSource : ISimplySignProcessSource
    {
        public SimplySignProcessState Read(int verifiedSessionId) => new(true, verifiedSessionId);

        public bool IsRunningInSession(int sessionId) => false;
    }

    private sealed class DelegateProbe(
        Func<CertificateAlias, CancellationToken, Task<ProbeResult>> callback) : ISimplySignProbe
    {
        public DelegateProbe(Func<CertificateAlias, CancellationToken, ProbeResult> callback)
            : this((alias, cancellationToken) => Task.FromResult(callback(alias, cancellationToken)))
        {
        }

        public Task<ProbeResult> ProbeAsync(CertificateAlias alias, CancellationToken cancellationToken) =>
            callback(alias, cancellationToken);
    }

    private sealed class CapturingRunner : IProcessRunner
    {
        public List<IReadOnlyList<string>> Arguments { get; } = [];

        public List<IReadOnlyList<string>> DetachedArguments { get; } = [];

        public ProcessLaunchResult DetachedResult { get; set; } =
            ProcessLaunchResult.Success("SimplySignDesktop.exe", TimeSpan.Zero);

        public Action? BeforeStartDetached { get; init; }

        public Task<ProcessResult> RunAsync(
            string executable,
            IReadOnlyList<string> arguments,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Arguments.Add(arguments.ToArray());
            return Task.FromResult(ProcessResult.Exited(Path.GetFileName(executable), 0, TimeSpan.Zero, string.Empty, string.Empty));
        }

        public Task<ProcessLaunchResult> StartDetachedAsync(
            string executable,
            IReadOnlyList<string> arguments,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            BeforeStartDetached?.Invoke();
            DetachedArguments.Add(arguments.ToArray());
            return Task.FromResult(DetachedResult);
        }
    }

    private sealed class FakeOtpStore(string account = "user") : IOtpStore
    {
        public int LoadCalls { get; private set; }

        public string Path => "/controlled/otp.dat";

        public Task SaveAsync(OtpauthProfile profile, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public Task<OtpauthProfile> LoadAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LoadCalls++;
            return Task.FromResult(new OtpauthProfile(
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
                "SHA256",
                6,
                30,
                "Certum",
                account));
        }
    }

    private sealed class FakeProcessSource(IReadOnlyList<int> runningSessions) : ISimplySignProcessSource
    {
        public IReadOnlyList<int> RunningSessions { get; set; } = runningSessions;

        public List<int> RequestedSessionIds { get; } = [];

        public bool IsRunningInSession(int sessionId)
        {
            RequestedSessionIds.Add(sessionId);
            return RunningSessions.Contains(sessionId);
        }

        public SimplySignProcessState Read(int verifiedSessionId) =>
            RunningSessions.Count == 0
                ? new SimplySignProcessState(false, null)
                : new SimplySignProcessState(
                    true,
                    RunningSessions.Contains(verifiedSessionId) ? verifiedSessionId : RunningSessions[0]);
    }

    private class ManualClock(DateTimeOffset utcNow) : ISimplySignClock
    {
        public DateTimeOffset UtcNow { get; protected set; } = utcNow;

        public TimeSpan TotalDelay { get; private set; }

        public List<TimeSpan> Delays { get; } = [];

        public virtual Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Delays.Add(delay);
            TotalDelay += delay;
            UtcNow += delay;
            return Task.CompletedTask;
        }
    }

    private sealed class CancellingClock(CancellationTokenSource cancellation) : ManualClock(DateTimeOffset.UnixEpoch)
    {
        public int DelayCalls { get; private set; }

        public override Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
        {
            DelayCalls++;
            cancellation.Cancel();
            cancellationToken.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }
    }

    private sealed class BlockingProbe(int sessionId) : ISimplySignProbe
    {
        private readonly TaskCompletionSource _firstEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _concurrency;

        public Task FirstEntered => _firstEntered.Task;

        public int Calls { get; private set; }

        public int MaximumConcurrency { get; private set; }

        public async Task<ProbeResult> ProbeAsync(CertificateAlias alias, CancellationToken cancellationToken)
        {
            Calls++;
            var concurrency = Interlocked.Increment(ref _concurrency);
            MaximumConcurrency = Math.Max(MaximumConcurrency, concurrency);
            try
            {
                if (Calls == 1)
                {
                    _firstEntered.TrySetResult();
                    await _release.Task.WaitAsync(cancellationToken);
                }

                return ProbeResult.ReadyFor(sessionId);
            }
            finally
            {
                Interlocked.Decrement(ref _concurrency);
            }
        }

        public void Release() => _release.TrySetResult();
    }
}
