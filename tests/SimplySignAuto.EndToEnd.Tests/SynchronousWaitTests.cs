using System.Net;
using System.Net.Http.Json;
using SimplySignAuto.Service.Api;
using SimplySignAuto.Service.Jobs;
using Xunit;

namespace SimplySignAuto.EndToEnd.Tests;

public sealed class SynchronousWaitTests
{
    [Theory]
    [InlineData(1)]
    [InlineData(120)]
    public async Task Inclusive_wait_seconds_boundaries_complete_through_real_http(int waitSeconds)
    {
        await using var harness = await EndToEndHarness.StartAsync();
        await harness.StartAgentAsync();

        using var response = await harness.Client.SendAsync(
            EndToEndFixtures.PdfRequest(
                $"/v1/sign?waitSeconds={waitSeconds}",
                idempotencyKey: "sync-boundary-" + waitSeconds));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Single(harness.Agent.ReceivedCommands);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(121)]
    public async Task Out_of_range_wait_seconds_are_rejected_before_job_creation(int waitSeconds)
    {
        await using var harness = await EndToEndHarness.StartAsync();

        using var response = await harness.Client.SendAsync(
            EndToEndFixtures.PdfRequest($"/v1/sign?waitSeconds={waitSeconds}"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(await harness.Jobs.GetAllAsync());
    }

    [Fact]
    public async Task Sign_returns_the_real_file_when_the_single_agent_finishes_inside_the_window()
    {
        await using var harness = await EndToEndHarness.StartAsync();
        await harness.StartAgentAsync();

        using var response = await harness.Client.SendAsync(
            EndToEndFixtures.PdfRequest("/v1/sign?waitSeconds=5", idempotencyKey: "sync-complete"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/pdf", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("document.signed.pdf", response.Content.Headers.ContentDisposition?.FileNameStar);
        Assert.Equal(
            EndToEndFixtures.TwoPagePdf.Concat(FakeAgent.SafeTrailer).ToArray(),
            await response.Content.ReadAsByteArrayAsync());
        Assert.Single(harness.Agent.ReceivedCommands);
    }

    [Fact]
    public async Task Sign_timeout_returns_the_same_job_without_cancelling_it()
    {
        await using var harness = await EndToEndHarness.StartAsync();
        await harness.StartAgentAsync(FakeAgentBehavior.HoldBeforeTerminal);

        using var response = await harness.Client.SendAsync(
            EndToEndFixtures.PdfRequest("/v1/sign?waitSeconds=1", idempotencyKey: "sync-timeout"));

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var accepted = Assert.IsType<CreateJobResponse>(
            await response.Content.ReadFromJsonAsync<CreateJobResponse>());
        Assert.Equal(accepted.JobId, (await harness.Agent.WaitForCommandAsync()).JobId);
        _ = await harness.WaitForStateAsync(accepted.JobId, "verifying");
        harness.Agent.ReleaseBeforeTerminal();
        _ = await harness.WaitForStateAsync(accepted.JobId, "succeeded");
        Assert.Single(harness.Agent.ReceivedCommands);
    }

    [Fact]
    public async Task Caller_cancellation_after_upload_does_not_cancel_the_persisted_job()
    {
        await using var harness = await EndToEndHarness.StartAsync();
        await harness.StartAgentAsync(FakeAgentBehavior.HoldBeforeTerminal);
        using var cancellation = new CancellationTokenSource();
        using var request = EndToEndFixtures.PdfRequest(
            "/v1/sign?waitSeconds=120",
            idempotencyKey: "sync-caller-cancel");

        var responseTask = harness.Client.SendAsync(request, cancellation.Token);
        var command = await harness.Agent.WaitForCommandAsync();
        await harness.Agent.BeforeTerminalReached.WaitAsync(TimeSpan.FromSeconds(10));
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => responseTask);

        harness.Agent.ReleaseBeforeTerminal();
        var succeeded = await harness.WaitForStateAsync(command.JobId, "succeeded");
        using var download = await harness.Client.GetAsync($"/v1/jobs/{command.JobId:D}/result");
        Assert.Equal(HttpStatusCode.OK, download.StatusCode);
        Assert.Equal("succeeded", succeeded.State);
        Assert.Single(harness.Agent.ReceivedCommands);
    }

    [Fact]
    public async Task Lost_sync_response_retries_the_same_idempotency_key_and_signs_only_once()
    {
        await using var harness = await EndToEndHarness.StartAsync();
        await harness.StartAgentAsync(FakeAgentBehavior.HoldBeforeTerminal);
        using var cancellation = new CancellationTokenSource();
        using var first = EndToEndFixtures.PdfRequest(
            "/v1/sign?waitSeconds=120",
            idempotencyKey: "sync-response-lost");

        var lostResponse = harness.Client.SendAsync(first, cancellation.Token);
        var command = await harness.Agent.WaitForCommandAsync();
        await harness.Agent.HeldBeforeTerminalReached.WaitAsync(TimeSpan.FromSeconds(10));
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => lostResponse);
        harness.Agent.ReleaseBeforeTerminal();
        _ = await harness.WaitForStateAsync(command.JobId, "succeeded");

        using var retry = await harness.Client.SendAsync(
            EndToEndFixtures.PdfRequest(
                "/v1/sign?waitSeconds=5",
                idempotencyKey: "sync-response-lost"));

        Assert.Equal(HttpStatusCode.OK, retry.StatusCode);
        Assert.Equal(
            EndToEndFixtures.TwoPagePdf.Concat(FakeAgent.SafeTrailer).ToArray(),
            await retry.Content.ReadAsByteArrayAsync());
        Assert.Single(harness.Agent.ReceivedCommands);
        Assert.Single(await harness.Jobs.GetAllAsync());
    }

    [Fact]
    public async Task Completion_after_waiter_registration_but_before_timeout_returns_terminal_file()
    {
        var time = new ControllableTimeProvider(DateTimeOffset.Parse("2026-08-09T00:00:00Z"));
        var registration = new WaitRegistrationObserver();
        var root = Directory.CreateTempSubdirectory("SSA-SYNC-COMPLETE-FIRST-").FullName;
        await using var harness = await EndToEndHarness.StartAsync(
            root,
            deleteRoot: true,
            timeProvider: time,
            waitRegistrationObserver: registration);
        await harness.StartAgentAsync(FakeAgentBehavior.HoldBeforeTerminal);
        using var request = EndToEndFixtures.PdfRequest(
            "/v1/sign?waitSeconds=1",
            idempotencyKey: "sync-complete-first");

        var responseTask = harness.Client.SendAsync(request);
        var command = await harness.Agent.WaitForCommandAsync();
        await harness.Agent.HeldBeforeTerminalReached.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(command.JobId, await registration.Registered.WaitAsync(TimeSpan.FromSeconds(10)));
        harness.Agent.ReleaseBeforeTerminal();
        using var response = await responseTask;

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(
            EndToEndFixtures.TwoPagePdf.Concat(FakeAgent.SafeTrailer).ToArray(),
            await response.Content.ReadAsByteArrayAsync());
        Assert.Single(harness.Agent.ReceivedCommands);
        Assert.Single(await harness.Jobs.GetAllAsync());
    }

    [Fact]
    public async Task Timeout_after_waiter_registration_returns_accepted_then_same_job_succeeds()
    {
        var time = new ControllableTimeProvider(DateTimeOffset.Parse("2026-08-09T00:00:00Z"));
        var registration = new WaitRegistrationObserver();
        var root = Directory.CreateTempSubdirectory("SSA-SYNC-TIMEOUT-FIRST-").FullName;
        await using var harness = await EndToEndHarness.StartAsync(
            root,
            deleteRoot: true,
            timeProvider: time,
            waitRegistrationObserver: registration);
        await harness.StartAgentAsync(FakeAgentBehavior.HoldBeforeTerminal);
        using var request = EndToEndFixtures.PdfRequest(
            "/v1/sign?waitSeconds=1",
            idempotencyKey: "sync-timeout-first");

        var responseTask = harness.Client.SendAsync(request);
        var command = await harness.Agent.WaitForCommandAsync();
        await harness.Agent.HeldBeforeTerminalReached.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(command.JobId, await registration.Registered.WaitAsync(TimeSpan.FromSeconds(10)));
        time.Advance(TimeSpan.FromSeconds(1));
        using var response = await responseTask;

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
        var accepted = Assert.IsType<CreateJobResponse>(
            await response.Content.ReadFromJsonAsync<CreateJobResponse>());
        Assert.Equal(command.JobId, accepted.JobId);

        harness.Agent.ReleaseBeforeTerminal();
        _ = await harness.WaitForStateAsync(command.JobId, "succeeded");
        Assert.Single(harness.Agent.ReceivedCommands);
        Assert.Single(await harness.Jobs.GetAllAsync());
    }

    [Fact]
    public async Task Failed_terminal_returns_a_safe_problem_immediately()
    {
        await using var harness = await EndToEndHarness.StartAsync();
        await harness.StartAgentAsync(FakeAgentBehavior.Fail);

        using var response = await harness.Client.SendAsync(
            EndToEndFixtures.PdfRequest("/v1/sign?waitSeconds=5", idempotencyKey: "sync-failed"));

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        var problem = Assert.IsType<ApiProblem>(await response.Content.ReadFromJsonAsync<ApiProblem>());
        Assert.Equal("pdf_sign_failed", problem.Code);
        Assert.NotEqual(Guid.Empty, problem.JobId);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain(harness.Root, body, StringComparison.Ordinal);
        Assert.DoesNotContain("Synthetic signing failure", body, StringComparison.Ordinal);
    }

    private sealed class WaitRegistrationObserver : IJobWaitRegistrationObserver
    {
        private readonly TaskCompletionSource<Guid> _registered =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<Guid> Registered => _registered.Task;

        public void OnRegistered(Guid jobId) => _registered.TrySetResult(jobId);
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
            if (elapsed < TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(elapsed));
            }

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
