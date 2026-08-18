using SimplySignAuto.Agent.Ipc;
using SimplySignAuto.Agent.Diagnostics;
using SimplySignAuto.Protocol;
using Xunit;

namespace SimplySignAuto.Agent.Tests;

public sealed class AgentStartupPreparationTests
{
    [Fact]
    public async Task Unexpected_failure_keeps_stable_result_and_reports_the_original_exception()
    {
        var expected = new InvalidOperationException("startup path=C:\\ProgramData\\SimplySignAuto line=91");
        var diagnostics = new RecordingAgentDiagnosticSink();
        using var cache = new AgentStartupPreparationCache(
            (_, _) => Task.FromException<PrepareSimplySignSessionResult>(expected),
            diagnostics);
        var command = new PrepareSimplySignSessionCommand(Guid.NewGuid());

        var result = await cache.ExecuteAsync(command, default);

        Assert.Equal(SimplySignSessionState.Failed, result.State);
        Assert.Equal("internal_error", result.ErrorCode);
        var diagnostic = Assert.Single(diagnostics.Diagnostics);
        Assert.Equal("startup_preparation", diagnostic.Stage);
        Assert.Equal("internal_error", diagnostic.StableCode);
        Assert.Same(expected, diagnostic.Exception);
    }

    [Fact]
    public async Task Concurrent_and_completed_duplicate_request_reuses_one_operation_and_result()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        var cache = new AgentStartupPreparationCache(async (command, token) =>
        {
            Interlocked.Increment(ref calls);
            entered.TrySetResult();
            await release.Task.WaitAsync(token);
            return new PrepareSimplySignSessionResult(command.RequestId, SimplySignSessionState.Ready, null);
        });
        var command = new PrepareSimplySignSessionCommand(Guid.NewGuid());

        var first = cache.ExecuteAsync(command, default);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(1));
        var duplicateWhileRunning = cache.ExecuteAsync(command, default);
        Assert.Same(first, duplicateWhileRunning);
        release.TrySetResult();
        var expected = await first;

        Assert.Equal(expected, await duplicateWhileRunning);
        Assert.Equal(expected, await cache.ExecuteAsync(command, default));
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task Completed_cache_is_bounded_to_sixteen_without_evicting_running_requests()
    {
        var calls = new Dictionary<Guid, int>();
        var blockedId = Guid.NewGuid();
        var blocked = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cache = new AgentStartupPreparationCache(async (command, token) =>
        {
            calls[command.RequestId] = calls.GetValueOrDefault(command.RequestId) + 1;
            if (command.RequestId == blockedId)
            {
                await blocked.Task.WaitAsync(token);
            }

            return new PrepareSimplySignSessionResult(command.RequestId, SimplySignSessionState.Ready, null);
        });
        var running = cache.ExecuteAsync(new PrepareSimplySignSessionCommand(blockedId), default);
        var completed = Enumerable.Range(0, 17).Select(_ => Guid.NewGuid()).ToArray();
        foreach (var requestId in completed)
        {
            await cache.ExecuteAsync(new PrepareSimplySignSessionCommand(requestId), default);
        }

        Assert.Same(running, cache.ExecuteAsync(new PrepareSimplySignSessionCommand(blockedId), default));
        await cache.ExecuteAsync(new PrepareSimplySignSessionCommand(completed[^1]), default);
        await cache.ExecuteAsync(new PrepareSimplySignSessionCommand(completed[0]), default);
        blocked.TrySetResult();
        await running;

        Assert.Equal(1, calls[blockedId]);
        Assert.Equal(1, calls[completed[^1]]);
        Assert.Equal(2, calls[completed[0]]);
    }

    [Fact]
    public async Task Process_shutdown_cancels_and_observes_a_running_preparation()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var cache = new AgentStartupPreparationCache(async (command, token) =>
        {
            entered.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return new PrepareSimplySignSessionResult(command.RequestId, SimplySignSessionState.Ready, null);
        });
        var operation = cache.ExecuteAsync(
            new PrepareSimplySignSessionCommand(Guid.NewGuid()),
            default);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(1));

        cache.Dispose();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation);
    }
}
